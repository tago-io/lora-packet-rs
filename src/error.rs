//! Crate-wide error type.
//!
//! Every fallible public function returns [`Result<T>`], which is an alias for
//! `core::result::Result<T, Error>`. The [`Error`] enum carries enough context
//! (lengths, key roles, field names) to diagnose failures without re-parsing
//! strings. Match on the variant, not on the `Display` output.

use alloc::string::String;

/// Every error this crate can produce.
///
/// Variants split into three rough buckets:
/// 1. **Parsing** ([`Error::TooShort`], [`Error::TooLong`],
///    [`Error::InvalidMType`], [`Error::InvalidMajor`],
///    [`Error::InvalidRejoinType`], [`Error::ConflictingMacCommands`],
///    [`Error::FOptsTooLong`], [`Error::InvalidJoinAcceptLength`]).
/// 2. **Construction** ([`Error::InvalidKeyLength`],
///    [`Error::InvalidIdentifierLength`], [`Error::MissingField`],
///    [`Error::PayloadTooLarge`]).
/// 3. **Crypto / MIC** ([`Error::MicMismatch`], [`Error::MissingKey`]).
///
/// The `Other`, `Hex`, and `Base64` variants exist for boundary conversions
/// and should not need to be matched in normal code paths.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// Wire buffer ran out before the expected structure was complete.
  ///
  /// Both `expected` and `got` are in bytes. Always inspect both fields; the
  /// `expected` value differs by message type (5 for the minimum
  /// `PHYPayload`, 18 for a Join Request body, etc.).
  #[error("invalid wire format: expected at least {expected} bytes, got {got}")]
  TooShort {
    /// Required minimum length.
    expected: usize,
    /// Actual length provided.
    got: usize,
  },

  /// Wire buffer exceeded the `LoRaWAN` PHY maximum of 256 bytes.
  ///
  /// PHY payload size varies by region but never exceeds 256 bytes total in
  /// any `LoRaWAN` regional plan. Beyond this limit, the 1-byte length field
  /// in CMAC B0/B1 blocks would silently wrap and produce a deterministic
  /// but wrong MIC. Reject the input early.
  #[error("invalid wire format: {got} bytes exceeds maximum of 256")]
  TooLong {
    /// Actual length provided.
    got: usize,
  },

  /// `MType` field in the MHDR did not match any known value.
  ///
  /// All 3-bit patterns are currently defined by the `LoRaWAN` spec, so this
  /// variant is reserved for forward compatibility.
  #[error("invalid MType: {0:#05b}")]
  InvalidMType(u8),

  /// Major version field in the MHDR was not zero (the only defined value).
  #[error("invalid major version: {0:#04b}")]
  InvalidMajor(u8),

  /// Rejoin Request type was not 0, 1, or 2.
  #[error("invalid rejoin type: {0}")]
  InvalidRejoinType(u8),

  /// `FRMPayload` present with `FPort = 0` alongside non-empty `FOpts`.
  ///
  /// The `LoRaWAN` MAC spec forbids carrying MAC commands in both places at
  /// once.
  #[error("FOpts and FPort=0 cannot both carry MAC commands")]
  ConflictingMacCommands,

  /// `FOpts` exceeds the 15-byte maximum encoded in `FCtrl.FOptsLen`.
  ///
  /// Returned by [`crate::LoraPacketBuilder::build_unsigned`] when the
  /// builder's `f_opts` vector is too long; not raised by wire parsing
  /// because `FCtrl` only carries 4 bits of length.
  #[error("FOpts length {0} exceeds maximum of 15")]
  FOptsTooLong(usize),

  /// A key slice supplied to `from_slice` had the wrong length.
  ///
  /// All `LoRaWAN` keys are 16 bytes (AES-128).
  #[error("expected key length {expected}, got {got}")]
  InvalidKeyLength {
    /// Required length.
    expected: usize,
    /// Actual slice length.
    got: usize,
  },

  /// An identifier slice supplied to `from_slice` had the wrong length.
  ///
  /// Lengths per identifier: `DevAddr` = 4, `NetId` = 3, `DevEui` /
  /// `AppEui` = 8, `DevNonce` = 2, `AppNonce` = 3.
  #[error("expected identifier length {expected}, got {got}")]
  InvalidIdentifierLength {
    /// Required length.
    expected: usize,
    /// Actual slice length.
    got: usize,
  },

  /// MIC verification failed.
  ///
  /// The compare is constant-time (via `subtle::ConstantTimeEq`). Treat this
  /// as a security event, not a parse error.
  #[error("MIC mismatch")]
  MicMismatch,

  /// A MIC or crypto operation required a key that was not supplied.
  ///
  /// The string argument names the missing role (e.g. `"nwk_s_key required
  /// for Data MIC"`).
  #[error("missing key for operation: {0}")]
  MissingKey(&'static str),

  /// Builder finalisation failed because a required field was not set.
  ///
  /// The string argument names the field (`"dev_addr"`, `"join_eui"`, etc.).
  /// Match on the field name to suggest a builder method to set it.
  #[error("required builder field not set: {0}")]
  MissingField(&'static str),

  /// `FRMPayload` exceeded the AES-CTR block-index limit (255 blocks =
  /// 4080 bytes).
  ///
  /// Beyond this size, the 1-byte block counter in the keystream block would
  /// overflow and silently produce ciphertext no other `LoRaWAN` stack can
  /// decrypt.
  #[error("payload too large: {0} bytes")]
  PayloadTooLarge(usize),

  /// Join Accept ciphertext had a length outside the valid range.
  ///
  /// A Join Accept is one AES block (17 bytes total: MHDR + 1 block + MIC)
  /// or two blocks with a `CFList` (33 bytes total).
  #[error("invalid Join Accept length: {0} bytes (expected 17 or 33)")]
  InvalidJoinAcceptLength(usize),

  /// Catch-all carrying a free-form message. Used sparingly for situations
  /// no other variant fits; downstream code should not match on the string.
  #[error("{0}")]
  Other(String),

  /// Hex decoding failed (only with the `hex_base64` feature).
  #[cfg(feature = "hex_base64")]
  #[error("hex decode error: {0}")]
  Hex(hex::FromHexError),

  /// Base64 decoding failed (only with the `hex_base64` feature).
  #[cfg(feature = "hex_base64")]
  #[error("base64 decode error: {0}")]
  Base64(base64::DecodeError),
}

#[cfg(feature = "hex_base64")]
impl From<hex::FromHexError> for Error {
  fn from(e: hex::FromHexError) -> Self {
    Self::Hex(e)
  }
}

#[cfg(feature = "hex_base64")]
impl From<base64::DecodeError> for Error {
  fn from(e: base64::DecodeError) -> Self {
    Self::Base64(e)
  }
}

/// Convenience alias for `core::result::Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
  use super::*;
  use alloc::string::ToString;

  #[test]
  fn error_display_includes_context() {
    let e = Error::TooShort { expected: 12, got: 7 };
    assert_eq!(e.to_string(), "invalid wire format: expected at least 12 bytes, got 7");
  }

  #[test]
  fn invalid_mtype_format() {
    let e = Error::InvalidMType(0b111);
    assert_eq!(e.to_string(), "invalid MType: 0b111");
  }

  #[test]
  fn result_alias_works() {
    #[allow(clippy::unnecessary_wraps)]
    fn ok() -> Result<u8> {
      Ok(42)
    }
    fn err() -> Result<u8> {
      Err(Error::MicMismatch)
    }
    assert_eq!(ok().unwrap(), 42);
    assert!(err().is_err());
  }
}
