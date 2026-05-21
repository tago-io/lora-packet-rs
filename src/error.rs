//! Crate-wide error type.

use alloc::string::String;

/// All errors produced by the crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// Wire-format buffer too short for the expected message structure.
  #[error("invalid wire format: expected at least {expected} bytes, got {got}")]
  TooShort {
    /// Required minimum length.
    expected: usize,
    /// Actual length provided.
    got: usize,
  },

  /// `MType` field in `MHDR` did not match any known value.
  #[error("invalid MType: {0:#05b}")]
  InvalidMType(u8),

  /// Major version field in `MHDR` was not zero (the only defined value).
  #[error("invalid major version: {0:#04b}")]
  InvalidMajor(u8),

  /// Rejoin Request type was not 0, 1, or 2.
  #[error("invalid rejoin type: {0}")]
  InvalidRejoinType(u8),

  /// `FRMPayload` present with `FPort` = 0 alongside non-empty `FOpts` (`LoRaWAN` forbids this).
  #[error("FOpts and FPort=0 cannot both carry MAC commands")]
  ConflictingMacCommands,

  /// `FOpts` exceeds the 15-byte maximum encoded in `FCtrl.FOptsLen`.
  #[error("FOpts length {0} exceeds maximum of 15")]
  FOptsTooLong(usize),

  /// A key slice supplied to a constructor had the wrong length.
  #[error("expected key length {expected}, got {got}")]
  InvalidKeyLength {
    /// Required length.
    expected: usize,
    /// Actual slice length.
    got: usize,
  },

  /// An identifier slice supplied to a constructor had the wrong length.
  #[error("expected identifier length {expected}, got {got}")]
  InvalidIdentifierLength {
    /// Required length.
    expected: usize,
    /// Actual slice length.
    got: usize,
  },

  /// MIC verification failed.
  #[error("MIC mismatch")]
  MicMismatch,

  /// A MIC or crypto operation needed a key that was not supplied.
  #[error("missing key for operation: {0}")]
  MissingKey(&'static str),

  /// Builder finalization failed because a required field was not set.
  #[error("required builder field not set: {0}")]
  MissingField(&'static str),

  /// Builder produced a payload larger than the wire encoding allows.
  #[error("payload too large: {0} bytes")]
  PayloadTooLarge(usize),

  /// Join Accept ciphertext had a length outside the valid range (17 or 33 bytes).
  #[error("invalid Join Accept length: {0} bytes (expected 17 or 33)")]
  InvalidJoinAcceptLength(usize),

  /// Generic catch-all with a string message (used sparingly).
  #[error("{0}")]
  Other(String),

  /// Hex decoding failed (only available with the `hex_base64` feature).
  #[cfg(feature = "hex_base64")]
  #[error("hex decode error: {0}")]
  Hex(hex::FromHexError),

  /// Base64 decoding failed (only available with the `hex_base64` feature).
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
