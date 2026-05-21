//! Strong typed primitives for `LoRaWAN` packets.
//!
//! Three groups of types live here:
//!
//! 1. **Message metadata enums:** [`MType`], [`Direction`], [`LorawanVersion`].
//! 2. **Bitfield byte wrappers:** [`Mhdr`], [`FCtrl`], [`DlSettings`].
//! 3. **Strong newtypes for identifiers and keys**: [`DevAddr`], [`DevEui`],
//!    [`AppEui`] (alias [`JoinEui`]), [`NetId`], [`DevNonce`], [`AppNonce`]
//!    (alias [`JoinNonce`]), [`AppKey`], [`NwkKey`], [`AppSKey`], [`NwkSKey`],
//!    [`FNwkSIntKey`], [`SNwkSIntKey`], [`NwkSEncKey`], [`JSIntKey`],
//!    [`JSEncKey`], [`RootWorSKey`], [`WorSIntKey`], [`WorSEncKey`].
//!
//! Identifier newtypes hold `Copy` byte arrays and impl `Debug`. Key newtypes
//! do *not* implement `Copy` and have a redacted `Debug` impl
//! (`AppKey(***)`); their bytes are wiped on drop via `zeroize::ZeroizeOnDrop`.
//! Pass keys by reference; clone only when ownership is genuinely required.
//!
//! ## Endianness
//!
//! All identifier newtypes store bytes in display order (big-endian,
//! left-to-right as you would print them). [`crate::LoraPacket::from_wire`]
//! and [`crate::LoraPacket::to_wire`] reverse byte order for you when reading
//! or writing the little-endian wire format.

use crate::error::{Error, Result};

/// `LoRaWAN` message types as encoded in the high 3 bits of the MHDR byte.
///
/// Use [`MType::from_mhdr`] to extract from a raw MHDR byte, or
/// [`Mhdr::m_type`] when you already have a [`Mhdr`] wrapper.
///
/// All variants are routed through the matching [`crate::Payload`] variant
/// when you parse with [`crate::LoraPacket::from_wire`].
///
/// # Examples
///
/// ```
/// use lora_packet::MType;
///
/// assert_eq!(MType::from_mhdr(0x40).unwrap(), MType::UnconfirmedDataUp);
/// assert_eq!(MType::from_mhdr(0xE0).unwrap(), MType::Proprietary);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MType {
  /// Device join request (OTAA, MHDR bits = `000`).
  JoinRequest = 0b000,
  /// Server response to a join request (MHDR bits = `001`).
  JoinAccept = 0b001,
  /// Uplink data without acknowledgment (MHDR bits = `010`).
  UnconfirmedDataUp = 0b010,
  /// Downlink data without acknowledgment (MHDR bits = `011`).
  UnconfirmedDataDown = 0b011,
  /// Uplink data with acknowledgment (MHDR bits = `100`).
  ConfirmedDataUp = 0b100,
  /// Downlink data with acknowledgment (MHDR bits = `101`).
  ConfirmedDataDown = 0b101,
  /// Rejoin request (`LoRaWAN` 1.1 only, MHDR bits = `110`).
  RejoinRequest = 0b110,
  /// Proprietary message body (MHDR bits = `111`).
  Proprietary = 0b111,
}

impl MType {
  /// Parse the 3-bit `MType` field from an MHDR byte.
  ///
  /// # Errors
  /// Returns [`Error::InvalidMType`] when the field does not match any defined value.
  /// All 3-bit patterns are currently defined, so this never fails in practice,
  /// but the signature is kept fallible for forward compatibility.
  pub const fn from_mhdr(mhdr: u8) -> Result<Self> {
    match (mhdr >> 5) & 0b111 {
      0b000 => Ok(Self::JoinRequest),
      0b001 => Ok(Self::JoinAccept),
      0b010 => Ok(Self::UnconfirmedDataUp),
      0b011 => Ok(Self::UnconfirmedDataDown),
      0b100 => Ok(Self::ConfirmedDataUp),
      0b101 => Ok(Self::ConfirmedDataDown),
      0b110 => Ok(Self::RejoinRequest),
      0b111 => Ok(Self::Proprietary),
      n => Err(Error::InvalidMType(n)),
    }
  }
}

/// Direction of a `LoRaWAN` data frame.
///
/// Set automatically when you parse with [`crate::LoraPacket::from_wire`]
/// (from the `MType`) or when you call [`crate::LoraPacketBuilder::data`].
/// Read it back on [`crate::Data::direction`].
///
/// Direction selects which key is used for `FRMPayload` and `FOpts` crypt
/// (see [`crate::Data::decrypt_payload`]) and which CMAC block layout is
/// used for the MIC (see [`crate::LoraPacket::calculate_mic_v1_0`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Direction {
  /// Device to network server.
  Uplink,
  /// Network server to device.
  Downlink,
}

/// `LoRaWAN` protocol version, used to pick the right MIC and crypto path.
///
/// 1.0 and 1.1 use the same AES-CMAC primitive but different key roles, B
/// blocks, and (for uplinks) a dual-MIC construction. The version is implicit
/// in which method you call:
///
/// - [`crate::LoraPacket::verify_mic_v1_0`] +
///   [`crate::V1_0MicKeys`] for 1.0.x.
/// - [`crate::LoraPacket::verify_mic_v1_1`] +
///   [`crate::V1_1MicKeys`] for 1.1.
///
/// This enum is exposed for callers that route or log by version; it does not
/// itself dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LorawanVersion {
  /// `LoRaWAN` 1.0.x.
  V1_0,
  /// `LoRaWAN` 1.1.
  V1_1,
}

/// MHDR byte: 3 bits `MType`, 3 bits RFU, 2 bits Major.
///
/// Wraps the leading byte of every `PHYPayload`. Build with
/// [`Mhdr::from_parts`] or wrap an existing byte with [`Mhdr::new`].
///
/// # Examples
///
/// ```
/// use lora_packet::{Mhdr, MType};
///
/// let m = Mhdr::from_parts(MType::UnconfirmedDataUp, 0);
/// assert_eq!(m.as_byte(), 0x40);
/// assert_eq!(m.m_type().unwrap(), MType::UnconfirmedDataUp);
/// assert_eq!(m.major(), 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mhdr(pub u8);

impl Mhdr {
  /// Construct from a raw byte.
  pub const fn new(b: u8) -> Self {
    Self(b)
  }

  /// Build MHDR from `MType` and major version (default major = 0).
  pub const fn from_parts(m_type: MType, major: u8) -> Self {
    Self(((m_type as u8) << 5) | (major & 0b11))
  }

  /// Decode the `MType`.
  ///
  /// # Errors
  /// Returns [`Error::InvalidMType`] if the field is not a defined value
  /// (currently all patterns are defined).
  pub const fn m_type(&self) -> Result<MType> {
    MType::from_mhdr(self.0)
  }

  /// Lower 2 bits, the major version. Only `0b00` is defined.
  pub const fn major(&self) -> u8 {
    self.0 & 0b11
  }

  /// Raw byte for serialization.
  pub const fn as_byte(&self) -> u8 {
    self.0
  }
}

/// `FCtrl` byte in a data-frame FHDR.
///
/// Bit layout (uplink and downlink differ on bit 4):
/// - Bit 7: ADR
/// - Bit 6: `ADRACKReq` (uplink) / RFU (downlink)
/// - Bit 5: ACK
/// - Bit 4: `ClassB` (uplink) / `FPending` (downlink)
/// - Bits 3..0: `FOptsLen`
///
/// # Examples
///
/// ```
/// use lora_packet::FCtrl;
///
/// let c = FCtrl(0b1010_0110);
/// assert!(c.adr());
/// assert!(c.ack());
/// assert_eq!(c.f_opts_len(), 6);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FCtrl(pub u8);

impl FCtrl {
  /// Construct from a raw byte.
  pub const fn new(b: u8) -> Self {
    Self(b)
  }

  /// ADR bit.
  pub const fn adr(&self) -> bool {
    self.0 & 0b1000_0000 != 0
  }

  /// `ADRACKReq` bit (uplink only).
  pub const fn adr_ack_req(&self) -> bool {
    self.0 & 0b0100_0000 != 0
  }

  /// ACK bit.
  pub const fn ack(&self) -> bool {
    self.0 & 0b0010_0000 != 0
  }

  /// `FPending` bit (downlink only; same position as `ClassB` on uplink).
  pub const fn f_pending(&self) -> bool {
    self.0 & 0b0001_0000 != 0
  }

  /// `ClassB` bit (uplink only; same position as `FPending` on downlink).
  pub const fn class_b(&self) -> bool {
    self.0 & 0b0001_0000 != 0
  }

  /// `FOpts` length in bytes (0..=15).
  pub const fn f_opts_len(&self) -> u8 {
    self.0 & 0b0000_1111
  }

  /// Raw byte for serialization.
  pub const fn as_byte(&self) -> u8 {
    self.0
  }
}

/// `DLSettings` byte in a Join Accept.
///
/// Bit layout:
/// - Bit 7: `OptNeg` (`LoRaWAN` 1.1 only)
/// - Bits 6..4: `RX1DRoffset`
/// - Bits 3..0: `RX2DataRate`
///
/// `OptNeg = 1` signals that the device should operate in 1.1 mode
/// (dual-MIC, separate JS keys, etc.); `OptNeg = 0` keeps the session in
/// 1.0 compatibility mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DlSettings(pub u8);

impl DlSettings {
  /// Construct from a raw byte.
  pub const fn new(b: u8) -> Self {
    Self(b)
  }

  /// RX1 data-rate offset (3 bits).
  pub const fn rx1_dr_offset(&self) -> u8 {
    (self.0 >> 4) & 0b111
  }

  /// RX2 data rate (4 bits).
  pub const fn rx2_data_rate(&self) -> u8 {
    self.0 & 0b1111
  }

  /// `OptNeg` bit. When set, the device is operating in `LoRaWAN` 1.1 mode.
  pub const fn opt_neg(&self) -> bool {
    self.0 & 0b1000_0000 != 0
  }

  /// Raw byte for serialization.
  pub const fn as_byte(&self) -> u8 {
    self.0
  }
}

/// Internal macro: declare a Copy newtype wrapping a fixed-size byte array.
macro_rules! id_newtype {
  ($(#[$meta:meta])* $name:ident, $len:expr) => {
    $(#[$meta])*
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct $name(pub [u8; $len]);

    impl $name {
      /// Construct from a fixed-size array.
      pub const fn new(bytes: [u8; $len]) -> Self {
        Self(bytes)
      }

      /// Construct from a slice, validating the length.
      ///
      /// # Errors
      /// Returns [`Error::InvalidIdentifierLength`] when the slice length
      /// does not match the expected size.
      pub const fn from_slice(s: &[u8]) -> Result<Self> {
        if s.len() != $len {
          return Err(Error::InvalidIdentifierLength { expected: $len, got: s.len() });
        }
        let mut arr = [0u8; $len];
        arr.copy_from_slice(s);
        Ok(Self(arr))
      }

      /// Borrow the underlying bytes.
      pub const fn as_bytes(&self) -> &[u8; $len] {
        &self.0
      }
    }

    #[cfg(feature = "hex_base64")]
    impl $name {
      /// Construct from a hex string.
      ///
      /// # Errors
      /// [`Error::Hex`] if the input is not valid hex.
      /// [`Error::InvalidIdentifierLength`] if the decoded byte length is wrong.
      pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
      }

      /// Construct from a standard base64 string.
      ///
      /// # Errors
      /// [`Error::Base64`] if the input is not valid base64.
      /// [`Error::InvalidIdentifierLength`] if the decoded byte length is wrong.
      pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_slice(&bytes)
      }
    }
  };
}

id_newtype!(
  /// Device address (4 bytes, big-endian display order).
  ///
  /// Assigned by the network during join, then carried in every Data frame.
  /// Wire bytes are little-endian; the struct keeps display order so
  /// `DevAddr([0x49, 0xBE, 0x7D, 0xF1])` prints as `49be7df1`.
  DevAddr, 4
);
id_newtype!(
  /// Device EUI (8 bytes, big-endian display order).
  ///
  /// IEEE EUI-64 globally unique device identifier. Carried in Join Request
  /// and Rejoin Request frames; the network uses it to look up the device.
  DevEui, 8
);
id_newtype!(
  /// Application EUI in `LoRaWAN` 1.0 / Join EUI in 1.1 (8 bytes).
  ///
  /// Identifies the Join Server responsible for the device. See alias
  /// [`JoinEui`].
  AppEui, 8
);
/// `LoRaWAN` 1.1 spec alias for [`AppEui`]. The 1.1 spec renamed the field
/// to `JoinEUI`; the bytes are the same.
pub use AppEui as JoinEui;

id_newtype!(
  /// Network ID (3 bytes).
  ///
  /// Identifies the home network. Carried in Join Accept and in the B0 block
  /// for some MIC calculations.
  NetId, 3
);
id_newtype!(
  /// Device nonce (2 bytes).
  ///
  /// Per-join random value generated by the device; used together with
  /// `AppNonce` for session-key derivation. The device must not reuse a
  /// `DevNonce` per the spec.
  DevNonce, 2
);
id_newtype!(
  /// Application nonce (1.0) / Join nonce (1.1), 3 bytes.
  ///
  /// Per-join random value generated by the network. See alias
  /// [`JoinNonce`].
  AppNonce, 3
);
/// `LoRaWAN` 1.1 spec alias for [`AppNonce`]. The 1.1 spec renamed the field
/// to `JoinNonce`; the bytes are the same.
pub use AppNonce as JoinNonce;

/// Internal macro: declare a 16-byte key newtype with redacted Debug,
/// explicit `Zeroize`, and the standard constructor/accessor surface.
///
/// Keys deliberately do not implement `Copy`. Copying secret material around
/// the stack defeats `ZeroizeOnDrop`: every implicit copy leaves a residue
/// no destructor can find. Callers borrow keys (`&key`) and explicitly clone
/// only when ownership is required.
macro_rules! key_newtype {
  ($(#[$meta:meta])* $name:ident) => {
    $(#[$meta])*
    #[derive(Clone, PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct $name([u8; 16]);

    impl $name {
      /// Construct from a 16-byte array.
      pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
      }

      /// Construct from a slice, validating the length.
      ///
      /// # Errors
      /// Returns [`Error::InvalidKeyLength`] when the slice is not 16 bytes.
      pub const fn from_slice(s: &[u8]) -> Result<Self> {
        if s.len() != 16 {
          return Err(Error::InvalidKeyLength { expected: 16, got: s.len() });
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(s);
        Ok(Self(arr))
      }

      /// Borrow the raw key bytes.
      pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
      }
    }

    impl core::fmt::Debug for $name {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, concat!(stringify!($name), "(***)"))
      }
    }

    #[cfg(feature = "hex_base64")]
    impl $name {
      /// Construct from a hex string (32 hex chars for 16 bytes).
      ///
      /// # Errors
      /// [`Error::Hex`] if the input is not valid hex.
      /// [`Error::InvalidKeyLength`] if the decoded byte length is not 16.
      pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
      }

      /// Construct from a standard base64 string.
      ///
      /// # Errors
      /// [`Error::Base64`] if the input is not valid base64.
      /// [`Error::InvalidKeyLength`] if the decoded byte length is not 16.
      pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_slice(&bytes)
      }
    }

    #[cfg(feature = "serde")]
    impl serde::Serialize for $name {
      fn serialize<S: serde::Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex_encode_16(&self.0))
      }
    }

    #[cfg(feature = "serde")]
    impl<'de> serde::Deserialize<'de> for $name {
      fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let s = <alloc::string::String as serde::Deserialize>::deserialize(deserializer)?;
        let bytes = hex_decode_16(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
      }
    }
  };
}

#[cfg(feature = "serde")]
fn hex_encode_16(b: &[u8; 16]) -> alloc::string::String {
  let mut s = alloc::string::String::with_capacity(32);
  for byte in b {
    use core::fmt::Write;
    let _ = write!(s, "{byte:02x}");
  }
  s
}

#[cfg(feature = "serde")]
fn hex_decode_16(s: &str) -> core::result::Result<[u8; 16], &'static str> {
  if s.len() != 32 {
    return Err("expected 32 hex characters for a 16-byte key");
  }
  let mut out = [0u8; 16];
  for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
    let hi = hex_nibble(chunk[0])?;
    let lo = hex_nibble(chunk[1])?;
    out[i] = (hi << 4) | lo;
  }
  Ok(out)
}

#[cfg(feature = "serde")]
const fn hex_nibble(b: u8) -> core::result::Result<u8, &'static str> {
  match b {
    b'0'..=b'9' => Ok(b - b'0'),
    b'a'..=b'f' => Ok(b - b'a' + 10),
    b'A'..=b'F' => Ok(b - b'A' + 10),
    _ => Err("invalid hex character"),
  }
}

key_newtype!(
  /// Root application key (`LoRaWAN` 1.0; also used for 1.1 `AppSKey`
  /// derivation).
  ///
  /// Provisioned in the device; never sent over the air. In 1.0 it derives
  /// both `AppSKey` and `NwkSKey` via [`crate::SessionKeys10::derive`]. In
  /// 1.1 it derives `AppSKey` via [`crate::SessionKeys11::derive`].
  AppKey
);
key_newtype!(
  /// Root network key (`LoRaWAN` 1.1).
  ///
  /// Provisioned in the device; never sent over the air. Used to derive
  /// `FNwkSIntKey`, `SNwkSIntKey`, `NwkSEncKey`, `JSIntKey`, and `JSEncKey`.
  /// Pass to [`crate::SessionKeys11::derive`] and
  /// [`crate::JoinServerKeys::derive`].
  NwkKey
);
key_newtype!(
  /// Application session key.
  ///
  /// Used to encrypt and decrypt `FRMPayload` when `FPort > 0` (the common
  /// case for application data). See [`crate::Data::decrypt_payload`].
  AppSKey
);
key_newtype!(
  /// Network session key (`LoRaWAN` 1.0).
  ///
  /// Used for:
  /// - Data MIC computation (see [`crate::LoraPacket::verify_mic_v1_0`]).
  /// - `FRMPayload` crypt when `FPort = 0` (MAC commands in `FRMPayload`).
  ///
  /// In 1.1, the equivalent roles split into `FNwkSIntKey`, `SNwkSIntKey`,
  /// and `NwkSEncKey`.
  NwkSKey
);
key_newtype!(
  /// Forwarding network session integrity key (`LoRaWAN` 1.1).
  ///
  /// Computes the lower 2 bytes of the dual-MIC for uplink Data frames.
  /// See [`crate::V1_1MicKeys`].
  FNwkSIntKey
);
key_newtype!(
  /// Serving network session integrity key (`LoRaWAN` 1.1).
  ///
  /// Computes the upper 2 bytes of the uplink dual-MIC and the full
  /// downlink MIC; also used for Rejoin types 0 and 2.
  SNwkSIntKey
);
key_newtype!(
  /// Network session encryption key (`LoRaWAN` 1.1).
  ///
  /// Encrypts `FOpts` MAC commands and `FRMPayload` with `FPort = 0`.
  /// See [`crate::Data::encrypt_fopts`].
  NwkSEncKey
);
key_newtype!(
  /// Join Server integrity key (`LoRaWAN` 1.1).
  ///
  /// MIC key for Join Accept and Rejoin Type 1. Derived from `NwkKey` and
  /// `DevEui` via [`crate::JoinServerKeys::derive`].
  JSIntKey
);
key_newtype!(
  /// Join Server encryption key (`LoRaWAN` 1.1).
  ///
  /// Re-encrypts the Join Accept body sent to a rejoining device. Derived
  /// from `NwkKey` and `DevEui` via [`crate::JoinServerKeys::derive`].
  JSEncKey
);
key_newtype!(
  /// Root key for Relay / Wake-On-Radio (WOR) sessions.
  ///
  /// Derived from `NwkSKey` via [`crate::WorKeys::root`]. Pass to
  /// [`crate::WorKeys::session`] together with a `DevAddr` to produce a
  /// `WorSessionKeys` pair.
  RootWorSKey
);
key_newtype!(
  /// WOR session integrity key.
  ///
  /// One half of the pair produced by [`crate::WorKeys::session`].
  WorSIntKey
);
key_newtype!(
  /// WOR session encryption key.
  ///
  /// One half of the pair produced by [`crate::WorKeys::session`].
  WorSEncKey
);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn mtype_from_mhdr_unconfirmed_up() {
    assert_eq!(MType::from_mhdr(0x40).unwrap(), MType::UnconfirmedDataUp);
  }

  #[test]
  fn mtype_from_mhdr_join_request() {
    assert_eq!(MType::from_mhdr(0x00).unwrap(), MType::JoinRequest);
  }

  #[test]
  fn mtype_from_mhdr_join_accept() {
    assert_eq!(MType::from_mhdr(0x20).unwrap(), MType::JoinAccept);
  }

  #[test]
  fn mtype_from_mhdr_proprietary() {
    assert_eq!(MType::from_mhdr(0xE0).unwrap(), MType::Proprietary);
  }

  #[test]
  fn mtype_from_mhdr_ignores_low_bits() {
    assert_eq!(MType::from_mhdr(0b010_00011).unwrap(), MType::UnconfirmedDataUp);
  }

  #[test]
  fn mhdr_from_parts_data_up() {
    let m = Mhdr::from_parts(MType::UnconfirmedDataUp, 0);
    assert_eq!(m.as_byte(), 0x40);
    assert_eq!(m.m_type().unwrap(), MType::UnconfirmedDataUp);
    assert_eq!(m.major(), 0);
  }

  #[test]
  fn fctrl_bits() {
    let c = FCtrl(0b1010_0110);
    assert!(c.adr());
    assert!(!c.adr_ack_req());
    assert!(c.ack());
    assert!(!c.f_pending());
    assert_eq!(c.f_opts_len(), 6);
  }

  #[test]
  fn dlsettings_layout() {
    let d = DlSettings(0b1011_0010);
    assert!(d.opt_neg());
    assert_eq!(d.rx1_dr_offset(), 0b011);
    assert_eq!(d.rx2_data_rate(), 0b0010);
  }

  #[test]
  fn dev_addr_from_slice_ok() {
    let a = DevAddr::from_slice(&[0x49, 0xBE, 0x7D, 0xF1]).unwrap();
    assert_eq!(a.as_bytes(), &[0x49, 0xBE, 0x7D, 0xF1]);
  }

  #[test]
  fn dev_addr_from_slice_wrong_length() {
    let e = DevAddr::from_slice(&[0x49, 0xBE, 0x7D]).unwrap_err();
    match e {
      Error::InvalidIdentifierLength { expected, got } => {
        assert_eq!(expected, 4);
        assert_eq!(got, 3);
      }
      _ => panic!("wrong error variant"),
    }
  }

  #[test]
  fn dev_eui_round_trip() {
    let bytes = [0x33, 0x31, 0x38, 0x32, 0x74, 0x35, 0x69, 0x05];
    let e = DevEui::new(bytes);
    assert_eq!(e.as_bytes(), &bytes);
  }

  #[test]
  fn join_eui_is_app_eui_alias() {
    let a: AppEui = JoinEui::new([1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(a.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
  }

  #[test]
  fn dev_nonce_two_bytes() {
    let n = DevNonce::from_slice(&[0xF1, 0x8E]).unwrap();
    assert_eq!(n.as_bytes(), &[0xF1, 0x8E]);
  }

  use alloc::format;

  #[test]
  fn app_key_from_slice_ok() {
    let k = AppKey::from_slice(&[0u8; 16]).unwrap();
    assert_eq!(k.as_bytes(), &[0u8; 16]);
  }

  #[test]
  fn app_key_from_slice_wrong_length() {
    let e = AppKey::from_slice(&[0u8; 15]).unwrap_err();
    match e {
      Error::InvalidKeyLength { expected, got } => {
        assert_eq!(expected, 16);
        assert_eq!(got, 15);
      }
      _ => panic!("wrong error variant"),
    }
  }

  #[test]
  fn key_debug_is_redacted() {
    let k = AppSKey::new([0xAB; 16]);
    let s = format!("{k:?}");
    assert_eq!(s, "AppSKey(***)");
    assert!(!s.contains("ab"));
  }

  #[test]
  fn key_zeroize_wipes_bytes() {
    use zeroize::Zeroize;
    let mut k = NwkSKey::new([0xFFu8; 16]);
    k.zeroize();
    assert_eq!(k.as_bytes(), &[0u8; 16]);
  }

  #[test]
  fn key_zeroize_on_drop() {
    // Direct verification of the drop-time wipe is not possible from safe
    // Rust: once a value is dropped its storage may be reused. The presence
    // of `zeroize::ZeroizeOnDrop` in the derives (see the macro) is what
    // gives the guarantee. As a smoke test, confirm that explicit
    // `Zeroize::zeroize` clears the bytes; the same impl runs on drop.
    use zeroize::Zeroize;
    let mut k = NwkSKey::new([0xff; 16]);
    k.zeroize();
    assert_eq!(k.as_bytes(), &[0u8; 16]);
  }
}
