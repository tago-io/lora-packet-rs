//! Strong typed primitives for `LoRaWAN` packets.
//!
//! Includes message-type enums, direction, version, key newtypes, and
//! bitfield wrappers (`MHDR`, `FCtrl`, `DLSettings`).

use crate::error::{Error, Result};

/// `LoRaWAN` message types as encoded in the high 3 bits of MHDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MType {
  /// Device join request (OTAA).
  JoinRequest = 0b000,
  /// Server response to a join request.
  JoinAccept = 0b001,
  /// Uplink data without acknowledgment.
  UnconfirmedDataUp = 0b010,
  /// Downlink data without acknowledgment.
  UnconfirmedDataDown = 0b011,
  /// Uplink data with acknowledgment.
  ConfirmedDataUp = 0b100,
  /// Downlink data with acknowledgment.
  ConfirmedDataDown = 0b101,
  /// Rejoin request (`LoRaWAN` 1.1).
  RejoinRequest = 0b110,
  /// Proprietary message.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
  /// Device to network server.
  Uplink,
  /// Network server to device.
  Downlink,
}

/// `LoRaWAN` protocol version used by a particular MIC or crypto operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LorawanVersion {
  /// `LoRaWAN` 1.0.x.
  V1_0,
  /// `LoRaWAN` 1.1.
  V1_1,
}

/// MHDR byte: 3 bits `MType`, 3 bits RFU, 2 bits Major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
      pub fn from_slice(s: &[u8]) -> Result<Self> {
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
  };
}

id_newtype!(
  /// Device address (4 bytes, big-endian display order).
  DevAddr, 4
);
id_newtype!(
  /// Device EUI (8 bytes, big-endian display order).
  DevEui, 8
);
id_newtype!(
  /// Application EUI / Join EUI (8 bytes, big-endian display order).
  AppEui, 8
);
/// `LoRaWAN` 1.1 spec alias for `AppEui`.
pub use AppEui as JoinEui;

id_newtype!(
  /// Network ID (3 bytes).
  NetId, 3
);
id_newtype!(
  /// Device nonce (2 bytes).
  DevNonce, 2
);
id_newtype!(
  /// Application nonce / Join nonce (3 bytes).
  AppNonce, 3
);
/// `LoRaWAN` 1.1 spec alias for `AppNonce`.
pub use AppNonce as JoinNonce;

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
}
