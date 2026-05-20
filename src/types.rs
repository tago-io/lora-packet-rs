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
}
