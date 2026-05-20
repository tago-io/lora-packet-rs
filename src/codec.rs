//! Wire-format codec for `LoRaWAN` packets.
//!
//! Parsing (`from_wire`), building (`builder()` / `to_wire`), and accessors.

use alloc::vec::Vec;

use crate::types::{AppEui, AppNonce, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, MType, Mhdr, NetId};

/// A `LoRaWAN` `PHYPayload`, parsed into structured fields.
///
/// `LoraPacket` is always exactly one of the five message types described by
/// `Payload`. The variant carries every field that is meaningful for that
/// message type; fields that do not apply are not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoraPacket {
  /// Full wire bytes (MHDR + `MACPayload` + MIC).
  pub phy_payload: Vec<u8>,
  /// MAC header byte.
  pub mhdr: Mhdr,
  /// 4-byte message integrity code.
  pub mic: [u8; 4],
  /// Type-specific payload fields.
  pub payload: Payload,
}

/// Discriminated union over `LoRaWAN` message variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
  /// OTAA join request.
  JoinRequest(JoinRequest),
  /// Server-issued join accept.
  JoinAccept(JoinAccept),
  /// Confirmed or unconfirmed data, uplink or downlink.
  Data(Data),
  /// `LoRaWAN` 1.1 rejoin request (any of 3 types).
  RejoinRequest(RejoinRequest),
  /// Proprietary message body.
  Proprietary(Vec<u8>),
}

/// Fields of an OTAA Join Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
  /// Join EUI (`LoRaWAN` 1.1 spec name for `AppEUI`).
  pub join_eui: AppEui,
  /// Device EUI.
  pub dev_eui: DevEui,
  /// Device-generated nonce.
  pub dev_nonce: DevNonce,
}

/// Fields of a Join Accept (plaintext, after decrypt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinAccept {
  /// Server-generated nonce.
  pub join_nonce: AppNonce,
  /// Network ID.
  pub net_id: NetId,
  /// Assigned device address.
  pub dev_addr: DevAddr,
  /// Downlink settings (RX1 offset, RX2 data rate, `OptNeg`).
  pub dl_settings: DlSettings,
  /// RX1 delay in seconds.
  pub rx_delay: u8,
  /// Optional channel frequency list (16 bytes).
  pub cf_list: Option<[u8; 16]>,
  /// `LoRaWAN` 1.1 only: rejoin/join-request distinguisher.
  pub join_req_type: Option<u8>,
}

/// Fields of a Data message (confirmed/unconfirmed, uplink/downlink).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
  /// Direction inferred from `MType`.
  pub direction: Direction,
  /// `true` for `ConfirmedData{Up,Down}`.
  pub confirmed: bool,
  /// Device address.
  pub dev_addr: DevAddr,
  /// Frame control byte.
  pub f_ctrl: FCtrl,
  /// Wire bytes for the lower 16 bits of `FCnt` (caller tracks the upper 16).
  pub f_cnt: [u8; 2],
  /// MAC commands carried in `FOpts` (empty when none).
  pub f_opts: Vec<u8>,
  /// `FPort` byte (0 = MAC commands in `FRMPayload`; >0 = application data).
  pub f_port: Option<u8>,
  /// Encrypted or plaintext payload (encrypted on the wire; plaintext post-decrypt).
  pub frm_payload: Option<Vec<u8>>,
}

/// Rejoin Request body (`LoRaWAN` 1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejoinRequest {
  /// Type 0: `NetID` + `DevEUI` + `RJCount0`.
  Type0 {
    /// Network ID.
    net_id: NetId,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 0.
    rj_count_0: [u8; 2],
  },
  /// Type 1: `JoinEUI` + `DevEUI` + `RJCount1`.
  Type1 {
    /// Join EUI.
    join_eui: AppEui,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 1.
    rj_count_1: [u8; 2],
  },
  /// Type 2: `NetID` + `DevEUI` + `RJCount0`.
  Type2 {
    /// Network ID.
    net_id: NetId,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 0.
    rj_count_0: [u8; 2],
  },
}

impl LoraPacket {
  /// Message type from the MHDR.
  ///
  /// # Panics
  /// Never panics on a packet produced by `from_wire` (parser rejects invalid `MType`).
  pub fn m_type(&self) -> MType {
    self.mhdr.m_type().expect("LoraPacket MHDR always has a valid MType")
  }

  /// True for `ConfirmedData`/`UnconfirmedData` (up or down).
  pub const fn is_data(&self) -> bool {
    matches!(self.payload, Payload::Data(_))
  }

  /// True for `ConfirmedDataUp` or `ConfirmedDataDown`.
  pub fn is_confirmed(&self) -> bool {
    matches!(self.m_type(), MType::ConfirmedDataUp | MType::ConfirmedDataDown)
  }

  /// True for Join Request.
  pub const fn is_join_request(&self) -> bool {
    matches!(self.payload, Payload::JoinRequest(_))
  }

  /// True for Join Accept.
  pub const fn is_join_accept(&self) -> bool {
    matches!(self.payload, Payload::JoinAccept(_))
  }

  /// True for Rejoin Request.
  pub const fn is_rejoin_request(&self) -> bool {
    matches!(self.payload, Payload::RejoinRequest(_))
  }

  /// Borrow as `Data` if this is a data message.
  pub const fn as_data(&self) -> Option<&Data> {
    if let Payload::Data(d) = &self.payload {
      Some(d)
    } else {
      None
    }
  }

  /// Mutably borrow as `Data` if this is a data message.
  pub const fn as_data_mut(&mut self) -> Option<&mut Data> {
    if let Payload::Data(d) = &mut self.payload {
      Some(d)
    } else {
      None
    }
  }

  /// Borrow as `JoinRequest` if applicable.
  pub const fn as_join_request(&self) -> Option<&JoinRequest> {
    if let Payload::JoinRequest(j) = &self.payload {
      Some(j)
    } else {
      None
    }
  }

  /// Borrow as `JoinAccept` if applicable.
  pub const fn as_join_accept(&self) -> Option<&JoinAccept> {
    if let Payload::JoinAccept(j) = &self.payload {
      Some(j)
    } else {
      None
    }
  }

  /// Borrow as `RejoinRequest` if applicable.
  pub const fn as_rejoin_request(&self) -> Option<&RejoinRequest> {
    if let Payload::RejoinRequest(r) = &self.payload {
      Some(r)
    } else {
      None
    }
  }
}

impl Data {
  /// Lower 16 bits of `FCnt` as read from the wire (little-endian).
  pub const fn f_cnt(&self) -> u16 {
    u16::from_le_bytes(self.f_cnt)
  }

  /// Full 32-bit `FCnt`, combining the wire LSB16 with a caller-tracked MSB16.
  pub const fn f_cnt_32(&self, msb: u16) -> u32 {
    ((msb as u32) << 16) | (self.f_cnt() as u32)
  }
}

impl LoraPacket {
  /// Parse a complete `PHYPayload` from wire bytes.
  ///
  /// # Errors
  /// - `Error::TooShort` if the buffer is shorter than the minimum 5 bytes (MHDR + MIC).
  /// - `Error::InvalidMType` if the MHDR encodes an unknown `MType`.
  /// - `Error::InvalidRejoinType` if a Rejoin Request has type byte not in {0, 1, 2}.
  pub fn from_wire(bytes: &[u8]) -> crate::Result<Self> {
    if bytes.len() < 5 {
      return Err(crate::Error::TooShort {
        expected: 5,
        got: bytes.len(),
      });
    }
    let mhdr = Mhdr::new(bytes[0]);
    let mic_offset = bytes.len() - 4;
    let mut mic = [0u8; 4];
    mic.copy_from_slice(&bytes[mic_offset..]);
    let m_type = mhdr.m_type()?;
    let body = &bytes[1..mic_offset];

    let payload = match m_type {
      MType::JoinRequest => Payload::JoinRequest(parse_join_request(body)?),
      MType::JoinAccept => {
        return Err(crate::Error::Other(alloc::string::String::from(
          "JoinAccept parsing requires decrypt; use JoinAccept::decrypt_from_wire",
        )));
      }
      MType::UnconfirmedDataUp | MType::UnconfirmedDataDown | MType::ConfirmedDataUp | MType::ConfirmedDataDown => {
        Payload::Data(parse_data(m_type, body)?)
      }
      MType::RejoinRequest => Payload::RejoinRequest(parse_rejoin_request(body)?),
      MType::Proprietary => Payload::Proprietary(body.to_vec()),
    };

    Ok(Self {
      phy_payload: bytes.to_vec(),
      mhdr,
      mic,
      payload,
    })
  }
}

fn parse_join_request(_body: &[u8]) -> crate::Result<JoinRequest> {
  Err(crate::Error::Other(alloc::string::String::from(
    "JoinRequest parser not yet implemented",
  )))
}

fn parse_data(_m_type: MType, _body: &[u8]) -> crate::Result<Data> {
  Err(crate::Error::Other(alloc::string::String::from(
    "Data parser not yet implemented",
  )))
}

fn parse_rejoin_request(_body: &[u8]) -> crate::Result<RejoinRequest> {
  Err(crate::Error::Other(alloc::string::String::from(
    "RejoinRequest parser not yet implemented",
  )))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn lora_packet_constructs_with_join_request_payload() {
    let p = LoraPacket {
      phy_payload: alloc::vec![0x00],
      mhdr: Mhdr::from_parts(MType::JoinRequest, 0),
      mic: [0u8; 4],
      payload: Payload::JoinRequest(JoinRequest {
        join_eui: AppEui::new([0u8; 8]),
        dev_eui: DevEui::new([0u8; 8]),
        dev_nonce: DevNonce::new([0u8; 2]),
      }),
    };
    assert!(matches!(p.payload, Payload::JoinRequest(_)));
  }

  fn sample_data_packet(confirmed: bool, direction: Direction) -> LoraPacket {
    let m_type = match (confirmed, direction) {
      (false, Direction::Uplink) => MType::UnconfirmedDataUp,
      (false, Direction::Downlink) => MType::UnconfirmedDataDown,
      (true, Direction::Uplink) => MType::ConfirmedDataUp,
      (true, Direction::Downlink) => MType::ConfirmedDataDown,
    };
    LoraPacket {
      phy_payload: alloc::vec![],
      mhdr: Mhdr::from_parts(m_type, 0),
      mic: [0u8; 4],
      payload: Payload::Data(Data {
        direction,
        confirmed,
        dev_addr: DevAddr::new([0u8; 4]),
        f_ctrl: FCtrl(0),
        f_cnt: [0, 0],
        f_opts: alloc::vec![],
        f_port: None,
        frm_payload: None,
      }),
    }
  }

  #[test]
  fn accessor_is_data() {
    let p = sample_data_packet(false, Direction::Uplink);
    assert!(p.is_data());
    assert!(!p.is_confirmed());
    assert!(p.as_data().is_some());
  }

  #[test]
  fn accessor_is_confirmed() {
    let p = sample_data_packet(true, Direction::Downlink);
    assert!(p.is_data());
    assert!(p.is_confirmed());
  }

  #[test]
  fn accessor_is_join_request() {
    let p = LoraPacket {
      phy_payload: alloc::vec![],
      mhdr: Mhdr::from_parts(MType::JoinRequest, 0),
      mic: [0u8; 4],
      payload: Payload::JoinRequest(JoinRequest {
        join_eui: AppEui::new([0u8; 8]),
        dev_eui: DevEui::new([0u8; 8]),
        dev_nonce: DevNonce::new([0u8; 2]),
      }),
    };
    assert!(p.is_join_request());
    assert!(p.as_join_request().is_some());
    assert!(p.as_data().is_none());
  }

  #[test]
  fn data_f_cnt_little_endian() {
    let d = Data {
      direction: Direction::Uplink,
      confirmed: false,
      dev_addr: DevAddr::new([0u8; 4]),
      f_ctrl: FCtrl(0),
      f_cnt: [0x02, 0x00],
      f_opts: alloc::vec![],
      f_port: None,
      frm_payload: None,
    };
    assert_eq!(d.f_cnt(), 2);
    assert_eq!(d.f_cnt_32(0), 2);
    assert_eq!(d.f_cnt_32(1), 0x0001_0002);
  }

  #[test]
  fn from_wire_rejects_empty() {
    let err = LoraPacket::from_wire(&[]).unwrap_err();
    assert!(matches!(err, crate::Error::TooShort { .. }));
  }

  #[test]
  fn from_wire_rejects_too_short() {
    let err = LoraPacket::from_wire(&[1, 2, 3, 4]).unwrap_err();
    assert!(matches!(err, crate::Error::TooShort { .. }));
  }
}
