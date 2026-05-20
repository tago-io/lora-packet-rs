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

impl JoinAccept {
  /// Parse an already-decrypted Join Accept (MHDR + body + MIC).
  ///
  /// Use `JoinAccept::decrypt_from_wire` (Phase 6) when starting from
  /// encrypted wire bytes.
  ///
  /// # Errors
  /// `Error::TooShort` if the total length is below 17 or the body is neither 12 nor 28 bytes.
  pub fn from_plaintext(bytes: &[u8]) -> crate::Result<Self> {
    if bytes.len() < 17 {
      return Err(crate::Error::TooShort {
        expected: 17,
        got: bytes.len(),
      });
    }
    let body = &bytes[1..bytes.len() - 4];
    if body.len() != 12 && body.len() != 28 {
      return Err(crate::Error::TooShort {
        expected: 12,
        got: body.len(),
      });
    }

    let mut join_nonce = [0u8; 3];
    join_nonce.copy_from_slice(&body[0..3]);
    join_nonce.reverse();
    let mut net_id = [0u8; 3];
    net_id.copy_from_slice(&body[3..6]);
    net_id.reverse();
    let mut dev_addr = [0u8; 4];
    dev_addr.copy_from_slice(&body[6..10]);
    dev_addr.reverse();
    let dl_settings = DlSettings(body[10]);
    let rx_delay = body[11];

    let cf_list = if body.len() == 28 {
      let mut cf = [0u8; 16];
      cf.copy_from_slice(&body[12..28]);
      Some(cf)
    } else {
      None
    };

    Ok(Self {
      join_nonce: AppNonce::new(join_nonce),
      net_id: NetId::new(net_id),
      dev_addr: DevAddr::new(dev_addr),
      dl_settings,
      rx_delay,
      cf_list,
      join_req_type: None,
    })
  }
}

fn parse_join_request(body: &[u8]) -> crate::Result<JoinRequest> {
  if body.len() != 18 {
    return Err(crate::Error::TooShort {
      expected: 18,
      got: body.len(),
    });
  }
  let mut app_eui = [0u8; 8];
  app_eui.copy_from_slice(&body[0..8]);
  app_eui.reverse();
  let mut dev_eui = [0u8; 8];
  dev_eui.copy_from_slice(&body[8..16]);
  dev_eui.reverse();
  let mut dev_nonce = [0u8; 2];
  dev_nonce.copy_from_slice(&body[16..18]);
  dev_nonce.reverse();

  Ok(JoinRequest {
    join_eui: AppEui::new(app_eui),
    dev_eui: DevEui::new(dev_eui),
    dev_nonce: DevNonce::new(dev_nonce),
  })
}

fn parse_data(m_type: MType, body: &[u8]) -> crate::Result<Data> {
  if body.len() < 7 {
    return Err(crate::Error::TooShort {
      expected: 7,
      got: body.len(),
    });
  }

  let mut dev_addr = [0u8; 4];
  dev_addr.copy_from_slice(&body[0..4]);
  dev_addr.reverse();
  let f_ctrl = FCtrl(body[4]);
  let mut f_cnt = [0u8; 2];
  f_cnt.copy_from_slice(&body[5..7]);

  let f_opts_len = f_ctrl.f_opts_len() as usize;
  if 7 + f_opts_len > body.len() {
    return Err(crate::Error::TooShort {
      expected: 7 + f_opts_len,
      got: body.len(),
    });
  }
  let f_opts = body[7..7 + f_opts_len].to_vec();

  let remainder_start = 7 + f_opts_len;
  let (f_port, frm_payload) = if remainder_start >= body.len() {
    (None, None)
  } else {
    let port = body[remainder_start];
    let payload = if remainder_start + 1 < body.len() {
      Some(body[remainder_start + 1..].to_vec())
    } else {
      Some(Vec::new())
    };
    (Some(port), payload)
  };

  let (direction, confirmed) = match m_type {
    MType::UnconfirmedDataUp => (Direction::Uplink, false),
    MType::ConfirmedDataUp => (Direction::Uplink, true),
    MType::UnconfirmedDataDown => (Direction::Downlink, false),
    MType::ConfirmedDataDown => (Direction::Downlink, true),
    _ => unreachable!("parse_data called with non-data MType"),
  };

  Ok(Data {
    direction,
    confirmed,
    dev_addr: DevAddr::new(dev_addr),
    f_ctrl,
    f_cnt,
    f_opts,
    f_port,
    frm_payload,
  })
}

fn parse_rejoin_request(body: &[u8]) -> crate::Result<RejoinRequest> {
  if body.is_empty() {
    return Err(crate::Error::TooShort { expected: 1, got: 0 });
  }
  let rejoin_type = body[0];
  match rejoin_type {
    0 | 2 => {
      if body.len() != 14 {
        return Err(crate::Error::TooShort {
          expected: 14,
          got: body.len(),
        });
      }
      let mut net_id = [0u8; 3];
      net_id.copy_from_slice(&body[1..4]);
      net_id.reverse();
      let mut dev_eui = [0u8; 8];
      dev_eui.copy_from_slice(&body[4..12]);
      dev_eui.reverse();
      let mut rj_count_0 = [0u8; 2];
      rj_count_0.copy_from_slice(&body[12..14]);
      rj_count_0.reverse();
      let dev_eui = DevEui::new(dev_eui);
      let net_id = NetId::new(net_id);
      if rejoin_type == 0 {
        Ok(RejoinRequest::Type0 {
          net_id,
          dev_eui,
          rj_count_0,
        })
      } else {
        Ok(RejoinRequest::Type2 {
          net_id,
          dev_eui,
          rj_count_0,
        })
      }
    }
    1 => {
      if body.len() != 19 {
        return Err(crate::Error::TooShort {
          expected: 19,
          got: body.len(),
        });
      }
      let mut join_eui = [0u8; 8];
      join_eui.copy_from_slice(&body[1..9]);
      join_eui.reverse();
      let mut dev_eui = [0u8; 8];
      dev_eui.copy_from_slice(&body[9..17]);
      dev_eui.reverse();
      let mut rj_count_1 = [0u8; 2];
      rj_count_1.copy_from_slice(&body[17..19]);
      rj_count_1.reverse();
      Ok(RejoinRequest::Type1 {
        join_eui: AppEui::new(join_eui),
        dev_eui: DevEui::new(dev_eui),
        rj_count_1,
      })
    }
    other => Err(crate::Error::InvalidRejoinType(other)),
  }
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

  /// Mirror of `__tests__/parse_test.ts`: "parses a Join Request"
  #[test]
  fn parse_join_request_known_vector() {
    let bytes = hex_to_vec("0039363463336913aa05693574323831338ef1c1d5ec6c");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    assert_eq!(p.mhdr.as_byte(), 0x00);
    assert_eq!(p.mic, [0xc1, 0xd5, 0xec, 0x6c]);
    let jr = p.as_join_request().expect("expected JoinRequest");
    assert_eq!(
      jr.join_eui.as_bytes(),
      &[0xaa, 0x13, 0x69, 0x33, 0x63, 0x34, 0x36, 0x39]
    );
    assert_eq!(jr.dev_eui.as_bytes(), &[0x33, 0x31, 0x38, 0x32, 0x74, 0x35, 0x69, 0x05]);
    assert_eq!(jr.dev_nonce.as_bytes(), &[0xf1, 0x8e]);
  }

  fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
      .collect()
  }

  #[test]
  fn parse_join_accept_plaintext_minimum() {
    let plaintext = hex_to_vec("20010203040506070809100001deadbeef");
    let ja = JoinAccept::from_plaintext(&plaintext).unwrap();
    assert_eq!(ja.join_nonce.as_bytes(), &[0x03, 0x02, 0x01]);
    assert_eq!(ja.net_id.as_bytes(), &[0x06, 0x05, 0x04]);
    assert_eq!(ja.dev_addr.as_bytes(), &[0x10, 0x09, 0x08, 0x07]);
    assert_eq!(ja.dl_settings.as_byte(), 0x00);
    assert_eq!(ja.rx_delay, 0x01);
    assert!(ja.cf_list.is_none());
    assert!(ja.join_req_type.is_none());
  }

  #[test]
  fn parse_join_accept_plaintext_with_cflist() {
    let plaintext = hex_to_vec(concat!(
      "20",
      "010203040506070809100001",
      "112233445566778899aabbccddeeff00",
      "deadbeef"
    ));
    let ja = JoinAccept::from_plaintext(&plaintext).unwrap();
    assert_eq!(
      ja.cf_list.unwrap(),
      [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
      ]
    );
  }

  /// Mirror of `__tests__/parse_test.ts`: "parses an unconfirmed data up"
  #[test]
  fn parse_data_up_known_vector() {
    let bytes = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    assert_eq!(p.mhdr.as_byte(), 0x40);
    assert_eq!(p.mic, [0x2b, 0x11, 0xff, 0x0d]);
    let d = p.as_data().expect("expected Data");
    assert_eq!(d.direction, Direction::Uplink);
    assert!(!d.confirmed);
    assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
    assert_eq!(d.f_ctrl.as_byte(), 0x00);
    assert_eq!(d.f_cnt(), 2);
    assert!(d.f_opts.is_empty());
    assert_eq!(d.f_port, Some(0x01));
    assert_eq!(d.frm_payload.as_deref(), Some(&[0x95, 0x43, 0x78, 0x76][..]));
  }

  #[test]
  fn parse_rejoin_type_0() {
    let bytes = hex_to_vec("c0000102030405060708090a0b0c0ddeadbeef");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    let rj = p.as_rejoin_request().expect("rejoin");
    match rj {
      RejoinRequest::Type0 {
        net_id,
        dev_eui,
        rj_count_0,
      } => {
        assert_eq!(net_id.as_bytes(), &[0x03, 0x02, 0x01]);
        assert_eq!(dev_eui.as_bytes(), &[0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04]);
        assert_eq!(rj_count_0, &[0x0d, 0x0c]);
      }
      _ => panic!("expected Type0"),
    }
  }

  #[test]
  fn parse_rejoin_type_1() {
    let bytes = hex_to_vec("c001aaaaaaaaaaaaaaaa0405060708090a0b0c0ddeadbeef");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    match p.as_rejoin_request().unwrap() {
      RejoinRequest::Type1 {
        join_eui,
        dev_eui,
        rj_count_1,
      } => {
        assert_eq!(join_eui.as_bytes(), &[0xaa; 8]);
        assert_eq!(dev_eui.as_bytes(), &[0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04]);
        assert_eq!(rj_count_1, &[0x0d, 0x0c]);
      }
      _ => panic!("expected Type1"),
    }
  }

  #[test]
  fn parse_rejoin_type_2() {
    let bytes = hex_to_vec("c0020102030405060708090a0b0c0ddeadbeef");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    assert!(matches!(p.as_rejoin_request().unwrap(), RejoinRequest::Type2 { .. }));
  }

  #[test]
  fn parse_rejoin_invalid_type() {
    let bytes = hex_to_vec("c0030102030405060708090a0b0c0ddeadbeef");
    let err = LoraPacket::from_wire(&bytes).unwrap_err();
    assert!(matches!(err, crate::Error::InvalidRejoinType(3)));
  }
}
