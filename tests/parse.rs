//! Wire-format parsing tests for [`LoraPacket::from_wire`].
//!
//! Assertions use the typed variant accessors (`as_data`, `as_join_request`,
//! `as_join_accept`, `as_rejoin_request`) rather than generic field access.

use lora_packet::{Direction, LoraPacket, MType, Payload};

fn hex_to_vec(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex string")
}

#[test]
fn parse_data_payload() {
  let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();

  assert_eq!(parsed.phy_payload, hex_to_vec("40f17dbe4900020001954378762b11ff0d"));
  assert_eq!(parsed.mhdr.as_byte(), 0x40);
  assert_eq!(parsed.mic, [0x2b, 0x11, 0xff, 0x0d]);

  let d = parsed.as_data().expect("expected Data");
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
  assert_eq!(d.f_cnt, [0x02, 0x00]);
  assert_eq!(d.f_port, Some(0x01));
  assert_eq!(d.frm_payload.as_deref(), Some(&[0x95, 0x43, 0x78, 0x76][..]));

  // non-buffer output
  assert_eq!(parsed.m_type(), MType::UnconfirmedDataUp);
  assert_eq!(d.direction, Direction::Uplink);
  assert_eq!(d.f_cnt(), 2);
  assert!(!d.f_ctrl.ack());
  assert!(!d.f_ctrl.adr());
  assert_eq!(d.f_port, Some(1));
}

#[test]
fn parse_join_request_payload() {
  let bytes = hex_to_vec("0039363463336913AA05693574323831338EF1C1D5EC6C");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();

  assert_eq!(
    parsed.phy_payload,
    hex_to_vec("0039363463336913aa05693574323831338ef1c1d5ec6c")
  );
  assert_eq!(parsed.mhdr.as_byte(), 0x00);
  assert_eq!(parsed.mic, [0xc1, 0xd5, 0xec, 0x6c]);

  let jr = parsed.as_join_request().expect("expected JoinRequest");
  assert_eq!(
    jr.join_eui.as_bytes(),
    &[0xaa, 0x13, 0x69, 0x33, 0x63, 0x34, 0x36, 0x39]
  );
  assert_eq!(jr.dev_eui.as_bytes(), &[0x33, 0x31, 0x38, 0x32, 0x74, 0x35, 0x69, 0x05]);
  assert_eq!(jr.dev_nonce.as_bytes(), &[0xf1, 0x8e]);

  assert_eq!(parsed.m_type(), MType::JoinRequest);
}

///
/// The TS API parses a Join Accept by treating the wire bytes as plaintext;
/// the Rust API exposes the same thing via `JoinAccept::from_plaintext`.
#[test]
fn parse_join_accept_payload() {
  let bytes = hex_to_vec("20386337CCBBAAE7CD2C010000D9D0A6E7");
  // Note: from_wire rejects JoinAccept since the body needs decrypt first.
  // Use the explicit plaintext parser, which is the public equivalent.
  let ja = lora_packet::JoinAccept::from_plaintext(&bytes).unwrap();
  assert_eq!(ja.app_nonce_alias().as_bytes(), &[0x37, 0x63, 0x38]);
  assert_eq!(ja.net_id.as_bytes(), &[0xaa, 0xbb, 0xcc]);
  assert_eq!(ja.dev_addr.as_bytes(), &[0x01, 0x2c, 0xcd, 0xe7]);
  assert_eq!(ja.dl_settings.as_byte(), 0x00);
  assert_eq!(ja.rx_delay, 0x00);
  assert!(ja.cf_list.is_none());

  // MHDR is the first byte; MIC is the last 4 bytes.
  assert_eq!(bytes[0], 0x20);
  assert_eq!(&bytes[bytes.len() - 4..], &[0xd9, 0xd0, 0xa6, 0xe7]);
}

// Helper alias to read the join_nonce field by its TS name in tests.
trait JoinAcceptNonceAlias {
  fn app_nonce_alias(&self) -> &lora_packet::AppNonce;
}
impl JoinAcceptNonceAlias for lora_packet::JoinAccept {
  fn app_nonce_alias(&self) -> &lora_packet::AppNonce {
    &self.join_nonce
  }
}

#[test]
fn parse_data_payload_with_empty_payload() {
  let bytes = hex_to_vec("40F17DBE49000300012A3518AF");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();

  assert_eq!(parsed.phy_payload, hex_to_vec("40f17dbe49000300012a3518af"));
  assert_eq!(parsed.mhdr.as_byte(), 0x40);
  assert_eq!(parsed.mic, [0x2a, 0x35, 0x18, 0xaf]);

  let d = parsed.as_data().expect("expected Data");
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
  assert_eq!(d.f_cnt, [0x03, 0x00]);
  assert_eq!(d.f_port, Some(0x01));
  // FRMPayload empty in TS; Rust stores Some(empty vec) when FPort present.
  assert_eq!(d.frm_payload.as_deref(), Some(&[][..]));

  assert_eq!(parsed.m_type(), MType::UnconfirmedDataUp);
  assert_eq!(d.direction, Direction::Uplink);
  assert_eq!(d.f_cnt(), 3);
  assert!(!d.f_ctrl.ack());
  assert!(!d.f_ctrl.adr());
}

#[test]
fn parse_large_data_payload() {
  let hex = "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";
  let bytes = hex_to_vec(hex);
  let parsed = LoraPacket::from_wire(&bytes).unwrap();

  assert_eq!(parsed.phy_payload, bytes);
  assert_eq!(parsed.mhdr.as_byte(), 0x40);
  assert_eq!(parsed.mic, [0x0a, 0xf3, 0xc5, 0xe7]);

  let d = parsed.as_data().expect("expected Data");
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
  assert_eq!(d.f_cnt, [0x04, 0x00]);
  assert_eq!(d.f_port, Some(0x01));
  let expected_payload =
    hex_to_vec("55332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a2");
  assert_eq!(d.frm_payload.as_deref(), Some(expected_payload.as_slice()));

  assert_eq!(parsed.m_type(), MType::UnconfirmedDataUp);
  assert_eq!(d.direction, Direction::Uplink);
  assert_eq!(d.f_cnt(), 4);
  assert!(!d.f_ctrl.ack());
  assert!(!d.f_ctrl.adr());
}

#[test]
fn parse_ack() {
  let bytes = hex_to_vec("60f17dbe4920020001f9d65d27");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();

  assert_eq!(parsed.phy_payload, bytes);
  assert_eq!(parsed.mhdr.as_byte(), 0x60);
  assert_eq!(parsed.mic, [0xf9, 0xd6, 0x5d, 0x27]);

  let d = parsed.as_data().expect("expected Data");
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_ctrl.as_byte(), 0x20);
  assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
  assert_eq!(d.f_cnt, [0x02, 0x00]);
  assert_eq!(d.f_port, Some(0x01));
  assert_eq!(d.frm_payload.as_deref(), Some(&[][..]));

  assert_eq!(parsed.m_type(), MType::UnconfirmedDataDown);
  assert_eq!(d.direction, Direction::Downlink);
  assert_eq!(d.f_cnt(), 2);
  assert!(d.f_ctrl.ack());
  assert!(!d.f_ctrl.adr());
}

///
/// The TS test fixture has 32 wire bytes (body = 27 bytes), which does not
/// match either valid Join Accept body length (12 or 28). The TS parser is
/// lenient and surfaces partial fields anyway. The Rust parser is strict and
/// rejects this body, so we verify the MHDR/MIC bytes and that the parser
/// correctly rejects the malformed body. The TS test is documented but cannot
/// pass byte-for-byte in Rust without breaking spec compliance.
#[test]
fn parse_join_accept_with_dl_settings() {
  let bytes = hex_to_vec("33105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E18AA8A235");

  // MHDR & MIC always decodable from raw bytes.
  let mhdr = lora_packet::Mhdr::new(bytes[0]);
  assert_eq!(mhdr.as_byte(), 0x33);
  assert_eq!(mhdr.m_type().unwrap(), MType::JoinAccept);
  assert_eq!(&bytes[bytes.len() - 4..], &[0x8A, 0xA8, 0xA2, 0x35]);

  // Strict parser rejects the 27-byte body.
  let err = lora_packet::JoinAccept::from_plaintext(&bytes).unwrap_err();
  assert!(matches!(err, lora_packet::Error::TooShort { .. }));
}

#[test]
fn parse_proprietary_packets() {
  let bytes = hex_to_vec("E0008B658839");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();

  assert_eq!(parsed.phy_payload, bytes);
  assert_eq!(parsed.mhdr.as_byte(), 0xE0);
  assert_eq!(parsed.mic, [0x8B, 0x65, 0x88, 0x39]);

  match &parsed.payload {
    Payload::Proprietary(body) => assert_eq!(body, &[0x00]),
    _ => panic!("expected Proprietary"),
  }
  assert_eq!(parsed.m_type(), MType::Proprietary);
}

#[test]
fn parse_rejoin_request_packets() {
  let bytes = hex_to_vec("C000112233112233445566778811228B658839");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();

  assert_eq!(parsed.phy_payload, bytes);
  assert_eq!(parsed.mhdr.as_byte(), 0xC0);
  assert_eq!(parsed.mic, [0x8B, 0x65, 0x88, 0x39]);
  assert_eq!(parsed.m_type(), MType::RejoinRequest);
  assert!(parsed.is_rejoin_request());
}
