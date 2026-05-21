//! Validation tests for [`LoraPacketBuilder`].
//!
//! Covers the construction surface: minimum-required-field builds,
//! per-variant `MissingField` errors with exact field names, clonability,
//! default state, idempotent setter overrides, `Self` chainability, round
//! tripping after `build_unsigned`, the three sign paths
//! (`sign_join_request`, `sign_join_request_v1_1`, `sign_join_accept`),
//! a known `sign_and_encrypt` test vector, and all three Rejoin types.

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, Error, FCtrl, JoinAccept,
  JoinRequest, LoraPacket, LoraPacketBuilder, MType, NetId, NwkKey, NwkSKey, Payload, RejoinRequest, V1_0MicKeys,
  V1_1MicKeys,
};

fn hex_to_vec(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex string")
}

fn key_from_hex(s: &str) -> [u8; 16] {
  let v = hex_to_vec(s);
  let mut arr = [0u8; 16];
  arr.copy_from_slice(&v);
  arr
}

fn expect_missing_field<T: core::fmt::Debug>(result: Result<T, Error>, field: &'static str) {
  match result {
    Err(Error::MissingField(name)) => {
      assert_eq!(
        name, field,
        "expected MissingField(\"{field}\"), got MissingField(\"{name}\")"
      );
    }
    other => panic!("expected MissingField(\"{field}\"), got {other:?}"),
  }
}

// ---------------------------------------------------------------------------
// Minimum required fields per variant
// ---------------------------------------------------------------------------

#[test]
fn build_join_request_minimum_fields_succeeds() {
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .dev_eui(DevEui::new([0u8; 8]))
    .dev_nonce(DevNonce::new([0u8; 2]))
    .build_unsigned()
    .unwrap();

  assert_eq!(packet.m_type(), MType::JoinRequest);
  assert!(matches!(packet.payload, Payload::JoinRequest(_)));
  assert_eq!(packet.mic, [0u8; 4]);
}

#[test]
fn build_join_accept_minimum_fields_succeeds() {
  let packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([1, 2, 3]))
    .net_id(NetId::new([4, 5, 6]))
    .dev_addr(DevAddr::new([7, 8, 9, 10]))
    .dl_settings(DlSettings::new(0))
    .build_unsigned()
    .unwrap();

  assert_eq!(packet.m_type(), MType::JoinAccept);
  let ja = packet.as_join_accept().expect("join accept payload");
  assert_eq!(ja.rx_delay, 0, "rx_delay should default to 0 when not set");
  assert!(ja.cf_list.is_none(), "cf_list should default to None when not set");
  assert!(ja.join_req_type.is_none());
}

#[test]
fn build_data_minimum_fields_succeeds() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .build_unsigned()
    .unwrap();

  assert_eq!(packet.m_type(), MType::UnconfirmedDataUp);
  let d = packet.as_data().expect("data payload");
  assert_eq!(d.f_cnt, [0, 0], "f_cnt should default to 0");
  assert!(d.f_opts.is_empty(), "f_opts should default to empty");
  assert!(d.f_port.is_none(), "f_port should default to None");
  assert!(d.frm_payload.is_none(), "frm_payload should default to None");
}

#[test]
fn build_rejoin_type_0_minimum_fields_succeeds() {
  let packet = LoraPacket::builder()
    .rejoin_request(0)
    .net_id(NetId::new([1, 2, 3]))
    .dev_eui(DevEui::new([4, 5, 6, 7, 8, 9, 10, 11]))
    .build_unsigned()
    .unwrap();

  assert_eq!(packet.m_type(), MType::RejoinRequest);
  match packet.as_rejoin_request().expect("rejoin") {
    RejoinRequest::Type0 { net_id, dev_eui, .. } => {
      assert_eq!(net_id.as_bytes(), &[1, 2, 3]);
      assert_eq!(dev_eui.as_bytes(), &[4, 5, 6, 7, 8, 9, 10, 11]);
    }
    other => panic!("expected Type0, got {other:?}"),
  }
}

#[test]
fn build_rejoin_type_1_minimum_fields_succeeds() {
  let packet = LoraPacket::builder()
    .rejoin_request(1)
    .join_eui(AppEui::new([8, 7, 6, 5, 4, 3, 2, 1]))
    .dev_eui(DevEui::new([1, 2, 3, 4, 5, 6, 7, 8]))
    .build_unsigned()
    .unwrap();

  match packet.as_rejoin_request().expect("rejoin") {
    RejoinRequest::Type1 { join_eui, dev_eui, .. } => {
      assert_eq!(join_eui.as_bytes(), &[8, 7, 6, 5, 4, 3, 2, 1]);
      assert_eq!(dev_eui.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
    other => panic!("expected Type1, got {other:?}"),
  }
}

#[test]
fn build_rejoin_type_2_minimum_fields_succeeds() {
  let packet = LoraPacket::builder()
    .rejoin_request(2)
    .net_id(NetId::new([9, 8, 7]))
    .dev_eui(DevEui::new([1, 2, 3, 4, 5, 6, 7, 8]))
    .build_unsigned()
    .unwrap();

  match packet.as_rejoin_request().expect("rejoin") {
    RejoinRequest::Type2 { net_id, dev_eui, .. } => {
      assert_eq!(net_id.as_bytes(), &[9, 8, 7]);
      assert_eq!(dev_eui.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
    other => panic!("expected Type2, got {other:?}"),
  }
}

// ---------------------------------------------------------------------------
// Missing required fields -> Error::MissingField with the exact name
// ---------------------------------------------------------------------------

#[test]
fn build_unsigned_without_m_type_reports_missing_m_type() {
  let result = LoraPacket::builder().build_unsigned();
  expect_missing_field(result, "m_type");
}

#[test]
fn build_join_request_missing_join_eui_reports_field_name() {
  let result = LoraPacket::builder()
    .join_request()
    .dev_eui(DevEui::new([0u8; 8]))
    .dev_nonce(DevNonce::new([0u8; 2]))
    .build_unsigned();
  expect_missing_field(result, "join_eui");
}

#[test]
fn build_join_request_missing_dev_eui_reports_field_name() {
  let result = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .dev_nonce(DevNonce::new([0u8; 2]))
    .build_unsigned();
  expect_missing_field(result, "dev_eui");
}

#[test]
fn build_join_request_missing_dev_nonce_reports_field_name() {
  let result = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .dev_eui(DevEui::new([0u8; 8]))
    .build_unsigned();
  expect_missing_field(result, "dev_nonce");
}

#[test]
fn build_join_accept_missing_join_nonce_reports_field_name() {
  let result = LoraPacket::builder()
    .join_accept()
    .net_id(NetId::new([0, 0, 0]))
    .dev_addr(DevAddr::new([0u8; 4]))
    .dl_settings(DlSettings::new(0))
    .build_unsigned();
  expect_missing_field(result, "join_nonce");
}

#[test]
fn build_join_accept_missing_net_id_reports_field_name() {
  let result = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0u8; 3]))
    .dev_addr(DevAddr::new([0u8; 4]))
    .dl_settings(DlSettings::new(0))
    .build_unsigned();
  expect_missing_field(result, "net_id");
}

#[test]
fn build_join_accept_missing_dev_addr_reports_field_name() {
  let result = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0u8; 3]))
    .net_id(NetId::new([0u8; 3]))
    .dl_settings(DlSettings::new(0))
    .build_unsigned();
  expect_missing_field(result, "dev_addr");
}

#[test]
fn build_join_accept_missing_dl_settings_reports_field_name() {
  let result = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0u8; 3]))
    .net_id(NetId::new([0u8; 3]))
    .dev_addr(DevAddr::new([0u8; 4]))
    .build_unsigned();
  expect_missing_field(result, "dl_settings");
}

#[test]
fn build_data_missing_dev_addr_reports_field_name() {
  let result = LoraPacket::builder().data(Direction::Uplink, false).build_unsigned();
  expect_missing_field(result, "dev_addr");
}

#[test]
fn build_rejoin_type_0_missing_dev_eui_reports_field_name() {
  let result = LoraPacket::builder()
    .rejoin_request(0)
    .net_id(NetId::new([0u8; 3]))
    .build_unsigned();
  expect_missing_field(result, "dev_eui");
}

#[test]
fn build_rejoin_type_0_missing_net_id_reports_field_name() {
  let result = LoraPacket::builder()
    .rejoin_request(0)
    .dev_eui(DevEui::new([0u8; 8]))
    .build_unsigned();
  expect_missing_field(result, "net_id");
}

#[test]
fn build_rejoin_type_1_missing_join_eui_reports_field_name() {
  let result = LoraPacket::builder()
    .rejoin_request(1)
    .dev_eui(DevEui::new([0u8; 8]))
    .build_unsigned();
  expect_missing_field(result, "join_eui");
}

#[test]
fn build_rejoin_type_2_missing_net_id_reports_field_name() {
  let result = LoraPacket::builder()
    .rejoin_request(2)
    .dev_eui(DevEui::new([0u8; 8]))
    .build_unsigned();
  expect_missing_field(result, "net_id");
}

// ---------------------------------------------------------------------------
// Builder state: clonable mid-construction, default empty, setter overrides
// ---------------------------------------------------------------------------

#[test]
fn builder_can_be_cloned_mid_construction() {
  let base = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([1, 2, 3, 4]))
    .f_cnt(5);

  let alt = base.clone().f_port(7).payload(b"alt");
  let original = base.f_port(1).payload(b"original");

  let alt_pkt = alt.build_unsigned().unwrap();
  let orig_pkt = original.build_unsigned().unwrap();

  let alt_d = alt_pkt.as_data().unwrap();
  let orig_d = orig_pkt.as_data().unwrap();
  assert_eq!(alt_d.f_port, Some(7));
  assert_eq!(orig_d.f_port, Some(1));
  assert_eq!(alt_d.frm_payload.as_deref(), Some(b"alt".as_slice()));
  assert_eq!(orig_d.frm_payload.as_deref(), Some(b"original".as_slice()));
  // Shared field is preserved on both clones.
  assert_eq!(alt_d.f_cnt, [5, 0]);
  assert_eq!(orig_d.f_cnt, [5, 0]);
}

#[test]
fn builder_default_is_empty() {
  // The default builder has no m_type set, so build_unsigned fails on m_type first.
  let result = LoraPacketBuilder::default().build_unsigned();
  expect_missing_field(result, "m_type");
}

#[test]
fn setting_same_field_twice_keeps_the_latest_value() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([1, 1, 1, 1]))
    .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
    .f_cnt(1)
    .f_cnt(2)
    .f_port(99)
    .f_port(1)
    .payload(b"first")
    .payload(b"second")
    .build_unsigned()
    .unwrap();

  let d = packet.as_data().unwrap();
  assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
  assert_eq!(d.f_cnt, [2, 0]);
  assert_eq!(d.f_port, Some(1));
  assert_eq!(d.frm_payload.as_deref(), Some(b"second".as_slice()));
}

#[test]
fn setting_message_variant_twice_keeps_the_latest_variant() {
  // Start as JoinRequest, then switch to Data Uplink. The resulting packet
  // must be a Data frame.
  let packet = LoraPacket::builder()
    .join_request()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0u8; 4]))
    .build_unsigned()
    .unwrap();

  assert_eq!(packet.m_type(), MType::UnconfirmedDataUp);
  assert!(packet.is_data());
}

#[test]
fn setters_return_self_for_chaining() {
  // This is a compile-time assertion: all the per-field setters must consume
  // `self` and return `Self`. If any of them returned `&mut Self` instead,
  // the expression below would not compile. The runtime check is just a
  // safety net to make sure the chain produced a real packet.
  fn takes_self(b: LoraPacketBuilder) -> LoraPacketBuilder {
    b
  }

  let chained: LoraPacketBuilder = takes_self(
    LoraPacket::builder()
      .data(Direction::Uplink, false)
      .dev_addr(DevAddr::new([0u8; 4]))
      .f_ctrl(FCtrl::new(0))
      .f_cnt(0)
      .f_opts(&[])
      .f_port(1)
      .payload(b"x")
      .join_eui(AppEui::new([0u8; 8]))
      .dev_eui(DevEui::new([0u8; 8]))
      .dev_nonce(DevNonce::new([0u8; 2]))
      .join_nonce(AppNonce::new([0u8; 3]))
      .net_id(NetId::new([0u8; 3]))
      .dl_settings(DlSettings::new(0))
      .rx_delay(1)
      .cf_list([0u8; 16])
      .join_req_type(0xff),
  );

  let pkt = chained.build_unsigned().unwrap();
  assert!(pkt.is_data());
}

// ---------------------------------------------------------------------------
// Round trip: build_unsigned -> to_wire -> from_wire
// ---------------------------------------------------------------------------

#[test]
fn build_unsigned_data_round_trips_via_wire() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
    .f_ctrl(FCtrl::new(0))
    .f_cnt(2)
    .f_port(1)
    .payload(&[0x95, 0x43, 0x78, 0x76])
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed, packet);
}

#[test]
fn build_unsigned_join_request_round_trips_via_wire() {
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0xaa, 0x13, 0x69, 0x33, 0x63, 0x34, 0x36, 0x39]))
    .dev_eui(DevEui::new([0x33, 0x31, 0x38, 0x32, 0x74, 0x35, 0x69, 0x05]))
    .dev_nonce(DevNonce::new([0xf1, 0x8e]))
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed, packet);

  let jr = parsed.as_join_request().unwrap();
  assert_eq!(jr.dev_nonce.as_bytes(), &[0xf1, 0x8e]);
}

#[test]
fn build_unsigned_rejoin_type_0_round_trips_via_wire() {
  let packet = LoraPacket::builder()
    .rejoin_request(0)
    .net_id(NetId::new([0x03, 0x02, 0x01]))
    .dev_eui(DevEui::new([0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04]))
    .build_unsigned()
    .unwrap();
  let wire = packet.to_wire();
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed, packet);
}

#[test]
fn build_unsigned_rejoin_type_1_round_trips_via_wire() {
  let packet = LoraPacket::builder()
    .rejoin_request(1)
    .join_eui(AppEui::new([0xaa; 8]))
    .dev_eui(DevEui::new([0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04]))
    .build_unsigned()
    .unwrap();
  let wire = packet.to_wire();
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed, packet);
}

#[test]
fn build_unsigned_rejoin_type_2_round_trips_via_wire() {
  let packet = LoraPacket::builder()
    .rejoin_request(2)
    .net_id(NetId::new([0x03, 0x02, 0x01]))
    .dev_eui(DevEui::new([0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04]))
    .build_unsigned()
    .unwrap();
  let wire = packet.to_wire();
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed, packet);
}

// ---------------------------------------------------------------------------
// Signing paths
// ---------------------------------------------------------------------------

#[test]
fn sign_join_request_with_all_fields_produces_verifiable_mic() {
  let app_key = AppKey::new([0u8; 16]);
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0xaa, 0x13, 0x69, 0x33, 0x63, 0x34, 0x36, 0x39]))
    .dev_eui(DevEui::new([0x33, 0x31, 0x38, 0x32, 0x74, 0x35, 0x69, 0x05]))
    .dev_nonce(DevNonce::new([0xf1, 0x8e]))
    .sign_join_request(&app_key)
    .unwrap();

  assert!(packet.is_join_request());
  // MIC was rewritten away from zero.
  assert_ne!(packet.mic, [0u8; 4], "sign_join_request must overwrite the zero MIC");

  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert!(packet.verify_mic_v1_0(&keys).unwrap());

  // phy_payload trailing 4 bytes match the MIC.
  let n = packet.phy_payload.len();
  assert_eq!(&packet.phy_payload[n - 4..], &packet.mic);
}

#[test]
fn sign_join_request_v1_1_with_all_fields_produces_verifiable_mic() {
  let nwk_key = NwkKey::new([1u8; 16]);
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([8, 7, 6, 5, 4, 3, 2, 1]))
    .dev_eui(DevEui::new([1, 2, 3, 4, 5, 6, 7, 8]))
    .dev_nonce(DevNonce::new([0x12, 0x34]))
    .sign_join_request_v1_1(&nwk_key)
    .unwrap();

  assert!(packet.is_join_request());
  assert_ne!(packet.mic, [0u8; 4]);
  let keys = V1_1MicKeys {
    nwk_key: Some(&nwk_key),
    ..Default::default()
  };
  assert!(packet.verify_mic_v1_1(&keys).unwrap());

  let n = packet.phy_payload.len();
  assert_eq!(&packet.phy_payload[n - 4..], &packet.mic);
}

#[test]
fn sign_join_request_missing_field_propagates() {
  let app_key = AppKey::new([0u8; 16]);
  let result = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .dev_eui(DevEui::new([0u8; 8]))
    .sign_join_request(&app_key);
  expect_missing_field(result, "dev_nonce");
}

#[test]
fn sign_join_request_v1_1_missing_field_propagates() {
  let nwk_key = NwkKey::new([0u8; 16]);
  let result = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .dev_nonce(DevNonce::new([0u8; 2]))
    .sign_join_request_v1_1(&nwk_key);
  expect_missing_field(result, "dev_eui");
}

#[test]
fn sign_join_accept_returns_packet_and_encrypted_wire() {
  let app_key = AppKey::new([0u8; 16]);
  let (packet, encrypted_wire) = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0, 0, 0]))
    .net_id(NetId::new([0, 0, 0]))
    .dev_addr(DevAddr::new([0, 0, 0, 0]))
    .dl_settings(DlSettings::new(0))
    .rx_delay(0)
    .sign_join_accept(&app_key)
    .unwrap();

  assert!(packet.is_join_accept());
  // Plaintext MIC for the all-zero JoinAccept under zero AppKey.
  assert_eq!(packet.mic, [0xf8, 0x6f, 0x0a, 0x91]);

  // The encrypted wire bytes differ from the plaintext phy_payload but match
  // the canonical join_accept_encrypt vector (see codec.rs unit tests).
  let expected_encrypted = hex_to_vec("20e3de108795f776b8037610ef7869b5b3");
  assert_eq!(encrypted_wire, expected_encrypted);
  assert_ne!(encrypted_wire, packet.phy_payload);

  // Round-trip decrypt the encrypted wire and compare with the plaintext.
  let decrypted = JoinAccept::decrypt_from_wire(&encrypted_wire, &app_key).unwrap();
  assert_eq!(decrypted, packet.phy_payload);
}

#[test]
fn sign_join_accept_missing_field_propagates() {
  let app_key = AppKey::new([0u8; 16]);
  let result = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0u8; 3]))
    .net_id(NetId::new([0u8; 3]))
    .dev_addr(DevAddr::new([0u8; 4]))
    .sign_join_accept(&app_key);
  expect_missing_field(result, "dl_settings");
}

#[test]
fn sign_and_encrypt_produces_expected_payload_and_mic_for_known_vector() {
  // Same vector as codec.rs::sign_and_encrypt_round_trip + the docs example.
  // AppSKey: ec925802ae430ca77fd3dd73cb2cc588
  // NwkSKey: 44024241ed4ce9a68c6a8bc055233fd3
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));

  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
    .f_ctrl(FCtrl::new(0))
    .f_cnt(2)
    .f_port(1)
    .payload(b"test")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let d = packet.as_data().expect("data");
  assert_eq!(
    d.frm_payload.as_deref(),
    Some(&[0x95, 0x43, 0x78, 0x76][..]),
    "FRMPayload should be the canonical AES-CTR encrypted ciphertext"
  );
  assert_eq!(packet.mic, [0x2b, 0x11, 0xff, 0x0d]);

  let expected_wire = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
  assert_eq!(packet.phy_payload, expected_wire);
  assert_eq!(packet.to_wire(), expected_wire);

  // MIC verifies under the same keys.
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

#[test]
fn sign_and_encrypt_missing_dev_addr_propagates() {
  let app_s_key = AppSKey::new([0u8; 16]);
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  let result = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .f_cnt(1)
    .f_port(1)
    .payload(b"x")
    .sign_and_encrypt(&app_s_key, &nwk_s_key);
  expect_missing_field(result, "dev_addr");
}

// ---------------------------------------------------------------------------
// Smoke check: build_unsigned of every variant exposes the right Payload
// ---------------------------------------------------------------------------

#[test]
fn build_unsigned_data_downlink_confirmed_has_right_m_type() {
  let packet = LoraPacket::builder()
    .data(Direction::Downlink, true)
    .dev_addr(DevAddr::new([0u8; 4]))
    .build_unsigned()
    .unwrap();
  assert_eq!(packet.m_type(), MType::ConfirmedDataDown);
  let d = packet.as_data().unwrap();
  assert_eq!(d.direction, Direction::Downlink);
  assert!(d.confirmed);
}

#[test]
fn variant_payload_matches_for_each_message_type() {
  let jr = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .dev_eui(DevEui::new([0u8; 8]))
    .dev_nonce(DevNonce::new([0u8; 2]))
    .build_unsigned()
    .unwrap();
  assert!(matches!(jr.payload, Payload::JoinRequest(JoinRequest { .. })));

  let ja = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0u8; 3]))
    .net_id(NetId::new([0u8; 3]))
    .dev_addr(DevAddr::new([0u8; 4]))
    .dl_settings(DlSettings::new(0))
    .build_unsigned()
    .unwrap();
  assert!(matches!(ja.payload, Payload::JoinAccept(_)));

  let data = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0u8; 4]))
    .build_unsigned()
    .unwrap();
  assert!(matches!(data.payload, Payload::Data(_)));

  let rj = LoraPacket::builder()
    .rejoin_request(1)
    .join_eui(AppEui::new([0u8; 8]))
    .dev_eui(DevEui::new([0u8; 8]))
    .build_unsigned()
    .unwrap();
  assert!(matches!(
    rj.payload,
    Payload::RejoinRequest(RejoinRequest::Type1 { .. })
  ));
}
