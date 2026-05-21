//! Exhaustive round-trip tests for every `LoraPacket` variant.
//!
//! For each message type we cover three axes:
//!
//! 1. Parse-then-emit: `from_wire(bytes).to_wire() == bytes`.
//! 2. Build-then-parse: a builder-produced packet survives a `to_wire` /
//!    `from_wire` cycle and equals the original struct.
//! 3. Sign-then-verify: `sign_and_encrypt` (or `sign_join_*`) output verifies
//!    via `verify_mic_v1_0` / `verify_mic_v1_1`.
//!
//! The 1.0 known test keys are reused so that any divergence between the
//! Rust implementation and the canonical `lora-packet` JS reference shows
//! up as a MIC mismatch.
//!
//! When extending this file, prefer adding a new top-level `#[test]` over
//! parameterising an existing one. Cargo reports each failure independently
//! and the diff is easier to read.

#![allow(clippy::too_many_arguments)]

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, JSIntKey, JoinAccept,
  LoraPacket, MType, NetId, NwkKey, NwkSKey, Payload, RejoinRequest, SNwkSIntKey, V1_0MicKeys, V1_1MicKeys,
};

const APP_S_KEY_HEX: &str = "ec925802ae430ca77fd3dd73cb2cc588";
const NWK_S_KEY_HEX: &str = "44024241ed4ce9a68c6a8bc055233fd3";

fn hex_to_vec(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex")
}

fn app_s_key() -> AppSKey {
  AppSKey::from_slice(&hex_to_vec(APP_S_KEY_HEX)).expect("16-byte key")
}

fn nwk_s_key() -> NwkSKey {
  NwkSKey::from_slice(&hex_to_vec(NWK_S_KEY_HEX)).expect("16-byte key")
}

/// Build a Data packet from the matrix of axes, sign it, and assert every
/// round-trip invariant. Returns the signed packet so callers can do extra
/// assertions if needed.
fn build_sign_verify_data(
  direction: Direction,
  confirmed: bool,
  dev_addr: [u8; 4],
  f_ctrl: u8,
  f_cnt: u16,
  f_opts: &[u8],
  f_port: Option<u8>,
  payload: Option<&[u8]>,
) -> LoraPacket {
  let app = app_s_key();
  let nwk = nwk_s_key();

  let mut b = LoraPacket::builder()
    .data(direction, confirmed)
    .dev_addr(DevAddr::new(dev_addr))
    .f_ctrl(FCtrl(f_ctrl))
    .f_cnt(f_cnt)
    .f_opts(f_opts);
  if let Some(p) = f_port {
    b = b.f_port(p);
  }
  if let Some(pl) = payload {
    b = b.payload(pl);
  }
  let packet = b.sign_and_encrypt(&app, &nwk).expect("sign_and_encrypt");

  // (1) parse-then-emit on the signed wire bytes.
  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).expect("from_wire");
  assert_eq!(reparsed.to_wire(), wire, "parse-then-emit must be byte-identical");

  // (2) reparsed struct equals original (including MIC and phy_payload).
  assert_eq!(reparsed, packet, "build->wire->parse must be equivalent");

  // (3) MIC verifies under the 1.0 keys.
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk),
    ..Default::default()
  };
  assert!(
    reparsed.verify_mic_v1_0(&keys).expect("verify_mic_v1_0"),
    "verify_mic_v1_0 must succeed for signed packet"
  );

  packet
}

/// Same as [`build_sign_verify_data`] but for the unsigned build path.
/// Asserts (1) and (2) only; the MIC is zero so verification is skipped.
fn build_unsigned_round_trip_data(
  direction: Direction,
  confirmed: bool,
  dev_addr: [u8; 4],
  f_ctrl: u8,
  f_cnt: u16,
  f_opts: &[u8],
  f_port: Option<u8>,
  payload: Option<&[u8]>,
) -> LoraPacket {
  let mut b = LoraPacket::builder()
    .data(direction, confirmed)
    .dev_addr(DevAddr::new(dev_addr))
    .f_ctrl(FCtrl(f_ctrl))
    .f_cnt(f_cnt)
    .f_opts(f_opts);
  if let Some(p) = f_port {
    b = b.f_port(p);
  }
  if let Some(pl) = payload {
    b = b.payload(pl);
  }
  let packet = b.build_unsigned().expect("build_unsigned");

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).expect("from_wire");
  assert_eq!(reparsed.to_wire(), wire);
  assert_eq!(reparsed, packet);
  packet
}

// ---------------------------------------------------------------------------
// Join Request
// ---------------------------------------------------------------------------

#[test]
fn join_request_build_unsigned_round_trip() {
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([1, 2, 3, 4, 5, 6, 7, 8]))
    .dev_eui(DevEui::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]))
    .dev_nonce(DevNonce::new([0xAB, 0xCD]))
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(reparsed, packet);
  assert_eq!(reparsed.to_wire(), wire);

  let jr = reparsed.as_join_request().unwrap();
  assert_eq!(jr.join_eui.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
  assert_eq!(jr.dev_eui.as_bytes(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
  assert_eq!(jr.dev_nonce.as_bytes(), &[0xAB, 0xCD]);
}

#[test]
fn join_request_sign_v1_0_then_verify() {
  let app_key = AppKey::new([0x42; 16]);
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([8; 8]))
    .dev_eui(DevEui::new([9; 8]))
    .dev_nonce(DevNonce::new([0x12, 0x34]))
    .sign_join_request(&app_key)
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(reparsed, packet);

  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert!(reparsed.verify_mic_v1_0(&keys).unwrap());
}

#[test]
fn join_request_sign_v1_1_then_verify() {
  let nwk_key = NwkKey::new([0x55; 16]);
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0; 8]))
    .dev_eui(DevEui::new([0xFF; 8]))
    .dev_nonce(DevNonce::new([0xFF, 0xFF]))
    .sign_join_request_v1_1(&nwk_key)
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(reparsed, packet);

  let keys = V1_1MicKeys {
    nwk_key: Some(&nwk_key),
    ..Default::default()
  };
  assert!(reparsed.verify_mic_v1_1(&keys).unwrap());
}

#[test]
fn join_request_known_vector_round_trip() {
  let wire = hex_to_vec("0039363463336913aa05693574323831338ef1c1d5ec6c");
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed.to_wire(), wire);
}

// ---------------------------------------------------------------------------
// Join Accept (plaintext)
// ---------------------------------------------------------------------------

#[test]
fn join_accept_plaintext_no_cflist_round_trip() {
  let packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0x01, 0x02, 0x03]))
    .net_id(NetId::new([0x04, 0x05, 0x06]))
    .dev_addr(DevAddr::new([0x07, 0x08, 0x09, 0x0A]))
    .dl_settings(DlSettings(0x12))
    .rx_delay(0x0F)
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire_join_accept_plaintext(&wire);
  assert_eq!(reparsed, packet);
}

#[test]
fn join_accept_plaintext_with_cflist_round_trip() {
  let cf = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
  ];
  let packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0xAA, 0xBB, 0xCC]))
    .net_id(NetId::new([0x11, 0x22, 0x33]))
    .dev_addr(DevAddr::new([0xDE, 0xAD, 0xBE, 0xEF]))
    .dl_settings(DlSettings(0x80))
    .rx_delay(0x01)
    .cf_list(cf)
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire_join_accept_plaintext(&wire);
  assert_eq!(reparsed, packet);

  let ja = reparsed.as_join_accept().unwrap();
  assert_eq!(ja.cf_list.unwrap(), cf);
}

#[test]
fn join_accept_sign_v1_0_then_decrypt_and_verify() {
  let app_key = AppKey::new([0x33; 16]);
  let (packet, encrypted_wire) = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0x01, 0x02, 0x03]))
    .net_id(NetId::new([0x04, 0x05, 0x06]))
    .dev_addr(DevAddr::new([0x07, 0x08, 0x09, 0x0A]))
    .dl_settings(DlSettings(0x00))
    .rx_delay(0x00)
    .sign_join_accept(&app_key)
    .unwrap();

  // Decrypt the wire form back to the plaintext we signed.
  let plaintext = JoinAccept::decrypt_from_wire(&encrypted_wire, &app_key).unwrap();
  assert_eq!(plaintext, packet.phy_payload);

  // The decrypted plaintext should parse as a Join Accept with a matching MIC.
  let reparsed = LoraPacket::from_wire_join_accept_plaintext(&plaintext);
  assert_eq!(reparsed.mic, packet.mic);

  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert!(reparsed.verify_mic_v1_0(&keys).unwrap());
}

#[test]
fn join_accept_sign_v1_1_then_verify() {
  // Use the same 16 bytes as both NwkKey and JSIntKey so we can recompute
  // the 1.1 MIC. In practice JSIntKey is derived via JoinServerKeys.
  let nwk_key_bytes = [0x77u8; 16];
  let js_int_key = JSIntKey::new(nwk_key_bytes);
  let join_eui = AppEui::new([1, 2, 3, 4, 5, 6, 7, 8]);
  let dev_nonce = DevNonce::new([0xAA, 0xBB]);

  let mut packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0x10, 0x20, 0x30]))
    .net_id(NetId::new([0x40, 0x50, 0x60]))
    .dev_addr(DevAddr::new([0xCA, 0xFE, 0xBA, 0xBE]))
    .dl_settings(DlSettings(0x80))
    .rx_delay(0x01)
    .build_unsigned()
    .unwrap();

  let keys = V1_1MicKeys {
    js_int_key: Some(&js_int_key),
    join_eui: Some(join_eui),
    dev_nonce: Some(dev_nonce),
    join_req_type: Some(0xFF),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&keys).unwrap();

  let plaintext_wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire_join_accept_plaintext(&plaintext_wire);
  assert_eq!(reparsed.mic, packet.mic);
  assert!(reparsed.verify_mic_v1_1(&keys).unwrap());
}

// ---------------------------------------------------------------------------
// Data uplink, unconfirmed
// ---------------------------------------------------------------------------

#[test]
fn data_uplink_unconfirmed_no_payload_no_fport() {
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x00,
    0,
    &[],
    None,
    None,
  );
}

#[test]
fn data_uplink_unconfirmed_fport_none_payload_empty() {
  // FPort = None implies frm_payload must be None as well (wire layout).
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x00,
    1,
    &[],
    None,
    None,
  );
}

#[test]
fn data_uplink_unconfirmed_fport_some_payload_empty() {
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x00,
    2,
    &[],
    Some(1),
    Some(&[]),
  );
}

#[test]
fn data_uplink_unconfirmed_fport_some_payload_1byte() {
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x00,
    3,
    &[],
    Some(1),
    Some(&[0x42]),
  );
}

#[test]
fn data_uplink_unconfirmed_fport_some_payload_max_practical() {
  let payload = vec![0xAB; 222];
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x00,
    4,
    &[],
    Some(1),
    Some(&payload),
  );
}

#[test]
fn data_uplink_unconfirmed_fopts_1byte() {
  // FOpts = 1 byte means FCtrl low nibble = 1.
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x01,
    5,
    &[0x02],
    Some(1),
    Some(b"hi"),
  );
}

#[test]
fn data_uplink_unconfirmed_fopts_15byte() {
  let opts = [0xFFu8; 15];
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x0F,
    6,
    &opts,
    Some(2),
    Some(b"x"),
  );
}

#[test]
fn data_uplink_unconfirmed_fport_zero() {
  // FPort 0 routes FRMPayload through NwkSKey.
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x00,
    7,
    &[],
    Some(0),
    Some(&[0x02]),
  );
}

#[test]
fn data_uplink_unconfirmed_fport_224() {
  // 224 is the highest application FPort (>= 224 is reserved or test).
  build_sign_verify_data(
    Direction::Uplink,
    false,
    [0xA1, 0xB2, 0xC3, 0xD4],
    0x00,
    8,
    &[],
    Some(224),
    Some(b"test224"),
  );
}

// ---------------------------------------------------------------------------
// Data uplink, confirmed
// ---------------------------------------------------------------------------

#[test]
fn data_uplink_confirmed_minimal() {
  build_sign_verify_data(
    Direction::Uplink,
    true,
    [0x11, 0x22, 0x33, 0x44],
    0x00,
    10,
    &[],
    Some(1),
    Some(b"c"),
  );
}

#[test]
fn data_uplink_confirmed_with_fopts_and_payload() {
  build_sign_verify_data(
    Direction::Uplink,
    true,
    [0x11, 0x22, 0x33, 0x44],
    0x03, // FOpts len = 3
    11,
    &[0x06, 0x73, 0x07],
    Some(10),
    Some(&[0x01, 0x02, 0x03, 0x04]),
  );
}

#[test]
fn data_uplink_confirmed_max_fcnt() {
  build_sign_verify_data(
    Direction::Uplink,
    true,
    [0x11, 0x22, 0x33, 0x44],
    0x00,
    u16::MAX,
    &[],
    Some(1),
    Some(b"max"),
  );
}

// ---------------------------------------------------------------------------
// Data downlink, unconfirmed
// ---------------------------------------------------------------------------

#[test]
fn data_downlink_unconfirmed_minimal() {
  build_sign_verify_data(
    Direction::Downlink,
    false,
    [0x49, 0xBE, 0x7D, 0xF1],
    0x00,
    20,
    &[],
    Some(1),
    Some(b"d"),
  );
}

#[test]
fn data_downlink_unconfirmed_with_fopts() {
  build_sign_verify_data(
    Direction::Downlink,
    false,
    [0x49, 0xBE, 0x7D, 0xF1],
    0x02,
    21,
    &[0xAA, 0xBB],
    Some(2),
    Some(b"dl"),
  );
}

#[test]
fn data_downlink_unconfirmed_fport_none() {
  build_sign_verify_data(
    Direction::Downlink,
    false,
    [0x49, 0xBE, 0x7D, 0xF1],
    0x00,
    22,
    &[],
    None,
    None,
  );
}

// ---------------------------------------------------------------------------
// Data downlink, confirmed
// ---------------------------------------------------------------------------

#[test]
fn data_downlink_confirmed_minimal() {
  build_sign_verify_data(
    Direction::Downlink,
    true,
    [0x49, 0xBE, 0x7D, 0xF1],
    0x00,
    30,
    &[],
    Some(1),
    Some(b"cd"),
  );
}

#[test]
fn data_downlink_confirmed_with_fopts_and_payload() {
  build_sign_verify_data(
    Direction::Downlink,
    true,
    [0x49, 0xBE, 0x7D, 0xF1],
    0x04,
    31,
    &[0x01, 0x02, 0x03, 0x04],
    Some(2),
    Some(&[0x00, 0xFF, 0x55, 0xAA]),
  );
}

#[test]
fn data_downlink_confirmed_fpending_bit_preserved() {
  // FPending (bit 4) is downlink-only; it must survive the round-trip.
  build_sign_verify_data(
    Direction::Downlink,
    true,
    [0x49, 0xBE, 0x7D, 0xF1],
    0x10, // FPending = 1
    32,
    &[],
    Some(1),
    Some(b"p"),
  );
}

// ---------------------------------------------------------------------------
// Data: unsigned build round-trips
// ---------------------------------------------------------------------------

#[test]
fn data_unsigned_round_trip_all_directions() {
  for (dir, conf) in [
    (Direction::Uplink, false),
    (Direction::Uplink, true),
    (Direction::Downlink, false),
    (Direction::Downlink, true),
  ] {
    build_unsigned_round_trip_data(dir, conf, [0xDE, 0xAD, 0xBE, 0xEF], 0x00, 1, &[], Some(1), Some(b"u"));
  }
}

#[test]
fn data_unsigned_round_trip_fopts_grid() {
  // FOpts lengths 0, 1, 15 across one direction.
  for opts_len in [0usize, 1, 15] {
    let opts = vec![0x5Au8; opts_len];
    // FCtrl low nibble must match FOpts length when the builder sets FCtrl
    // explicitly. Here we let the builder default (FCtrl = opts_len).
    let packet = LoraPacket::builder()
      .data(Direction::Uplink, false)
      .dev_addr(DevAddr::new([1, 2, 3, 4]))
      .f_cnt(opts_len as u16)
      .f_opts(&opts)
      .f_port(1)
      .payload(b"p")
      .build_unsigned()
      .unwrap();
    let wire = packet.to_wire();
    let reparsed = LoraPacket::from_wire(&wire).unwrap();
    assert_eq!(reparsed, packet);
  }
}

// ---------------------------------------------------------------------------
// Rejoin Request: Type 0, Type 1, Type 2
// ---------------------------------------------------------------------------

#[test]
fn rejoin_type_0_build_unsigned_round_trip() {
  let packet = LoraPacket::builder()
    .rejoin_request(0)
    .net_id(NetId::new([0x01, 0x02, 0x03]))
    .dev_eui(DevEui::new([0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]))
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(reparsed, packet);

  match reparsed.as_rejoin_request().unwrap() {
    RejoinRequest::Type0 {
      net_id,
      dev_eui,
      rj_count_0,
    } => {
      assert_eq!(net_id.as_bytes(), &[0x01, 0x02, 0x03]);
      assert_eq!(dev_eui.as_bytes(), &[0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]);
      assert_eq!(rj_count_0, &[0, 0]);
    }
    _ => panic!("expected Type 0"),
  }
}

#[test]
fn rejoin_type_0_sign_v1_1_and_verify() {
  let s_key = SNwkSIntKey::new([0x42; 16]);
  let mut packet = LoraPacket::builder()
    .rejoin_request(0)
    .net_id(NetId::new([0x10, 0x20, 0x30]))
    .dev_eui(DevEui::new([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]))
    .build_unsigned()
    .unwrap();

  let keys = V1_1MicKeys {
    s_nwk_s_int_key: Some(&s_key),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&keys).unwrap();

  let reparsed = LoraPacket::from_wire(&packet.to_wire()).unwrap();
  assert_eq!(reparsed, packet);
  assert!(reparsed.verify_mic_v1_1(&keys).unwrap());
}

#[test]
fn rejoin_type_1_build_unsigned_round_trip() {
  let packet = LoraPacket::builder()
    .rejoin_request(1)
    .join_eui(AppEui::new([0xAA; 8]))
    .dev_eui(DevEui::new([0xBB; 8]))
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(reparsed, packet);

  match reparsed.as_rejoin_request().unwrap() {
    RejoinRequest::Type1 {
      join_eui,
      dev_eui,
      rj_count_1,
    } => {
      assert_eq!(join_eui.as_bytes(), &[0xAA; 8]);
      assert_eq!(dev_eui.as_bytes(), &[0xBB; 8]);
      assert_eq!(rj_count_1, &[0, 0]);
    }
    _ => panic!("expected Type 1"),
  }
}

#[test]
fn rejoin_type_1_sign_v1_1_and_verify() {
  let js_key = JSIntKey::new([0x77; 16]);
  let mut packet = LoraPacket::builder()
    .rejoin_request(1)
    .join_eui(AppEui::new([1, 2, 3, 4, 5, 6, 7, 8]))
    .dev_eui(DevEui::new([9, 8, 7, 6, 5, 4, 3, 2]))
    .build_unsigned()
    .unwrap();

  let keys = V1_1MicKeys {
    js_int_key: Some(&js_key),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&keys).unwrap();

  let reparsed = LoraPacket::from_wire(&packet.to_wire()).unwrap();
  assert_eq!(reparsed, packet);
  assert!(reparsed.verify_mic_v1_1(&keys).unwrap());
}

#[test]
fn rejoin_type_2_build_unsigned_round_trip() {
  let packet = LoraPacket::builder()
    .rejoin_request(2)
    .net_id(NetId::new([0xCC, 0xCC, 0xCC]))
    .dev_eui(DevEui::new([0xDD; 8]))
    .build_unsigned()
    .unwrap();

  let wire = packet.to_wire();
  let reparsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(reparsed, packet);

  assert!(matches!(
    reparsed.as_rejoin_request().unwrap(),
    RejoinRequest::Type2 { .. }
  ));
}

#[test]
fn rejoin_type_2_sign_v1_1_and_verify() {
  let s_key = SNwkSIntKey::new([0x99; 16]);
  let mut packet = LoraPacket::builder()
    .rejoin_request(2)
    .net_id(NetId::new([0x11, 0x22, 0x33]))
    .dev_eui(DevEui::new([0xEE; 8]))
    .build_unsigned()
    .unwrap();

  let keys = V1_1MicKeys {
    s_nwk_s_int_key: Some(&s_key),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&keys).unwrap();

  let reparsed = LoraPacket::from_wire(&packet.to_wire()).unwrap();
  assert_eq!(reparsed, packet);
  assert!(reparsed.verify_mic_v1_1(&keys).unwrap());
}

#[test]
fn rejoin_type_0_known_vector_round_trip() {
  let wire = hex_to_vec("c0000102030405060708090a0b0c0ddeadbeef");
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed.to_wire(), wire);
}

#[test]
fn rejoin_type_1_known_vector_round_trip() {
  let wire = hex_to_vec("c001aaaaaaaaaaaaaaaa0405060708090a0b0c0ddeadbeef");
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed.to_wire(), wire);
}

#[test]
fn rejoin_type_2_known_vector_round_trip() {
  let wire = hex_to_vec("c0020102030405060708090a0b0c0ddeadbeef");
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed.to_wire(), wire);
}

// ---------------------------------------------------------------------------
// Proprietary
// ---------------------------------------------------------------------------

#[test]
fn proprietary_known_vector_round_trip() {
  let wire = hex_to_vec("e0deadbeefcafe11223344");
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed.to_wire(), wire);
  match &parsed.payload {
    Payload::Proprietary(body) => assert_eq!(body, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
    _ => panic!("expected Proprietary"),
  }
}

#[test]
fn proprietary_empty_body_round_trip() {
  // MHDR(0xE0) + 0-byte body + MIC(4 bytes).
  let wire = vec![0xE0, 0x11, 0x22, 0x33, 0x44];
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed.to_wire(), wire);
  match &parsed.payload {
    Payload::Proprietary(body) => assert!(body.is_empty()),
    _ => panic!("expected Proprietary"),
  }
}

#[test]
fn proprietary_large_body_round_trip() {
  let mut wire = vec![0xE0];
  wire.extend(std::iter::repeat_n(0xA5u8, 200));
  wire.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
  let parsed = LoraPacket::from_wire(&wire).unwrap();
  assert_eq!(parsed.to_wire(), wire);
  match &parsed.payload {
    Payload::Proprietary(body) => assert_eq!(body.len(), 200),
    _ => panic!("expected Proprietary"),
  }
}

// ---------------------------------------------------------------------------
// Cross-cutting: every Data MType byte at the wire level
// ---------------------------------------------------------------------------

/// Sanity: parse + emit covers the entire {direction, confirmed} matrix and
/// the MType byte is exactly what we expect.
#[test]
fn data_mtype_byte_matrix() {
  let cases: &[(Direction, bool, u8, MType)] = &[
    (Direction::Uplink, false, 0x40, MType::UnconfirmedDataUp),
    (Direction::Downlink, false, 0x60, MType::UnconfirmedDataDown),
    (Direction::Uplink, true, 0x80, MType::ConfirmedDataUp),
    (Direction::Downlink, true, 0xA0, MType::ConfirmedDataDown),
  ];
  for &(dir, conf, mhdr_byte, expected) in cases {
    let packet = build_unsigned_round_trip_data(dir, conf, [1, 2, 3, 4], 0x00, 0, &[], Some(1), Some(b"x"));
    assert_eq!(packet.mhdr.as_byte(), mhdr_byte);
    assert_eq!(packet.m_type(), expected);
  }
}

// ---------------------------------------------------------------------------
// Helper: parse a plaintext Join Accept into a full LoraPacket struct.
// `LoraPacket::from_wire` rejects MType::JoinAccept inputs (they need decrypt
// first), so we wrap `JoinAccept::from_plaintext` and reconstruct the struct.
// ---------------------------------------------------------------------------

trait LoraPacketJoinAcceptPlaintext {
  fn from_wire_join_accept_plaintext(bytes: &[u8]) -> LoraPacket;
}

impl LoraPacketJoinAcceptPlaintext for LoraPacket {
  fn from_wire_join_accept_plaintext(bytes: &[u8]) -> LoraPacket {
    let ja = JoinAccept::from_plaintext(bytes).expect("valid Join Accept plaintext");
    let mut mic = [0u8; 4];
    mic.copy_from_slice(&bytes[bytes.len() - 4..]);
    LoraPacket {
      phy_payload: bytes.to_vec(),
      mhdr: lora_packet::Mhdr::from_parts(MType::JoinAccept, 0),
      mic,
      payload: Payload::JoinAccept(ja),
    }
  }
}
