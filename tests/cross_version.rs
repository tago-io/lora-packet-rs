//! Cross-version (LoRaWAN 1.0 vs 1.1) behaviour tests.
//!
//! Exercises MIC and key-derivation differences between the two protocol
//! versions on the same logical inputs (frame bytes, root keys, nonces).

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, FNwkSIntKey, JSIntKey,
  LoraPacket, NetId, NwkKey, NwkSKey, Payload, SNwkSIntKey, SessionKeys10, SessionKeys11, V1_0MicKeys, V1_1MicKeys,
};

const APP_KEY_BYTES: [u8; 16] = [
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const NWK_KEY_BYTES: [u8; 16] = [
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const JOIN_EUI_BYTES: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
const DEV_EUI_BYTES: [u8; 8] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27];
const DEV_NONCE_BYTES: [u8; 2] = [0xab, 0xcd];
const APP_NONCE_BYTES: [u8; 3] = [0xc1, 0xd5, 0xec];
const NET_ID_BYTES: [u8; 3] = [0x00, 0x00, 0x01];
const DEV_ADDR_BYTES: [u8; 4] = [0x49, 0xbe, 0x7d, 0xf1];

// ---------------------------------------------------------------------------
// Join Request: same algorithm, different key (AppKey 1.0 vs NwkKey 1.1)
// ---------------------------------------------------------------------------

/// 1.0 signs Join Request with AppKey; the same packet must verify with the
/// 1.0 key set.
#[test]
fn join_request_v1_0_signs_and_verifies_with_app_key() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new(JOIN_EUI_BYTES))
    .dev_eui(DevEui::new(DEV_EUI_BYTES))
    .dev_nonce(DevNonce::new(DEV_NONCE_BYTES))
    .sign_join_request(&app_key)
    .unwrap();

  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

/// 1.1 signs Join Request with NwkKey; verify under the 1.1 key set.
#[test]
fn join_request_v1_1_signs_and_verifies_with_nwk_key() {
  let nwk_key = NwkKey::new(NWK_KEY_BYTES);
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new(JOIN_EUI_BYTES))
    .dev_eui(DevEui::new(DEV_EUI_BYTES))
    .dev_nonce(DevNonce::new(DEV_NONCE_BYTES))
    .sign_join_request_v1_1(&nwk_key)
    .unwrap();

  let keys = V1_1MicKeys {
    nwk_key: Some(&nwk_key),
    ..Default::default()
  };
  assert!(packet.verify_mic_v1_1(&keys).unwrap());
}

/// The Join Request CMAC algorithm is identical between 1.0 and 1.1; only
/// the key changes. Using identical key bytes through both signing paths
/// must yield byte-for-byte identical MICs.
#[test]
fn join_request_same_key_bytes_produce_identical_mic_across_versions() {
  let shared = [0x7fu8; 16];
  let app_key = AppKey::new(shared);
  let nwk_key = NwkKey::new(shared);

  let pkt_10 = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new(JOIN_EUI_BYTES))
    .dev_eui(DevEui::new(DEV_EUI_BYTES))
    .dev_nonce(DevNonce::new(DEV_NONCE_BYTES))
    .sign_join_request(&app_key)
    .unwrap();
  let pkt_11 = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new(JOIN_EUI_BYTES))
    .dev_eui(DevEui::new(DEV_EUI_BYTES))
    .dev_nonce(DevNonce::new(DEV_NONCE_BYTES))
    .sign_join_request_v1_1(&nwk_key)
    .unwrap();

  assert_eq!(pkt_10.mic, pkt_11.mic);
  assert_eq!(pkt_10.phy_payload, pkt_11.phy_payload);
}

/// With distinct AppKey and NwkKey bytes, 1.0 and 1.1 Join Request MICs must
/// differ.
#[test]
fn join_request_different_keys_produce_different_mic() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let nwk_key = NwkKey::new(NWK_KEY_BYTES);

  let pkt_10 = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new(JOIN_EUI_BYTES))
    .dev_eui(DevEui::new(DEV_EUI_BYTES))
    .dev_nonce(DevNonce::new(DEV_NONCE_BYTES))
    .sign_join_request(&app_key)
    .unwrap();
  let pkt_11 = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new(JOIN_EUI_BYTES))
    .dev_eui(DevEui::new(DEV_EUI_BYTES))
    .dev_nonce(DevNonce::new(DEV_NONCE_BYTES))
    .sign_join_request_v1_1(&nwk_key)
    .unwrap();

  assert_ne!(pkt_10.mic, pkt_11.mic);
}

/// 1.0 signature must NOT verify under the 1.1 key set (different key /
/// different field).
#[test]
fn join_request_v1_0_signature_rejected_by_v1_1_verify() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let nwk_key = NwkKey::new(NWK_KEY_BYTES);

  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new(JOIN_EUI_BYTES))
    .dev_eui(DevEui::new(DEV_EUI_BYTES))
    .dev_nonce(DevNonce::new(DEV_NONCE_BYTES))
    .sign_join_request(&app_key)
    .unwrap();

  let keys_11 = V1_1MicKeys {
    nwk_key: Some(&nwk_key),
    ..Default::default()
  };
  assert!(!packet.verify_mic_v1_1(&keys_11).unwrap());
}

// ---------------------------------------------------------------------------
// Join Accept: 1.0 (AppKey only) vs 1.1 (JSIntKey + JoinReqType||JoinEUI||DevNonce)
// ---------------------------------------------------------------------------

/// Build an unsigned Join Accept packet (MHDR + body, MIC slot zeroed) so MIC
/// computation routes through the public `calculate_mic_v1_0` /
/// `calculate_mic_v1_1` entry points.
fn unsigned_join_accept_packet() -> LoraPacket {
  LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new(APP_NONCE_BYTES))
    .net_id(NetId::new(NET_ID_BYTES))
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .dl_settings(DlSettings(0))
    .rx_delay(1)
    .build_unsigned()
    .unwrap()
}

/// 1.0 Join Accept MIC uses CMAC(AppKey, MHDR||Body); 1.1 prepends
/// JoinReqType||JoinEUI||DevNonce and signs with JSIntKey. Even with the same
/// underlying 16 key bytes, the prefix alone must change the MIC.
#[test]
fn join_accept_v1_0_vs_v1_1_produce_different_mic() {
  let shared = [0x42u8; 16];
  let app_key = AppKey::new(shared);
  let js_int_key = JSIntKey::new(shared);
  let packet = unsigned_join_accept_packet();

  let mic_10 = packet
    .calculate_mic_v1_0(&V1_0MicKeys {
      app_key: Some(&app_key),
      ..Default::default()
    })
    .unwrap();

  let mic_11 = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      js_int_key: Some(&js_int_key),
      join_eui: Some(AppEui::new(JOIN_EUI_BYTES)),
      dev_nonce: Some(DevNonce::new(DEV_NONCE_BYTES)),
      join_req_type: Some(0xFF),
      ..Default::default()
    })
    .unwrap();

  assert_ne!(mic_10, mic_11);
}

/// 1.1 Join Accept MIC depends on JoinReqType: re-keying or rejoin changes
/// the byte and therefore the MIC.
#[test]
fn join_accept_v1_1_mic_depends_on_join_req_type() {
  let js_int_key = JSIntKey::new([0x11u8; 16]);
  let packet = unsigned_join_accept_packet();
  let eui = AppEui::new(JOIN_EUI_BYTES);
  let nonce = DevNonce::new(DEV_NONCE_BYTES);

  let mic_for = |t: u8| {
    packet
      .calculate_mic_v1_1(&V1_1MicKeys {
        js_int_key: Some(&js_int_key),
        join_eui: Some(eui),
        dev_nonce: Some(nonce),
        join_req_type: Some(t),
        ..Default::default()
      })
      .unwrap()
  };
  let mic_join = mic_for(0xFF);
  let mic_rejoin0 = mic_for(0x00);
  let mic_rejoin2 = mic_for(0x02);

  assert_ne!(mic_join, mic_rejoin0);
  assert_ne!(mic_join, mic_rejoin2);
  assert_ne!(mic_rejoin0, mic_rejoin2);
}

/// 1.1 Join Accept MIC must change with DevNonce (it's mixed into the prefix
/// bytes alongside JoinEUI).
#[test]
fn join_accept_v1_1_mic_depends_on_dev_nonce() {
  let js_int_key = JSIntKey::new([0x33u8; 16]);
  let packet = unsigned_join_accept_packet();
  let eui = AppEui::new(JOIN_EUI_BYTES);

  let mic_for = |n: [u8; 2]| {
    packet
      .calculate_mic_v1_1(&V1_1MicKeys {
        js_int_key: Some(&js_int_key),
        join_eui: Some(eui),
        dev_nonce: Some(DevNonce::new(n)),
        join_req_type: Some(0xFF),
        ..Default::default()
      })
      .unwrap()
  };

  assert_ne!(mic_for([0x00, 0x01]), mic_for([0x00, 0x02]));
}

// ---------------------------------------------------------------------------
// Data uplink: 1.0 single MIC vs 1.1 dual-MIC (different byte layout)
// ---------------------------------------------------------------------------

fn build_uplink_packet() -> LoraPacket {
  let app_s_key = AppSKey::new([0u8; 16]);
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(7)
    .f_port(1)
    .payload(b"hello")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap()
}

/// On the same uplink frame, 1.0 MIC = CMAC(NwkSKey, B0||...)[..4]; 1.1 MIC =
/// CMAC_S[..2] || CMAC_F[..2] under two different keys. Different scheme, so
/// the MIC bytes differ even when 1.1 keys are derived from the same root.
#[test]
fn data_uplink_v1_0_vs_v1_1_mic_byte_layout_differs() {
  let mut packet = build_uplink_packet();

  // 1.0 MIC over the same wire
  let nwk_s_key = NwkSKey::new([0x77u8; 16]);
  let keys_10 = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  let mic_10 = packet.calculate_mic_v1_0(&keys_10).unwrap();

  // 1.1 MIC over the same wire, dual-key
  let f_key = FNwkSIntKey::new([0x77u8; 16]); // intentionally same bytes as 1.0
  let s_key = SNwkSIntKey::new([0x77u8; 16]);
  let keys_11 = V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_key),
    s_nwk_s_int_key: Some(&s_key),
    ..Default::default()
  };
  let mic_11 = packet.calculate_mic_v1_1(&keys_11).unwrap();

  // Even with the *same* 16 key bytes, the dual-MIC layout differs from
  // single-MIC because the B1 block has different bytes 1..5 semantics
  // (ConfFCntDown||TxDr||TxCh defaults to zero here, matching B0). The
  // halves come from independent CMACs under the same key here, so MIC[0..2]
  // == CMAC_S[..2] but MIC[2..4] == CMAC_F[..2] and the full output is not
  // the 1.0 MIC.
  assert_ne!(mic_10, mic_11);

  // Sanity: round-trip the original sign so the test isn't relying on a
  // stale phy_payload.
  packet.mic = [0u8; 4];
  packet.phy_payload = packet.to_wire();
}

/// The 1.1 dual-MIC must change when FNwkSIntKey changes (lower two bytes
/// come from a CMAC under that key).
#[test]
fn data_uplink_v1_1_mic_changes_with_f_nwk_s_int_key() {
  let packet = build_uplink_packet();
  let s_key = SNwkSIntKey::new([0x22u8; 16]);

  let f_key_a = FNwkSIntKey::new([0x11u8; 16]);
  let mic_a = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      f_nwk_s_int_key: Some(&f_key_a),
      s_nwk_s_int_key: Some(&s_key),
      ..Default::default()
    })
    .unwrap();

  let f_key_b = FNwkSIntKey::new([0xaau8; 16]);
  let mic_b = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      f_nwk_s_int_key: Some(&f_key_b),
      s_nwk_s_int_key: Some(&s_key),
      ..Default::default()
    })
    .unwrap();

  assert_ne!(mic_a, mic_b);
  // High two bytes come from S-key only, so they must be identical.
  assert_eq!(mic_a[0..2], mic_b[0..2]);
  // Low two bytes come from F-key only, so they must differ.
  assert_ne!(mic_a[2..4], mic_b[2..4]);
}

/// 1.1 dual-MIC changes with SNwkSIntKey (upper two MIC bytes).
#[test]
fn data_uplink_v1_1_mic_changes_with_s_nwk_s_int_key() {
  let packet = build_uplink_packet();
  let f_key = FNwkSIntKey::new([0x55u8; 16]);

  let s_key_a = SNwkSIntKey::new([0x11u8; 16]);
  let mic_a = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      f_nwk_s_int_key: Some(&f_key),
      s_nwk_s_int_key: Some(&s_key_a),
      ..Default::default()
    })
    .unwrap();

  let s_key_b = SNwkSIntKey::new([0xbbu8; 16]);
  let mic_b = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      f_nwk_s_int_key: Some(&f_key),
      s_nwk_s_int_key: Some(&s_key_b),
      ..Default::default()
    })
    .unwrap();

  assert_ne!(mic_a, mic_b);
  assert_ne!(mic_a[0..2], mic_b[0..2]);
  assert_eq!(mic_a[2..4], mic_b[2..4]);
}

/// 1.1 dual-MIC mixes ConfFCntDown||TxDr||TxCh into B1 (under SNwkSIntKey);
/// changing it must shift only the upper two MIC bytes.
#[test]
fn data_uplink_v1_1_mic_changes_with_conf_fcnt_context() {
  let packet = build_uplink_packet();
  let f_key = FNwkSIntKey::new([0x10u8; 16]);
  let s_key = SNwkSIntKey::new([0x20u8; 16]);

  let mic_zero = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      f_nwk_s_int_key: Some(&f_key),
      s_nwk_s_int_key: Some(&s_key),
      conf_fcnt_down_tx_dr_tx_ch: Some([0; 4]),
      ..Default::default()
    })
    .unwrap();

  let mic_ctx = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      f_nwk_s_int_key: Some(&f_key),
      s_nwk_s_int_key: Some(&s_key),
      conf_fcnt_down_tx_dr_tx_ch: Some([0xde, 0xad, 0xbe, 0xef]),
      ..Default::default()
    })
    .unwrap();

  assert_ne!(mic_zero, mic_ctx);
  // F-MIC (B0, no context) untouched.
  assert_eq!(mic_zero[2..4], mic_ctx[2..4]);
  // S-MIC (B1, with context) changes.
  assert_ne!(mic_zero[0..2], mic_ctx[0..2]);
}

// ---------------------------------------------------------------------------
// Data downlink: 1.0 vs 1.1 with ConfFCntDownTxDrTxCh
// ---------------------------------------------------------------------------

fn build_downlink_packet() -> LoraPacket {
  let app_s_key = AppSKey::new([0u8; 16]);
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  LoraPacket::builder()
    .data(Direction::Downlink, true)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(42)
    .f_port(2)
    .payload(b"down")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap()
}

/// 1.0 downlink MIC (NwkSKey, B0 with zero context) vs 1.1 downlink MIC
/// (SNwkSIntKey, B0-style block where bytes 1..5 carry ConfFCntDownTxDrTxCh).
/// With the same 16 key bytes and zero context the algorithms are identical
/// except for the direction byte handling, which both set to 1 for downlink.
/// Setting a non-zero ConfFCntDown changes only the 1.1 MIC.
#[test]
fn data_downlink_v1_0_vs_v1_1_mic_diverges_with_conf_fcnt() {
  let packet = build_downlink_packet();
  let shared = [0x5au8; 16];
  let nwk_s_key = NwkSKey::new(shared);
  let s_key = SNwkSIntKey::new(shared);

  // With zero context, downlink MIC of both versions uses identical B0 blocks
  // and the same key bytes, so the result should be the same.
  let mic_10 = packet
    .calculate_mic_v1_0(&V1_0MicKeys {
      nwk_s_key: Some(&nwk_s_key),
      ..Default::default()
    })
    .unwrap();
  let mic_11_zero = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      s_nwk_s_int_key: Some(&s_key),
      conf_fcnt_down_tx_dr_tx_ch: Some([0; 4]),
      ..Default::default()
    })
    .unwrap();
  assert_eq!(mic_10, mic_11_zero);

  // Non-zero context: 1.1 MIC diverges from 1.0.
  let mic_11_ctx = packet
    .calculate_mic_v1_1(&V1_1MicKeys {
      s_nwk_s_int_key: Some(&s_key),
      conf_fcnt_down_tx_dr_tx_ch: Some([0x01, 0x02, 0x03, 0x04]),
      ..Default::default()
    })
    .unwrap();
  assert_ne!(mic_10, mic_11_ctx);
}

/// Downlink 1.1 MIC must verify when signed and re-checked with the same
/// SNwkSIntKey and context.
#[test]
fn data_downlink_v1_1_round_trip_sign_and_verify() {
  let mut packet = build_downlink_packet();
  let s_key = SNwkSIntKey::new([0x99u8; 16]);
  let keys = V1_1MicKeys {
    s_nwk_s_int_key: Some(&s_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([0x01, 0x00, 0x00, 0x00]),
    ..Default::default()
  };

  packet.recalculate_mic_v1_1(&keys).unwrap();
  assert!(packet.verify_mic_v1_1(&keys).unwrap());

  // Same MIC must not verify if the ConfFCntDown context drifts.
  let keys_wrong = V1_1MicKeys {
    s_nwk_s_int_key: Some(&s_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([0x02, 0x00, 0x00, 0x00]),
    ..Default::default()
  };
  assert!(!packet.verify_mic_v1_1(&keys_wrong).unwrap());
}

// ---------------------------------------------------------------------------
// Direction handling
// ---------------------------------------------------------------------------

/// The direction byte enters the B0 block, so swapping uplink for downlink
/// must change the 1.0 Data MIC.
#[test]
fn data_v1_0_mic_changes_with_direction() {
  let app_s_key = AppSKey::new([0u8; 16]);
  let nwk_s_key = NwkSKey::new([0x44u8; 16]);

  let up = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(5)
    .f_port(1)
    .payload(b"x")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();
  let down = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(5)
    .f_port(1)
    .payload(b"x")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  let mic_up = up.calculate_mic_v1_0(&keys).unwrap();
  let mic_down = down.calculate_mic_v1_0(&keys).unwrap();
  // Wire bytes differ only by MHDR (different MType) and the direction byte.
  assert_ne!(mic_up, mic_down);
}

/// Uplink in 1.1 routes through the dual-MIC path; downlink uses the single
/// MIC. The MIC byte layout differs across paths.
#[test]
fn data_v1_1_uplink_vs_downlink_mic_paths_differ() {
  let app_s_key = AppSKey::new([0u8; 16]);
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  let up = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(12)
    .f_port(1)
    .payload(b"ab")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();
  let down = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(12)
    .f_port(1)
    .payload(b"ab")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let f_key = FNwkSIntKey::new([0x33u8; 16]);
  let s_key = SNwkSIntKey::new([0x44u8; 16]);

  let mic_up = up
    .calculate_mic_v1_1(&V1_1MicKeys {
      f_nwk_s_int_key: Some(&f_key),
      s_nwk_s_int_key: Some(&s_key),
      ..Default::default()
    })
    .unwrap();
  let mic_down = down
    .calculate_mic_v1_1(&V1_1MicKeys {
      s_nwk_s_int_key: Some(&s_key),
      ..Default::default()
    })
    .unwrap();

  assert_ne!(mic_up, mic_down);
}

// ---------------------------------------------------------------------------
// SessionKeys10 vs SessionKeys11 derivation
// ---------------------------------------------------------------------------

/// 1.0 derives two keys (AppSKey, NwkSKey) from AppKey + NetID + AppNonce + DevNonce.
/// 1.1 derives four keys from AppKey + NwkKey + JoinEUI + AppNonce + DevNonce.
/// With identical "shared" inputs, none of the 1.1 keys should equal the 1.0 keys
/// (the derivation block layout differs: NetID vs JoinEUI, 1.0 has 3-byte NetID
/// + 0-byte gap, 1.1 has 8-byte JoinEUI).
#[test]
fn session_keys_10_vs_11_produce_distinct_key_sets() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let nwk_key = NwkKey::new(APP_KEY_BYTES); // intentionally identical bytes
  let app_nonce = AppNonce::new(APP_NONCE_BYTES);
  let dev_nonce = DevNonce::new(DEV_NONCE_BYTES);
  let net_id = NetId::new(NET_ID_BYTES);
  let join_eui = AppEui::new(JOIN_EUI_BYTES);

  let v10 = SessionKeys10::derive(&app_key, &net_id, &app_nonce, &dev_nonce);
  let v11 = SessionKeys11::derive(&app_key, &nwk_key, &join_eui, &app_nonce, &dev_nonce);

  // 1.0 NwkSKey and 1.1 FNwkSIntKey both use prefix 0x01 under their network
  // root, but the block layouts differ -> must not match.
  assert_ne!(v10.nwk_s_key.as_bytes(), v11.f_nwk_s_int_key.as_bytes());
  assert_ne!(v10.nwk_s_key.as_bytes(), v11.s_nwk_s_int_key.as_bytes());
  assert_ne!(v10.nwk_s_key.as_bytes(), v11.nwk_s_enc_key.as_bytes());
  // 1.0 AppSKey vs 1.1 AppSKey: both use prefix 0x02 under AppKey but
  // different block layouts.
  assert_ne!(v10.app_s_key.as_bytes(), v11.app_s_key.as_bytes());
}

/// 1.1 has a strict separation between AppKey-derived and NwkKey-derived
/// material. Changing only NwkKey must leave AppSKey untouched.
#[test]
fn session_keys_11_app_s_key_depends_only_on_app_key() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let join_eui = AppEui::new(JOIN_EUI_BYTES);
  let app_nonce = AppNonce::new(APP_NONCE_BYTES);
  let dev_nonce = DevNonce::new(DEV_NONCE_BYTES);

  let a = SessionKeys11::derive(&app_key, &NwkKey::new([0x11u8; 16]), &join_eui, &app_nonce, &dev_nonce);
  let b = SessionKeys11::derive(&app_key, &NwkKey::new([0xeeu8; 16]), &join_eui, &app_nonce, &dev_nonce);

  // AppSKey unchanged
  assert_eq!(a.app_s_key.as_bytes(), b.app_s_key.as_bytes());
  // Network keys must all change
  assert_ne!(a.f_nwk_s_int_key.as_bytes(), b.f_nwk_s_int_key.as_bytes());
  assert_ne!(a.s_nwk_s_int_key.as_bytes(), b.s_nwk_s_int_key.as_bytes());
  assert_ne!(a.nwk_s_enc_key.as_bytes(), b.nwk_s_enc_key.as_bytes());
}

/// Symmetrical check: changing only AppKey must leave the three 1.1 network
/// keys untouched.
#[test]
fn session_keys_11_network_keys_depend_only_on_nwk_key() {
  let nwk_key = NwkKey::new(NWK_KEY_BYTES);
  let join_eui = AppEui::new(JOIN_EUI_BYTES);
  let app_nonce = AppNonce::new(APP_NONCE_BYTES);
  let dev_nonce = DevNonce::new(DEV_NONCE_BYTES);

  let a = SessionKeys11::derive(&AppKey::new([0x11u8; 16]), &nwk_key, &join_eui, &app_nonce, &dev_nonce);
  let b = SessionKeys11::derive(&AppKey::new([0xeeu8; 16]), &nwk_key, &join_eui, &app_nonce, &dev_nonce);

  assert_eq!(a.f_nwk_s_int_key.as_bytes(), b.f_nwk_s_int_key.as_bytes());
  assert_eq!(a.s_nwk_s_int_key.as_bytes(), b.s_nwk_s_int_key.as_bytes());
  assert_eq!(a.nwk_s_enc_key.as_bytes(), b.nwk_s_enc_key.as_bytes());
  assert_ne!(a.app_s_key.as_bytes(), b.app_s_key.as_bytes());
}

/// JoinEUI is bound into every 1.1 session key (it sits in the block layout
/// directly). Changing it must change all four keys.
#[test]
fn session_keys_11_depend_on_join_eui() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let nwk_key = NwkKey::new(NWK_KEY_BYTES);
  let app_nonce = AppNonce::new(APP_NONCE_BYTES);
  let dev_nonce = DevNonce::new(DEV_NONCE_BYTES);

  let a = SessionKeys11::derive(&app_key, &nwk_key, &AppEui::new([0u8; 8]), &app_nonce, &dev_nonce);
  let b = SessionKeys11::derive(&app_key, &nwk_key, &AppEui::new([0xffu8; 8]), &app_nonce, &dev_nonce);

  assert_ne!(a.app_s_key.as_bytes(), b.app_s_key.as_bytes());
  assert_ne!(a.f_nwk_s_int_key.as_bytes(), b.f_nwk_s_int_key.as_bytes());
  assert_ne!(a.s_nwk_s_int_key.as_bytes(), b.s_nwk_s_int_key.as_bytes());
  assert_ne!(a.nwk_s_enc_key.as_bytes(), b.nwk_s_enc_key.as_bytes());
}

/// 1.0 SessionKeys: NetID is mixed into the block. Different NetID -> both
/// keys must change.
#[test]
fn session_keys_10_depend_on_net_id() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let app_nonce = AppNonce::new(APP_NONCE_BYTES);
  let dev_nonce = DevNonce::new(DEV_NONCE_BYTES);

  let a = SessionKeys10::derive(&app_key, &NetId::new([0, 0, 0]), &app_nonce, &dev_nonce);
  let b = SessionKeys10::derive(&app_key, &NetId::new([0, 0, 1]), &app_nonce, &dev_nonce);

  assert_ne!(a.app_s_key.as_bytes(), b.app_s_key.as_bytes());
  assert_ne!(a.nwk_s_key.as_bytes(), b.nwk_s_key.as_bytes());
}

/// 1.1 keys have four distinct prefixes (0x01-0x04). With all other inputs
/// equal, the four keys must all differ from each other.
#[test]
fn session_keys_11_four_keys_all_distinct() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let nwk_key = NwkKey::new(APP_KEY_BYTES); // same root bytes for both
  let keys = SessionKeys11::derive(
    &app_key,
    &nwk_key,
    &AppEui::new(JOIN_EUI_BYTES),
    &AppNonce::new(APP_NONCE_BYTES),
    &DevNonce::new(DEV_NONCE_BYTES),
  );

  let a = keys.app_s_key.as_bytes();
  let f = keys.f_nwk_s_int_key.as_bytes();
  let s = keys.s_nwk_s_int_key.as_bytes();
  let e = keys.nwk_s_enc_key.as_bytes();

  assert_ne!(a, f);
  assert_ne!(a, s);
  assert_ne!(a, e);
  assert_ne!(f, s);
  assert_ne!(f, e);
  assert_ne!(s, e);
}

// ---------------------------------------------------------------------------
// End-to-end: derived keys verify the MIC they signed
// ---------------------------------------------------------------------------

/// Full OTAA flow for 1.0: derive session keys, sign uplink, verify MIC.
#[test]
fn otaa_v1_0_end_to_end_sign_and_verify() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let sk = SessionKeys10::derive(
    &app_key,
    &NetId::new(NET_ID_BYTES),
    &AppNonce::new(APP_NONCE_BYTES),
    &DevNonce::new(DEV_NONCE_BYTES),
  );

  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(1)
    .f_port(1)
    .payload(b"e2e10")
    .sign_and_encrypt(&sk.app_s_key, &sk.nwk_s_key)
    .unwrap();

  let keys = V1_0MicKeys {
    nwk_s_key: Some(&sk.nwk_s_key),
    ..Default::default()
  };
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

/// Full OTAA flow for 1.1: derive session keys, build + sign uplink with the
/// dual-MIC path, then verify.
#[test]
fn otaa_v1_1_end_to_end_sign_and_verify_uplink() {
  let app_key = AppKey::new(APP_KEY_BYTES);
  let nwk_key = NwkKey::new(NWK_KEY_BYTES);
  let sk = SessionKeys11::derive(
    &app_key,
    &nwk_key,
    &AppEui::new(JOIN_EUI_BYTES),
    &AppNonce::new(APP_NONCE_BYTES),
    &DevNonce::new(DEV_NONCE_BYTES),
  );

  // Encrypt payload manually under AppSKey (sign_and_encrypt is 1.0-only).
  // For the MIC path, the NwkSKey argument is only used when FPort == 0, so
  // pass any NwkSKey-typed key here; encrypt_payload uses AppSKey for FPort>0.
  let mut packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .f_ctrl(FCtrl(0))
    .f_cnt(9)
    .f_port(2)
    .payload(b"e2e11up")
    .build_unsigned()
    .unwrap();

  let plaintext = packet.as_data().unwrap().frm_payload.clone().unwrap();
  let nwk_s_key_proxy = NwkSKey::new([0u8; 16]);
  let ct = packet
    .as_data()
    .unwrap()
    .encrypt_payload(&plaintext, &sk.app_s_key, &nwk_s_key_proxy, 0)
    .unwrap();
  if let Payload::Data(d) = &mut packet.payload {
    d.frm_payload = Some(ct);
  }
  packet.phy_payload = packet.to_wire();

  let keys = V1_1MicKeys {
    f_nwk_s_int_key: Some(&sk.f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&sk.s_nwk_s_int_key),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&keys).unwrap();
  assert!(packet.verify_mic_v1_1(&keys).unwrap());
}

/// 1.1 Join Accept MIC: verify against the JSIntKey path through the public
/// API. Builds an unsigned Join Accept, signs with the 1.1 keyset directly,
/// then verifies.
#[test]
fn join_accept_v1_1_public_api_sign_and_verify() {
  let js_int_key = JSIntKey::new([0x66u8; 16]);
  let join_eui = AppEui::new(JOIN_EUI_BYTES);
  let dev_nonce = DevNonce::new(DEV_NONCE_BYTES);

  let mut packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new(APP_NONCE_BYTES))
    .net_id(NetId::new(NET_ID_BYTES))
    .dev_addr(DevAddr::new(DEV_ADDR_BYTES))
    .dl_settings(DlSettings(0))
    .rx_delay(1)
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
  assert!(packet.verify_mic_v1_1(&keys).unwrap());

  // Drift JoinReqType -> verify must fail.
  let keys_drift = V1_1MicKeys {
    js_int_key: Some(&js_int_key),
    join_eui: Some(join_eui),
    dev_nonce: Some(dev_nonce),
    join_req_type: Some(0x00),
    ..Default::default()
  };
  assert!(!packet.verify_mic_v1_1(&keys_drift).unwrap());
}
