//! End-to-end scenario tests that mimic real-world usage patterns of a
//! `LoRaWAN` stack: OTAA joins, uplink and downlink data frames, MAC commands
//! in `FOpts`, Rejoin requests, multi-frame sessions, and confirmed/ACK flows.
//!
//! Each test is a self-contained "scenario" demonstrating a complete workflow
//! that a Lambda middleware or embedded device might perform.

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, FNwkSIntKey, JSIntKey,
  JoinAccept, JoinServerKeys, LoraPacket, NetId, NwkKey, NwkSEncKey, NwkSKey, SNwkSIntKey, SessionKeys10,
  SessionKeys11, V1_0MicKeys, V1_1MicKeys,
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

/// Scenario 1: full OTAA Join for `LoRaWAN` 1.0.
///
/// Device builds and signs a Join Request under `AppKey`. The network server
/// parses it, verifies the MIC, picks an `AppNonce`/`NetID`/`DevAddr`, and
/// builds a Join Accept signed and encrypted with the same `AppKey`. Both
/// sides derive `SessionKeys10` from the same inputs and end up with identical
/// `AppSKey` and `NwkSKey`.
#[test]
fn scenario_otaa_join_1_0() {
  // Provisioned in the device.
  let app_key = AppKey::new(key_from_hex("98929b92c49edba9676d646d3b612456"));
  let join_eui = AppEui::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
  let dev_eui = DevEui::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
  let dev_nonce = DevNonce::new([0xf1, 0x8e]);

  // Device side: build and sign Join Request.
  let jr_packet = LoraPacket::builder()
    .join_request()
    .join_eui(join_eui)
    .dev_eui(dev_eui)
    .dev_nonce(dev_nonce)
    .sign_join_request(&app_key)
    .expect("sign_join_request");

  // Air transit, then parse on the network side.
  let wire = jr_packet.to_wire();
  let parsed = LoraPacket::from_wire(&wire).expect("parse Join Request");
  let parsed_jr = parsed.as_join_request().expect("Join Request variant");
  assert_eq!(parsed_jr.join_eui, join_eui);
  assert_eq!(parsed_jr.dev_eui, dev_eui);
  assert_eq!(parsed_jr.dev_nonce, dev_nonce);

  // Network verifies MIC under AppKey (1.0).
  let jr_mic_keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert!(parsed.verify_mic_v1_0(&jr_mic_keys).expect("verify Join Request MIC"));

  // Network picks join parameters.
  let net_id = NetId::new([0xaa, 0xbb, 0xcc]);
  let app_nonce = AppNonce::new([0x37, 0x63, 0x38]);
  let dev_addr = DevAddr::new([0x12, 0x34, 0x56, 0x78]);

  // Network builds and signs and encrypts Join Accept.
  let (ja_plain, ja_wire) = LoraPacket::builder()
    .join_accept()
    .join_nonce(app_nonce)
    .net_id(net_id)
    .dev_addr(dev_addr)
    .dl_settings(DlSettings(0))
    .rx_delay(1)
    .sign_join_accept(&app_key)
    .expect("sign_join_accept");
  assert!(ja_plain.is_join_accept());

  // Device side: decrypt wire bytes, parse back, verify MIC.
  let ja_decrypted = JoinAccept::decrypt_from_wire(&ja_wire, &app_key).expect("decrypt Join Accept");
  assert_eq!(ja_decrypted, ja_plain.phy_payload);
  let parsed_ja_packet = {
    let parsed_ja = JoinAccept::from_plaintext(&ja_decrypted).expect("parse Join Accept plaintext");
    assert_eq!(parsed_ja.join_nonce, app_nonce);
    assert_eq!(parsed_ja.net_id, net_id);
    assert_eq!(parsed_ja.dev_addr, dev_addr);
    ja_plain
  };

  // Device verifies the Join Accept MIC (1.0) using the same AppKey.
  let ja_mic_keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert!(
    parsed_ja_packet
      .verify_mic_v1_0(&ja_mic_keys)
      .expect("verify Join Accept MIC")
  );

  // Both sides derive the same session keys.
  let device_keys = SessionKeys10::derive(&app_key, &net_id, &app_nonce, &dev_nonce);
  let server_keys = SessionKeys10::derive(&app_key, &net_id, &app_nonce, &dev_nonce);
  assert_eq!(device_keys.app_s_key.as_bytes(), server_keys.app_s_key.as_bytes());
  assert_eq!(device_keys.nwk_s_key.as_bytes(), server_keys.nwk_s_key.as_bytes());
}

/// Scenario 2: full OTAA Join for `LoRaWAN` 1.1.
///
/// Same shape as scenario 1, but with the 1.1 key split (`NwkKey` + `AppKey`),
/// the four-way `SessionKeys11` derivation, and a Join Accept signed with the
/// derived `JSIntKey` (which also depends on `DevEUI`).
#[test]
fn scenario_otaa_join_1_1() {
  let app_key = AppKey::new(key_from_hex("01000000000000000000000000000001"));
  let nwk_key = NwkKey::new(key_from_hex("00000000000000000000000000000001"));
  let join_eui = AppEui::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
  let dev_eui = DevEui::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
  let dev_nonce = DevNonce::new([0xe8, 0xc2]);

  // Device side: 1.1 Join Request is signed with NwkKey.
  let jr_packet = LoraPacket::builder()
    .join_request()
    .join_eui(join_eui)
    .dev_eui(dev_eui)
    .dev_nonce(dev_nonce)
    .sign_join_request_v1_1(&nwk_key)
    .expect("sign_join_request_v1_1");
  let jr_wire = jr_packet.to_wire();

  // Network parses and verifies the Join Request MIC under NwkKey.
  let parsed_jr = LoraPacket::from_wire(&jr_wire).expect("parse Join Request");
  let jr_mic_keys = V1_1MicKeys {
    nwk_key: Some(&nwk_key),
    ..Default::default()
  };
  assert!(
    parsed_jr
      .verify_mic_v1_1(&jr_mic_keys)
      .expect("verify Join Request 1.1 MIC")
  );

  // Network picks join parameters and derives JS keys for the Join Accept MIC.
  let net_id = NetId::new([0x00, 0x00, 0x60]);
  let app_nonce = AppNonce::new([0x00, 0x00, 0x03]);
  let dev_addr = DevAddr::new([0x01, 0x02, 0x03, 0x04]);
  let js = JoinServerKeys::derive(&nwk_key, &dev_eui);

  // Build the Join Accept body unsigned, then compute the 1.1 MIC under JSIntKey.
  let mut ja_packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(app_nonce)
    .net_id(net_id)
    .dev_addr(dev_addr)
    .dl_settings(DlSettings(0b1000_0000)) // OptNeg = 1 => 1.1 mode
    .rx_delay(1)
    .build_unsigned()
    .expect("build unsigned Join Accept");

  let ja_mic_keys = V1_1MicKeys {
    js_int_key: Some(&js.js_int_key),
    join_eui: Some(join_eui),
    dev_nonce: Some(dev_nonce),
    join_req_type: Some(0xFF),
    ..Default::default()
  };
  ja_packet
    .recalculate_mic_v1_1(&ja_mic_keys)
    .expect("recalculate Join Accept 1.1 MIC");

  // Server-side encryption of the Join Accept body (uses NwkKey as the AppKey
  // input to the ECB-decrypt step in 1.1).
  let app_key_for_ja = AppKey::new(*nwk_key.as_bytes());
  let ja_wire = JoinAccept::encrypt_for_wire(&ja_packet.phy_payload, &app_key_for_ja).expect("encrypt Join Accept");

  // Device side: decrypt, parse, verify MIC.
  let ja_plaintext = JoinAccept::decrypt_from_wire(&ja_wire, &app_key_for_ja).expect("decrypt Join Accept");
  assert_eq!(ja_plaintext, ja_packet.phy_payload);
  let parsed_ja = JoinAccept::from_plaintext(&ja_plaintext).expect("parse Join Accept");
  assert!(parsed_ja.dl_settings.opt_neg(), "OptNeg bit must be set for 1.1");
  assert_eq!(parsed_ja.dev_addr, dev_addr);

  // Independently rebuild the same packet on the device side to verify the MIC
  // (verification requires the JoinEUI/DevNonce/JoinReqType context fields).
  let device_view = LoraPacket::builder()
    .join_accept()
    .join_nonce(parsed_ja.join_nonce)
    .net_id(parsed_ja.net_id)
    .dev_addr(parsed_ja.dev_addr)
    .dl_settings(parsed_ja.dl_settings)
    .rx_delay(parsed_ja.rx_delay)
    .build_unsigned()
    .expect("rebuild Join Accept");
  let mut device_view_with_mic = device_view;
  device_view_with_mic
    .recalculate_mic_v1_1(&ja_mic_keys)
    .expect("device-side MIC");
  assert_eq!(device_view_with_mic.mic, ja_packet.mic);

  // Both sides derive the four 1.1 session keys identically.
  let device_keys = SessionKeys11::derive(&app_key, &nwk_key, &join_eui, &app_nonce, &dev_nonce);
  let server_keys = SessionKeys11::derive(&app_key, &nwk_key, &join_eui, &app_nonce, &dev_nonce);
  assert_eq!(device_keys.app_s_key.as_bytes(), server_keys.app_s_key.as_bytes());
  assert_eq!(
    device_keys.f_nwk_s_int_key.as_bytes(),
    server_keys.f_nwk_s_int_key.as_bytes()
  );
  assert_eq!(
    device_keys.s_nwk_s_int_key.as_bytes(),
    server_keys.s_nwk_s_int_key.as_bytes()
  );
  assert_eq!(
    device_keys.nwk_s_enc_key.as_bytes(),
    server_keys.nwk_s_enc_key.as_bytes()
  );
}

/// Scenario 3: a real 1.0 uplink. Device builds and encrypts and signs an
/// uplink Data frame; the network parses, verifies the MIC, and decrypts.
#[test]
fn scenario_uplink_data_frame_1_0() {
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let dev_addr = DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]);
  let plaintext: &[u8] = b"test";

  // Device builds, encrypts, and signs in one shot.
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(dev_addr)
    .f_ctrl(FCtrl(0))
    .f_cnt(2)
    .f_port(1)
    .payload(plaintext)
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .expect("sign_and_encrypt");
  let wire = packet.to_wire();

  // Network parses the wire bytes.
  let parsed = LoraPacket::from_wire(&wire).expect("parse uplink");
  assert!(parsed.is_data());
  let d = parsed.as_data().expect("Data variant");
  assert_eq!(d.direction, Direction::Uplink);
  assert!(!d.confirmed);
  assert_eq!(d.dev_addr, dev_addr);
  assert_eq!(d.f_cnt(), 2);
  assert_eq!(d.f_port, Some(1));

  // Network verifies MIC.
  let mic_keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert!(parsed.verify_mic_v1_0(&mic_keys).expect("verify uplink MIC"));

  // Network decrypts FRMPayload.
  let decrypted = d
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .expect("decrypt FRMPayload");
  assert_eq!(decrypted, plaintext);

  // Round-trip wire form matches the canonical test vector for these keys.
  assert_eq!(wire, hex_to_vec("40f17dbe4900020001954378762b11ff0d"));
}

/// Scenario 4: 1.0 downlink with the `FPending` bit set. Network builds and
/// encrypts and signs the downlink; the device parses, verifies the MIC, sees
/// `FPending`, and decrypts the payload.
#[test]
fn scenario_downlink_data_frame_with_fpending() {
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let dev_addr = DevAddr::new([0x12, 0x34, 0x56, 0x78]);
  let downlink_payload: &[u8] = b"ack-data";

  // Network builds the downlink with FPending (bit 4 in FCtrl) set so the
  // device knows another downlink is queued.
  let packet = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(dev_addr)
    .f_ctrl(FCtrl(0b0001_0000)) // FPending = 1
    .f_cnt(7)
    .f_port(2)
    .payload(downlink_payload)
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .expect("sign_and_encrypt downlink");
  let wire = packet.to_wire();

  // Device side: parse from the wire.
  let parsed = LoraPacket::from_wire(&wire).expect("parse downlink");
  let d = parsed.as_data().expect("Data variant");
  assert_eq!(d.direction, Direction::Downlink);
  assert!(d.f_ctrl.f_pending(), "FPending must be set");
  assert_eq!(d.f_cnt(), 7);

  // Device verifies MIC, then decrypts.
  let mic_keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert!(parsed.verify_mic_v1_0(&mic_keys).expect("verify downlink MIC"));
  let decrypted = d
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .expect("decrypt FRMPayload");
  assert_eq!(decrypted, downlink_payload);
}

/// Scenario 5: 1.1 downlink carrying encrypted MAC commands in `FOpts`.
///
/// In `LoRaWAN` 1.1, `FOpts` is encrypted under `NwkSEncKey`. Downlink with
/// `FPort > 0` uses the `aFCntDown` keystream variant (byte 4 = 0x02). The MIC
/// here uses the 1.0 dispatch path under `SNwkSIntKey` (matching the
/// brocaar/lorawan reference behaviour and the existing `fopts.rs` integration
/// test).
#[test]
fn scenario_fopts_mac_commands_1_1() {
  let s_nwk_s_int_key_bytes: [u8; 16] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0];
  let nwk_s_enc_key = NwkSEncKey::new([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0]);
  let app_s_key = AppSKey::new([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
  let dev_addr = DevAddr::new([0x01, 0x02, 0x03, 0x04]);

  // Network builds an unsigned downlink with plaintext FOpts.
  let mut packet = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(dev_addr)
    .f_cnt(0)
    .f_ctrl(FCtrl(0x03)) // FOpts len = 3
    .f_opts(&[0x02, 0x07, 0x01]) // LinkADRReq-style MAC commands
    .f_port(1)
    .payload(&hex_to_vec("01020304"))
    .build_unsigned()
    .expect("build_unsigned downlink");

  // Encrypt FRMPayload with AppSKey.
  let frm_cipher = packet
    .as_data()
    .unwrap()
    .encrypt_payload(&hex_to_vec("01020304"), &app_s_key, &NwkSKey::new([0u8; 16]), 0)
    .expect("encrypt FRMPayload");
  packet.as_data_mut().unwrap().frm_payload = Some(frm_cipher);

  // Encrypt FOpts with NwkSEncKey (1.1 specific).
  let fopts_cipher = packet
    .as_data()
    .unwrap()
    .encrypt_fopts(&nwk_s_enc_key, 0)
    .expect("encrypt FOpts");
  packet.as_data_mut().unwrap().f_opts = fopts_cipher;

  // Recompute MIC after encryption.
  packet.phy_payload = packet.to_wire();
  let nwk_s_key_mic = NwkSKey::new(s_nwk_s_int_key_bytes);
  let mic_keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key_mic),
    ..Default::default()
  };
  packet.recalculate_mic_v1_0(&mic_keys).expect("recalculate MIC");

  // Device side: parse the wire bytes.
  let wire = packet.to_wire();
  assert_eq!(wire, hex_to_vec("600403020103000022ac0a01f0b468ddaa5ed13a"));
  let parsed = LoraPacket::from_wire(&wire).expect("parse downlink");

  // Verify MIC.
  assert!(parsed.verify_mic_v1_0(&mic_keys).expect("verify downlink MIC"));

  // Device decrypts FOpts to recover the MAC commands.
  let d = parsed.as_data().expect("Data variant");
  let decrypted_fopts = d.decrypt_fopts(&nwk_s_enc_key, 0).expect("decrypt FOpts");
  assert_eq!(
    decrypted_fopts,
    &[0x02, 0x07, 0x01],
    "MAC commands recovered from FOpts"
  );

  // And device decrypts FRMPayload.
  let decrypted = d
    .decrypt_payload(&app_s_key, &NwkSKey::new([0u8; 16]), 0)
    .expect("decrypt FRMPayload");
  assert_eq!(decrypted, hex_to_vec("01020304"));
}

/// Scenario 6: 1.1 Rejoin Type 1.
///
/// Type 1 carries `JoinEUI || DevEUI || RJCount1` and is signed with
/// `JSIntKey` (derived from `NwkKey` and `DevEUI`). The network verifies the
/// MIC using the same derived key.
#[test]
fn scenario_rejoin_type_1_1_1() {
  let nwk_key = NwkKey::new(key_from_hex("01010101010101010101010101010101"));
  let join_eui = AppEui::new([0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]);
  let dev_eui = DevEui::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

  // Both sides derive JSIntKey from NwkKey + DevEUI.
  let js = JoinServerKeys::derive(&nwk_key, &dev_eui);

  // Device builds the Rejoin Type 1 frame unsigned, then signs it.
  let mut packet = LoraPacket::builder()
    .rejoin_request(1)
    .join_eui(join_eui)
    .dev_eui(dev_eui)
    .build_unsigned()
    .expect("build_unsigned rejoin");

  let mic_keys = V1_1MicKeys {
    js_int_key: Some(&js.js_int_key),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).expect("sign rejoin");

  // Network parses and verifies.
  let wire = packet.to_wire();
  let parsed = LoraPacket::from_wire(&wire).expect("parse rejoin");
  let rj = parsed.as_rejoin_request().expect("rejoin variant");
  match rj {
    lora_packet::RejoinRequest::Type1 {
      join_eui: parsed_je,
      dev_eui: parsed_de,
      rj_count_1,
    } => {
      assert_eq!(*parsed_je, join_eui);
      assert_eq!(*parsed_de, dev_eui);
      assert_eq!(*rj_count_1, [0, 0]);
    }
    _ => panic!("expected Rejoin Type 1"),
  }

  let verify_keys = V1_1MicKeys {
    js_int_key: Some(&js.js_int_key),
    ..Default::default()
  };
  assert!(parsed.verify_mic_v1_1(&verify_keys).expect("verify rejoin MIC"));
}

/// Scenario 7: a multi-frame uplink session.
///
/// Same `DevAddr`/session keys, incrementing `FCnt` across three frames. Each
/// frame is built and signed independently, parsed independently, verified,
/// and decrypted. This is the steady-state pattern after an OTAA join.
#[test]
fn scenario_multi_frame_session() {
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let dev_addr = DevAddr::new([0x12, 0x34, 0x56, 0x78]);

  let payloads: &[&[u8]] = &[b"frame-one", b"frame-two", b"frame-three"];

  let mic_keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };

  for (i, plaintext) in payloads.iter().enumerate() {
    let f_cnt = u16::try_from(10 + i).expect("fits in u16");

    let packet = LoraPacket::builder()
      .data(Direction::Uplink, false)
      .dev_addr(dev_addr)
      .f_ctrl(FCtrl(0))
      .f_cnt(f_cnt)
      .f_port(1)
      .payload(plaintext)
      .sign_and_encrypt(&app_s_key, &nwk_s_key)
      .expect("sign_and_encrypt");
    let wire = packet.to_wire();

    let parsed = LoraPacket::from_wire(&wire).expect("parse frame");
    let d = parsed.as_data().expect("Data variant");

    assert_eq!(d.dev_addr, dev_addr);
    assert_eq!(d.f_cnt(), f_cnt);
    assert!(parsed.verify_mic_v1_0(&mic_keys).expect("verify MIC"), "frame {i} MIC");

    let decrypted = d
      .decrypt_payload(&app_s_key, &nwk_s_key, 0)
      .expect("decrypt FRMPayload");
    assert_eq!(decrypted.as_slice(), *plaintext, "frame {i} payload");
  }
}

/// Scenario 8: Confirmed uplink followed by an Unconfirmed downlink with
/// the ACK bit set.
///
/// Device sends `ConfirmedDataUp`; network verifies, then responds with
/// `UnconfirmedDataDown` carrying the ACK bit in `FCtrl`. The device verifies
/// the downlink and observes the ACK.
#[test]
fn scenario_confirmed_uplink_with_ack_downlink() {
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let dev_addr = DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]);

  // Device sends ConfirmedDataUp.
  let uplink = LoraPacket::builder()
    .data(Direction::Uplink, true) // confirmed = true
    .dev_addr(dev_addr)
    .f_ctrl(FCtrl(0))
    .f_cnt(42)
    .f_port(1)
    .payload(b"please-ack-me")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .expect("sign_and_encrypt confirmed uplink");
  let uplink_wire = uplink.to_wire();

  // Network parses and verifies.
  let parsed_uplink = LoraPacket::from_wire(&uplink_wire).expect("parse uplink");
  assert!(parsed_uplink.is_confirmed());
  assert_eq!(parsed_uplink.m_type(), lora_packet::MType::ConfirmedDataUp);

  let mic_keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert!(
    parsed_uplink
      .verify_mic_v1_0(&mic_keys)
      .expect("verify confirmed uplink MIC")
  );

  let uplink_data = parsed_uplink.as_data().expect("Data variant");
  let uplink_plain = uplink_data
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .expect("decrypt uplink");
  assert_eq!(uplink_plain, b"please-ack-me");

  // Network builds an UnconfirmedDataDown with the ACK bit set.
  let downlink = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(dev_addr)
    .f_ctrl(FCtrl(0b0010_0000)) // ACK = 1
    .f_cnt(1)
    .f_port(1)
    .payload(b"acked")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .expect("sign_and_encrypt ACK downlink");
  let downlink_wire = downlink.to_wire();

  // Device parses, verifies, observes ACK, decrypts.
  let parsed_downlink = LoraPacket::from_wire(&downlink_wire).expect("parse downlink");
  let downlink_data = parsed_downlink.as_data().expect("Data variant");
  assert!(downlink_data.f_ctrl.ack(), "downlink must carry ACK bit");
  assert_eq!(parsed_downlink.m_type(), lora_packet::MType::UnconfirmedDataDown);
  assert!(
    parsed_downlink
      .verify_mic_v1_0(&mic_keys)
      .expect("verify ACK downlink MIC")
  );

  let downlink_plain = downlink_data
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .expect("decrypt downlink");
  assert_eq!(downlink_plain, b"acked");
}

/// Bonus scenario: 1.1 uplink with the dual-MIC construction.
///
/// `LoRaWAN` 1.1 uplinks use both `FNwkSIntKey` and `SNwkSIntKey` to compute a
/// dual MIC. This scenario builds a 1.1-style uplink end-to-end, including
/// the `conf_fcnt_down_tx_dr_tx_ch` context bytes, and verifies the MIC on
/// the network side.
#[test]
fn scenario_uplink_data_frame_1_1_dual_mic() {
  let app_s_key = AppSKey::new(key_from_hex("38034b6efc87cf9c40ac0b45b460d395"));
  let f_nwk_s_int_key = FNwkSIntKey::new(key_from_hex("07c105892e1bbb7f7101d13a5f78249b"));
  let s_nwk_s_int_key = SNwkSIntKey::new(key_from_hex("f9162a2fcf6e70867cee523249282844"));
  let dev_addr = DevAddr::new([0xe0, 0x10, 0x98, 0x67]);
  let conf_ctx = [0x00, 0x00, 0x00, 0x01];
  let f_cnt = 0u16;
  let plaintext: &[u8] = &[0x0B, 0x01];

  // Build unsigned uplink and encrypt FRMPayload manually (1.1 sign needs a
  // separate step because sign_and_encrypt uses the 1.0 MIC).
  let mut packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(dev_addr)
    .f_ctrl(FCtrl(0x80)) // ADR set
    .f_cnt(f_cnt)
    .f_port(2)
    .payload(plaintext)
    .build_unsigned()
    .expect("build_unsigned uplink");

  let frm_cipher = packet
    .as_data()
    .unwrap()
    .encrypt_payload(plaintext, &app_s_key, &NwkSKey::new([0u8; 16]), 0)
    .expect("encrypt FRMPayload");
  packet.as_data_mut().unwrap().frm_payload = Some(frm_cipher);
  packet.phy_payload = packet.to_wire();

  let mic_keys = V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    conf_fcnt_down_tx_dr_tx_ch: Some(conf_ctx),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).expect("sign 1.1 uplink");

  let wire = packet.to_wire();

  // Network: parse, verify dual-MIC, decrypt payload.
  let parsed = LoraPacket::from_wire(&wire).expect("parse 1.1 uplink");
  assert_eq!(parsed.as_data().unwrap().direction, Direction::Uplink);
  assert!(parsed.verify_mic_v1_1(&mic_keys).expect("verify dual-MIC"));

  let decrypted = parsed
    .as_data()
    .unwrap()
    .decrypt_payload(&app_s_key, &NwkSKey::new([0u8; 16]), 0)
    .expect("decrypt FRMPayload");
  assert_eq!(decrypted, plaintext);
}

/// A sanity scenario covering JSIntKey-based Join Accept signing in isolation.
///
/// Demonstrates that two independent participants (e.g. a Lambda handler and
/// the on-device firmware) computing `JoinServerKeys::derive(&nwk_key,
/// &dev_eui)` end up with the same `JSIntKey`, so the MIC computed by one
/// verifies on the other.
#[test]
fn scenario_join_server_keys_share_js_int_key() {
  let nwk_key = NwkKey::new(key_from_hex("01010101010101010101010101010101"));
  let dev_eui = DevEui::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

  let js_a = JoinServerKeys::derive(&nwk_key, &dev_eui);
  let js_b = JoinServerKeys::derive(&nwk_key, &dev_eui);
  assert_eq!(js_a.js_int_key.as_bytes(), js_b.js_int_key.as_bytes());
  assert_eq!(js_a.js_enc_key.as_bytes(), js_b.js_enc_key.as_bytes());

  // Round-trip: build a Join Accept signed under one side's JSIntKey and
  // verify it from a JSIntKey freshly rebuilt on the other side.
  let join_eui = AppEui::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
  let dev_nonce = DevNonce::new([0x01, 0x02]);

  let mut packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0x10, 0x20, 0x30]))
    .net_id(NetId::new([0xaa, 0xbb, 0xcc]))
    .dev_addr(DevAddr::new([0x11, 0x22, 0x33, 0x44]))
    .dl_settings(DlSettings(0b1000_0000))
    .rx_delay(1)
    .build_unsigned()
    .expect("build_unsigned");

  let signing_key = JSIntKey::new(*js_a.js_int_key.as_bytes());
  let sign_keys = V1_1MicKeys {
    js_int_key: Some(&signing_key),
    join_eui: Some(join_eui),
    dev_nonce: Some(dev_nonce),
    join_req_type: Some(0xFF),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&sign_keys).expect("sign Join Accept");

  let verifying_key = JSIntKey::new(*js_b.js_int_key.as_bytes());
  let verify_keys = V1_1MicKeys {
    js_int_key: Some(&verifying_key),
    join_eui: Some(join_eui),
    dev_nonce: Some(dev_nonce),
    join_req_type: Some(0xFF),
    ..Default::default()
  };
  assert!(packet.verify_mic_v1_1(&verify_keys).expect("cross-verify"));
}
