//! Integration tests mirroring `__tests__/join_accept_encrypt.ts`.

use lora_packet::{
  AppEui, AppKey, AppNonce, DevAddr, DevNonce, DlSettings, JoinAccept, LoraPacket, NetId, NwkKey, V1_1MicKeys,
};

fn hex_to_vec(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex string")
}

/// Mirror of `__tests__/join_accept_encrypt.ts`:
/// "should create join accept packet with zero value"
///
/// Build a Join Accept with all-zero fields under an all-zero AppKey, sign
/// it (1.0 MIC), then encrypt for the wire. The decrypted form parses back
/// to the original plaintext.
#[test]
fn should_create_join_accept_packet_with_zero_value() {
  let app_key = AppKey::new([0u8; 16]);

  let (packet, encrypted_wire) = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0, 0, 0]))
    .net_id(NetId::new([0, 0, 0]))
    .dev_addr(DevAddr::new([0, 0, 0, 0]))
    .dl_settings(DlSettings(0))
    .rx_delay(0)
    .sign_join_accept(&app_key)
    .unwrap();

  // Plaintext form: MHDR + zeroed body + MIC `f86f0a91`.
  let expected_plaintext_phy = hex_to_vec("20000000000000000000000000f86f0a91");
  assert_eq!(packet.phy_payload, expected_plaintext_phy);
  assert_eq!(packet.mhdr.as_byte(), 0x20);
  assert_eq!(packet.mic, [0xf8, 0x6f, 0x0a, 0x91]);

  let ja = packet.as_join_accept().unwrap();
  assert_eq!(ja.join_nonce.as_bytes(), &[0, 0, 0]);
  assert_eq!(ja.net_id.as_bytes(), &[0, 0, 0]);
  assert_eq!(ja.dev_addr.as_bytes(), &[0, 0, 0, 0]);
  assert_eq!(ja.dl_settings.as_byte(), 0x00);
  assert_eq!(ja.rx_delay, 0x00);
  assert!(ja.cf_list.is_none());

  // Encrypted (wire) form matches the TS expectation.
  let expected_encrypted = hex_to_vec("20e3de108795f776b8037610ef7869b5b3");
  assert_eq!(encrypted_wire, expected_encrypted);

  // Round-trip: decrypt the wire bytes -> plaintext form, parse back.
  let decrypted = JoinAccept::decrypt_from_wire(&encrypted_wire, &app_key).unwrap();
  assert_eq!(decrypted, expected_plaintext_phy);

  let parsed = JoinAccept::from_plaintext(&decrypted).unwrap();
  assert_eq!(parsed.join_nonce.as_bytes(), &[0, 0, 0]);
  assert_eq!(parsed.net_id.as_bytes(), &[0, 0, 0]);
  assert_eq!(parsed.dev_addr.as_bytes(), &[0, 0, 0, 0]);
  assert_eq!(parsed.dl_settings.as_byte(), 0x00);
  assert_eq!(parsed.rx_delay, 0x00);
  assert!(parsed.cf_list.is_none());
}

/// Mirror of `__tests__/join_accept_encrypt.ts`:
/// "should create join accept as in brocaar/lorawan 1.1"
///
/// Builds a `LoRaWAN` 1.1 Join Accept with OptNeg set, signs under JSIntKey
/// (= the NwkKey here, per the TS test which uses the same key for both
/// places), and encrypts for the wire.
///
/// base64 "IHq+6gawKSDxHALQNI/PGBU=" decodes to
/// `207abeea06b02920f11c02d0348fcf1815`.
#[test]
fn should_create_join_accept_as_in_brocaar_lorawan_1_1() {
  let nwk_key = NwkKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  let join_eui = AppEui::new([8, 7, 6, 5, 4, 3, 2, 1]);
  let dev_nonce = DevNonce::new([1, 2]);

  let mut packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0x01, 0x01, 0x01]))
    .net_id(NetId::new([0x02, 0x02, 0x02]))
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .dl_settings(DlSettings(0b1000_0000)) // OptNeg = 1
    .rx_delay(0)
    .build_unsigned()
    .unwrap();

  let js_int_key = lora_packet::JSIntKey::new(*nwk_key.as_bytes());
  let mic_keys = V1_1MicKeys {
    js_int_key: Some(&js_int_key),
    join_eui: Some(join_eui),
    dev_nonce: Some(dev_nonce),
    join_req_type: Some(0xFF),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).unwrap();

  // App key (= NwkKey here) for the join-accept ECB-decrypt-on-server step.
  let app_key = AppKey::new(*nwk_key.as_bytes());
  let encrypted = JoinAccept::encrypt_for_wire(&packet.phy_payload, &app_key).unwrap();

  let expected = hex_to_vec("207abeea06b02920f11c02d0348fcf1815");
  assert_eq!(encrypted, expected);
}
