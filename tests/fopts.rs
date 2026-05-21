//! FOpts encrypt and decrypt tests (LoRaWAN 1.1).
use lora_packet::{
  AppSKey, DevAddr, Direction, FCtrl, FNwkSIntKey, LoraPacket, NwkSEncKey, NwkSKey, SNwkSIntKey, V1_0MicKeys,
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

#[test]
fn should_parse_packet_1() {
  let bytes = hex_to_vec("4084412505A3010009110308B33750F504D4B86A");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();
  let d = parsed.as_data().unwrap();
  assert_eq!(d.f_opts, hex_to_vec("091103"));
}

/// "should encode packet with Lorawan11 Encrypted Fopts"
///
/// Downlink with FPort > 0 (the `aFCntDown` path; `fopts_crypt` uses 0x02
/// in byte 4). The TS test calls `encryptFOpts` then verifies the full
/// PHYPayload. The Rust API requires three steps: build unsigned, encrypt
/// FRMPayload, encrypt FOpts in place, recompute the MIC. The MIC here is
/// the LoRaWAN 1.0-style MIC under sNwkSIntKey (the TS uses
/// `recalculateMIC(payload, NwkSKey=sNwkSIntKey, ...)` which routes to 1.0).
#[test]
fn should_encode_packet_with_lorawan_1_1_encrypted_fopts() {
  let s_nwk_s_int_key_bytes: [u8; 16] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0];
  let nwk_s_enc_key = NwkSEncKey::new([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0]);
  let app_s_key = AppSKey::new([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

  let mut packet = LoraPacket::builder()
    .data(Direction::Downlink, false) // MHDR = 0x60
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .f_cnt(0)
    .f_ctrl(FCtrl(0x03)) // FOpts len = 3
    .f_opts(&[0x02, 0x07, 0x01])
    .f_port(1)
    .payload(&hex_to_vec("01020304"))
    .build_unsigned()
    .unwrap();

  // Encrypt FRMPayload (FPort > 0 -> AppSKey).
  let nwk_s_key_unused = NwkSKey::new([0u8; 16]);
  let encrypted_payload = packet
    .as_data()
    .unwrap()
    .encrypt_payload(&hex_to_vec("01020304"), &app_s_key, &nwk_s_key_unused, 0)
    .unwrap();
  packet.as_data_mut().unwrap().frm_payload = Some(encrypted_payload);

  // Encrypt FOpts (downlink with FPort > 0 -> aFCntDown path; key byte 4 = 0x02).
  let encrypted_fopts = packet.as_data().unwrap().encrypt_fopts(&nwk_s_enc_key, 0).unwrap();
  packet.as_data_mut().unwrap().f_opts = encrypted_fopts;

  packet.phy_payload = packet.to_wire();

  // MIC = 1.0 MIC under sNwkSIntKey.
  let nwk_s_key = NwkSKey::new(s_nwk_s_int_key_bytes);
  let mic_keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  packet.recalculate_mic_v1_0(&mic_keys).unwrap();

  let expected = hex_to_vec("600403020103000022ac0a01f0b468ddaa5ed13a");
  assert_eq!(packet.phy_payload, expected);

  let d = packet.as_data().unwrap();
  assert_eq!(d.dev_addr.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
  assert_eq!(d.frm_payload.as_deref(), Some(hex_to_vec("f0b468dd").as_slice()));
  assert_eq!(d.f_opts, hex_to_vec("22ac0a"));
  assert_eq!(d.f_ctrl.as_byte(), 0x03);
  assert_eq!(d.f_port, Some(0x01));
  assert_eq!(d.f_cnt, [0x00, 0x00]);
  assert_eq!(packet.mhdr.as_byte(), 0x60);
  assert_eq!(packet.mic, [0xaa, 0x5e, 0xd1, 0x3a]);
}

/// "should decode packet with Lorawan1.0 Encrypted Fopts"
///
/// The TS test parses a wire packet (provided as base64; we use the hex
/// equivalent), verifies the MIC, decrypts FOpts, and decrypts FRMPayload.
#[test]
fn should_decode_packet_with_lorawan_1_0_encrypted_fopts() {
  let s_nwk_s_int_key_bytes: [u8; 16] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0];
  let nwk_s_enc_key = NwkSEncKey::new([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0]);
  let app_s_key = AppSKey::new([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

  // base64 "YAQDAgEDAAAirAoB8LRo3ape0To=" decoded to hex.
  let bytes = hex_to_vec("600403020103000022ac0a01f0b468ddaa5ed13a");
  let packet = LoraPacket::from_wire(&bytes).unwrap();

  // 1.0 MIC under sNwkSIntKey.
  let nwk_s_key = NwkSKey::new(s_nwk_s_int_key_bytes);
  let mic_keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&mic_keys).unwrap(), [0xaa, 0x5e, 0xd1, 0x3a]);

  // FOpts decryption (downlink with FPort > 0 -> aFCntDown path).
  let d = packet.as_data().unwrap();
  let decrypted_fopts = d.decrypt_fopts(&nwk_s_enc_key, 0).unwrap();
  assert_eq!(decrypted_fopts, hex_to_vec("020701"));

  // FRMPayload decryption (FPort > 0 -> AppSKey).
  let decrypted_payload = d.decrypt_payload(&app_s_key, &nwk_s_key, 0).unwrap();
  assert_eq!(decrypted_payload, hex_to_vec("01020304"));
}

/// "should decode rekeyind packet with Lorawan11 Encrypted"
#[test]
fn should_decode_rekeyind_packet_with_lorawan_1_1_encrypted() {
  let bytes = hex_to_vec("40679810e080000000c2c5248de748");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let f_nwk_s_int_key = FNwkSIntKey::new(key_from_hex("07c105892e1bbb7f7101d13a5f78249b"));
  let s_nwk_s_int_key = SNwkSIntKey::new(key_from_hex("f9162a2fcf6e70867cee523249282844"));
  let nwk_s_enc_key = NwkSEncKey::new(key_from_hex("a5406d11c50850c965c2545ad81980a7"));
  let app_s_key = AppSKey::new(key_from_hex("38034b6efc87cf9c40ac0b45b460d395"));

  // FPort == 0 on uplink: TS zeroes confFCnt LE bytes via writeUInt16BE(0).
  // Initial buffer was [0x00, 0x00, 0x00, 0x01] (confFCnt=0x0000, TxDr=0x00, TxCh=0x01),
  // and after the zero-write it stays the same.
  let mic_keys = V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([0x00, 0x00, 0x00, 0x01]),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_1(&mic_keys).unwrap(), [0x24, 0x8d, 0xe7, 0x48]);

  // Decrypt FRMPayload (FPort > 0 -> AppSKey).
  let d = packet.as_data().unwrap();
  // TS test uses NwkSEncKey as the second decrypt key, but FPort > 0 picks AppSKey.
  // To match the TS effective call: `decrypt(packet, appSKey, NwkSEncKey)` with
  // FPort != 0 -> AppSKey wins.
  let nwk_unused = NwkSKey::new(*nwk_s_enc_key.as_bytes());
  let decrypted = d.decrypt_payload(&app_s_key, &nwk_unused, 0).unwrap();
  assert_eq!(decrypted, hex_to_vec("0B01"));
}

/// "should encrypt rekeyconf packet with Lorawan11 Encrypted"
///
/// Identical test body to "should decode rekeyind packet..." in the TS
/// source. Kept here for parity.
#[test]
fn should_encrypt_rekeyconf_packet_with_lorawan_1_1_encrypted() {
  let bytes = hex_to_vec("40679810e080000000c2c5248de748");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let f_nwk_s_int_key = FNwkSIntKey::new(key_from_hex("07c105892e1bbb7f7101d13a5f78249b"));
  let s_nwk_s_int_key = SNwkSIntKey::new(key_from_hex("f9162a2fcf6e70867cee523249282844"));
  let nwk_s_enc_key = NwkSEncKey::new(key_from_hex("a5406d11c50850c965c2545ad81980a7"));
  let app_s_key = AppSKey::new(key_from_hex("38034b6efc87cf9c40ac0b45b460d395"));

  let mic_keys = V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([0x00, 0x00, 0x00, 0x01]),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_1(&mic_keys).unwrap(), [0x24, 0x8d, 0xe7, 0x48]);

  let d = packet.as_data().unwrap();
  let nwk_unused = NwkSKey::new(*nwk_s_enc_key.as_bytes());
  let decrypted = d.decrypt_payload(&app_s_key, &nwk_unused, 0).unwrap();
  assert_eq!(decrypted, hex_to_vec("0B01"));
}
