//! MIC calculate, verify, and recalculate tests for LoRaWAN 1.0 and 1.1.
use lora_packet::{AppKey, FNwkSIntKey, LoraPacket, NwkKey, NwkSKey, SNwkSIntKey, V1_0MicKeys, V1_1MicKeys};

fn hex_to_vec(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex string")
}

fn key_from_hex(s: &str) -> [u8; 16] {
  let v = hex_to_vec(s);
  let mut arr = [0u8; 16];
  arr.copy_from_slice(&v);
  arr
}

/// "should calculate & verify correct data packet MIC" (vector #1)
#[test]
fn should_calculate_and_verify_correct_data_packet_mic_1() {
  let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0x2b, 0x11, 0xff, 0x0d]);
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

/// "should calculate & verify correct data packet MIC" (vector #2)
#[test]
fn should_calculate_and_verify_correct_data_packet_mic_2() {
  let bytes = hex_to_vec("40F17DBE49000300012A3518AF");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0x2a, 0x35, 0x18, 0xaf]);
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

#[test]
fn should_detect_incorrect_data_packet_mic() {
  // Last byte AA instead of AF
  let bytes = hex_to_vec("40F17DBE49000300012A3518AA");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  // Calculation gives the correct MIC regardless.
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0x2a, 0x35, 0x18, 0xaf]);
  // Verification against the bodged MIC fails.
  assert!(!packet.verify_mic_v1_0(&keys).unwrap());
}

/// "should calculate & verify correct data packet MIC for ACK"
#[test]
fn should_calculate_and_verify_correct_data_packet_mic_for_ack() {
  let bytes = hex_to_vec("60f17dbe4920020001f9d65d27");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0xf9, 0xd6, 0x5d, 0x27]);
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

/// "recalculateMIC should calculate & overwrite existing data packet MIC"
#[test]
fn recalculate_mic_overwrites_existing_data_packet_mic() {
  let bytes = hex_to_vec("60f17dbe4920020001f9d65d27");
  let mut packet = LoraPacket::from_wire(&bytes).unwrap();

  // Overwrite the MIC with junk.
  packet.mic = [0xEE, 0xEE, 0xEE, 0xEE];
  // (TS asserts the MIC matches the overwrite; covered by the next line.)
  assert_eq!(packet.mic, [0xEE, 0xEE, 0xEE, 0xEE]);

  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  // Verification fails with the wrong MIC.
  assert!(!packet.verify_mic_v1_0(&keys).unwrap());

  // recalculate -> verify succeeds and MIC matches the canonical value.
  packet.recalculate_mic_v1_0(&keys).unwrap();
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
  assert_eq!(packet.mic, [0xf9, 0xd6, 0x5d, 0x27]);
}

/// "recalculateMIC should calculate & overwrite existing data packet MIC and
/// Update PHYpayload & MACPayloadWithMIC"
#[test]
fn recalculate_mic_updates_phy_payload() {
  let bytes = hex_to_vec("40f17dbe490002000195437876eeeeeeee");
  let expected_phy_payload = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
  let mut packet = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(packet.mic, [0xEE, 0xEE, 0xEE, 0xEE]);

  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };

  assert!(!packet.verify_mic_v1_0(&keys).unwrap());

  packet.recalculate_mic_v1_0(&keys).unwrap();
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
  assert_eq!(packet.mic, [0x2b, 0x11, 0xff, 0x0d]);
  assert_eq!(packet.phy_payload, expected_phy_payload);
}

/// "should calculate & verify correct join request packet MIC"
#[test]
fn should_calculate_and_verify_correct_join_request_mic() {
  let bytes = hex_to_vec("0039363463336913AA05693574323831330489C65B1304");
  let packet = LoraPacket::from_wire(&bytes).unwrap();

  let app_key = AppKey::new(key_from_hex("98929b92c49edba9676d646d3b612456"));
  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0xc6, 0x5b, 0x13, 0x04]);
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

/// "should detect incorrect join request packet MIC"
#[test]
fn should_detect_incorrect_join_request_mic() {
  // Final byte 05 instead of 04 (bodged MIC).
  let bytes = hex_to_vec("0039363463336913AA05693574323831330489C65B1305");
  let packet = LoraPacket::from_wire(&bytes).unwrap();

  let app_key = AppKey::new(key_from_hex("98929b92c49edba9676d646d3b612456"));
  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0xc6, 0x5b, 0x13, 0x04]);
  assert!(!packet.verify_mic_v1_0(&keys).unwrap());
}

/// "should calculate & verify correct join accept packet MIC"
///
/// The wire bytes here are treated as a plaintext Join Accept (MHDR + body +
/// MIC). The Rust API computes the Join Accept MIC over MHDR + body.
#[test]
fn should_calculate_and_verify_correct_join_accept_mic() {
  // 17-byte wire frame: MHDR(1) + body(12) + MIC(4). Per spec the only valid
  // body lengths are 12 and 28.
  let bytes = hex_to_vec("20386337CCBBAAE7CD2C010000D9D0A6E7");
  // Parse via JoinAccept::from_plaintext to get the structured form.
  let ja = lora_packet::JoinAccept::from_plaintext(&bytes).unwrap();
  // Wrap it in a LoraPacket so calculate_mic_v1_0 takes it.
  let app_key = AppKey::new(key_from_hex("98929b92c49edba9676d646d3b612456"));
  let mhdr = lora_packet::Mhdr::new(bytes[0]);
  let mut mic_bytes = [0u8; 4];
  mic_bytes.copy_from_slice(&bytes[bytes.len() - 4..]);
  let packet = LoraPacket {
    phy_payload: bytes.clone(),
    mhdr,
    mic: mic_bytes,
    payload: lora_packet::Payload::JoinAccept(ja),
  };
  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0xd9, 0xd0, 0xa6, 0xe7]);
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

/// "should detect incorrect join accept packet MIC"
#[test]
fn should_detect_incorrect_join_accept_mic() {
  // Final byte E8 instead of E7.
  let bytes = hex_to_vec("20386337CCBBAAE7CD2C010000D9D0A6E8");
  let ja = lora_packet::JoinAccept::from_plaintext(&bytes).unwrap();
  let app_key = AppKey::new(key_from_hex("98929b92c49edba9676d646d3b612456"));
  let mhdr = lora_packet::Mhdr::new(bytes[0]);
  let mut mic_bytes = [0u8; 4];
  mic_bytes.copy_from_slice(&bytes[bytes.len() - 4..]);
  let packet = LoraPacket {
    phy_payload: bytes.clone(),
    mhdr,
    mic: mic_bytes,
    payload: lora_packet::Payload::JoinAccept(ja),
  };
  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0xd9, 0xd0, 0xa6, 0xe7]);
  assert!(!packet.verify_mic_v1_0(&keys).unwrap());
}

/// "should calculate & verify MIC when 32-bit FCnts are used"
///
/// The TS test passes an explicit 16-bit FCnt MSB of 0x0000 alongside the
/// existing 16-bit wire FCnt. Same calculation as the default 1.0 vector.
#[test]
fn should_calculate_and_verify_mic_with_32bit_fcnts() {
  let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    f_cnt_msb: 0x0000,
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0x2b, 0x11, 0xff, 0x0d]);
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

#[test]
fn should_calculate_and_verify_mic_in_port_0() {
  let bytes = hex_to_vec("4006DC00FCC07400000244925050");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_s_key = NwkSKey::new(key_from_hex("581c4d08ef04cda30b1fef7a8b2c74b8"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    f_cnt_msb: 0x0000,
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0x44, 0x92, 0x50, 0x50]);
  assert!(packet.verify_mic_v1_0(&keys).unwrap());
}

/// "should calculate & verify MIC when 1.0 are used (Matteo Packets)"
///
/// TS uses both NwkSKey and a second key; only the NwkSKey result is checked
/// here, which matches the 1.0 algorithm.
#[test]
fn should_calculate_mic_when_1_0_used_matteo_packets() {
  let bytes = hex_to_vec("40F7EC10E081000002015A171220B0C6D6470FC3");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_s_key = NwkSKey::new(key_from_hex("17da125f3d55b28cc16a8111bd1d6c0b"));
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    f_cnt_msb: 0x0000,
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_0(&keys).unwrap(), [0xd6, 0x47, 0x0f, 0xc3]);
}

/// "should calculate & verify correct join request packet MIC in 1.1"
#[test]
fn should_calculate_and_verify_join_request_mic_1_1() {
  let bytes = hex_to_vec("00010000000000000001000000000000000ce83685eb17");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let nwk_key = NwkKey::new(key_from_hex("01010101010101010101010101010101"));
  let keys = V1_1MicKeys {
    nwk_key: Some(&nwk_key),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_1(&keys).unwrap(), [0x36, 0x85, 0xeb, 0x17]);
  assert!(packet.verify_mic_v1_1(&keys).unwrap());
}

/// "should calculate & verify incorrect join request packet MIC in 1.1"
#[test]
fn should_detect_incorrect_join_request_mic_1_1() {
  let bytes = hex_to_vec("00010000000000000001000000000000000ce83685eb17");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let wrong_key = NwkKey::new(key_from_hex("02020202020202020202020202020202"));
  let keys = V1_1MicKeys {
    nwk_key: Some(&wrong_key),
    ..Default::default()
  };
  // MIC computed with the wrong key cannot match.
  assert_ne!(packet.calculate_mic_v1_1(&keys).unwrap(), [0x36, 0x85, 0xeb, 0x17]);
  assert!(!packet.verify_mic_v1_1(&keys).unwrap());
}

/// "should calculate & verify correct unconfirmed data up packet MIC 1.1"
#[test]
fn should_calculate_and_verify_unconfirmed_data_up_mic_1_1() {
  let bytes = hex_to_vec("40736310e080000000c86c36165131");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let f_nwk_s_int_key = FNwkSIntKey::new(key_from_hex("e163635133105cc690cb2d57ba9c31b9"));
  let s_nwk_s_int_key = SNwkSIntKey::new(key_from_hex("05ec7c795b2f0b5bcdfa710db52b9d8f"));
  let keys = V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    f_cnt_msb: 0x0000,
    conf_fcnt_down_tx_dr_tx_ch: Some([0x00, 0x00, 0x00, 0x01]),
    ..Default::default()
  };
  assert_eq!(packet.calculate_mic_v1_1(&keys).unwrap(), [0x36, 0x16, 0x51, 0x31]);
  assert!(packet.verify_mic_v1_1(&keys).unwrap());
}
