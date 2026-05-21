//! Negative tests for `lora-packet`.
//!
//! Each test asserts that an invalid input or misuse produces the exact
//! expected `Error` variant (matched, not stringified). Crypto, parsing,
//! builder, and (with the `hex_base64` feature) decoder failure paths are
//! covered here.

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, Error, FNwkSIntKey, JSIntKey,
  JoinAccept, LoraPacket, NetId, NwkKey, NwkSKey, SNwkSIntKey, V1_0MicKeys, V1_1MicKeys,
};

fn hex_to_vec(s: &str) -> Vec<u8> {
  (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
    .collect()
}

// ---------------------------------------------------------------------------
// Key constructors: 16-byte keys reject wrong-length slices.
// ---------------------------------------------------------------------------

#[test]
fn app_key_from_slice_rejects_15_bytes() {
  let err = AppKey::from_slice(&[0u8; 15]).unwrap_err();
  assert!(matches!(err, Error::InvalidKeyLength { expected: 16, got: 15 }));
}

#[test]
fn app_key_from_slice_rejects_17_bytes() {
  let err = AppKey::from_slice(&[0u8; 17]).unwrap_err();
  assert!(matches!(err, Error::InvalidKeyLength { expected: 16, got: 17 }));
}

#[test]
fn nwk_s_key_from_slice_rejects_empty() {
  let err = NwkSKey::from_slice(&[]).unwrap_err();
  assert!(matches!(err, Error::InvalidKeyLength { expected: 16, got: 0 }));
}

#[test]
fn nwk_key_from_slice_rejects_too_long() {
  let err = NwkKey::from_slice(&[0u8; 32]).unwrap_err();
  assert!(matches!(err, Error::InvalidKeyLength { expected: 16, got: 32 }));
}

#[test]
fn app_s_key_from_slice_rejects_one_short() {
  let err = AppSKey::from_slice(&[0u8; 15]).unwrap_err();
  assert!(matches!(err, Error::InvalidKeyLength { expected: 16, got: 15 }));
}

// ---------------------------------------------------------------------------
// Identifier constructors: each fixed-size newtype rejects wrong length.
// ---------------------------------------------------------------------------

#[test]
fn dev_addr_from_slice_wrong_length() {
  let err = DevAddr::from_slice(&[0u8; 5]).unwrap_err();
  assert!(matches!(err, Error::InvalidIdentifierLength { expected: 4, got: 5 }));
}

#[test]
fn dev_eui_from_slice_wrong_length() {
  let err = DevEui::from_slice(&[0u8; 7]).unwrap_err();
  assert!(matches!(err, Error::InvalidIdentifierLength { expected: 8, got: 7 }));
}

#[test]
fn app_eui_from_slice_wrong_length() {
  let err = AppEui::from_slice(&[0u8; 9]).unwrap_err();
  assert!(matches!(err, Error::InvalidIdentifierLength { expected: 8, got: 9 }));
}

#[test]
fn net_id_from_slice_wrong_length() {
  let err = NetId::from_slice(&[0u8; 2]).unwrap_err();
  assert!(matches!(err, Error::InvalidIdentifierLength { expected: 3, got: 2 }));
}

#[test]
fn dev_nonce_from_slice_wrong_length() {
  let err = DevNonce::from_slice(&[0u8; 3]).unwrap_err();
  assert!(matches!(err, Error::InvalidIdentifierLength { expected: 2, got: 3 }));
}

#[test]
fn app_nonce_from_slice_wrong_length() {
  let err = AppNonce::from_slice(&[0u8; 4]).unwrap_err();
  assert!(matches!(err, Error::InvalidIdentifierLength { expected: 3, got: 4 }));
}

// ---------------------------------------------------------------------------
// LoraPacket::from_wire: rejects malformed wire bytes without panicking.
// ---------------------------------------------------------------------------

#[test]
fn from_wire_rejects_empty() {
  let err = LoraPacket::from_wire(&[]).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 5, got: 0 }));
}

#[test]
fn from_wire_rejects_under_five_bytes() {
  let err = LoraPacket::from_wire(&[0x40, 0x00, 0x00, 0x00]).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 5, got: 4 }));
}

#[test]
fn from_wire_rejects_data_frame_with_truncated_fhdr() {
  // Data MHDR (0x40) + only 4 bytes body + 4 MIC = 9 bytes total.
  // Data parsing requires at least 7 body bytes.
  let err = LoraPacket::from_wire(&[0x40, 0x01, 0x02, 0x03, 0x04, 0xde, 0xad, 0xbe, 0xef]).unwrap_err();
  assert!(matches!(err, Error::TooShort { .. }));
}

#[test]
fn from_wire_rejects_join_request_wrong_body_length() {
  // Join Request body must be exactly 18 bytes.
  // MHDR (0x00) + 10 body + 4 MIC = 15 bytes.
  let mut bytes = vec![0x00u8];
  bytes.extend_from_slice(&[0u8; 10]);
  bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 18, .. }));
}

#[test]
fn from_wire_rejects_join_accept_directly() {
  // JoinAccept needs decrypt_from_wire; calling from_wire should error.
  let bytes = hex_to_vec("20e3de108795f776b8037610ef7869b5b3");
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::Other(_)));
}

#[test]
fn from_wire_rejects_rejoin_invalid_type_byte() {
  // MHDR 0xC0 (RejoinRequest) + body starting with type=0x05 (invalid).
  let bytes = hex_to_vec("c0050102030405060708090a0b0c0ddeadbeef");
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(5)));
}

#[test]
fn from_wire_rejects_rejoin_type_3() {
  // Rejoin type byte must be 0, 1, or 2.
  let bytes = hex_to_vec("c0030102030405060708090a0b0c0ddeadbeef");
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(3)));
}

#[test]
fn from_wire_rejects_data_with_fopts_overflow() {
  // FCtrl.f_opts_len = 15 but body too short to contain 15 bytes after FHDR.
  // MHDR (0x40) + DevAddr(4) + FCtrl(0x0F = fopts=15) + FCnt(2) + 4 MIC. Total 12, no room for FOpts.
  let bytes = hex_to_vec("400102030405060708090a0b");
  // Body = bytes[1..len-4] = "0102030405060708" = 8 bytes total.
  // FCtrl = body[4] = 0x05 (fopts=5) but 7+5 > 8 -> TooShort.
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::TooShort { .. }));
}

// ---------------------------------------------------------------------------
// MIC verification: wrong key returns Ok(false), missing key returns Err.
// ---------------------------------------------------------------------------

#[test]
fn verify_mic_v1_0_returns_false_for_wrong_key() {
  let bytes = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let wrong_key = NwkSKey::new([0xAAu8; 16]);
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&wrong_key),
    ..Default::default()
  };
  assert!(!packet.verify_mic_v1_0(&keys).unwrap());
}

#[test]
fn verify_mic_v1_0_data_missing_nwk_s_key_errors() {
  let bytes = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let keys = V1_0MicKeys::default();
  let err = packet.verify_mic_v1_0(&keys).unwrap_err();
  assert!(matches!(err, Error::MissingKey(_)));
}

#[test]
fn verify_mic_v1_0_join_request_missing_app_key_errors() {
  let bytes = hex_to_vec("0039363463336913aa05693574323831338ef1c1d5ec6c");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let keys = V1_0MicKeys::default();
  let err = packet.verify_mic_v1_0(&keys).unwrap_err();
  assert!(matches!(err, Error::MissingKey(_)));
}

#[test]
fn verify_mic_v1_1_returns_false_for_wrong_key_downlink() {
  // Downlink data frame; verify under wrong sNwkSIntKey.
  let bytes = hex_to_vec("60f17dbe4920020001f9d65d27");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let wrong_s = SNwkSIntKey::new([0x55u8; 16]);
  let keys = V1_1MicKeys {
    s_nwk_s_int_key: Some(&wrong_s),
    ..Default::default()
  };
  assert!(!packet.verify_mic_v1_1(&keys).unwrap());
}

#[test]
fn verify_mic_v1_1_uplink_missing_f_nwk_s_int_key_errors() {
  let bytes = hex_to_vec("40679810e080000000c2c5248de748");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let s_key = SNwkSIntKey::new([0u8; 16]);
  let keys = V1_1MicKeys {
    s_nwk_s_int_key: Some(&s_key),
    ..Default::default()
  };
  let err = packet.verify_mic_v1_1(&keys).unwrap_err();
  assert!(matches!(err, Error::MissingKey(_)));
}

#[test]
fn verify_mic_v1_1_uplink_missing_s_nwk_s_int_key_errors() {
  let bytes = hex_to_vec("40679810e080000000c2c5248de748");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let f_key = FNwkSIntKey::new([0u8; 16]);
  let keys = V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_key),
    ..Default::default()
  };
  let err = packet.verify_mic_v1_1(&keys).unwrap_err();
  assert!(matches!(err, Error::MissingKey(_)));
}

#[test]
fn calculate_mic_v1_1_join_accept_missing_join_eui_errors() {
  // Encrypt a tiny join accept and sign it via the builder, then mutate keys.
  let app_key = AppKey::new([0u8; 16]);
  let (packet, _) = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0, 0, 0]))
    .net_id(NetId::new([0, 0, 0]))
    .dev_addr(DevAddr::new([0, 0, 0, 0]))
    .dl_settings(DlSettings(0))
    .rx_delay(0)
    .sign_join_accept(&app_key)
    .unwrap();

  let js_key = JSIntKey::new([0u8; 16]);
  // Missing join_eui: 1.1 Join Accept MIC dispatch needs join_eui in keys.
  let keys = V1_1MicKeys {
    js_int_key: Some(&js_key),
    dev_nonce: Some(DevNonce::new([0, 0])),
    ..Default::default()
  };
  let err = packet.calculate_mic_v1_1(&keys).unwrap_err();
  assert!(matches!(err, Error::MissingKey(_)));
}

// ---------------------------------------------------------------------------
// Builder: each variant errors on missing required fields.
// ---------------------------------------------------------------------------

#[test]
fn builder_build_unsigned_no_variant_chosen() {
  let err = LoraPacket::builder().build_unsigned().unwrap_err();
  assert!(matches!(err, Error::MissingField("m_type")));
}

#[test]
fn builder_data_missing_dev_addr() {
  let err = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::MissingField("dev_addr")));
}

#[test]
fn builder_join_request_missing_join_eui() {
  let err = LoraPacket::builder().join_request().build_unsigned().unwrap_err();
  assert!(matches!(err, Error::MissingField("join_eui")));
}

#[test]
fn builder_join_request_missing_dev_eui() {
  let err = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::MissingField("dev_eui")));
}

#[test]
fn builder_join_request_missing_dev_nonce() {
  let err = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0u8; 8]))
    .dev_eui(DevEui::new([0u8; 8]))
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::MissingField("dev_nonce")));
}

#[test]
fn builder_join_accept_missing_join_nonce() {
  let err = LoraPacket::builder().join_accept().build_unsigned().unwrap_err();
  assert!(matches!(err, Error::MissingField("join_nonce")));
}

#[test]
fn builder_join_accept_missing_net_id() {
  let err = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0u8; 3]))
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::MissingField("net_id")));
}

#[test]
fn builder_join_accept_missing_dl_settings() {
  let err = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0u8; 3]))
    .net_id(NetId::new([0u8; 3]))
    .dev_addr(DevAddr::new([0u8; 4]))
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::MissingField("dl_settings")));
}

#[test]
fn builder_rejoin_missing_dev_eui() {
  let err = LoraPacket::builder().rejoin_request(0).build_unsigned().unwrap_err();
  assert!(matches!(err, Error::MissingField("dev_eui")));
}

#[test]
fn builder_rejoin_type_1_missing_join_eui() {
  let err = LoraPacket::builder()
    .rejoin_request(1)
    .dev_eui(DevEui::new([0u8; 8]))
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::MissingField("join_eui")));
}

#[test]
fn builder_rejoin_invalid_type_4() {
  let err = LoraPacket::builder()
    .rejoin_request(4)
    .dev_eui(DevEui::new([0u8; 8]))
    .net_id(NetId::new([0u8; 3]))
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(4)));
}

// ---------------------------------------------------------------------------
// FOpts > 15 bytes (recent fix): builder rejects with FOptsTooLong.
// ---------------------------------------------------------------------------

#[test]
fn builder_fopts_16_bytes_rejected() {
  let err = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0u8; 4]))
    .f_opts(&[0u8; 16])
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::FOptsTooLong(16)));
}

#[test]
fn builder_fopts_300_bytes_rejected() {
  // u8 conversion fails first, also routed to FOptsTooLong.
  let too_many = vec![0u8; 300];
  let err = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(DevAddr::new([0u8; 4]))
    .f_opts(&too_many)
    .build_unsigned()
    .unwrap_err();
  assert!(matches!(err, Error::FOptsTooLong(300)));
}

// ---------------------------------------------------------------------------
// JoinAccept length validation (recent fix): only 17 or 33 bytes accepted.
// ---------------------------------------------------------------------------

#[test]
fn join_accept_decrypt_rejects_18_bytes() {
  let app_key = AppKey::new([0u8; 16]);
  let err = JoinAccept::decrypt_from_wire(&[0u8; 18], &app_key).unwrap_err();
  assert!(matches!(err, Error::InvalidJoinAcceptLength(18)));
}

#[test]
fn join_accept_decrypt_rejects_16_bytes() {
  let app_key = AppKey::new([0u8; 16]);
  let err = JoinAccept::decrypt_from_wire(&[0u8; 16], &app_key).unwrap_err();
  assert!(matches!(err, Error::InvalidJoinAcceptLength(16)));
}

#[test]
fn join_accept_decrypt_rejects_32_bytes() {
  let app_key = AppKey::new([0u8; 16]);
  let err = JoinAccept::decrypt_from_wire(&[0u8; 32], &app_key).unwrap_err();
  assert!(matches!(err, Error::InvalidJoinAcceptLength(32)));
}

#[test]
fn join_accept_decrypt_rejects_34_bytes() {
  let app_key = AppKey::new([0u8; 16]);
  let err = JoinAccept::decrypt_from_wire(&[0u8; 34], &app_key).unwrap_err();
  assert!(matches!(err, Error::InvalidJoinAcceptLength(34)));
}

#[test]
fn join_accept_decrypt_rejects_empty() {
  let app_key = AppKey::new([0u8; 16]);
  let err = JoinAccept::decrypt_from_wire(&[], &app_key).unwrap_err();
  assert!(matches!(err, Error::InvalidJoinAcceptLength(0)));
}

#[test]
fn join_accept_encrypt_rejects_18_bytes() {
  let app_key = AppKey::new([0u8; 16]);
  let err = JoinAccept::encrypt_for_wire(&[0u8; 18], &app_key).unwrap_err();
  assert!(matches!(err, Error::InvalidJoinAcceptLength(18)));
}

#[test]
fn join_accept_from_plaintext_rejects_short_buffer() {
  // Less than 17 bytes: should be TooShort.
  let err = JoinAccept::from_plaintext(&[0u8; 10]).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 17, got: 10 }));
}

// ---------------------------------------------------------------------------
// hex/base64 decode failures (only with the `hex_base64` feature).
// ---------------------------------------------------------------------------

#[cfg(feature = "hex_base64")]
mod hex_base64_failures {
  use super::*;

  #[test]
  fn lora_packet_from_hex_invalid_chars() {
    let err = LoraPacket::from_hex("zzzz").unwrap_err();
    assert!(matches!(err, Error::Hex(_)));
  }

  #[test]
  fn lora_packet_from_hex_odd_length() {
    let err = LoraPacket::from_hex("4f1").unwrap_err();
    assert!(matches!(err, Error::Hex(_)));
  }

  #[test]
  fn lora_packet_from_base64_invalid_chars() {
    let err = LoraPacket::from_base64("not-base64!").unwrap_err();
    assert!(matches!(err, Error::Base64(_)));
  }

  #[test]
  fn app_key_from_hex_invalid() {
    let err = AppKey::from_hex("invalid").unwrap_err();
    assert!(matches!(err, Error::Hex(_)));
  }

  #[test]
  fn app_key_from_hex_wrong_length() {
    // Valid hex chars but only 8 bytes once decoded.
    let err = AppKey::from_hex("0102030405060708").unwrap_err();
    assert!(matches!(err, Error::InvalidKeyLength { expected: 16, got: 8 }));
  }

  #[test]
  fn app_key_from_base64_invalid() {
    let err = AppKey::from_base64("not valid base64!@#").unwrap_err();
    assert!(matches!(err, Error::Base64(_)));
  }

  #[test]
  fn dev_addr_from_hex_invalid_chars() {
    let err = DevAddr::from_hex("ghij").unwrap_err();
    assert!(matches!(err, Error::Hex(_)));
  }

  #[test]
  fn dev_addr_from_hex_wrong_decoded_length() {
    let err = DevAddr::from_hex("0102").unwrap_err();
    assert!(matches!(err, Error::InvalidIdentifierLength { expected: 4, got: 2 }));
  }

  #[test]
  fn dev_eui_from_base64_invalid() {
    let err = DevEui::from_base64("****").unwrap_err();
    assert!(matches!(err, Error::Base64(_)));
  }
}

// ---------------------------------------------------------------------------
// Sanity: builder data with FOpts at the 15-byte boundary should succeed.
// Acts as a negative-test guard against over-rejection.
// ---------------------------------------------------------------------------

#[test]
fn builder_fopts_exactly_15_bytes_accepted() {
  let ok = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0u8; 4]))
    .f_opts(&[0u8; 15])
    .build_unsigned();
  assert!(ok.is_ok(), "15-byte FOpts must be accepted, got {ok:?}");
}

#[test]
fn calculate_mic_v1_0_rejoin_returns_missing_key() {
  // The 1.0 surface does not handle Rejoin; should surface MissingKey-style error.
  let bytes = hex_to_vec("c0000102030405060708090a0b0c0ddeadbeef");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let app_key = AppKey::new([0u8; 16]);
  let keys = V1_0MicKeys {
    app_key: Some(&app_key),
    ..Default::default()
  };
  let err = packet.calculate_mic_v1_0(&keys).unwrap_err();
  assert!(matches!(err, Error::MissingKey(_)));
}

#[test]
fn calculate_mic_v1_1_proprietary_errors() {
  let bytes = hex_to_vec("e0deadbeefcafe11223344");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let keys = V1_1MicKeys::default();
  let err = packet.calculate_mic_v1_1(&keys).unwrap_err();
  assert!(matches!(err, Error::MissingKey(_)));
}
