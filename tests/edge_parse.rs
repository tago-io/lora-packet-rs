//! Parser edge case tests for `LoraPacket::from_wire`.
//!
//! These tests probe the boundaries of wire parsing: minimum lengths,
//! length-claim mismatches, every MType discriminator, every Rejoin type
//! discriminator, and adversarial byte patterns. The goal is to lock in
//! the parser's behavior on malformed input and to catch any panic
//! regression introduced by future changes.
//!
//! Where the parser is more permissive than the LoRaWAN spec
//! (FPort=0 with FOpts present, non-zero Major version, etc.), the
//! tests document the actual behavior and call out the gap with a
//! comment so a future tightening can find them quickly.

use lora_packet::{Direction, Error, LoraPacket, MType, Payload, RejoinRequest};

fn hex_to_vec(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex string")
}

// ---------------------------------------------------------------------------
// Minimum length boundary
// ---------------------------------------------------------------------------

#[test]
fn empty_buffer_returns_too_short() {
  let err = LoraPacket::from_wire(&[]).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 5);
      assert_eq!(got, 0);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn single_byte_returns_too_short() {
  let err = LoraPacket::from_wire(&[0x40]).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 5, got: 1 }));
}

#[test]
fn two_byte_buffer_returns_too_short() {
  let err = LoraPacket::from_wire(&[0xC0, 0x00]).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 5, got: 2 }));
}

#[test]
fn three_byte_buffer_returns_too_short() {
  let err = LoraPacket::from_wire(&[0x40, 0x00, 0x00]).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 5, got: 3 }));
}

#[test]
fn four_byte_buffer_returns_too_short() {
  // Even four MIC bytes alone is too short: there's no MHDR room left.
  let err = LoraPacket::from_wire(&[1, 2, 3, 4]).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 5, got: 4 }));
}

#[test]
fn five_byte_buffer_mhdr_plus_mic_is_proprietary_only() {
  // A 5-byte buffer satisfies the global 5-byte minimum (MHDR + MIC).
  // Only Proprietary (MHDR 0xE0..=0xFF) has no required body, so this
  // is the only MType that parses successfully with no body bytes.
  let bytes = [0xE0, 0xAA, 0xBB, 0xCC, 0xDD];
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::Proprietary);
  assert_eq!(p.mic, [0xAA, 0xBB, 0xCC, 0xDD]);
  match &p.payload {
    Payload::Proprietary(body) => assert!(body.is_empty()),
    other => panic!("expected Proprietary, got {other:?}"),
  }
}

#[test]
fn five_byte_data_uplink_has_no_body_room() {
  // Data needs at least 7 body bytes (DevAddr + FCtrl + FCnt). With
  // only MHDR + MIC available, the body length is 0.
  let bytes = [0x40, 0xAA, 0xBB, 0xCC, 0xDD];
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 7, got: 0 }));
}

#[test]
fn five_byte_join_request_has_no_body_room() {
  // Join Request body must be exactly 18 bytes.
  let bytes = [0x00, 0xAA, 0xBB, 0xCC, 0xDD];
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 18, got: 0 }));
}

#[test]
fn five_byte_rejoin_has_no_type_byte() {
  let bytes = [0xC0, 0xAA, 0xBB, 0xCC, 0xDD];
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 1, got: 0 }));
}

#[test]
fn five_byte_join_accept_rejects_with_other_error() {
  // JoinAccept can never be parsed via from_wire; it's always encrypted.
  let bytes = [0x20, 0xAA, 0xBB, 0xCC, 0xDD];
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::Other(_)));
}

// ---------------------------------------------------------------------------
// All 8 MType discriminator values (3-bit field, exhaustive)
// ---------------------------------------------------------------------------

#[test]
fn mtype_000_join_request_minimum_body() {
  // MHDR 0x00 = JoinRequest. Body must be 18 bytes.
  let mut bytes = vec![0x00];
  bytes.extend_from_slice(&[0u8; 18]); // 8 + 8 + 2 join_eui+dev_eui+dev_nonce
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::JoinRequest);
  assert!(p.is_join_request());
}

#[test]
fn mtype_001_join_accept_via_from_wire_rejected() {
  // MHDR 0x20 = JoinAccept. from_wire refuses; must go through decrypt.
  let bytes = hex_to_vec("20010203040506070809100001deadbeef");
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::Other(msg) => assert!(msg.contains("decrypt")),
    other => panic!("expected Other(decrypt msg), got {other:?}"),
  }
}

#[test]
fn mtype_010_unconfirmed_data_up_parses() {
  let bytes = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::UnconfirmedDataUp);
  let d = p.as_data().unwrap();
  assert_eq!(d.direction, Direction::Uplink);
  assert!(!d.confirmed);
}

#[test]
fn mtype_011_unconfirmed_data_down_parses() {
  // 0b011 << 5 = 0x60
  let bytes = hex_to_vec("60f17dbe4920020001f9d65d27");
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::UnconfirmedDataDown);
  let d = p.as_data().unwrap();
  assert_eq!(d.direction, Direction::Downlink);
  assert!(!d.confirmed);
}

#[test]
fn mtype_100_confirmed_data_up_parses() {
  // 0b100 << 5 = 0x80
  let mut bytes = vec![0x80];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49, 0x00, 0x02, 0x00]); // dev_addr + fctrl + fcnt
  bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // mic
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::ConfirmedDataUp);
  let d = p.as_data().unwrap();
  assert_eq!(d.direction, Direction::Uplink);
  assert!(d.confirmed);
}

#[test]
fn mtype_101_confirmed_data_down_parses() {
  // 0b101 << 5 = 0xA0
  let mut bytes = vec![0xA0];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49, 0x00, 0x02, 0x00]);
  bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::ConfirmedDataDown);
  let d = p.as_data().unwrap();
  assert_eq!(d.direction, Direction::Downlink);
  assert!(d.confirmed);
}

#[test]
fn mtype_110_rejoin_request_parses() {
  // 0b110 << 5 = 0xC0
  let bytes = hex_to_vec("c0000102030405060708090a0b0c0ddeadbeef");
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::RejoinRequest);
  assert!(p.is_rejoin_request());
}

#[test]
fn mtype_111_proprietary_parses() {
  // 0b111 << 5 = 0xE0
  let bytes = hex_to_vec("e0deadbeefcafe11223344");
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::Proprietary);
  match &p.payload {
    Payload::Proprietary(body) => assert_eq!(body.as_slice(), &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]),
    other => panic!("expected Proprietary, got {other:?}"),
  }
}

// ---------------------------------------------------------------------------
// FCtrl.FOptsLen edge cases
// ---------------------------------------------------------------------------

#[test]
fn data_fopts_len_exceeds_available_body() {
  // FCtrl = 0x0F claims 15 bytes of FOpts, but the body has none beyond
  // the 7-byte header. Parser must reject with TooShort.
  let mut bytes = vec![0x40]; // UnconfirmedDataUp
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49]); // dev_addr
  bytes.push(0x0F); // f_ctrl, FOptsLen = 15
  bytes.extend_from_slice(&[0x02, 0x00]); // f_cnt
  // body length so far = 7; FOpts would require 7 + 15 = 22, body only 7.
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // mic
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 22);
      assert_eq!(got, 7);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn data_fopts_len_one_byte_short() {
  // FOptsLen claims 5, but only 4 bytes of FOpts follow.
  let mut bytes = vec![0x40];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49]);
  bytes.push(0x05); // FOptsLen = 5
  bytes.extend_from_slice(&[0x02, 0x00]);
  bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // only 4 FOpts bytes
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // mic
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 12); // 7 + 5
      assert_eq!(got, 11); // 7 + 4
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn data_fopts_len_15_with_exactly_15_fopts_no_fport() {
  // FOptsLen = 15 (max), exactly 15 FOpts bytes, no FPort or FRMPayload.
  let mut bytes = vec![0x40];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49]); // dev_addr
  bytes.push(0x0F); // FCtrl, FOptsLen = 15
  bytes.extend_from_slice(&[0x02, 0x00]); // f_cnt
  bytes.extend_from_slice(&[0x11; 15]); // 15 FOpts bytes
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // mic
  let p = LoraPacket::from_wire(&bytes).unwrap();
  let d = p.as_data().unwrap();
  assert_eq!(d.f_ctrl.f_opts_len(), 15);
  assert_eq!(d.f_opts.len(), 15);
  assert_eq!(d.f_opts, vec![0x11; 15]);
  assert_eq!(d.f_port, None);
  assert_eq!(d.frm_payload, None);
  assert_eq!(p.mic, [0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn data_fopts_len_15_with_15_fopts_and_fport_only() {
  // FOptsLen = 15, exactly 15 FOpts bytes, then FPort but no FRMPayload.
  let mut bytes = vec![0x40];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49]);
  bytes.push(0x0F);
  bytes.extend_from_slice(&[0x02, 0x00]);
  bytes.extend_from_slice(&[0x22; 15]);
  bytes.push(0x07); // FPort
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // mic
  let p = LoraPacket::from_wire(&bytes).unwrap();
  let d = p.as_data().unwrap();
  assert_eq!(d.f_opts.len(), 15);
  assert_eq!(d.f_port, Some(0x07));
  // Per parser semantics, when FPort is present but no FRMPayload bytes
  // remain, frm_payload is Some(empty).
  assert_eq!(d.frm_payload.as_deref(), Some(&[][..]));
}

#[test]
fn data_fopts_len_zero_no_fport_no_payload() {
  // Minimum valid Data frame: 7-byte body, no FOpts, no FPort, no payload.
  let mut bytes = vec![0x40];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49]); // dev_addr
  bytes.push(0x00); // FCtrl
  bytes.extend_from_slice(&[0x01, 0x00]); // f_cnt
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // mic
  let p = LoraPacket::from_wire(&bytes).unwrap();
  let d = p.as_data().unwrap();
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_port, None);
  assert_eq!(d.frm_payload, None);
}

#[test]
fn data_fport_0_with_fopts_present_parser_accepts() {
  // LoRaWAN forbids carrying MAC commands in both FOpts and FRMPayload
  // (when FPort=0). The parser currently does NOT enforce this rule:
  // `Error::ConflictingMacCommands` exists in the error enum but is
  // never raised by `from_wire`. This test pins the actual permissive
  // behavior so a future tightening becomes a visible change.
  let mut bytes = vec![0x40];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49]); // dev_addr
  bytes.push(0x03); // FCtrl, FOptsLen = 3
  bytes.extend_from_slice(&[0x02, 0x00]); // f_cnt
  bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 FOpts bytes (MAC cmds)
  bytes.push(0x00); // FPort = 0 (MAC commands in FRMPayload)
  bytes.extend_from_slice(&[0x11, 0x22]); // FRMPayload bytes
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // mic
  let p = LoraPacket::from_wire(&bytes).unwrap();
  let d = p.as_data().unwrap();
  assert_eq!(d.f_port, Some(0));
  assert_eq!(d.f_opts, vec![0xAA, 0xBB, 0xCC]);
  assert_eq!(d.frm_payload.as_deref(), Some(&[0x11, 0x22][..]));
}

// ---------------------------------------------------------------------------
// Join Request body length edge cases
// ---------------------------------------------------------------------------

#[test]
fn join_request_body_17_bytes_rejected() {
  // 17-byte body (1 short).
  let mut bytes = vec![0x00];
  bytes.extend_from_slice(&[0u8; 17]);
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 18);
      assert_eq!(got, 17);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn join_request_body_19_bytes_rejected() {
  // 19-byte body (1 too long).
  let mut bytes = vec![0x00];
  bytes.extend_from_slice(&[0u8; 19]);
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 18);
      assert_eq!(got, 19);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn join_request_body_0_bytes_rejected() {
  // MHDR + MIC only.
  let bytes = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF];
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 18, got: 0 }));
}

#[test]
fn join_request_exact_18_byte_body_parses() {
  let mut bytes = vec![0x00];
  bytes.extend_from_slice(&[0u8; 18]);
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let p = LoraPacket::from_wire(&bytes).unwrap();
  let jr = p.as_join_request().unwrap();
  assert_eq!(jr.join_eui.as_bytes(), &[0u8; 8]);
  assert_eq!(jr.dev_eui.as_bytes(), &[0u8; 8]);
  assert_eq!(jr.dev_nonce.as_bytes(), &[0u8; 2]);
}

// ---------------------------------------------------------------------------
// Rejoin Request: every invalid type byte (3..=255 enumerated at boundaries)
// ---------------------------------------------------------------------------

#[test]
fn rejoin_type_3_invalid() {
  let bytes = hex_to_vec("c0030102030405060708090a0b0c0ddeadbeef");
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(3)));
}

#[test]
fn rejoin_type_4_invalid() {
  let bytes = hex_to_vec("c0040102030405060708090a0b0c0ddeadbeef");
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(4)));
}

#[test]
fn rejoin_type_5_invalid() {
  let bytes = hex_to_vec("c0050102030405060708090a0b0c0ddeadbeef");
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(5)));
}

#[test]
fn rejoin_type_127_invalid_midrange() {
  let mut bytes = vec![0xC0, 127];
  bytes.extend_from_slice(&[0u8; 13]); // 14 - 1 = 13 (after type)
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(127)));
}

#[test]
fn rejoin_type_254_invalid() {
  let mut bytes = vec![0xC0, 254];
  bytes.extend_from_slice(&[0u8; 13]);
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(254)));
}

#[test]
fn rejoin_type_255_invalid() {
  let mut bytes = vec![0xC0, 255];
  bytes.extend_from_slice(&[0u8; 13]);
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::InvalidRejoinType(255)));
}

#[test]
fn rejoin_all_invalid_types_3_through_255() {
  // Sweep: every byte value not in {0, 1, 2} must produce InvalidRejoinType.
  // We pad to 15-byte body so the only failure source is the type byte.
  for t in 3u8..=255 {
    let mut bytes = vec![0xC0, t];
    bytes.extend_from_slice(&[0u8; 13]);
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let err = LoraPacket::from_wire(&bytes).unwrap_err();
    match err {
      Error::InvalidRejoinType(got) => assert_eq!(got, t, "type byte {t} surfaced as {got}"),
      other => panic!("type byte {t} produced {other:?}"),
    }
  }
}

// ---------------------------------------------------------------------------
// Rejoin Request: valid type with wrong body length
// ---------------------------------------------------------------------------

#[test]
fn rejoin_type_0_short_body() {
  // Type 0 needs 14 body bytes total. Provide 13.
  let mut bytes = vec![0xC0, 0x00];
  bytes.extend_from_slice(&[0u8; 12]); // 13 - 1 = 12 after type
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 14);
      assert_eq!(got, 13);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn rejoin_type_0_long_body() {
  // Type 0 with 15 body bytes (1 too many).
  let mut bytes = vec![0xC0, 0x00];
  bytes.extend_from_slice(&[0u8; 14]); // 15 - 1 = 14 after type
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 14);
      assert_eq!(got, 15);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn rejoin_type_1_short_body() {
  // Type 1 needs 19 body bytes total. Provide 18.
  let mut bytes = vec![0xC0, 0x01];
  bytes.extend_from_slice(&[0u8; 17]); // 18 - 1 = 17 after type
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 19);
      assert_eq!(got, 18);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn rejoin_type_2_short_body() {
  // Type 2 also needs 14 body bytes total.
  let mut bytes = vec![0xC0, 0x02];
  bytes.extend_from_slice(&[0u8; 12]); // 13 total body
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  match err {
    Error::TooShort { expected, got } => {
      assert_eq!(expected, 14);
      assert_eq!(got, 13);
    }
    other => panic!("expected TooShort, got {other:?}"),
  }
}

#[test]
fn rejoin_type_2_parses_into_type2_variant() {
  let bytes = hex_to_vec("c0020102030405060708090a0b0c0ddeadbeef");
  let p = LoraPacket::from_wire(&bytes).unwrap();
  match p.as_rejoin_request().unwrap() {
    RejoinRequest::Type2 { .. } => {}
    other => panic!("expected Type2, got {other:?}"),
  }
}

// ---------------------------------------------------------------------------
// Adversarial byte patterns
// ---------------------------------------------------------------------------

#[test]
fn all_zero_buffer_5_bytes_parses_as_join_request_too_short() {
  // 0x00 = JoinRequest MType, but only MHDR + MIC, no 18-byte body.
  let bytes = [0u8; 5];
  let err = LoraPacket::from_wire(&bytes).unwrap_err();
  assert!(matches!(err, Error::TooShort { expected: 18, got: 0 }));
}

#[test]
fn all_zero_buffer_23_bytes_parses_as_join_request() {
  // MHDR=0x00 + 18 body + 4 MIC = 23. All zeros.
  let bytes = [0u8; 23];
  let p = LoraPacket::from_wire(&bytes).unwrap();
  let jr = p.as_join_request().unwrap();
  assert_eq!(jr.join_eui.as_bytes(), &[0u8; 8]);
  assert_eq!(jr.dev_eui.as_bytes(), &[0u8; 8]);
  assert_eq!(jr.dev_nonce.as_bytes(), &[0u8; 2]);
  assert_eq!(p.mic, [0, 0, 0, 0]);
}

#[test]
fn all_ff_buffer_5_bytes_parses_as_proprietary() {
  // 0xFF top 3 bits = 0b111 = Proprietary. No body required.
  let bytes = [0xFFu8; 5];
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::Proprietary);
  assert_eq!(p.mic, [0xFF; 4]);
  match &p.payload {
    Payload::Proprietary(body) => assert!(body.is_empty()),
    other => panic!("expected Proprietary, got {other:?}"),
  }
}

#[test]
fn all_ff_buffer_32_bytes_parses_as_proprietary() {
  // All-0xFF, longer buffer: still Proprietary, with a 27-byte opaque body.
  let bytes = [0xFFu8; 32];
  let p = LoraPacket::from_wire(&bytes).unwrap();
  match &p.payload {
    Payload::Proprietary(body) => {
      assert_eq!(body.len(), 27);
      assert!(body.iter().all(|b| *b == 0xFF));
    }
    other => panic!("expected Proprietary, got {other:?}"),
  }
  assert_eq!(p.mic, [0xFF; 4]);
}

#[test]
fn alternating_aa_buffer_parses_as_confirmed_data_down() {
  // 0xAA = 0b10101010. Top 3 bits = 0b101 = ConfirmedDataDown.
  // Major = 0b10 = 2 (the spec only defines 0; parser does NOT
  // enforce this and accepts non-zero Major — pinning that gap here).
  // FCtrl = 0xAA -> FOptsLen = 0xA = 10 bytes claimed.
  // Need: 1 MHDR + 7 (dev_addr+fctrl+fcnt) + 10 FOpts + 4 MIC = 22.
  let bytes = [0xAAu8; 22];
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::ConfirmedDataDown);
  let d = p.as_data().unwrap();
  assert_eq!(d.direction, Direction::Downlink);
  assert!(d.confirmed);
  assert_eq!(d.f_ctrl.f_opts_len(), 10);
  assert_eq!(d.f_opts.len(), 10);
  assert_eq!(d.f_opts, vec![0xAA; 10]);
  assert_eq!(d.f_port, None);
  assert_eq!(d.frm_payload, None);
  // Parser accepts major=2 silently (spec only defines major=0).
  // The MHDR major bits = 0xAA & 0b11 = 0b10 = 2.
  assert_eq!(p.mhdr.as_byte() & 0b11, 0b10);
  assert_eq!(p.mic, [0xAA; 4]);
}

#[test]
fn alternating_55_buffer_parses_as_unconfirmed_data_up_with_unaligned_fopts() {
  // 0x55 = 0b01010101. Top 3 bits = 0b010 = UnconfirmedDataUp.
  // FCtrl = 0x55 -> FOptsLen = 5.
  // Need: 1 MHDR + 4 DevAddr + 1 FCtrl + 2 FCnt + 5 FOpts = 13 body bytes
  // + (FPort + payload) optional + 4 MIC.
  // Provide exactly 13 body bytes plus FPort byte: total = 1 + 14 + 4 = 19.
  let bytes = [0x55u8; 19];
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::UnconfirmedDataUp);
  let d = p.as_data().unwrap();
  assert_eq!(d.f_ctrl.f_opts_len(), 5);
  assert_eq!(d.f_opts, vec![0x55; 5]);
  assert_eq!(d.f_port, Some(0x55));
  // body = 14 bytes: 4 dev_addr + 1 fctrl + 2 fcnt + 5 fopts + 1 fport + 1 leftover
  assert_eq!(d.frm_payload.as_deref(), Some(&[0x55][..]));
}

#[test]
fn major_version_nonzero_accepted_by_parser() {
  // The LoRaWAN spec only defines Major = 0. The parser accepts other
  // values silently (Error::InvalidMajor is defined but never raised).
  // Pin the actual behavior so a future tightening becomes visible.
  // MHDR 0x43 = MType UnconfirmedDataUp (0b010) with Major = 0b11 = 3.
  let mut bytes = vec![0x43];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49, 0x00, 0x02, 0x00]);
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.mhdr.as_byte() & 0b11, 0b11);
  assert_eq!(p.m_type(), MType::UnconfirmedDataUp);
}

// ---------------------------------------------------------------------------
// Large / upper-bound size frames
// ---------------------------------------------------------------------------

#[test]
fn data_frame_with_large_frm_payload_parses() {
  // 222-byte FRMPayload is well within practical limits (LoRaWAN regional
  // max payload sizes around 222 bytes for SF7/EU868). 1 + 7 + 1 + 222 + 4 = 235.
  let mut bytes = vec![0x40];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49, 0x00, 0x02, 0x00]); // dev_addr+fctrl+fcnt
  bytes.push(0x01); // fport
  bytes.extend_from_slice(&vec![0xCC; 222]); // payload
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // mic
  let p = LoraPacket::from_wire(&bytes).unwrap();
  let d = p.as_data().unwrap();
  assert_eq!(d.f_port, Some(0x01));
  assert_eq!(d.frm_payload.as_deref().unwrap().len(), 222);
  assert!(d.frm_payload.as_deref().unwrap().iter().all(|b| *b == 0xCC));
}

#[test]
fn proprietary_with_large_body_parses() {
  // 1 MHDR + 4080 body + 4 MIC = 4085. The crate's payload limit of 4080
  // applies only to FRMPayload AES-CTR encryption, not to Proprietary or
  // parse paths. Make sure parser handles the size without panic.
  let mut bytes = vec![0xE0];
  bytes.extend_from_slice(&vec![0x77; 4080]);
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.m_type(), MType::Proprietary);
  match &p.payload {
    Payload::Proprietary(body) => {
      assert_eq!(body.len(), 4080);
      assert!(body.iter().all(|b| *b == 0x77));
    }
    other => panic!("expected Proprietary, got {other:?}"),
  }
  assert_eq!(p.mic, [0xDE, 0xAD, 0xBE, 0xEF]);
}

// ---------------------------------------------------------------------------
// Round-trip safety on parsed edge frames
// ---------------------------------------------------------------------------

#[test]
fn data_round_trip_preserves_bytes_with_max_fopts() {
  let mut bytes = vec![0x40];
  bytes.extend_from_slice(&[0xf1, 0x7d, 0xbe, 0x49]);
  bytes.push(0x0F);
  bytes.extend_from_slice(&[0x02, 0x00]);
  bytes.extend_from_slice(&[0x11; 15]);
  bytes.push(0x07);
  bytes.extend_from_slice(&[0x99, 0xAA, 0xBB]); // small FRMPayload
  bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.to_wire(), bytes);
}

#[test]
fn proprietary_round_trip_preserves_bytes() {
  let bytes = hex_to_vec("e0deadbeefcafe11223344");
  let p = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(p.to_wire(), bytes);
}
