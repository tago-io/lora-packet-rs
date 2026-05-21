//! Integration tests mirroring `__tests__/packet_test.ts`.
//!
//! The TypeScript `LoraPayload.fromFields(...)` API builds packets and (when
//! keys are provided) signs and encrypts them. The Rust equivalent is
//! `LoraPacket::builder()` plus `build_unsigned` / `sign_and_encrypt` /
//! `sign_join_request` / `sign_join_accept`.
//!
//! When the TS test provides no keys, the placeholder MIC is `EEEEEEEE`. The
//! Rust builder defaults the MIC to `00000000`. Tests that depend on the
//! placeholder MIC value are adjusted to check the zero MIC instead.

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, FNwkSIntKey, JoinAccept,
  JoinEui, LoraPacket, MType, NetId, NwkKey, NwkSEncKey, NwkSKey, Payload, SNwkSIntKey, V1_0MicKeys,
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

/// Mirror of `__tests__/packet_test.ts`: "should create packet with minimal input"
///
/// TS: `LoraPayload.fromFields({ payload: "test", DevAddr: 0xa1b2c3d4 })`.
/// No keys supplied -> default MType is "Unconfirmed Data Up", default FCnt 0,
/// default FPort 1, placeholder MIC. Rust builder defaults MIC to 0.
#[test]
fn should_create_packet_with_minimal_input() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(0)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();

  // PHYPayload: MHDR(40) + FHDR(d4c3b2a1 + 00 + 0000) + FPort(01) + payload("test") + MIC(0)
  let expected_phy_payload = hex_to_vec("40d4c3b2a10000000174657374")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  assert_eq!(packet.mhdr.as_byte(), 0x40);
  assert_eq!(packet.mic, [0, 0, 0, 0]);

  let d = packet.as_data().unwrap();
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert_eq!(d.dev_addr.as_bytes(), &[0xa1, 0xb2, 0xc3, 0xd4]);
  assert_eq!(d.f_cnt, [0x00, 0x00]);
  assert_eq!(d.f_port, Some(0x01));
  assert_eq!(d.frm_payload.as_deref(), Some(b"test".as_slice()));

  // Round-trip parse.
  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should omit FPort if no FRMPayload & no FPort supplied"
#[test]
fn should_omit_fport_if_no_payload_or_port() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(1)
    .build_unsigned()
    .unwrap();

  // PHYPayload: MHDR(40) + DevAddr + FCtrl(00) + FCnt(0100) + MIC(0)
  let expected_phy_payload = hex_to_vec("40d4c3b2a1000100")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  assert_eq!(packet.mhdr.as_byte(), 0x40);
  assert_eq!(packet.mic, [0, 0, 0, 0]);

  let d = packet.as_data().unwrap();
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert_eq!(d.dev_addr.as_bytes(), &[0xa1, 0xb2, 0xc3, 0xd4]);
  assert_eq!(d.f_cnt, [0x01, 0x00]);
  // No FPort, no FRMPayload.
  assert_eq!(d.f_port, None);
  assert!(d.frm_payload.is_none());

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with MType as integer"
///
/// TS: `MType: 5` selects "Confirmed Data Down". Rust has a typed enum.
#[test]
fn should_create_packet_with_mtype_as_integer_5() {
  let packet = LoraPacket::builder()
    .data(Direction::Downlink, true) // MType 5 = ConfirmedDataDown
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(1)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("A0d4c3b2a10001000174657374")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  assert_eq!(packet.mhdr.as_byte(), 0xA0);
  let d = packet.as_data().unwrap();
  assert_eq!(d.dev_addr.as_bytes(), &[0xa1, 0xb2, 0xc3, 0xd4]);
  assert_eq!(d.f_cnt, [0x01, 0x00]);
  assert_eq!(d.f_port, Some(0x01));
  assert_eq!(d.frm_payload.as_deref(), Some(b"test".as_slice()));

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with MType as string"
///
/// TS: `MType: "Confirmed Data Up"`.
#[test]
fn should_create_packet_with_mtype_as_string_confirmed_data_up() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, true)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(1)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("80d4c3b2a10001000174657374")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  assert_eq!(packet.mhdr.as_byte(), 0x80);

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`: "should verify MType confirmed"
#[test]
fn should_verify_mtype_confirmed() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, true)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(1)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  assert!(packet.is_confirmed());
}

/// Mirror of `__tests__/packet_test.ts`: "should verify MType unconfirmed"
#[test]
fn should_verify_mtype_unconfirmed() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(1)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  assert!(!packet.is_confirmed());
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with FCnt as buffer"
///
/// TS: `FCnt: Buffer.from("1234", "hex")` (big-endian 0x1234 = 4660).
#[test]
fn should_create_packet_with_fcnt_as_buffer() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(0x1234)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("40d4c3b2a10034120174657374")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  let d = packet.as_data().unwrap();
  // FCnt is little-endian on the wire (0x1234 -> bytes 34 12).
  assert_eq!(d.f_cnt, [0x34, 0x12]);
  assert_eq!(d.f_cnt(), 0x1234);

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with FCnt as number"
#[test]
fn should_create_packet_with_fcnt_as_number() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(4660)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("40d4c3b2a10034120174657374")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  let d = packet.as_data().unwrap();
  assert_eq!(d.f_cnt, [0x34, 0x12]);
  assert_eq!(d.f_cnt(), 4660);

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with FOpts"
#[test]
fn should_create_packet_with_fopts() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_opts(&[0xF0, 0xF1, 0xF2, 0xF3])
    .f_cnt(1)
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("40d4c3b2a1040100F0F1F2F30174657374")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  let d = packet.as_data().unwrap();
  assert_eq!(d.f_opts, vec![0xF0, 0xF1, 0xF2, 0xF3]);
  assert_eq!(d.f_ctrl.as_byte(), 0x04);

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with correct FCtrl.ACK"
#[test]
fn should_create_packet_with_correct_fctrl_ack() {
  let packet_ack_true = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_ctrl(FCtrl(0x20))
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  let d = packet_ack_true.as_data().unwrap();
  assert_eq!(d.f_ctrl.as_byte(), 0x20);
  assert!(d.f_ctrl.ack());

  let packet_ack_false = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_ctrl(FCtrl(0x00))
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  let d = packet_ack_false.as_data().unwrap();
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert!(!d.f_ctrl.ack());
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with correct FCtrl.ADR"
#[test]
fn should_create_packet_with_correct_fctrl_adr() {
  let packet_adr_true = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_ctrl(FCtrl(0x80))
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  let d = packet_adr_true.as_data().unwrap();
  assert_eq!(d.f_ctrl.as_byte(), 0x80);
  assert!(d.f_ctrl.adr());

  let packet_adr_false = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_ctrl(FCtrl(0x00))
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  let d = packet_adr_false.as_data().unwrap();
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert!(!d.f_ctrl.adr());
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should create packet with correct FCtrl when all flags set"
#[test]
fn should_create_packet_with_correct_fctrl_all_flags() {
  // ADR=1, ADRACKReq=1, ACK=1, FPending(downlink only, here uplink ClassB)=1
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_ctrl(FCtrl(0xF0))
    .f_port(1)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  let d = packet.as_data().unwrap();
  assert_eq!(d.f_ctrl.as_byte(), 0xF0);
  assert!(d.f_ctrl.adr());
  assert!(d.f_ctrl.adr_ack_req());
  assert!(d.f_ctrl.ack());
  // For uplinks bit 4 is ClassB; the same bit position is FPending on downlinks.
  assert!(d.f_ctrl.class_b());
}

/// Mirror of `__tests__/packet_test.ts`: "should create join request packet"
#[test]
fn should_create_join_request_packet() {
  let packet = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD]))
    .dev_eui(DevEui::new([0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD]))
    .dev_nonce(DevNonce::new([0xAA, 0xBB]))
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("00DDCCBBAADDCCBBAADDCCBBAADDCCBBAABBAA")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  assert_eq!(packet.mhdr.as_byte(), 0x00);

  let jr = packet.as_join_request().unwrap();
  assert_eq!(
    jr.join_eui.as_bytes(),
    &[0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD]
  );
  assert_eq!(jr.dev_eui.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD]);
  assert_eq!(jr.dev_nonce.as_bytes(), &[0xAA, 0xBB]);

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should create join accept packet with minimal input"
#[test]
fn should_create_join_accept_packet_with_minimal_input() {
  let packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0xAA, 0xBB, 0xCC]))
    .net_id(NetId::new([0xAA, 0xBB, 0xCC]))
    .dev_addr(DevAddr::new([0xAA, 0xBB, 0xCC, 0xDD]))
    .dl_settings(DlSettings(0x00))
    .rx_delay(0x00)
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("20CCBBAACCBBAADDCCBBAA0000")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  let ja = packet.as_join_accept().unwrap();
  assert_eq!(ja.join_nonce.as_bytes(), &[0xAA, 0xBB, 0xCC]);
  assert_eq!(ja.net_id.as_bytes(), &[0xAA, 0xBB, 0xCC]);
  assert_eq!(ja.dev_addr.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD]);
  assert_eq!(ja.dl_settings.as_byte(), 0x00);
  assert_eq!(ja.rx_delay, 0x00);
  assert!(ja.cf_list.is_none());
}

/// Mirror of `__tests__/packet_test.ts`: "should create join accept packet"
#[test]
fn should_create_join_accept_packet() {
  let packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0xAA, 0xBB, 0xCC]))
    .net_id(NetId::new([0xAA, 0xBB, 0xCC]))
    .dev_addr(DevAddr::new([0xAA, 0xBB, 0xCC, 0xDD]))
    .dl_settings(DlSettings(0x12))
    .rx_delay(0x0F)
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("20CCBBAACCBBAADDCCBBAA120F")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  let ja = packet.as_join_accept().unwrap();
  assert_eq!(ja.dl_settings.as_byte(), 0x12);
  assert_eq!(ja.rx_delay, 0x0F);
  assert!(ja.cf_list.is_none());
}

/// Mirror of `__tests__/packet_test.ts`: "should create join accept packet with CFList"
#[test]
fn should_create_join_accept_packet_with_cflist() {
  let cf_list_bytes = hex_to_vec("11223311223311223311223311223300");
  let mut cf_list = [0u8; 16];
  cf_list.copy_from_slice(&cf_list_bytes);

  let packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0xAA, 0xBB, 0xCC]))
    .net_id(NetId::new([0xAA, 0xBB, 0xCC]))
    .dev_addr(DevAddr::new([0xAA, 0xBB, 0xCC, 0xDD]))
    .dl_settings(DlSettings(0x12))
    .rx_delay(0x0F)
    .cf_list(cf_list)
    .build_unsigned()
    .unwrap();

  let expected_phy_payload = hex_to_vec("20CCBBAACCBBAADDCCBBAA120F11223311223311223311223311223300")
    .into_iter()
    .chain([0, 0, 0, 0])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_phy_payload);
  let ja = packet.as_join_accept().unwrap();
  assert_eq!(ja.cf_list.unwrap(), cf_list);
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with correct FPort"
#[test]
fn should_create_packet_with_correct_fport() {
  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_port(42)
    .payload(b"test")
    .build_unsigned()
    .unwrap();
  assert_eq!(packet.as_data().unwrap().f_port, Some(42));
}

/// Mirror of `__tests__/packet_test.ts`: "should calculate MIC if keys provided"
#[test]
fn should_calculate_mic_if_keys_provided() {
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));

  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
    .f_cnt(2)
    .f_port(1)
    .payload(b"test")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let expected_phy_payload = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
  assert_eq!(packet.phy_payload, expected_phy_payload);
  assert_eq!(packet.mhdr.as_byte(), 0x40);
  assert_eq!(packet.mic, [0x2b, 0x11, 0xff, 0x0d]);
  let d = packet.as_data().unwrap();
  assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
  assert_eq!(d.f_cnt, [0x02, 0x00]);
  assert_eq!(d.f_port, Some(0x01));
  assert_eq!(d.frm_payload.as_deref(), Some(&[0x95, 0x43, 0x78, 0x76][..]));

  let parsed = LoraPacket::from_wire(&packet.phy_payload).unwrap();
  assert_eq!(parsed, packet);
}

/// Mirror of `__tests__/packet_test.ts`: "should encrypt if keys provided"
///
/// Same expected output as the MIC test above; the TS test duplicates the
/// vector but emphasises that encryption happened in the builder.
#[test]
fn should_encrypt_if_keys_provided() {
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3"));

  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
    .f_cnt(2)
    .f_port(1)
    .payload(b"test")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let expected_phy_payload = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
  assert_eq!(packet.phy_payload, expected_phy_payload);
}

/// Mirror of `__tests__/packet_test.ts`: "should parse packet #1"
#[test]
fn should_parse_packet_1() {
  let bytes = hex_to_vec("4084412505A3010009110308B33750F504D4B86A");
  let parsed = LoraPacket::from_wire(&bytes).unwrap();
  let d = parsed.as_data().unwrap();
  assert_eq!(d.f_opts, hex_to_vec("091103"));
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with port 0"
#[test]
fn should_create_packet_with_port_0() {
  let nwk_s_key = NwkSKey::new(key_from_hex("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));
  let app_s_key = AppSKey::new([0u8; 16]); // unused at port 0

  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(16)
    .f_port(0)
    .payload(&[0x02])
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let expected_phy_payload = hex_to_vec("40D4C3B2A1001000002712A3F9C9");
  assert_eq!(packet.phy_payload, expected_phy_payload);
  assert_eq!(packet.mhdr.as_byte(), 0x40);
  assert_eq!(packet.mic, [0x12, 0xA3, 0xF9, 0xC9]);
  let d = packet.as_data().unwrap();
  assert_eq!(d.dev_addr.as_bytes(), &[0xa1, 0xb2, 0xc3, 0xd4]);
  assert_eq!(d.f_cnt, [0x10, 0x00]);
  assert_eq!(d.f_port, Some(0x00));
  assert_eq!(d.frm_payload.as_deref(), Some(&[0x27][..]));
  assert_eq!(d.f_ctrl.as_byte(), 0x00);
  assert!(d.f_opts.is_empty());
}

/// Mirror of `__tests__/packet_test.ts`: "should create packet with OptNeg"
///
/// `LoRaWAN` 1.1 Join Accept with OptNeg bit set. The 1.1 MIC algorithm needs
/// `JoinReqType`, `JoinEUI` and `DevNonce` context. Uses `sign_join_accept` via
/// the 1.1 dispatch path. Our Rust API computes the 1.0 MIC by default in
/// `sign_join_accept`. The TS test produces an OptNeg-set packet with a known
/// 1.1 MIC value. We translate this by building unsigned, then recalculating
/// the MIC with V1_1MicKeys, and finally re-encrypting for the wire.
#[test]
fn should_create_packet_with_opt_neg() {
  let nwk_key = NwkKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  let join_eui = AppEui::new([8, 7, 6, 5, 4, 3, 2, 1]);
  let dev_nonce = DevNonce::new([1, 2]);

  let mut packet = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0x01, 0x01, 0x01]))
    .net_id(NetId::new([0x02, 0x02, 0x02]))
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .dl_settings(DlSettings(0b1000_0000)) // OptNeg = 1
    .rx_delay(0x00)
    .build_unsigned()
    .unwrap();

  let js_int_key = lora_packet::JSIntKey::new(*nwk_key.as_bytes());
  let mic_keys = lora_packet::V1_1MicKeys {
    js_int_key: Some(&js_int_key),
    join_eui: Some(join_eui),
    dev_nonce: Some(dev_nonce),
    join_req_type: Some(0xFF),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).unwrap();
  assert_eq!(packet.mic, [0x93, 0xff, 0x9a, 0x3a]);
  let expected_plaintext = hex_to_vec("20010101020202040302018000")
    .into_iter()
    .chain([0x93, 0xff, 0x9a, 0x3a])
    .collect::<Vec<_>>();
  assert_eq!(packet.phy_payload, expected_plaintext);

  // Encrypted form on the wire.
  let app_key = AppKey::new(*nwk_key.as_bytes());
  let encrypted = JoinAccept::encrypt_for_wire(&packet.phy_payload, &app_key).unwrap();
  let expected_encrypted = hex_to_vec("207abeea06b02920f11c02d0348fcf1815");
  assert_eq!(encrypted, expected_encrypted);
}

/// Mirror of `__tests__/packet_test.ts`: "should encode packet with Lorawan10"
#[test]
fn should_encode_packet_with_lorawan_1_0() {
  let nwk_s_key = NwkSKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  let app_s_key = AppSKey::new([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

  let packet = LoraPacket::builder()
    .data(Direction::Uplink, true) // Confirmed Data Up
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .f_ctrl(FCtrl(0x03)) // FOpts len = 3
    .f_port(10)
    .f_opts(&[0x06, 0x73, 0x07])
    .payload(&hex_to_vec("01020304"))
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  assert_eq!(
    hex::encode(&packet.phy_payload),
    "80040302010300000673070ae264d4f7e117d2c0"
  );
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should encode packet with Lorawan11 (1. FRMPayload data)"
///
/// LoRaWAN 1.1 dual-MIC uplink. The Rust API doesn't have a one-shot
/// "sign_and_encrypt for 1.1", so we build unsigned, encrypt the FRMPayload
/// with AppSKey, then recompute the 1.1 MIC.
///
/// Note: per `LoRaWAN` 1.1 spec, the ConfFCnt portion of B1 is only included
/// when the uplink has ACK set (or is a port-0 uplink in 1.1). Otherwise the
/// first two bytes of the 4-byte `conf_fcnt_down_tx_dr_tx_ch` block are
/// zeroed. The TS implementation zeroes them inside `calculateMIC`; the Rust
/// API expects the caller to pass the final 4 bytes.
#[test]
fn should_encode_packet_with_lorawan_1_1_frm_payload() {
  let s_nwk_s_int_key = SNwkSIntKey::new([2; 16]);
  let f_nwk_s_int_key = FNwkSIntKey::new({
    let mut k = [2u8; 16];
    k[15] = 3;
    k
  });
  let app_s_key = AppSKey::new([1; 16]);
  // ACK off + FPort != 0 -> ConfFCnt is zeroed in B1.
  let tx_dr = 0x02u8;
  let tx_ch = 0x03u8;

  let mut packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .f_ctrl(FCtrl(0x80)) // ADR = 1
    .f_cnt(1)
    .f_port(1)
    .payload(b"hello")
    .build_unsigned()
    .unwrap();

  // Encrypt FRMPayload manually (no port-0 path).
  let nwk_s_key_unused = NwkSKey::new([0u8; 16]);
  let encrypted = packet
    .as_data()
    .unwrap()
    .encrypt_payload(b"hello", &app_s_key, &nwk_s_key_unused, 0)
    .unwrap();
  packet.as_data_mut().unwrap().frm_payload = Some(encrypted);
  packet.phy_payload = packet.to_wire();

  let mic_keys = lora_packet::V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([0x00, 0x00, tx_dr, tx_ch]),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).unwrap();

  let expected = [64, 4, 3, 2, 1, 128, 1, 0, 1, 166, 148, 100, 38, 21, 118, 18, 54, 106];
  assert_eq!(packet.phy_payload, expected);
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should encode packet with Lorawan11 (2. FRMPayload data with ACK)"
///
/// ACK is set, so the confirmed FCnt down is used in B1. In TS the bytes are
/// transformed via `writeUInt16BE(readUInt16LE(...))`, which converts the LE
/// confFCnt of 0x0001 to BE 0x0001 (numerically the same, both produce
/// `[0x00, 0x01]`).
#[test]
fn should_encode_packet_with_lorawan_1_1_frm_payload_with_ack() {
  let s_nwk_s_int_key = SNwkSIntKey::new([2; 16]);
  let f_nwk_s_int_key = FNwkSIntKey::new({
    let mut k = [2u8; 16];
    k[15] = 3;
    k
  });
  let app_s_key = AppSKey::new([1; 16]);
  let tx_dr = 0x02u8;
  let tx_ch = 0x03u8;

  let mut packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .f_ctrl(FCtrl(0xA0)) // ADR=1, ACK=1
    .f_cnt(1)
    .f_port(1)
    .payload(b"hello")
    .build_unsigned()
    .unwrap();

  let nwk_s_key_unused = NwkSKey::new([0u8; 16]);
  let encrypted = packet
    .as_data()
    .unwrap()
    .encrypt_payload(b"hello", &app_s_key, &nwk_s_key_unused, 0)
    .unwrap();
  packet.as_data_mut().unwrap().frm_payload = Some(encrypted);
  packet.phy_payload = packet.to_wire();

  // TS confFCnt = [0x00, 0x01] LE = readUInt16LE = 256, then writeUInt16BE(256)
  // = [0x01, 0x00]. So B1 receives [0x01, 0x00, tx_dr, tx_ch].
  let mic_keys = lora_packet::V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([0x01, 0x00, tx_dr, tx_ch]),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).unwrap();

  let expected = [64, 4, 3, 2, 1, 160, 1, 0, 1, 166, 148, 100, 38, 21, 248, 66, 196, 185];
  assert_eq!(packet.phy_payload, expected);
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should encode packet with Lorawan11 (3. Mac-commands in FOpts using NFCntDown)"
///
/// Downlink with FOpts encrypted via NwkSEncKey and no FPort (so NFCntDown
/// path is taken). MHDR = 0x60 = UnconfirmedDataDown.
#[test]
fn should_encode_packet_with_lorawan_1_1_fopts_nfcntdown() {
  let s_nwk_s_int_key = SNwkSIntKey::new([2; 16]);
  let f_nwk_s_int_key = FNwkSIntKey::new({
    let mut k = [2u8; 16];
    k[15] = 3;
    k
  });
  let nwk_s_enc_key = NwkSEncKey::new({
    let mut k = [2u8; 16];
    k[15] = 4;
    k
  });

  let mut packet = LoraPacket::builder()
    .data(Direction::Downlink, false) // 0x60 UnconfirmedDataDown
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .f_cnt(0)
    .f_opts(&[0x02, 0x07, 0x01])
    .payload(b"")
    .build_unsigned()
    .unwrap();

  // Encrypt FOpts (downlink with no FPort -> NFCntDown path; key byte 4 = 0x01).
  let enc_fopts = packet.as_data().unwrap().encrypt_fopts(&nwk_s_enc_key, 0).unwrap();
  packet.as_data_mut().unwrap().f_opts = enc_fopts;
  // Clear payload so wire doesn't include it as FPort + FRMPayload.
  packet.as_data_mut().unwrap().f_port = None;
  packet.as_data_mut().unwrap().frm_payload = None;
  packet.phy_payload = packet.to_wire();

  let mic_keys = lora_packet::V1_1MicKeys {
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).unwrap();

  let expected = [96, 4, 3, 2, 1, 3, 0, 0, 223, 180, 241, 226, 79, 31, 159];
  assert_eq!(packet.phy_payload, expected);
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should encode packet with Lorawan11 (4. Mac-commands in FOpts using AFCntDown)"
///
/// Downlink with FOpts (plaintext) + FPort > 0. The TS test does NOT call
/// `encryptFOpts` here. MHDR = 0x60 = UnconfirmedDataDown.
#[test]
fn should_encode_packet_with_lorawan_1_1_fopts_afcntdown() {
  let s_nwk_s_int_key = SNwkSIntKey::new([2; 16]);
  let f_nwk_s_int_key = FNwkSIntKey::new({
    let mut k = [2u8; 16];
    k[15] = 3;
    k
  });

  let mut packet = LoraPacket::builder()
    .data(Direction::Downlink, false) // 0x60 UnconfirmedDataDown
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .f_cnt(0)
    .f_port(1)
    .f_opts(&[0x02, 0x07, 0x01])
    .payload(b"")
    .build_unsigned()
    .unwrap();

  let mic_keys = lora_packet::V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([0x00, 0x00, 0, 0]),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).unwrap();

  let expected = [96, 4, 3, 2, 1, 3, 0, 0, 2, 7, 1, 1, 119, 112, 30, 163];
  assert_eq!(packet.phy_payload, expected);
}

/// Mirror of `__tests__/packet_test.ts`:
/// "should encode packet with Lorawan11 (5. Mac-commands in FRMPayload)"
#[test]
fn should_encode_packet_with_lorawan_1_1_fopts_in_frm_payload() {
  let s_nwk_s_int_key = SNwkSIntKey::new([2; 16]);
  let f_nwk_s_int_key = FNwkSIntKey::new({
    let mut k = [2u8; 16];
    k[15] = 3;
    k
  });
  let nwk_s_enc_key = NwkSEncKey::new({
    let mut k = [2u8; 16];
    k[15] = 4;
    k
  });
  let conf_fcnt = [0x00, 0x00];
  let tx_dr = 0x02u8;
  let tx_ch = 0x03u8;

  let mac_commands = [0x02u8, 0x03, 0x05];

  let mut packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x01, 0x02, 0x03, 0x04]))
    .f_cnt(0)
    .f_port(0)
    .payload(&mac_commands)
    .build_unsigned()
    .unwrap();

  // Port-0 FRMPayload encryption uses NwkSEncKey (in TS it's passed as the first
  // arg of fromFields; here use encrypt_payload with NwkSEncKey as NwkSKey).
  let nwk_s_as_enc = NwkSKey::new(*nwk_s_enc_key.as_bytes());
  let app_unused = AppSKey::new([0u8; 16]);
  let encrypted = packet
    .as_data()
    .unwrap()
    .encrypt_payload(&mac_commands, &app_unused, &nwk_s_as_enc, 0)
    .unwrap();
  packet.as_data_mut().unwrap().frm_payload = Some(encrypted);
  packet.phy_payload = packet.to_wire();

  let mic_keys = lora_packet::V1_1MicKeys {
    f_nwk_s_int_key: Some(&f_nwk_s_int_key),
    s_nwk_s_int_key: Some(&s_nwk_s_int_key),
    conf_fcnt_down_tx_dr_tx_ch: Some([conf_fcnt[0], conf_fcnt[1], tx_dr, tx_ch]),
    ..Default::default()
  };
  packet.recalculate_mic_v1_1(&mic_keys).unwrap();

  let expected = hex_to_vec("400403020100000000f7ded3cc995ea7");
  assert_eq!(packet.phy_payload, expected);

  // Round-trip: decrypt should recover the plaintext MAC commands.
  let decrypted = packet
    .as_data()
    .unwrap()
    .decrypt_payload(&app_unused, &nwk_s_as_enc, 0)
    .unwrap();
  assert_eq!(decrypted, mac_commands);
}

// Avoid unused-import warnings if some types only appear behind features.
#[allow(dead_code)]
fn _silence_unused_imports() {
  let _ = JoinEui::new([0; 8]);
  let _ = MType::JoinRequest;
  let _ = Payload::Proprietary(Vec::new());
  let _ = V1_0MicKeys::default();
}
