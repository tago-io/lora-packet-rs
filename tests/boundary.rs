//! Boundary-condition tests for the `lora-packet` public API.
//!
//! Each test exercises one extreme of a field's domain (min, max, edge bits)
//! and asserts the matching getter or wire output reflects the value
//! verbatim. Coverage spans frame counters, FOpts/FRMPayload lengths, AES
//! block-boundary crossings, identifier extremes, and bit-position sweeps for
//! `FCtrl`, `DlSettings`, and `MType`.

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, JoinEui, JoinNonce,
  LoraPacket, MType, Mhdr, NetId, NwkSKey, Payload, RejoinRequest, V1_0MicKeys,
};

fn build_minimal_uplink(f_cnt: u16) -> LoraPacket {
  LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_cnt(f_cnt)
    .f_port(1)
    .payload(b"x")
    .build_unsigned()
    .expect("builder accepts minimal uplink")
}

// ---------------------------------------------------------------------------
// FCnt boundaries (u16)
// ---------------------------------------------------------------------------

#[test]
fn f_cnt_zero_round_trips() {
  let pkt = build_minimal_uplink(0);
  let d = pkt.as_data().unwrap();
  assert_eq!(d.f_cnt(), 0);
  assert_eq!(d.f_cnt, [0x00, 0x00]);
}

#[test]
fn f_cnt_one_round_trips() {
  let pkt = build_minimal_uplink(1);
  let d = pkt.as_data().unwrap();
  assert_eq!(d.f_cnt(), 1);
  assert_eq!(d.f_cnt, [0x01, 0x00]);
}

#[test]
fn f_cnt_near_max_round_trips() {
  let pkt = build_minimal_uplink(0xFFFE);
  let d = pkt.as_data().unwrap();
  assert_eq!(d.f_cnt(), 0xFFFE);
  assert_eq!(d.f_cnt, [0xFE, 0xFF]);
}

#[test]
fn f_cnt_max_u16_round_trips() {
  let pkt = build_minimal_uplink(0xFFFF);
  let d = pkt.as_data().unwrap();
  assert_eq!(d.f_cnt(), 0xFFFF);
  assert_eq!(d.f_cnt, [0xFF, 0xFF]);
}

// ---------------------------------------------------------------------------
// f_cnt_32 with the caller-tracked MSB16
// ---------------------------------------------------------------------------

#[test]
fn f_cnt_32_msb_zero_low_zero() {
  let pkt = build_minimal_uplink(0);
  assert_eq!(pkt.as_data().unwrap().f_cnt_32(0), 0);
}

#[test]
fn f_cnt_32_msb_zero_low_max() {
  let pkt = build_minimal_uplink(0xFFFF);
  assert_eq!(pkt.as_data().unwrap().f_cnt_32(0), 0x0000_FFFF);
}

#[test]
fn f_cnt_32_msb_one_low_zero_first_wrap() {
  let pkt = build_minimal_uplink(0);
  assert_eq!(pkt.as_data().unwrap().f_cnt_32(1), 0x0001_0000);
}

#[test]
fn f_cnt_32_msb_max_low_max_is_u32_max() {
  let pkt = build_minimal_uplink(0xFFFF);
  assert_eq!(pkt.as_data().unwrap().f_cnt_32(0xFFFF), u32::MAX);
}

#[test]
fn f_cnt_32_msb_max_low_zero() {
  let pkt = build_minimal_uplink(0);
  assert_eq!(pkt.as_data().unwrap().f_cnt_32(0xFFFF), 0xFFFF_0000);
}

// ---------------------------------------------------------------------------
// FOpts length: 0, 1, 15 (the 4-bit FOptsLen field maxes at 15)
// ---------------------------------------------------------------------------

#[test]
fn f_opts_empty() {
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0)
    .f_port(1)
    .payload(b"x")
    .build_unsigned()
    .unwrap();
  let d = pkt.as_data().unwrap();
  assert!(d.f_opts.is_empty());
  assert_eq!(d.f_ctrl.f_opts_len(), 0);
}

#[test]
fn f_opts_single_byte() {
  let opts = [0xAB];
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0)
    .f_opts(&opts)
    .build_unsigned()
    .unwrap();
  let d = pkt.as_data().unwrap();
  assert_eq!(d.f_opts, opts);
  assert_eq!(d.f_ctrl.f_opts_len(), 1);
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  assert_eq!(parsed.as_data().unwrap().f_opts, opts);
}

#[test]
fn f_opts_max_15_bytes() {
  let opts: Vec<u8> = (0..15).collect();
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0)
    .f_opts(&opts)
    .build_unsigned()
    .unwrap();
  let d = pkt.as_data().unwrap();
  assert_eq!(d.f_opts.len(), 15);
  assert_eq!(d.f_opts, opts);
  assert_eq!(d.f_ctrl.f_opts_len(), 15);
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  assert_eq!(parsed.as_data().unwrap().f_opts.len(), 15);
}

// ---------------------------------------------------------------------------
// FRMPayload lengths: 0, 1, 250 (typical regional max)
// ---------------------------------------------------------------------------

#[test]
fn frm_payload_empty_with_port() {
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0)
    .f_port(1)
    .payload(&[])
    .build_unsigned()
    .unwrap();
  let d = pkt.as_data().unwrap();
  assert_eq!(d.frm_payload.as_deref(), Some(&[][..]));
  assert_eq!(d.f_port, Some(1));
}

#[test]
fn frm_payload_one_byte() {
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0)
    .f_port(1)
    .payload(&[0x42])
    .build_unsigned()
    .unwrap();
  let d = pkt.as_data().unwrap();
  assert_eq!(d.frm_payload.as_deref(), Some(&[0x42][..]));
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  assert_eq!(parsed.as_data().unwrap().frm_payload.as_deref(), Some(&[0x42][..]));
}

#[test]
fn frm_payload_239_bytes_round_trips() {
  // 239 bytes is the largest FRMPayload that still fits the 256-byte PHY
  // cap (256 - 1 MHDR - 7 FHDR - 1 FPort - 4 MIC = 243; we use 239 to be
  // well clear). The cap exists to keep CMAC B0/B1 length bytes in range.
  let payload: Vec<u8> = (0..239).map(|i| i as u8).collect();
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0)
    .f_port(1)
    .payload(&payload)
    .build_unsigned()
    .unwrap();
  let d = pkt.as_data().unwrap();
  assert_eq!(d.frm_payload.as_deref().unwrap().len(), 239);
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  assert_eq!(parsed.as_data().unwrap().frm_payload.as_deref().unwrap(), &payload[..]);
}

// ---------------------------------------------------------------------------
// AES block boundaries (block size = 16). Round-trip encrypt + decrypt.
// ---------------------------------------------------------------------------

fn encrypt_decrypt_round_trip(plaintext_len: usize) {
  let app_s_key = AppSKey::new([0x11u8; 16]);
  let nwk_s_key = NwkSKey::new([0x22u8; 16]);
  let plaintext: Vec<u8> = (0..plaintext_len).map(|i| (i & 0xff) as u8).collect();

  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
    .f_cnt(7)
    .f_port(1)
    .payload(&plaintext)
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let d = pkt.as_data().unwrap();
  let ciphertext_len = d.frm_payload.as_deref().map_or(0, <[u8]>::len);
  assert_eq!(ciphertext_len, plaintext_len);

  let decoded = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  let decoded_data = decoded.as_data().unwrap();
  let recovered = decoded_data.decrypt_payload(&app_s_key, &nwk_s_key, 0).unwrap();
  assert_eq!(recovered, plaintext, "round-trip mismatch at len {plaintext_len}");
}

#[test]
fn payload_crosses_aes_block_at_16_bytes() {
  encrypt_decrypt_round_trip(16);
}

#[test]
fn payload_crosses_aes_block_at_17_bytes() {
  encrypt_decrypt_round_trip(17);
}

#[test]
fn payload_crosses_aes_block_at_32_bytes() {
  encrypt_decrypt_round_trip(32);
}

#[test]
fn payload_crosses_aes_block_at_33_bytes() {
  encrypt_decrypt_round_trip(33);
}

// ---------------------------------------------------------------------------
// Multi-block payload at the u8 block-index limit (255 blocks = 4080 bytes)
// ---------------------------------------------------------------------------

#[test]
fn payload_at_255_block_limit_succeeds() {
  let len = 255 * 16;
  let app_s_key = AppSKey::new([0x33u8; 16]);
  let nwk_s_key = NwkSKey::new([0x44u8; 16]);
  let plaintext = vec![0xCDu8; len];

  let pkt = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(DevAddr::new([0xff, 0xee, 0xdd, 0xcc]))
    .f_cnt(0)
    .f_port(2)
    .payload(&plaintext)
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let ct_len = pkt.as_data().unwrap().frm_payload.as_deref().unwrap().len();
  assert_eq!(ct_len, len);

  let recovered = pkt
    .as_data()
    .unwrap()
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .unwrap();
  assert_eq!(recovered, plaintext);
}

#[test]
fn payload_one_byte_over_255_block_limit_rejected() {
  let too_big = vec![0u8; 255 * 16 + 1];
  let app_s_key = AppSKey::new([0u8; 16]);
  let nwk_s_key = NwkSKey::new([0u8; 16]);

  let err = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0)
    .f_port(1)
    .payload(&too_big)
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap_err();
  assert!(matches!(err, lora_packet::Error::PayloadTooLarge(n) if n == 255 * 16 + 1));
}

// ---------------------------------------------------------------------------
// DevAddr extremes
// ---------------------------------------------------------------------------

#[test]
fn dev_addr_all_zeros() {
  let addr = DevAddr::new([0x00; 4]);
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(addr)
    .f_cnt(0)
    .build_unsigned()
    .unwrap();
  assert_eq!(pkt.as_data().unwrap().dev_addr.as_bytes(), &[0x00; 4]);
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  assert_eq!(parsed.as_data().unwrap().dev_addr.as_bytes(), &[0x00; 4]);
}

#[test]
fn dev_addr_all_ones() {
  let addr = DevAddr::new([0xFF; 4]);
  let pkt = LoraPacket::builder()
    .data(Direction::Downlink, true)
    .dev_addr(addr)
    .f_cnt(0)
    .build_unsigned()
    .unwrap();
  assert_eq!(pkt.as_data().unwrap().dev_addr.as_bytes(), &[0xFF; 4]);
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  assert_eq!(parsed.as_data().unwrap().dev_addr.as_bytes(), &[0xFF; 4]);
}

// ---------------------------------------------------------------------------
// DevEUI / AppEUI / JoinEUI extremes
// ---------------------------------------------------------------------------

#[test]
fn dev_eui_all_zeros_round_trips_in_join_request() {
  let app_key = AppKey::new([0u8; 16]);
  let pkt = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0; 8]))
    .dev_eui(DevEui::new([0; 8]))
    .dev_nonce(DevNonce::new([0; 2]))
    .sign_join_request(&app_key)
    .unwrap();
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  let jr = parsed.as_join_request().unwrap();
  assert_eq!(jr.dev_eui.as_bytes(), &[0u8; 8]);
  assert_eq!(jr.join_eui.as_bytes(), &[0u8; 8]);
}

#[test]
fn dev_eui_all_ones_round_trips_in_join_request() {
  let app_key = AppKey::new([0u8; 16]);
  let pkt = LoraPacket::builder()
    .join_request()
    .join_eui(AppEui::new([0xFF; 8]))
    .dev_eui(DevEui::new([0xFF; 8]))
    .dev_nonce(DevNonce::new([0xFF, 0xFF]))
    .sign_join_request(&app_key)
    .unwrap();
  let parsed = LoraPacket::from_wire(&pkt.phy_payload).unwrap();
  let jr = parsed.as_join_request().unwrap();
  assert_eq!(jr.dev_eui.as_bytes(), &[0xFFu8; 8]);
  assert_eq!(jr.join_eui.as_bytes(), &[0xFFu8; 8]);
}

#[test]
fn join_eui_alias_matches_app_eui() {
  let zeroed: JoinEui = AppEui::new([0; 8]);
  let ones: AppEui = JoinEui::new([0xFF; 8]);
  assert_eq!(zeroed.as_bytes(), &[0u8; 8]);
  assert_eq!(ones.as_bytes(), &[0xFFu8; 8]);
}

// ---------------------------------------------------------------------------
// DevNonce extremes
// ---------------------------------------------------------------------------

#[test]
fn dev_nonce_all_zeros() {
  let n = DevNonce::new([0x00, 0x00]);
  assert_eq!(n.as_bytes(), &[0x00, 0x00]);
}

#[test]
fn dev_nonce_all_ones() {
  let n = DevNonce::from_slice(&[0xFF, 0xFF]).unwrap();
  assert_eq!(n.as_bytes(), &[0xFF, 0xFF]);
}

// ---------------------------------------------------------------------------
// AppNonce / JoinNonce extremes
// ---------------------------------------------------------------------------

#[test]
fn app_nonce_all_zeros_round_trips_in_join_accept() {
  let app_key = AppKey::new([0u8; 16]);
  let (packet, _wire) = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0, 0, 0]))
    .net_id(NetId::new([0, 0, 0]))
    .dev_addr(DevAddr::new([0; 4]))
    .dl_settings(DlSettings(0))
    .rx_delay(0)
    .sign_join_accept(&app_key)
    .unwrap();
  let ja = packet.as_join_accept().unwrap();
  assert_eq!(ja.join_nonce.as_bytes(), &[0u8; 3]);
}

#[test]
fn join_nonce_alias_matches_app_nonce() {
  let zero: JoinNonce = AppNonce::new([0, 0, 0]);
  let max: AppNonce = JoinNonce::new([0xFF, 0xFF, 0xFF]);
  assert_eq!(zero.as_bytes(), &[0, 0, 0]);
  assert_eq!(max.as_bytes(), &[0xFF, 0xFF, 0xFF]);
}

#[test]
fn app_nonce_all_ones() {
  let n = AppNonce::from_slice(&[0xFF, 0xFF, 0xFF]).unwrap();
  assert_eq!(n.as_bytes(), &[0xFF, 0xFF, 0xFF]);
}

// ---------------------------------------------------------------------------
// RxDelay: 0 and 15 (only 4 bits are meaningful for RX1 delay seconds)
// ---------------------------------------------------------------------------

#[test]
fn rx_delay_zero_round_trips() {
  let app_key = AppKey::new([0u8; 16]);
  let (packet, _wire) = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0, 0, 0]))
    .net_id(NetId::new([0, 0, 0]))
    .dev_addr(DevAddr::new([0; 4]))
    .dl_settings(DlSettings(0))
    .rx_delay(0)
    .sign_join_accept(&app_key)
    .unwrap();
  assert_eq!(packet.as_join_accept().unwrap().rx_delay, 0);
}

#[test]
fn rx_delay_fifteen_round_trips() {
  let app_key = AppKey::new([0u8; 16]);
  let (packet, _wire) = LoraPacket::builder()
    .join_accept()
    .join_nonce(AppNonce::new([0, 0, 0]))
    .net_id(NetId::new([0, 0, 0]))
    .dev_addr(DevAddr::new([0; 4]))
    .dl_settings(DlSettings(0))
    .rx_delay(15)
    .sign_join_accept(&app_key)
    .unwrap();
  assert_eq!(packet.as_join_accept().unwrap().rx_delay, 15);
}

// ---------------------------------------------------------------------------
// DLSettings bit positions (OptNeg = bit 7, RX1DRoffset = bits 6..4,
// RX2DataRate = bits 3..0). Test each individual bit on.
// ---------------------------------------------------------------------------

#[test]
fn dl_settings_opt_neg_bit_only() {
  let d = DlSettings::new(0b1000_0000);
  assert!(d.opt_neg());
  assert_eq!(d.rx1_dr_offset(), 0);
  assert_eq!(d.rx2_data_rate(), 0);
  assert_eq!(d.as_byte(), 0x80);
}

#[test]
fn dl_settings_rx1_dr_offset_high_bit() {
  let d = DlSettings::new(0b0100_0000);
  assert!(!d.opt_neg());
  assert_eq!(d.rx1_dr_offset(), 0b100);
  assert_eq!(d.rx2_data_rate(), 0);
}

#[test]
fn dl_settings_rx1_dr_offset_mid_bit() {
  let d = DlSettings::new(0b0010_0000);
  assert_eq!(d.rx1_dr_offset(), 0b010);
}

#[test]
fn dl_settings_rx1_dr_offset_low_bit() {
  let d = DlSettings::new(0b0001_0000);
  assert_eq!(d.rx1_dr_offset(), 0b001);
}

#[test]
fn dl_settings_rx2_data_rate_each_bit() {
  for shift in 0..4 {
    let d = DlSettings::new(1 << shift);
    assert_eq!(d.rx2_data_rate(), 1 << shift, "rx2_data_rate failed at bit {shift}");
    assert!(!d.opt_neg());
    assert_eq!(d.rx1_dr_offset(), 0);
  }
}

#[test]
fn dl_settings_all_bits_set() {
  let d = DlSettings::new(0xFF);
  assert!(d.opt_neg());
  assert_eq!(d.rx1_dr_offset(), 0b111);
  assert_eq!(d.rx2_data_rate(), 0b1111);
  assert_eq!(d.as_byte(), 0xFF);
}

// ---------------------------------------------------------------------------
// FCtrl bit positions
// ---------------------------------------------------------------------------

#[test]
fn f_ctrl_adr_bit_only() {
  let c = FCtrl::new(0b1000_0000);
  assert!(c.adr());
  assert!(!c.adr_ack_req());
  assert!(!c.ack());
  assert!(!c.class_b());
  assert!(!c.f_pending());
  assert_eq!(c.f_opts_len(), 0);
}

#[test]
fn f_ctrl_adr_ack_req_bit_only() {
  let c = FCtrl::new(0b0100_0000);
  assert!(!c.adr());
  assert!(c.adr_ack_req());
  assert!(!c.ack());
  assert!(!c.class_b());
}

#[test]
fn f_ctrl_ack_bit_only() {
  let c = FCtrl::new(0b0010_0000);
  assert!(!c.adr());
  assert!(c.ack());
  assert!(!c.class_b());
}

#[test]
fn f_ctrl_class_b_and_f_pending_share_bit_four() {
  let c = FCtrl::new(0b0001_0000);
  // Bit 4 is ClassB on uplink and FPending on downlink; same accessor bit.
  assert!(c.class_b());
  assert!(c.f_pending());
  assert!(!c.adr());
  assert!(!c.ack());
}

#[test]
fn f_ctrl_f_opts_len_each_bit() {
  for shift in 0..4 {
    let c = FCtrl::new(1 << shift);
    assert_eq!(c.f_opts_len(), 1 << shift, "f_opts_len failed at bit {shift}");
    assert!(!c.adr());
    assert!(!c.ack());
  }
}

#[test]
fn f_ctrl_max_f_opts_len_only() {
  let c = FCtrl::new(0x0F);
  assert_eq!(c.f_opts_len(), 15);
  assert!(!c.adr());
  assert!(!c.adr_ack_req());
  assert!(!c.ack());
  assert!(!c.class_b());
}

#[test]
fn f_ctrl_all_bits_set() {
  let c = FCtrl::new(0xFF);
  assert!(c.adr());
  assert!(c.adr_ack_req());
  assert!(c.ack());
  assert!(c.class_b());
  assert!(c.f_pending());
  assert_eq!(c.f_opts_len(), 0x0F);
  assert_eq!(c.as_byte(), 0xFF);
}

// ---------------------------------------------------------------------------
// MType: each of the 8 values round-trips through Mhdr
// ---------------------------------------------------------------------------

#[test]
fn mtype_join_request_round_trip() {
  let m = Mhdr::from_parts(MType::JoinRequest, 0);
  assert_eq!(m.as_byte(), 0x00);
  assert_eq!(m.m_type().unwrap(), MType::JoinRequest);
  assert_eq!(MType::from_mhdr(0x00).unwrap(), MType::JoinRequest);
}

#[test]
fn mtype_join_accept_round_trip() {
  let m = Mhdr::from_parts(MType::JoinAccept, 0);
  assert_eq!(m.as_byte(), 0x20);
  assert_eq!(m.m_type().unwrap(), MType::JoinAccept);
  assert_eq!(MType::from_mhdr(0x20).unwrap(), MType::JoinAccept);
}

#[test]
fn mtype_unconfirmed_up_round_trip() {
  let m = Mhdr::from_parts(MType::UnconfirmedDataUp, 0);
  assert_eq!(m.as_byte(), 0x40);
  assert_eq!(m.m_type().unwrap(), MType::UnconfirmedDataUp);
}

#[test]
fn mtype_unconfirmed_down_round_trip() {
  let m = Mhdr::from_parts(MType::UnconfirmedDataDown, 0);
  assert_eq!(m.as_byte(), 0x60);
  assert_eq!(m.m_type().unwrap(), MType::UnconfirmedDataDown);
}

#[test]
fn mtype_confirmed_up_round_trip() {
  let m = Mhdr::from_parts(MType::ConfirmedDataUp, 0);
  assert_eq!(m.as_byte(), 0x80);
  assert_eq!(m.m_type().unwrap(), MType::ConfirmedDataUp);
}

#[test]
fn mtype_confirmed_down_round_trip() {
  let m = Mhdr::from_parts(MType::ConfirmedDataDown, 0);
  assert_eq!(m.as_byte(), 0xA0);
  assert_eq!(m.m_type().unwrap(), MType::ConfirmedDataDown);
}

#[test]
fn mtype_rejoin_request_round_trip() {
  let m = Mhdr::from_parts(MType::RejoinRequest, 0);
  assert_eq!(m.as_byte(), 0xC0);
  assert_eq!(m.m_type().unwrap(), MType::RejoinRequest);
}

#[test]
fn mtype_proprietary_round_trip() {
  let m = Mhdr::from_parts(MType::Proprietary, 0);
  assert_eq!(m.as_byte(), 0xE0);
  assert_eq!(m.m_type().unwrap(), MType::Proprietary);
}

// ---------------------------------------------------------------------------
// Cross-check: MIC verification still works at boundary FCnt values
// ---------------------------------------------------------------------------

#[test]
fn mic_verifies_at_f_cnt_max_u16() {
  let nwk_s_key = NwkSKey::new([0x55u8; 16]);
  let pkt = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0; 4]))
    .f_cnt(0xFFFF)
    .f_port(1)
    .payload(b"end")
    .sign_and_encrypt(&AppSKey::new([0x66u8; 16]), &nwk_s_key)
    .unwrap();
  let keys = V1_0MicKeys {
    nwk_s_key: Some(&nwk_s_key),
    ..Default::default()
  };
  assert!(pkt.verify_mic_v1_0(&keys).unwrap());
}

// ---------------------------------------------------------------------------
// from_wire boundary: minimum 5 bytes (MHDR + MIC) for a Proprietary frame
// ---------------------------------------------------------------------------

#[test]
fn from_wire_minimum_5_bytes_proprietary() {
  let bytes = [0xE0, 0xDE, 0xAD, 0xBE, 0xEF];
  let pkt = LoraPacket::from_wire(&bytes).unwrap();
  assert_eq!(pkt.mhdr.as_byte(), 0xE0);
  assert_eq!(pkt.mic, [0xDE, 0xAD, 0xBE, 0xEF]);
  match &pkt.payload {
    Payload::Proprietary(b) => assert!(b.is_empty()),
    _ => panic!("expected Proprietary"),
  }
}

#[test]
fn from_wire_rejects_4_bytes() {
  let err = LoraPacket::from_wire(&[0; 4]).unwrap_err();
  assert!(matches!(err, lora_packet::Error::TooShort { .. }));
}

// ---------------------------------------------------------------------------
// Rejoin Type extremes round-trip
// ---------------------------------------------------------------------------

#[test]
fn rejoin_type_0_max_rj_count_round_trips() {
  // MHDR(C0) + type(00) + NetID(LE) + DevEUI(LE) + RJCount0(LE) + MIC
  let wire = hex_decode("c000ffffff0807060504030201ffff00112233");
  let pkt = LoraPacket::from_wire(&wire).unwrap();
  match pkt.as_rejoin_request().unwrap() {
    RejoinRequest::Type0 {
      net_id,
      dev_eui,
      rj_count_0,
    } => {
      assert_eq!(net_id.as_bytes(), &[0xFF, 0xFF, 0xFF]);
      assert_eq!(dev_eui.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
      assert_eq!(rj_count_0, &[0xFF, 0xFF]);
    }
    _ => panic!("expected Type0"),
  }
}

fn hex_decode(s: &str) -> Vec<u8> {
  (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
    .collect()
}
