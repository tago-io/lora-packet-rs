//! Smoke test: build and exercise the crate in no_std + alloc mode.
//!
//! This file only runs in `--no-default-features` mode. It's a guardrail
//! that catches accidental dependence on `std::` paths in the public API.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg(not(feature = "std"))]

extern crate alloc;

use alloc::vec;
use lora_packet::{AppSKey, LoraPacket, NwkSKey, Payload};

#[test]
fn parse_and_decrypt_in_no_std() {
  let bytes = vec![
    0x40, 0xf1, 0x7d, 0xbe, 0x49, 0x00, 0x02, 0x00, 0x01, 0x95, 0x43, 0x78, 0x76, 0x2b, 0x11, 0xff, 0x0d,
  ];
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  assert!(matches!(packet.payload, Payload::Data(_)));

  let data = packet.as_data().unwrap();
  let app_s_key = AppSKey::new([
    0xec, 0x92, 0x58, 0x02, 0xae, 0x43, 0x0c, 0xa7, 0x7f, 0xd3, 0xdd, 0x73, 0xcb, 0x2c, 0xc5, 0x88,
  ]);
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  let plain = data.decrypt_payload(&app_s_key, &nwk_s_key, 0).unwrap();
  assert_eq!(plain, b"test");
}
