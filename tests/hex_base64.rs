//! Integration tests for the `hex_base64` feature.

#![cfg(feature = "hex_base64")]

#[test]
fn from_hex_parses_data_up() {
  let p = lora_packet::LoraPacket::from_hex("40f17dbe4900020001954378762b11ff0d").unwrap();
  assert!(p.is_data());
}

#[test]
fn from_hex_propagates_decode_error() {
  let err = lora_packet::LoraPacket::from_hex("zzzz").unwrap_err();
  assert!(matches!(err, lora_packet::Error::Hex(_)));
}

#[test]
fn from_base64_parses_data_up() {
  use base64::Engine as _;
  let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d").unwrap();
  let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
  let p = lora_packet::LoraPacket::from_base64(&b64).unwrap();
  assert!(p.is_data());
}

#[test]
fn key_from_hex_round_trip() {
  let key = lora_packet::AppKey::from_hex("44024241ed4ce9a68c6a8bc055233fd3").unwrap();
  assert_eq!(key.as_bytes()[0], 0x44);
  assert_eq!(key.as_bytes()[15], 0xd3);
}

#[test]
fn id_from_hex_round_trip() {
  let dev_addr = lora_packet::DevAddr::from_hex("49be7df1").unwrap();
  assert_eq!(dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
}
