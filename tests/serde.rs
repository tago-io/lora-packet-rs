//! Round-trip integration test for the `serde` feature.

#![cfg(feature = "serde")]

#[test]
fn serde_round_trip_lora_packet() {
  let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d").unwrap();
  let packet = lora_packet::LoraPacket::from_wire(&bytes).unwrap();
  let json = serde_json::to_string(&packet).unwrap();
  let parsed: lora_packet::LoraPacket = serde_json::from_str(&json).unwrap();
  assert_eq!(parsed, packet);
}

#[test]
fn serde_round_trip_key_is_hex_string() {
  let key = lora_packet::AppKey::new([0xAB; 16]);
  let json = serde_json::to_string(&key).unwrap();
  // Manual hex serialization: 32 chars wrapped in quotes.
  assert_eq!(json, "\"abababababababababababababababab\"");
  let parsed: lora_packet::AppKey = serde_json::from_str(&json).unwrap();
  assert_eq!(parsed.as_bytes(), &[0xAB; 16]);
}
