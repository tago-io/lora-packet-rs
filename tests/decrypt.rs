//! FRMPayload encrypt and decrypt tests.
use lora_packet::{AppSKey, DevAddr, Direction, FCtrl, LoraPacket, NwkSKey};

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
fn should_decrypt_test_payload() {
  let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  // NwkSKey is unused for FPort > 0, but the API takes both.
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  let decrypted = packet
    .as_data()
    .unwrap()
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .unwrap();
  assert_eq!(decrypted, b"test");
}

#[test]
fn should_decrypt_large_payload() {
  let hex = "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";
  let packet = LoraPacket::from_wire(&hex_to_vec(hex)).unwrap();
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  let decrypted = packet
    .as_data()
    .unwrap()
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .unwrap();
  assert_eq!(decrypted, b"The quick brown fox jumps over the lazy dog.");
}

#[test]
fn bad_key_scrambles_payload() {
  let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc580"));
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  let decrypted = packet
    .as_data()
    .unwrap()
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .unwrap();
  assert_eq!(decrypted, hex_to_vec("5999fc3f"));
}

#[test]
fn bad_data_lightly_scrambles_payload() {
  // Single byte flipped in the ciphertext.
  let bytes = hex_to_vec("40F17DBE4900020001954478762B11FF0D");
  let packet = LoraPacket::from_wire(&bytes).unwrap();
  let app_s_key = AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588"));
  let nwk_s_key = NwkSKey::new([0u8; 16]);
  let decrypted = packet
    .as_data()
    .unwrap()
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .unwrap();
  assert_eq!(decrypted, b"tbst");
}

///
/// Build a packet with FPort = 0 (so the NwkSKey is used for FRMPayload
/// crypt), then decrypt to recover the plaintext.
#[test]
fn should_decode_port_0() {
  let nwk_s_key = NwkSKey::new(key_from_hex("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));
  // FRMPayload here is a single byte 0x02; for port 0, NwkSKey is used.
  let plaintext = vec![0x02u8];
  // AppSKey unused when FPort == 0; pass an arbitrary key.
  let app_s_key = AppSKey::new([0u8; 16]);

  let packet = LoraPacket::builder()
    .data(Direction::Uplink, false)
    .dev_addr(DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]))
    .f_ctrl(FCtrl(0))
    .f_cnt(10)
    .f_port(0)
    .payload(&plaintext)
    .sign_and_encrypt(&app_s_key, &nwk_s_key)
    .unwrap();

  let decrypted = packet
    .as_data()
    .unwrap()
    .decrypt_payload(&app_s_key, &nwk_s_key, 0)
    .unwrap();
  assert_eq!(decrypted, hex_to_vec("02"));
}
