//! AES-ECB primitives, `FRMPayload`/`FOpts` crypt, Join Accept crypt, and
//! session/JS/WOR key derivation.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use crate::types::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, FNwkSIntKey, JSEncKey, JSIntKey, NetId, NwkKey,
  NwkSEncKey, NwkSKey, RootWorSKey, SNwkSIntKey, WorSEncKey, WorSIntKey,
};

/// Encrypt one 16-byte block under AES-128 ECB. The low-level primitive.
pub fn aes_ecb_encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
  let cipher = Aes128::new(&Array::from(*key));
  let mut buf = Array::from(*block);
  cipher.encrypt_block(&mut buf);
  buf.into()
}

/// Decrypt one 16-byte block under AES-128 ECB. The low-level primitive.
pub fn aes_ecb_decrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
  let cipher = Aes128::new(&Array::from(*key));
  let mut buf = Array::from(*block);
  cipher.decrypt_block(&mut buf);
  buf.into()
}

/// `LoRaWAN` 1.0 session keys derived during OTAA.
#[derive(Debug, Clone)]
pub struct SessionKeys10 {
  /// Application session key.
  pub app_s_key: AppSKey,
  /// Network session key.
  pub nwk_s_key: NwkSKey,
}

impl SessionKeys10 {
  /// Derive `AppSKey` and `NwkSKey` from the OTAA root key and join nonces.
  ///
  /// # Examples
  ///
  /// ```
  /// use lora_packet::{SessionKeys10, AppKey, NetId, AppNonce, DevNonce};
  ///
  /// let app_key = AppKey::new([0u8; 16]);
  /// let keys = SessionKeys10::derive(
  ///   &app_key,
  ///   &NetId::new([0, 0, 0]),
  ///   &AppNonce::new([0, 0, 0]),
  ///   &DevNonce::new([0, 0]),
  /// );
  /// assert_ne!(keys.app_s_key.as_bytes(), keys.nwk_s_key.as_bytes());
  /// ```
  // All key-derivation helpers take inputs by reference for a uniform public API
  // even though the small identifier types are `Copy`.
  #[allow(clippy::trivially_copy_pass_by_ref)]
  pub fn derive(app_key: &AppKey, net_id: &NetId, app_nonce: &AppNonce, dev_nonce: &DevNonce) -> Self {
    let app_s_key = AppSKey::new(derive_session_key_10(0x02, app_key, net_id, app_nonce, dev_nonce));
    let nwk_s_key = NwkSKey::new(derive_session_key_10(0x01, app_key, net_id, app_nonce, dev_nonce));
    Self { app_s_key, nwk_s_key }
  }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn derive_session_key_10(
  prefix: u8,
  app_key: &AppKey,
  net_id: &NetId,
  app_nonce: &AppNonce,
  dev_nonce: &DevNonce,
) -> [u8; 16] {
  let mut block = [0u8; 16];
  block[0] = prefix;
  let mut n = *app_nonce.as_bytes();
  n.reverse();
  block[1..4].copy_from_slice(&n);
  let mut id = *net_id.as_bytes();
  id.reverse();
  block[4..7].copy_from_slice(&id);
  let mut dn = *dev_nonce.as_bytes();
  dn.reverse();
  block[7..9].copy_from_slice(&dn);
  aes_ecb_encrypt(&block, app_key.as_bytes())
}

/// `LoRaWAN` 1.1 session keys derived during OTAA.
#[derive(Debug, Clone)]
pub struct SessionKeys11 {
  /// Application session key (`FRMPayload` crypt with `FPort` > 0).
  pub app_s_key: AppSKey,
  /// Forwarding network session integrity key (uplink MIC, first 2 bytes).
  pub f_nwk_s_int_key: FNwkSIntKey,
  /// Serving network session integrity key (uplink + downlink MIC).
  pub s_nwk_s_int_key: SNwkSIntKey,
  /// Network session encryption key (`FOpts` and `FRMPayload` with `FPort` = 0).
  pub nwk_s_enc_key: NwkSEncKey,
}

impl SessionKeys11 {
  /// Derive all four 1.1 session keys.
  ///
  /// # Examples
  ///
  /// ```
  /// use lora_packet::{SessionKeys11, AppKey, NwkKey, AppEui, AppNonce, DevNonce};
  ///
  /// let keys = SessionKeys11::derive(
  ///   &AppKey::new([0u8; 16]),
  ///   &NwkKey::new([0u8; 16]),
  ///   &AppEui::new([0u8; 8]),
  ///   &AppNonce::new([0, 0, 0]),
  ///   &DevNonce::new([0, 0]),
  /// );
  /// assert_ne!(keys.app_s_key.as_bytes(), keys.f_nwk_s_int_key.as_bytes());
  /// ```
  #[allow(clippy::trivially_copy_pass_by_ref)]
  pub fn derive(
    app_key: &AppKey,
    nwk_key: &NwkKey,
    join_eui: &AppEui,
    app_nonce: &AppNonce,
    dev_nonce: &DevNonce,
  ) -> Self {
    let app_s_key = AppSKey::new(derive_session_key_11(
      0x02,
      app_key.as_bytes(),
      join_eui,
      app_nonce,
      dev_nonce,
    ));
    let f_nwk_s_int_key = FNwkSIntKey::new(derive_session_key_11(
      0x01,
      nwk_key.as_bytes(),
      join_eui,
      app_nonce,
      dev_nonce,
    ));
    let s_nwk_s_int_key = SNwkSIntKey::new(derive_session_key_11(
      0x03,
      nwk_key.as_bytes(),
      join_eui,
      app_nonce,
      dev_nonce,
    ));
    let nwk_s_enc_key = NwkSEncKey::new(derive_session_key_11(
      0x04,
      nwk_key.as_bytes(),
      join_eui,
      app_nonce,
      dev_nonce,
    ));
    Self {
      app_s_key,
      f_nwk_s_int_key,
      s_nwk_s_int_key,
      nwk_s_enc_key,
    }
  }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn derive_session_key_11(
  prefix: u8,
  key: &[u8; 16],
  join_eui: &AppEui,
  app_nonce: &AppNonce,
  dev_nonce: &DevNonce,
) -> [u8; 16] {
  let mut block = [0u8; 16];
  block[0] = prefix;
  let mut n = *app_nonce.as_bytes();
  n.reverse();
  block[1..4].copy_from_slice(&n);
  let mut e = *join_eui.as_bytes();
  e.reverse();
  block[4..12].copy_from_slice(&e);
  let mut dn = *dev_nonce.as_bytes();
  dn.reverse();
  block[12..14].copy_from_slice(&dn);
  aes_ecb_encrypt(&block, key)
}

/// Join Server keys derived from `NwkKey` and `DevEUI`.
#[derive(Debug, Clone)]
pub struct JoinServerKeys {
  /// Integrity key for Join Server operations.
  pub js_int_key: JSIntKey,
  /// Encryption key for Join Server operations.
  pub js_enc_key: JSEncKey,
}

impl JoinServerKeys {
  /// Derive both JS keys.
  #[allow(clippy::trivially_copy_pass_by_ref)]
  pub fn derive(nwk_key: &NwkKey, dev_eui: &DevEui) -> Self {
    let mut block = [0u8; 16];
    block[0] = 0x06;
    let mut e = *dev_eui.as_bytes();
    e.reverse();
    block[1..9].copy_from_slice(&e);
    let js_int_key = JSIntKey::new(aes_ecb_encrypt(&block, nwk_key.as_bytes()));
    block[0] = 0x05;
    let js_enc_key = JSEncKey::new(aes_ecb_encrypt(&block, nwk_key.as_bytes()));
    Self { js_int_key, js_enc_key }
  }
}

/// Relay (WOR) session keys derived from `RootWorSKey` and `DevAddr`.
#[derive(Debug, Clone)]
pub struct WorSessionKeys {
  /// WOR session integrity key.
  pub wor_s_int_key: WorSIntKey,
  /// WOR session encryption key.
  pub wor_s_enc_key: WorSEncKey,
}

/// Namespace for Relay/WOR key derivation.
pub struct WorKeys;

impl WorKeys {
  /// Derive `RootWorSKey` from `NwkSKey`.
  pub fn root(nwk_s_key: &NwkSKey) -> RootWorSKey {
    let mut block = [0u8; 16];
    block[0] = 0x01;
    RootWorSKey::new(aes_ecb_encrypt(&block, nwk_s_key.as_bytes()))
  }

  /// Derive WOR session keys from a root key and `DevAddr`.
  #[allow(clippy::trivially_copy_pass_by_ref)]
  pub fn session(root: &RootWorSKey, dev_addr: &DevAddr) -> WorSessionKeys {
    let mut block = [0u8; 16];
    block[0] = 0x01;
    let mut a = *dev_addr.as_bytes();
    a.reverse();
    block[1..5].copy_from_slice(&a);
    let wor_s_int_key = WorSIntKey::new(aes_ecb_encrypt(&block, root.as_bytes()));
    block[0] = 0x02;
    let wor_s_enc_key = WorSEncKey::new(aes_ecb_encrypt(&block, root.as_bytes()));
    WorSessionKeys {
      wor_s_int_key,
      wor_s_enc_key,
    }
  }
}

impl crate::codec::Data {
  /// Encrypt or decrypt `FRMPayload`. The XOR keystream construction makes
  /// the same operation work in both directions.
  ///
  /// Selects `NwkSKey` when `FPort == 0`, `AppSKey` otherwise.
  ///
  /// # Errors
  /// Currently infallible (returns `Result` for forward compatibility).
  ///
  /// # Examples
  ///
  /// ```
  /// use lora_packet::{LoraPacket, AppSKey, NwkSKey};
  ///
  /// let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d").unwrap();
  /// let packet = LoraPacket::from_wire(&bytes).unwrap();
  /// let app_s_key = AppSKey::from_slice(&hex::decode("ec925802ae430ca77fd3dd73cb2cc588").unwrap()).unwrap();
  /// let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3").unwrap()).unwrap();
  /// let plain = packet.as_data().unwrap().decrypt_payload(&app_s_key, &nwk_s_key, 0).unwrap();
  /// assert_eq!(&plain, b"test");
  /// ```
  pub fn decrypt_payload(
    &self,
    app_s_key: &AppSKey,
    nwk_s_key: &NwkSKey,
    f_cnt_msb: u16,
  ) -> crate::Result<alloc::vec::Vec<u8>> {
    let cipher = self.frm_payload.as_deref().unwrap_or(&[]);
    let key = if self.f_port == Some(0) {
      nwk_s_key.as_bytes()
    } else {
      app_s_key.as_bytes()
    };
    Ok(payload_crypt(
      cipher,
      key,
      self.direction,
      self.dev_addr,
      self.f_cnt_32(f_cnt_msb),
    ))
  }

  /// Encrypt the given plaintext under the `FRMPayload` keystream.
  ///
  /// Selects `NwkSKey` when `FPort == 0`, `AppSKey` otherwise.
  ///
  /// # Errors
  /// Currently infallible.
  pub fn encrypt_payload(
    &self,
    plaintext: &[u8],
    app_s_key: &AppSKey,
    nwk_s_key: &NwkSKey,
    f_cnt_msb: u16,
  ) -> crate::Result<alloc::vec::Vec<u8>> {
    let key = if self.f_port == Some(0) {
      nwk_s_key.as_bytes()
    } else {
      app_s_key.as_bytes()
    };
    Ok(payload_crypt(
      plaintext,
      key,
      self.direction,
      self.dev_addr,
      self.f_cnt_32(f_cnt_msb),
    ))
  }
}

fn payload_crypt(
  input: &[u8],
  key: &[u8; 16],
  direction: crate::types::Direction,
  dev_addr: DevAddr,
  f_cnt_32: u32,
) -> alloc::vec::Vec<u8> {
  let dir_byte = u8::from(!matches!(direction, crate::types::Direction::Uplink));
  let mut out = alloc::vec::Vec::with_capacity(input.len());
  let mut addr = *dev_addr.as_bytes();
  addr.reverse();
  for (i_chunk, chunk) in input.chunks(16).enumerate() {
    let mut ai = [0u8; 16];
    ai[0] = 0x01;
    ai[5] = dir_byte;
    ai[6..10].copy_from_slice(&addr);
    ai[10..14].copy_from_slice(&f_cnt_32.to_le_bytes());
    ai[15] = u8::try_from(i_chunk + 1).unwrap_or(0xFF);
    let s = aes_ecb_encrypt(&ai, key);
    for (j, b) in chunk.iter().enumerate() {
      out.push(b ^ s[j]);
    }
  }
  out
}

impl crate::codec::Data {
  /// Decrypt `FOpts` MAC commands (`LoRaWAN` 1.1 only).
  ///
  /// Uses the keystream layout from the official `LoRa` Alliance errata
  /// "`FCntDwn` Usage in `FOpts` Encryption" (CR v2 r1). When the frame is a
  /// downlink with `FPort` > 0 the `aFCntDown` flag selects byte 4 = 0x02;
  /// otherwise it is 0x01.
  ///
  /// # Errors
  /// Currently infallible.
  pub fn decrypt_fopts(
    &self,
    nwk_s_enc_key: &crate::types::NwkSEncKey,
    f_cnt_msb: u16,
  ) -> crate::Result<alloc::vec::Vec<u8>> {
    Ok(fopts_crypt(
      &self.f_opts,
      nwk_s_enc_key.as_bytes(),
      self.direction,
      self.dev_addr,
      self.f_port,
      self.f_cnt_32(f_cnt_msb),
    ))
  }

  /// Encrypt `FOpts` MAC commands (`LoRaWAN` 1.1 only).
  ///
  /// # Errors
  /// Currently infallible.
  pub fn encrypt_fopts(
    &self,
    nwk_s_enc_key: &crate::types::NwkSEncKey,
    f_cnt_msb: u16,
  ) -> crate::Result<alloc::vec::Vec<u8>> {
    Ok(fopts_crypt(
      &self.f_opts,
      nwk_s_enc_key.as_bytes(),
      self.direction,
      self.dev_addr,
      self.f_port,
      self.f_cnt_32(f_cnt_msb),
    ))
  }
}

impl crate::codec::JoinAccept {
  /// Decrypt a wire-format Join Accept (`MHDR` + ciphertext body + MIC).
  ///
  /// On-air the device applies AES-ECB-encrypt to undo the server's
  /// AES-ECB-decrypt; the MHDR passes through unchanged. The total length
  /// must be 17 (one block) or 33 (two blocks).
  ///
  /// # Errors
  /// `Error::TooShort` when the total length is outside {17, 33}.
  pub fn decrypt_from_wire(ciphertext: &[u8], app_key: &AppKey) -> crate::Result<alloc::vec::Vec<u8>> {
    join_accept_transform(ciphertext, app_key, aes_ecb_encrypt)
  }

  /// Encrypt a plaintext Join Accept (server-side AES-ECB-decrypt of the
  /// body); the MHDR is left as-is.
  ///
  /// # Errors
  /// `Error::TooShort` when the total length is outside {17, 33}.
  pub fn encrypt_for_wire(plaintext: &[u8], app_key: &AppKey) -> crate::Result<alloc::vec::Vec<u8>> {
    join_accept_transform(plaintext, app_key, aes_ecb_decrypt)
  }
}

fn join_accept_transform(
  input: &[u8],
  app_key: &AppKey,
  op: fn(&[u8; 16], &[u8; 16]) -> [u8; 16],
) -> crate::Result<alloc::vec::Vec<u8>> {
  if input.len() != 17 && input.len() != 33 {
    return Err(crate::Error::TooShort {
      expected: 17,
      got: input.len(),
    });
  }
  let mut out = alloc::vec::Vec::with_capacity(input.len());
  out.push(input[0]);
  for chunk in input[1..].chunks(16) {
    let mut block = [0u8; 16];
    block.copy_from_slice(chunk);
    out.extend_from_slice(&op(&block, app_key.as_bytes()));
  }
  Ok(out)
}

fn fopts_crypt(
  input: &[u8],
  key: &[u8; 16],
  direction: crate::types::Direction,
  dev_addr: DevAddr,
  f_port: Option<u8>,
  f_cnt_32: u32,
) -> alloc::vec::Vec<u8> {
  let is_downlink = matches!(direction, crate::types::Direction::Downlink);
  let dir_byte = u8::from(is_downlink);
  let a_f_cnt_down = is_downlink && f_port.is_some_and(|p| p > 0);

  let mut ai = [0u8; 16];
  ai[0] = 0x01;
  ai[4] = if a_f_cnt_down { 0x02 } else { 0x01 };
  ai[5] = dir_byte;
  let mut addr = *dev_addr.as_bytes();
  addr.reverse();
  ai[6..10].copy_from_slice(&addr);
  ai[10..14].copy_from_slice(&f_cnt_32.to_le_bytes());
  ai[15] = 0x01;
  let s = aes_ecb_encrypt(&ai, key);

  input.iter().enumerate().map(|(i, b)| b ^ s[i]).collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  /// NIST AES-128 test vector from FIPS-197 Appendix B.
  #[test]
  fn aes_ecb_encrypt_nist_vector() {
    let key = [
      0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let plaintext = [
      0x32u8, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    ];
    let expected = [
      0x39u8, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    ];
    assert_eq!(aes_ecb_encrypt(&plaintext, &key), expected);
  }

  #[test]
  fn session_keys_10_distinct() {
    let app_key = AppKey::new([
      0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ]);
    let net_id = NetId::new([0x00, 0x00, 0x01]);
    let app_nonce = AppNonce::new([0xC1, 0xD5, 0xEC]);
    let dev_nonce = DevNonce::new([0xC8, 0xF8]);
    let keys = SessionKeys10::derive(&app_key, &net_id, &app_nonce, &dev_nonce);
    assert_ne!(keys.app_s_key.as_bytes(), keys.nwk_s_key.as_bytes());
    // Same inputs -> same outputs (deterministic)
    let keys2 = SessionKeys10::derive(&app_key, &net_id, &app_nonce, &dev_nonce);
    assert_eq!(keys.app_s_key.as_bytes(), keys2.app_s_key.as_bytes());
    assert_eq!(keys.nwk_s_key.as_bytes(), keys2.nwk_s_key.as_bytes());
  }

  #[test]
  fn session_keys_11_distinct() {
    let app_key = AppKey::new([0x11u8; 16]);
    let nwk_key = NwkKey::new([0x22u8; 16]);
    let join_eui = AppEui::new([0x33u8; 8]);
    let app_nonce = AppNonce::new([0x44, 0x55, 0x66]);
    let dev_nonce = DevNonce::new([0x77, 0x88]);
    let k = SessionKeys11::derive(&app_key, &nwk_key, &join_eui, &app_nonce, &dev_nonce);
    assert_ne!(k.app_s_key.as_bytes(), k.f_nwk_s_int_key.as_bytes());
    assert_ne!(k.f_nwk_s_int_key.as_bytes(), k.s_nwk_s_int_key.as_bytes());
    assert_ne!(k.s_nwk_s_int_key.as_bytes(), k.nwk_s_enc_key.as_bytes());
  }

  #[test]
  fn js_keys_distinct() {
    let nwk_key = NwkKey::new([0x42u8; 16]);
    let dev_eui = DevEui::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    let k = JoinServerKeys::derive(&nwk_key, &dev_eui);
    assert_ne!(k.js_int_key.as_bytes(), k.js_enc_key.as_bytes());
  }

  #[test]
  fn wor_root_key_deterministic() {
    let nwk = NwkSKey::new([0x00u8; 16]);
    let r1 = WorKeys::root(&nwk);
    let r2 = WorKeys::root(&nwk);
    assert_eq!(r1.as_bytes(), r2.as_bytes());
  }

  #[test]
  fn wor_session_keys_distinct() {
    let nwk = NwkSKey::new([0x33u8; 16]);
    let root = WorKeys::root(&nwk);
    let dev = DevAddr::new([0x01, 0x02, 0x03, 0x04]);
    let s = WorKeys::session(&root, &dev);
    assert_ne!(s.wor_s_int_key.as_bytes(), s.wor_s_enc_key.as_bytes());
  }

  use crate::codec::LoraPacket;
  use alloc::vec::Vec;

  fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
      .collect()
  }

  fn hex_to_arr_16(s: &str) -> [u8; 16] {
    let mut arr = [0u8; 16];
    for (i, byte) in (0..s.len()).step_by(2).enumerate() {
      arr[i] = u8::from_str_radix(&s[byte..byte + 2], 16).unwrap();
    }
    arr
  }

  /// Mirror of `__tests__/decrypt_test.ts`: "should decrypt test payload".
  #[test]
  fn decrypt_payload_test_text() {
    let bytes = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let data = packet.as_data().unwrap();
    let app_s_key = AppSKey::new(hex_to_arr_16("ec925802ae430ca77fd3dd73cb2cc588"));
    let nwk_s_key = NwkSKey::new([0u8; 16]);
    let plain = data.decrypt_payload(&app_s_key, &nwk_s_key, 0).unwrap();
    assert_eq!(plain, b"test");
  }

  /// Round-trip: encrypt -> decrypt produces original.
  #[test]
  fn encrypt_then_decrypt_round_trip() {
    let bytes = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let data = packet.as_data().unwrap();
    let app_s_key = AppSKey::new(hex_to_arr_16("ec925802ae430ca77fd3dd73cb2cc588"));
    let nwk_s_key = NwkSKey::new([0u8; 16]);
    let plain = b"hello world!";
    let ct = data.encrypt_payload(plain, &app_s_key, &nwk_s_key, 0).unwrap();
    assert_ne!(ct, plain);
    let mut clone = data.clone();
    clone.frm_payload = Some(ct);
    let decrypted = clone.decrypt_payload(&app_s_key, &nwk_s_key, 0).unwrap();
    assert_eq!(decrypted, plain);
  }

  /// Vector from <https://pkg.go.dev/github.com/brocaar/lorawan>, mirrored in
  /// `__tests__/fopts_test.ts`: "should encode packet with Lorawan11
  /// Encrypted Fopts". Downlink with `FPort` > 0 means `aFCntDown` is true.
  #[test]
  fn encrypt_fopts_1_1_vector() {
    use crate::codec::Data;
    use crate::types::{Direction, FCtrl, NwkSEncKey};

    let data = Data {
      direction: Direction::Downlink,
      confirmed: false,
      dev_addr: DevAddr::new([0x01, 0x02, 0x03, 0x04]),
      f_ctrl: FCtrl(0x03),
      f_cnt: [0x00, 0x00],
      f_opts: alloc::vec![0x02, 0x07, 0x01],
      f_port: Some(1),
      frm_payload: Some(alloc::vec![0x01, 0x02, 0x03, 0x04]),
    };
    let nwk_s_enc_key = NwkSEncKey::new([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0]);
    let encrypted = data.encrypt_fopts(&nwk_s_enc_key, 0).unwrap();
    assert_eq!(encrypted, [0x22, 0xac, 0x0a]);

    let mut clone = data;
    clone.f_opts = encrypted;
    let decrypted = clone.decrypt_fopts(&nwk_s_enc_key, 0).unwrap();
    assert_eq!(decrypted, [0x02, 0x07, 0x01]);
  }

  /// Mirror of `__tests__/join_accept_encrypt.ts`: "should create join
  /// accept packet with zero value" (server-side encrypt produces wire form).
  #[test]
  fn join_accept_encrypt_zero_app_key() {
    let app_key = AppKey::new([0u8; 16]);
    let plaintext = hex_to_vec("20000000000000000000000000f86f0a91");
    let encrypted = crate::codec::JoinAccept::encrypt_for_wire(&plaintext, &app_key).unwrap();
    let expected = hex_to_vec("20e3de108795f776b8037610ef7869b5b3");
    assert_eq!(encrypted, expected);
  }

  /// `encrypt_for_wire` and `decrypt_from_wire` are inverses (the on-air
  /// AES-ECB trick).
  #[test]
  fn join_accept_decrypt_round_trip() {
    let app_key = AppKey::new([0u8; 16]);
    let plaintext = hex_to_vec("20000000000000000000000000f86f0a91");
    let encrypted = crate::codec::JoinAccept::encrypt_for_wire(&plaintext, &app_key).unwrap();
    let decrypted = crate::codec::JoinAccept::decrypt_from_wire(&encrypted, &app_key).unwrap();
    assert_eq!(decrypted, plaintext);
  }
}
