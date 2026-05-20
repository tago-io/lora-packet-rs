//! AES-ECB primitives, `FRMPayload`/`FOpts` crypt, Join Accept crypt, and
//! session/JS/WOR key derivation.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

use crate::types::{
  AppEui, AppKey, AppNonce, AppSKey, DevEui, DevNonce, FNwkSIntKey, JSEncKey, JSIntKey, NetId, NwkKey, NwkSEncKey,
  NwkSKey, SNwkSIntKey,
};

/// Encrypt one 16-byte block under AES-128 ECB. The low-level primitive.
pub fn aes_ecb_encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
  let cipher = Aes128::new(&Array::from(*key));
  let mut buf = Array::from(*block);
  cipher.encrypt_block(&mut buf);
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
}
