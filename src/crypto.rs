//! AES-ECB primitives, `FRMPayload`/`FOpts` crypt, Join Accept crypt, and
//! session/JS/WOR key derivation.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

use crate::types::{AppKey, AppNonce, AppSKey, DevNonce, NetId, NwkSKey};

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
}
