//! AES-ECB primitives, `FRMPayload`/`FOpts` crypt, Join Accept crypt, and
//! session/JS/WOR key derivation.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

/// Encrypt one 16-byte block under AES-128 ECB. The low-level primitive.
pub fn aes_ecb_encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
  let cipher = Aes128::new(&Array::from(*key));
  let mut buf = Array::from(*block);
  cipher.encrypt_block(&mut buf);
  buf.into()
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
}
