//! Internal byte helpers shared across modules.
//!
//! `LoRaWAN` sends multi-byte identifiers on the wire in little-endian, but the
//! `LoraPacket` struct stores them in big-endian display order. These helpers
//! convert between the two.

// `pub(crate)` is intentional: these helpers must be reachable from sibling
// modules (codec/crypto/mic) added in later tasks, even though the parent
// module is private. Suppress the redundancy lint that fires before those
// callers exist.
#![allow(clippy::redundant_pub_crate, dead_code)]

use alloc::vec::Vec;

/// Reverse the bytes of `buf` in place.
pub(crate) const fn reverse_in_place(buf: &mut [u8]) {
  buf.reverse();
}

/// Return a new `Vec` containing the bytes of `buf` in reverse order.
pub(crate) fn reversed(buf: &[u8]) -> Vec<u8> {
  let mut out = buf.to_vec();
  out.reverse();
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reverse_in_place_swaps_bytes() {
    let mut b = [1u8, 2, 3, 4];
    reverse_in_place(&mut b);
    assert_eq!(b, [4, 3, 2, 1]);
  }

  #[test]
  fn reversed_returns_new_vec() {
    let src = [0xDE, 0xAD, 0xBE, 0xEF];
    let out = reversed(&src);
    assert_eq!(out, [0xEF, 0xBE, 0xAD, 0xDE]);
    assert_eq!(src, [0xDE, 0xAD, 0xBE, 0xEF]);
  }

  #[test]
  fn reverse_empty() {
    let mut b: [u8; 0] = [];
    reverse_in_place(&mut b);
    assert_eq!(b, []);
    assert_eq!(reversed(&b), Vec::<u8>::new());
  }
}
