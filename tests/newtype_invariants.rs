//! Invariant tests for the strong-typed newtype layer.
//!
//! Verifies the public API surface of every key and identifier newtype:
//! - `::new([bytes])` from exact-size array.
//! - `::from_slice(&[bytes])` succeeds for correct length, errors otherwise.
//! - `::as_bytes()` round-trips the original bytes.
//! - `Debug` is redacted for keys, transparent for identifiers.
//! - `Clone`, `PartialEq`, `Eq`, `Hash` work as expected.
//! - Keys: `Zeroize::zeroize` wipes the bytes, and `ZeroizeOnDrop` is derived.

use std::collections::HashSet;

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Error, FNwkSIntKey, JSEncKey, JSIntKey, NetId, NwkKey,
  NwkSEncKey, NwkSKey, RootWorSKey, SNwkSIntKey, WorSEncKey, WorSIntKey,
};

// Compile-time witness that a type implements `ZeroizeOnDrop`.
fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

// Compile-time witness that a type implements `Zeroize`.
fn assert_zeroize<T: zeroize::Zeroize>() {}

// ---------------------------------------------------------------------------
// Key newtype tests (12 types × ~6 tests each).
// ---------------------------------------------------------------------------

macro_rules! key_invariants {
  ($mod_name:ident, $ty:ident) => {
    mod $mod_name {
      use super::*;

      const SAMPLE: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      ];

      #[test]
      fn new_from_array() {
        let k = $ty::new(SAMPLE);
        assert_eq!(k.as_bytes(), &SAMPLE);
      }

      #[test]
      fn from_slice_ok() {
        let k = $ty::from_slice(&SAMPLE).expect("16-byte slice must succeed");
        assert_eq!(k.as_bytes(), &SAMPLE);
      }

      #[test]
      fn from_slice_too_short() {
        let err = $ty::from_slice(&[0u8; 15]).expect_err("15 bytes must fail");
        match err {
          Error::InvalidKeyLength { expected, got } => {
            assert_eq!(expected, 16);
            assert_eq!(got, 15);
          }
          other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
      }

      #[test]
      fn from_slice_too_long() {
        let err = $ty::from_slice(&[0u8; 17]).expect_err("17 bytes must fail");
        match err {
          Error::InvalidKeyLength { expected, got } => {
            assert_eq!(expected, 16);
            assert_eq!(got, 17);
          }
          other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
      }

      #[test]
      fn from_slice_empty() {
        let err = $ty::from_slice(&[]).expect_err("empty slice must fail");
        match err {
          Error::InvalidKeyLength { expected, got } => {
            assert_eq!(expected, 16);
            assert_eq!(got, 0);
          }
          other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
      }

      #[test]
      fn debug_is_redacted() {
        let k = $ty::new([0xAB; 16]);
        let s = format!("{k:?}");
        let expected = concat!(stringify!($ty), "(***)");
        assert_eq!(s, expected);
        assert!(!s.contains("ab"), "debug output must not leak key bytes");
        assert!(!s.contains("AB"), "debug output must not leak key bytes");
      }

      #[test]
      fn clone_preserves_bytes() {
        let a = $ty::new(SAMPLE);
        let b = a.clone();
        assert_eq!(a.as_bytes(), b.as_bytes());
      }

      #[test]
      fn partial_eq_equal() {
        let a = $ty::new(SAMPLE);
        let b = $ty::new(SAMPLE);
        assert_eq!(a, b);
      }

      #[test]
      fn partial_eq_not_equal() {
        let a = $ty::new(SAMPLE);
        let mut diff = SAMPLE;
        diff[0] = diff[0].wrapping_add(1);
        let b = $ty::new(diff);
        assert_ne!(a, b);
      }

      // PartialEq + Eq are both derived; this verifies Eq is in scope.
      #[test]
      fn eq_is_reflexive() {
        let a = $ty::new(SAMPLE);
        fn requires_eq<T: Eq>(_: &T) {}
        requires_eq(&a);
        assert_eq!(a, a);
      }

      #[test]
      fn hash_works_in_hashset() {
        let mut set = HashSet::new();
        set.insert($ty::new(SAMPLE));
        set.insert($ty::new(SAMPLE));
        assert_eq!(set.len(), 1, "equal keys must hash to the same slot");

        let mut diff = SAMPLE;
        diff[15] = diff[15].wrapping_add(1);
        set.insert($ty::new(diff));
        assert_eq!(set.len(), 2);
      }

      #[test]
      fn zeroize_wipes_bytes() {
        use zeroize::Zeroize;
        let mut k = $ty::new([0xFF; 16]);
        k.zeroize();
        assert_eq!(k.as_bytes(), &[0u8; 16]);
      }

      #[test]
      fn implements_zeroize_traits() {
        // Compile-time witnesses: the key type must derive both Zeroize and
        // ZeroizeOnDrop. ZeroizeOnDrop is what gives the drop-time wipe
        // guarantee documented on the module.
        assert_zeroize::<$ty>();
        assert_zeroize_on_drop::<$ty>();
      }
    }
  };
}

key_invariants!(app_key, AppKey);
key_invariants!(nwk_key, NwkKey);
key_invariants!(app_s_key, AppSKey);
key_invariants!(nwk_s_key, NwkSKey);
key_invariants!(f_nwk_s_int_key, FNwkSIntKey);
key_invariants!(s_nwk_s_int_key, SNwkSIntKey);
key_invariants!(nwk_s_enc_key, NwkSEncKey);
key_invariants!(js_int_key, JSIntKey);
key_invariants!(js_enc_key, JSEncKey);
key_invariants!(root_wor_s_key, RootWorSKey);
key_invariants!(wor_s_int_key, WorSIntKey);
key_invariants!(wor_s_enc_key, WorSEncKey);

// ---------------------------------------------------------------------------
// Identifier newtype tests (6 types × ~6 tests each).
// ---------------------------------------------------------------------------

macro_rules! id_invariants {
  ($mod_name:ident, $ty:ident, $len:expr) => {
    mod $mod_name {
      use super::*;

      const LEN: usize = $len;
      const SAMPLE: [u8; LEN] = {
        let mut arr = [0u8; LEN];
        let mut i = 0;
        while i < LEN {
          arr[i] = (i as u8).wrapping_add(0x10);
          i += 1;
        }
        arr
      };

      #[test]
      fn new_from_array() {
        let id = $ty::new(SAMPLE);
        assert_eq!(id.as_bytes(), &SAMPLE);
      }

      #[test]
      fn from_slice_ok() {
        let id = $ty::from_slice(&SAMPLE).expect("exact-length slice must succeed");
        assert_eq!(id.as_bytes(), &SAMPLE);
      }

      #[test]
      fn from_slice_too_short() {
        let err = $ty::from_slice(&[0u8; LEN - 1][..]).expect_err("short slice must fail");
        match err {
          Error::InvalidIdentifierLength { expected, got } => {
            assert_eq!(expected, LEN);
            assert_eq!(got, LEN - 1);
          }
          other => panic!("expected InvalidIdentifierLength, got {other:?}"),
        }
      }

      #[test]
      fn from_slice_too_long() {
        let err = $ty::from_slice(&[0u8; LEN + 1][..]).expect_err("long slice must fail");
        match err {
          Error::InvalidIdentifierLength { expected, got } => {
            assert_eq!(expected, LEN);
            assert_eq!(got, LEN + 1);
          }
          other => panic!("expected InvalidIdentifierLength, got {other:?}"),
        }
      }

      #[test]
      fn debug_shows_bytes() {
        // Identifier Debug must NOT redact: it shows the byte array as
        // derived by the standard `#[derive(Debug)]`.
        let id = $ty::new(SAMPLE);
        let s = format!("{id:?}");
        assert!(s.starts_with(stringify!($ty)), "debug should start with type name");
        // The derived Debug for `Foo(pub [u8; N])` prints each byte as a
        // decimal integer. Verify the first byte is present.
        let first_byte_str = format!("{}", SAMPLE[0]);
        assert!(
          s.contains(&first_byte_str),
          "debug `{s}` should expose identifier bytes (looking for `{first_byte_str}`)"
        );
      }

      #[test]
      fn clone_preserves_bytes() {
        let a = $ty::new(SAMPLE);
        let b = a.clone();
        assert_eq!(a.as_bytes(), b.as_bytes());
      }

      #[test]
      fn partial_eq_equal() {
        let a = $ty::new(SAMPLE);
        let b = $ty::new(SAMPLE);
        assert_eq!(a, b);
      }

      #[test]
      fn partial_eq_not_equal() {
        let a = $ty::new(SAMPLE);
        let mut diff = SAMPLE;
        diff[0] = diff[0].wrapping_add(1);
        let b = $ty::new(diff);
        assert_ne!(a, b);
      }

      #[test]
      fn eq_is_reflexive() {
        let a = $ty::new(SAMPLE);
        fn requires_eq<T: Eq>(_: &T) {}
        requires_eq(&a);
        assert_eq!(a, a);
      }

      #[test]
      fn hash_works_in_hashset() {
        let mut set = HashSet::new();
        set.insert($ty::new(SAMPLE));
        set.insert($ty::new(SAMPLE));
        assert_eq!(set.len(), 1, "equal identifiers must hash to the same slot");

        let mut diff = SAMPLE;
        diff[LEN - 1] = diff[LEN - 1].wrapping_add(1);
        set.insert($ty::new(diff));
        assert_eq!(set.len(), 2);
      }
    }
  };
}

id_invariants!(dev_addr, DevAddr, 4);
id_invariants!(dev_eui, DevEui, 8);
id_invariants!(app_eui, AppEui, 8);
id_invariants!(net_id, NetId, 3);
id_invariants!(dev_nonce, DevNonce, 2);
id_invariants!(app_nonce, AppNonce, 3);
