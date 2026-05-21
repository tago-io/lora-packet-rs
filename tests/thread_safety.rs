//! Thread-safety tests for `lora-packet`.
//!
//! `lora-packet` is a sync library with no internal mutation outside `&mut self`,
//! but downstream consumers run it inside multi-threaded runtimes (tokio
//! multi-thread, rayon, AWS Lambda multi-thread executors). These tests assert
//! that every public type is `Send + Sync` and that parsing, MIC verification,
//! and decryption all run cleanly from multiple OS threads against the same
//! immutable inputs.
//!
//! The `std::thread::spawn` portion only runs with the `std` feature (the
//! default). The static `Send + Sync` assertions compile-check the trait bounds
//! and require no runtime support.
//!
//! Run with: `cargo test --test thread_safety --all-features`.
//!
//! Mirrors the audit list provided in the team task: `LoraPacket`, every key
//! newtype, every identifier newtype, `Error`, `LoraPacketBuilder`, every enum
//! (`MType`, `Direction`, `LorawanVersion`, `Payload`, `RejoinRequest`), and
//! the MIC key bundles `V1_0MicKeys` / `V1_1MicKeys`.

use lora_packet::{
  AppEui, AppKey, AppNonce, AppSKey, Data, DevAddr, DevEui, DevNonce, Direction, DlSettings, Error, FCtrl, FNwkSIntKey,
  JSEncKey, JSIntKey, JoinAccept, JoinEui, JoinNonce, JoinRequest, JoinServerKeys, LoraPacket, LoraPacketBuilder,
  LorawanVersion, MType, Mhdr, NetId, NwkKey, NwkSEncKey, NwkSKey, Payload, RejoinRequest, RootWorSKey, SNwkSIntKey,
  SessionKeys10, SessionKeys11, V1_0MicKeys, V1_1MicKeys, WorKeys, WorSEncKey, WorSIntKey, WorSessionKeys,
};

/// Compile-time assertion that `T: Send + Sync`.
///
/// Calling this function with a turbofish forces the trait resolver to prove
/// the bounds; if a type ever loses `Send` or `Sync` the test file fails to
/// compile, which is the whole point of the audit.
const fn assert_send_sync<T: Send + Sync>() {}

/// Compile-time assertion that `T: Send + Sync + 'static`.
///
/// Useful for types that need to cross thread boundaries via `thread::spawn`
/// (which requires the captured closure to be `'static`).
const fn assert_send_sync_static<T: Send + Sync + 'static>() {}

// ---------------------------------------------------------------------------
// Static `Send + Sync` audit
// ---------------------------------------------------------------------------

#[test]
fn key_newtypes_are_send_sync() {
  // Root keys
  assert_send_sync::<AppKey>();
  assert_send_sync::<NwkKey>();

  // 1.0 session keys
  assert_send_sync::<AppSKey>();
  assert_send_sync::<NwkSKey>();

  // 1.1 session keys
  assert_send_sync::<FNwkSIntKey>();
  assert_send_sync::<SNwkSIntKey>();
  assert_send_sync::<NwkSEncKey>();

  // 1.1 Join Server keys
  assert_send_sync::<JSIntKey>();
  assert_send_sync::<JSEncKey>();

  // Relay / WOR keys
  assert_send_sync::<RootWorSKey>();
  assert_send_sync::<WorSIntKey>();
  assert_send_sync::<WorSEncKey>();
}

#[test]
fn key_newtypes_are_static() {
  // All keys must also be `'static` so they can move into spawned threads.
  assert_send_sync_static::<AppKey>();
  assert_send_sync_static::<NwkKey>();
  assert_send_sync_static::<AppSKey>();
  assert_send_sync_static::<NwkSKey>();
  assert_send_sync_static::<FNwkSIntKey>();
  assert_send_sync_static::<SNwkSIntKey>();
  assert_send_sync_static::<NwkSEncKey>();
  assert_send_sync_static::<JSIntKey>();
  assert_send_sync_static::<JSEncKey>();
  assert_send_sync_static::<RootWorSKey>();
  assert_send_sync_static::<WorSIntKey>();
  assert_send_sync_static::<WorSEncKey>();
}

#[test]
fn identifier_newtypes_are_send_sync() {
  assert_send_sync::<DevAddr>();
  assert_send_sync::<DevEui>();
  assert_send_sync::<AppEui>();
  // `JoinEui` is a type alias for `AppEui`; covered above but asserted
  // explicitly for documentation.
  assert_send_sync::<JoinEui>();
  assert_send_sync::<NetId>();
  assert_send_sync::<DevNonce>();
  assert_send_sync::<AppNonce>();
  // `JoinNonce` aliases `AppNonce`.
  assert_send_sync::<JoinNonce>();
}

#[test]
fn bitfield_wrappers_are_send_sync() {
  // Not on the audit list but trivial to assert; included for completeness
  // since they appear on `Data` and `JoinAccept` fields.
  assert_send_sync::<Mhdr>();
  assert_send_sync::<FCtrl>();
  assert_send_sync::<DlSettings>();
}

#[test]
fn error_is_send_sync() {
  assert_send_sync::<Error>();
  // `'static` lets errors be returned from spawned threads via `JoinHandle`.
  assert_send_sync_static::<Error>();
}

#[test]
fn enums_are_send_sync() {
  assert_send_sync::<MType>();
  assert_send_sync::<Direction>();
  assert_send_sync::<LorawanVersion>();
  assert_send_sync::<Payload>();
  assert_send_sync::<RejoinRequest>();
}

#[test]
fn packet_and_payload_structs_are_send_sync() {
  assert_send_sync::<LoraPacket>();
  assert_send_sync::<LoraPacketBuilder>();
  assert_send_sync::<JoinRequest>();
  assert_send_sync::<JoinAccept>();
  assert_send_sync::<Data>();
}

#[test]
fn derivation_outputs_are_send_sync() {
  assert_send_sync::<SessionKeys10>();
  assert_send_sync::<SessionKeys11>();
  assert_send_sync::<JoinServerKeys>();
  assert_send_sync::<WorSessionKeys>();
  assert_send_sync::<WorKeys>();
}

#[test]
fn mic_key_bundles_are_send_sync() {
  // `V1_0MicKeys<'a>` / `V1_1MicKeys<'a>` borrow their keys. With a `'static`
  // lifetime they must still be `Send + Sync` so they can travel into
  // long-running threads alongside their referents.
  assert_send_sync::<V1_0MicKeys<'static>>();
  assert_send_sync::<V1_1MicKeys<'static>>();

  // Also assert with a shorter (named) lifetime so the bound is verified for
  // arbitrary lifetimes, not just `'static`. Phrased via a marker type so the
  // lifetime is actually used in the signature (silences clippy's
  // `extra_unused_lifetimes`).
  fn check<'a>(_: core::marker::PhantomData<&'a ()>) {
    assert_send_sync::<V1_0MicKeys<'a>>();
    assert_send_sync::<V1_1MicKeys<'a>>();
  }
  check(core::marker::PhantomData);
}

// ---------------------------------------------------------------------------
// Runtime concurrency: parse + verify + decrypt across threads (std only)
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
mod runtime {
  use super::*;
  use std::sync::Arc;
  use std::thread;

  fn key_from_hex(s: &str) -> [u8; 16] {
    let v = hex::decode(s).expect("valid hex");
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&v);
    arr
  }

  /// Spawns N OS threads that each parse, verify, and decrypt the same wire
  /// bytes against the same shared keys. Verifies that no data races occur
  /// and every thread agrees on the result.
  ///
  /// Sharing immutable inputs across threads exercises `Sync`; moving an
  /// `Arc` clone into each closure exercises `Send`. Any failure here would
  /// almost certainly surface as a miscompile or a sanitizer report, but the
  /// test still serves as a regression guard against future changes that
  /// might introduce hidden interior mutability.
  #[test]
  fn parse_verify_decrypt_in_parallel_threads() {
    // Canonical test vector reused from `tests/decrypt.rs` and
    // `tests/mic.rs`: a single uplink data frame whose MIC keys and AppSKey
    // are both known.
    let wire_hex = "40F17DBE4900020001954378762B11FF0D";
    let wire: Arc<Vec<u8>> = Arc::new(hex::decode(wire_hex).expect("valid hex"));

    let nwk_s_key = Arc::new(NwkSKey::new(key_from_hex("44024241ed4ce9a68c6a8bc055233fd3")));
    let app_s_key = Arc::new(AppSKey::new(key_from_hex("ec925802ae430ca77fd3dd73cb2cc588")));

    // 16 threads, each running 64 iterations: enough scheduling churn to
    // shake out any thread-local state hiding inside the AES / CMAC backends.
    let thread_count = 16;
    let iterations = 64;

    let handles: Vec<_> = (0..thread_count)
      .map(|tid| {
        let wire = Arc::clone(&wire);
        let nwk_s_key = Arc::clone(&nwk_s_key);
        let app_s_key = Arc::clone(&app_s_key);
        thread::spawn(move || {
          for i in 0..iterations {
            let packet = LoraPacket::from_wire(&wire).unwrap_or_else(|e| panic!("thread {tid} iter {i}: parse: {e}"));

            let keys = V1_0MicKeys {
              nwk_s_key: Some(&nwk_s_key),
              ..Default::default()
            };
            let ok = packet
              .verify_mic_v1_0(&keys)
              .unwrap_or_else(|e| panic!("thread {tid} iter {i}: mic: {e}"));
            assert!(ok, "thread {tid} iter {i}: MIC verification failed");

            let data = packet.as_data().expect("data frame");
            let plaintext = data
              .decrypt_payload(&app_s_key, &nwk_s_key, 0)
              .unwrap_or_else(|e| panic!("thread {tid} iter {i}: decrypt: {e}"));
            assert_eq!(plaintext, b"test", "thread {tid} iter {i}: wrong plaintext");
          }
        })
      })
      .collect();

    for h in handles {
      h.join().expect("worker thread panicked");
    }
  }

  /// Builds a fresh packet in each thread to exercise the encrypt + MIC
  /// path under contention. Each thread uses a distinct `FCnt` so the
  /// outputs differ, ruling out any accidental shared-state caching.
  #[test]
  fn build_and_encrypt_in_parallel_threads() {
    let app_s_key = Arc::new(AppSKey::new([0x11; 16]));
    let nwk_s_key = Arc::new(NwkSKey::new([0x22; 16]));
    let dev_addr = DevAddr::new([0xa1, 0xb2, 0xc3, 0xd4]);

    let handles: Vec<_> = (0..8u16)
      .map(|tid| {
        let app_s_key = Arc::clone(&app_s_key);
        let nwk_s_key = Arc::clone(&nwk_s_key);
        thread::spawn(move || {
          let f_cnt: u16 = tid * 1_000 + 1;
          let payload = format!("hello-{tid}");
          let built = LoraPacket::builder()
            .data(Direction::Uplink, false)
            .dev_addr(dev_addr)
            .f_ctrl(FCtrl(0))
            .f_cnt(f_cnt)
            .f_port(1)
            .payload(payload.as_bytes())
            .sign_and_encrypt(&app_s_key, &nwk_s_key)
            .expect("build");

          let wire = built.to_wire();

          // Round-trip: re-parse the wire and decrypt with the same keys.
          let reparsed = LoraPacket::from_wire(&wire).expect("re-parse");
          let mic_keys = V1_0MicKeys {
            nwk_s_key: Some(&nwk_s_key),
            ..Default::default()
          };
          assert!(reparsed.verify_mic_v1_0(&mic_keys).expect("verify"));

          let plaintext = reparsed
            .as_data()
            .expect("data frame")
            .decrypt_payload(&app_s_key, &nwk_s_key, 0)
            .expect("decrypt");
          assert_eq!(plaintext, payload.as_bytes());
        })
      })
      .collect();

    for h in handles {
      h.join().expect("worker thread panicked");
    }
  }

  /// Exercises OTAA key derivation in parallel. The inputs are all `Copy`
  /// (or are `Arc`'d when not), and the output `SessionKeys10` /
  /// `SessionKeys11` must travel safely back to the joining thread.
  #[test]
  fn derive_session_keys_in_parallel_threads() {
    let app_key = Arc::new(AppKey::new([0x33; 16]));
    let nwk_key = Arc::new(NwkKey::new([0x44; 16]));
    let net_id = NetId::new([0x12, 0x34, 0x56]);
    let join_eui = AppEui::new([0xAA; 8]);
    let app_nonce = AppNonce::new([0x01, 0x02, 0x03]);
    let dev_nonce = DevNonce::new([0x04, 0x05]);

    let handles: Vec<_> = (0..8)
      .map(|_| {
        let app_key = Arc::clone(&app_key);
        let nwk_key = Arc::clone(&nwk_key);
        thread::spawn(move || {
          let v10 = SessionKeys10::derive(&app_key, &net_id, &app_nonce, &dev_nonce);
          let v11 = SessionKeys11::derive(&app_key, &nwk_key, &join_eui, &app_nonce, &dev_nonce);
          // Returning the derived keys back across the thread boundary
          // forces `Send` on the structs themselves.
          (v10, v11)
        })
      })
      .collect();

    let results: Vec<_> = handles
      .into_iter()
      .map(|h| h.join().expect("worker panicked"))
      .collect();

    // Every thread used the same inputs, so every output must match the
    // first one. Catches any non-determinism caused by hidden shared state.
    let (first_v10, first_v11) = &results[0];
    for (i, (v10, v11)) in results.iter().enumerate().skip(1) {
      assert_eq!(
        v10.app_s_key.as_bytes(),
        first_v10.app_s_key.as_bytes(),
        "thread {i}: v1.0 AppSKey diverged",
      );
      assert_eq!(
        v10.nwk_s_key.as_bytes(),
        first_v10.nwk_s_key.as_bytes(),
        "thread {i}: v1.0 NwkSKey diverged",
      );
      assert_eq!(
        v11.app_s_key.as_bytes(),
        first_v11.app_s_key.as_bytes(),
        "thread {i}: v1.1 AppSKey diverged",
      );
      assert_eq!(
        v11.f_nwk_s_int_key.as_bytes(),
        first_v11.f_nwk_s_int_key.as_bytes(),
        "thread {i}: v1.1 FNwkSIntKey diverged",
      );
      assert_eq!(
        v11.s_nwk_s_int_key.as_bytes(),
        first_v11.s_nwk_s_int_key.as_bytes(),
        "thread {i}: v1.1 SNwkSIntKey diverged",
      );
      assert_eq!(
        v11.nwk_s_enc_key.as_bytes(),
        first_v11.nwk_s_enc_key.as_bytes(),
        "thread {i}: v1.1 NwkSEncKey diverged",
      );
    }
  }
}
