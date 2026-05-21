//! # lora-packet
//!
//! `LoRaWAN` 1.0 and 1.1 packet codec for Rust. Parses and builds `PHYPayload`
//! frames, performs AES-ECB `FRMPayload` and `FOpts` crypt, computes AES-CMAC
//! MICs, and derives OTAA, Join Server, and WOR (relay) keys.
//!
//! - Works on `std` and on `no_std + alloc` targets (one feature flag away).
//! - No `unsafe`; constant-time MIC compares; keys auto-zeroize on drop.
//! - Strong newtypes for every key and identifier so a `NwkSKey` cannot be
//!   confused with an `AppSKey` or with raw `[u8; 16]` bytes at compile time.
//!
//! See the [`README`](https://github.com/tago-io/lora-packet-rs) for a wider
//! introduction and the per-module pages for full API references.
//!
//! ## Quick start: parse, verify, decrypt
//!
//! ```
//! use lora_packet::{LoraPacket, AppSKey, NwkSKey, V1_0MicKeys};
//!
//! let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
//! let packet = LoraPacket::from_wire(&bytes)?;
//!
//! let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
//! let app_s_key = AppSKey::from_slice(&hex::decode("ec925802ae430ca77fd3dd73cb2cc588")?)?;
//!
//! let keys = V1_0MicKeys { nwk_s_key: Some(&nwk_s_key), ..Default::default() };
//! assert!(packet.verify_mic_v1_0(&keys)?);
//!
//! let data = packet.as_data().expect("data frame");
//! let plaintext = data.decrypt_payload(&app_s_key, &nwk_s_key, 0)?;
//! assert_eq!(&plaintext, b"test");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Building a downlink
//!
//! [`LoraPacket::builder`] composes a packet field by field. Terminal methods
//! (`sign_and_encrypt`, `sign_join_request`, `sign_join_accept`) finalise the
//! MIC and produce wire bytes via [`LoraPacket::to_wire`].
//!
//! ```
//! use lora_packet::{LoraPacket, Direction, DevAddr, AppSKey, NwkSKey};
//!
//! let app_s_key = AppSKey::new([0u8; 16]);
//! let nwk_s_key = NwkSKey::new([0u8; 16]);
//!
//! let packet = LoraPacket::builder()
//!   .data(Direction::Downlink, false)
//!   .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
//!   .f_cnt(2)
//!   .f_port(1)
//!   .payload(b"hello")
//!   .sign_and_encrypt(&app_s_key, &nwk_s_key)?;
//!
//! let wire: Vec<u8> = packet.to_wire();
//! assert!(!wire.is_empty());
//! # Ok::<(), lora_packet::Error>(())
//! ```
//!
//! ## OTAA session key derivation
//!
//! ```
//! use lora_packet::{SessionKeys10, SessionKeys11, AppKey, NwkKey, NetId, AppNonce, DevNonce, AppEui};
//!
//! let app_key = AppKey::new([0u8; 16]);
//! let nwk_key = NwkKey::new([0u8; 16]);
//!
//! let v10 = SessionKeys10::derive(
//!   &app_key,
//!   &NetId::new([0, 0, 0]),
//!   &AppNonce::new([0, 0, 0]),
//!   &DevNonce::new([0, 0]),
//! );
//!
//! let v11 = SessionKeys11::derive(
//!   &app_key,
//!   &nwk_key,
//!   &AppEui::new([0u8; 8]),
//!   &AppNonce::new([0, 0, 0]),
//!   &DevNonce::new([0, 0]),
//! );
//!
//! let _ = (v10.app_s_key, v11.s_nwk_s_int_key);
//! ```
//!
//! ## API surface at a glance
//!
//! | Entry point                                       | Purpose                                            |
//! | ------------------------------------------------- | -------------------------------------------------- |
//! | [`LoraPacket::from_wire`]                         | Parse `PHYPayload` bytes                           |
//! | [`LoraPacket::builder`]                           | Compose a packet field by field                    |
//! | [`LoraPacket::verify_mic_v1_0`] / `_v1_1`         | Constant-time MIC verification                     |
//! | [`LoraPacket::calculate_mic_v1_0`] / `_v1_1`      | MIC computation                                    |
//! | [`LoraPacket::recalculate_mic_v1_0`] / `_v1_1`    | Overwrite MIC after mutations                      |
//! | [`Data::decrypt_payload`] / `encrypt_payload`     | `FRMPayload` AES-CTR-style crypt                   |
//! | [`Data::decrypt_fopts`] / `encrypt_fopts`         | 1.1 `FOpts` MAC-command crypt                      |
//! | [`JoinAccept::decrypt_from_wire`] / `encrypt_for_wire` | Join Accept on-air decrypt/encrypt            |
//! | [`SessionKeys10::derive`] / [`SessionKeys11::derive`]  | OTAA session-key derivation                   |
//! | [`JoinServerKeys::derive`]                        | 1.1 JS key derivation                              |
//! | [`WorKeys::root`] / [`WorKeys::session`]          | Relay (WOR) key derivation                         |
//! | [`aes_ecb_encrypt`]                               | Low-level AES-128 ECB primitive                    |
//!
//! ## The five message variants
//!
//! Every [`LoraPacket`] holds exactly one [`Payload`] variant. Match on it to
//! pull out type-specific fields:
//!
//! ```
//! use lora_packet::{LoraPacket, Payload, RejoinRequest};
//!
//! let wire = hex::decode("c0000102030405060708090a0b0c0ddeadbeef")?;
//! let packet = LoraPacket::from_wire(&wire)?;
//!
//! match &packet.payload {
//!   Payload::JoinRequest(_) => {}
//!   Payload::JoinAccept(_) => {}
//!   Payload::Data(_) => {}
//!   Payload::RejoinRequest(rj) => match rj {
//!     RejoinRequest::Type0 { .. } | RejoinRequest::Type2 { .. } => {}
//!     RejoinRequest::Type1 { .. } => {}
//!   },
//!   Payload::Proprietary(_) => {}
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Cargo features
//!
//! | Feature      | Default | Effect                                                                |
//! | ------------ | ------- | --------------------------------------------------------------------- |
//! | `std`        | yes     | Enables `std::error::Error` impls via `thiserror/std`                 |
//! | `serde`      | no      | Derives `Serialize` / `Deserialize` on packet types and keys          |
//! | `hex_base64` | no      | Adds `from_hex` / `from_base64` constructors on keys, ids, packets    |
//!
//! ## `no_std` support
//!
//! ```text
//! cargo add lora-packet --no-default-features
//! ```
//!
//! The crate uses `alloc::vec::Vec` and `alloc::string::String`; targets must
//! supply a global allocator. Every public API works identically with or
//! without the `std` feature; `std` only switches `Error: std::error::Error`
//! on or off.
//!
//! ## Endianness contract
//!
//! - **Wire format** is little-endian (per the `LoRaWAN` MAC spec).
//! - **Struct fields** display in network/big-endian order so that printing a
//!   `DevAddr([0x49, 0xbe, 0x7d, 0xf1])` matches the value used to identify a
//!   device on a console.
//!
//! [`LoraPacket::from_wire`] and [`LoraPacket::to_wire`] handle the byte
//! reversal; you only see big-endian fields on the struct.
//!
//! ## Reference specifications
//!
//! - `LoRaWAN` 1.0.4 Specification (`TS001-1.0.4`).
//! - `LoRaWAN` 1.1 Specification (`TS001-1.1`).
//! - `LoRaWAN` Regional Parameters `RP002-1.0.4`.
//! - `LoRa` Alliance Errata "`FCntDwn` Usage in `FOpts` Encryption"
//!   (`CR v2 r1`).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

extern crate alloc;

pub mod codec;
pub mod crypto;
pub mod error;
pub mod mic;
pub mod types;
mod util;

pub use codec::{Data, JoinAccept, JoinRequest, LoraPacket, LoraPacketBuilder, Payload, RejoinRequest};
pub use crypto::{JoinServerKeys, SessionKeys10, SessionKeys11, WorKeys, WorSessionKeys, aes_ecb_encrypt};
pub use error::{Error, Result};
pub use mic::{V1_0MicKeys, V1_1MicKeys};
pub use types::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, FNwkSIntKey, JSEncKey,
  JSIntKey, JoinEui, JoinNonce, LorawanVersion, MType, Mhdr, NetId, NwkKey, NwkSEncKey, NwkSKey, RootWorSKey,
  SNwkSIntKey, WorSEncKey, WorSIntKey,
};
