//! `LoRaWAN` 1.0/1.1 packet decoder and encoder.
//!
//! See the crate `README` for a quickstart.

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
pub mod types;
mod util;

pub use codec::{Data, JoinAccept, JoinRequest, LoraPacket, LoraPacketBuilder, Payload, RejoinRequest};
pub use crypto::{JoinServerKeys, SessionKeys10, SessionKeys11, aes_ecb_encrypt};
pub use error::{Error, Result};
pub use types::{
  AppEui, AppKey, AppNonce, AppSKey, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, FNwkSIntKey, JSEncKey,
  JSIntKey, JoinEui, JoinNonce, LorawanVersion, MType, Mhdr, NetId, NwkKey, NwkSEncKey, NwkSKey, RootWorSKey,
  SNwkSIntKey, WorSEncKey, WorSIntKey,
};
