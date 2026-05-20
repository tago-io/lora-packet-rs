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
