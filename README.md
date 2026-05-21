# lora-packet

LoRaWAN 1.0 / 1.1 packet decoder and encoder for Rust.

[![crates.io](https://img.shields.io/crates/v/lora-packet.svg)](https://crates.io/crates/lora-packet)
[![docs.rs](https://docs.rs/lora-packet/badge.svg)](https://docs.rs/lora-packet)

Parse and build PHYPayload frames, AES-ECB FRMPayload + FOpts crypt, AES-CMAC MIC, and OTAA/JS/WOR key derivation. Works on `std` and `no_std + alloc`.

## Why this crate

- **Strong newtypes for every key and identifier.** `AppSKey`, `NwkSKey`, `DevAddr`, and `FNwkSIntKey` are distinct types. The compiler stops you mixing them up.
- **Constant-time MIC comparison.** Verification uses `subtle::ConstantTimeEq` so timing side-channels do not leak.
- **Keys auto-zeroize on drop.** Every key newtype derives `ZeroizeOnDrop`; their `Debug` impls are redacted.
- **`no_std + alloc` ready.** Switch the `std` feature off and the same API works on embedded targets with a global allocator.
- **No `unsafe`.** `#![deny(unsafe_code)]` is enforced at the crate root.

## Quickstart

```rust
use lora_packet::{LoraPacket, AppSKey, NwkSKey, V1_0MicKeys};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
  let packet = LoraPacket::from_wire(&bytes)?;

  let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
  let app_s_key = AppSKey::from_slice(&hex::decode("ec925802ae430ca77fd3dd73cb2cc588")?)?;

  let keys = V1_0MicKeys { nwk_s_key: Some(&nwk_s_key), ..Default::default() };
  if packet.verify_mic_v1_0(&keys)? {
    if let Some(data) = packet.as_data() {
      let plaintext = data.decrypt_payload(&app_s_key, &nwk_s_key, 0)?;
      println!("payload: {plaintext:?}");
    }
  }
  Ok(())
}
```

## Build a downlink

```rust
use lora_packet::{LoraPacket, Direction, DevAddr, AppSKey, NwkSKey};

fn main() -> Result<(), lora_packet::Error> {
  let app_s_key = AppSKey::new([0u8; 16]);
  let nwk_s_key = NwkSKey::new([0u8; 16]);

  let packet = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
    .f_cnt(2)
    .f_port(1)
    .payload(b"hello")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)?;

  let wire: Vec<u8> = packet.to_wire();
  let _ = wire;
  Ok(())
}
```

## OTAA session keys

```rust
use lora_packet::{SessionKeys10, SessionKeys11, AppKey, NwkKey, NetId, AppNonce, DevNonce, AppEui};

let app_key = AppKey::new([0u8; 16]);
let nwk_key = NwkKey::new([0u8; 16]);
let net_id = NetId::new([0, 0, 0]);
let app_nonce = AppNonce::new([0, 0, 0]);
let dev_nonce = DevNonce::new([0, 0]);
let join_eui = AppEui::new([0u8; 8]);

let keys_10 = SessionKeys10::derive(&app_key, &net_id, &app_nonce, &dev_nonce);
let keys_11 = SessionKeys11::derive(&app_key, &nwk_key, &join_eui, &app_nonce, &dev_nonce);
```

## Rejoin Request

```rust
use lora_packet::{LoraPacket, Payload, RejoinRequest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let wire = hex::decode("c0000102030405060708090a0b0c0ddeadbeef")?;
  let packet = LoraPacket::from_wire(&wire)?;

  if let Payload::RejoinRequest(rj) = &packet.payload {
    match rj {
      RejoinRequest::Type0 { net_id, dev_eui, rj_count_0 } => { let _ = (net_id, dev_eui, rj_count_0); }
      RejoinRequest::Type1 { join_eui, dev_eui, rj_count_1 } => { let _ = (join_eui, dev_eui, rj_count_1); }
      RejoinRequest::Type2 { net_id, dev_eui, rj_count_0 } => { let _ = (net_id, dev_eui, rj_count_0); }
    }
  }
  Ok(())
}
```

## Features

| Feature      | Default | Effect                                                                |
| ------------ | ------- | --------------------------------------------------------------------- |
| `std`        | yes     | Enables `std::error::Error` impls via `thiserror/std`                 |
| `serde`      | no      | Derives `Serialize` and `Deserialize` on packet types and keys        |
| `hex_base64` | no      | Adds `from_hex` and `from_base64` constructors on keys, ids, packets  |

Embedded users: `cargo add lora-packet --no-default-features`.

## LoRaWAN reference

- [LoRaWAN 1.0.4 Specification (TS001-1.0.4)](https://resources.lora-alliance.org/technical-specifications/ts001-1-0-4-lorawan-l2-1-0-4-specification)
- [LoRaWAN 1.1 Specification (TS001-1.1)](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [LoRaWAN Regional Parameters RP002-1.0.4](https://resources.lora-alliance.org/technical-specifications/rp002-1-0-4-regional-parameters)
- [LoRa Alliance Errata: `FCntDwn` Usage in `FOpts` Encryption (CR v2 r1)](https://resources.lora-alliance.org/document/lorawan-1-1-specification-errata)

## License

MIT
