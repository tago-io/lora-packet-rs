# Migration map: lora-packet (TS) to lora-packet (Rust)

This document maps every public function in `lora-packet` (npm) to its Rust equivalent in this crate. It exists to help anyone porting code from the TypeScript reference implementation.

## At a glance

| TS                              | Rust                                                            |
| ------------------------------- | --------------------------------------------------------------- |
| `fromWire(buffer)`              | `LoraPacket::from_wire(&bytes)`                                 |
| `fromFields(fields, ...)`       | `LoraPacket::builder()...`                                      |
| `decrypt(payload, ...)`         | `data.decrypt_payload(&app_s_key, &nwk_s_key, f_cnt_msb)`       |
| `decryptJoin(payload, AppKey)`  | `JoinAccept::decrypt_from_wire(&bytes, &app_key)`               |
| `decryptJoinAccept(...)`        | `JoinAccept::decrypt_from_wire(&bytes, &app_key)`               |
| `encrypt(buffer, key)`          | `aes_ecb_encrypt(&block, &key)`                                 |
| `generateSessionKeys(...)`      | `SessionKeys10::derive(...)`                                    |
| `generateSessionKeys10(...)`    | `SessionKeys10::derive(...)`                                    |
| `generateSessionKeys11(...)`    | `SessionKeys11::derive(...)`                                    |
| `generateJSKeys(...)`           | `JoinServerKeys::derive(...)`                                   |
| `generateWORKey(NwkSKey)`       | `WorKeys::root(&nwk_s_key)`                                     |
| `generateWORSessionKeys(...)`   | `WorKeys::session(&root, &dev_addr)`                            |
| `calculateMIC(...)`             | `LoraPacket::calculate_mic_v1_0(...)` / `_v1_1(...)`            |
| `verifyMIC(...)`                | `LoraPacket::verify_mic_v1_0(...)` / `_v1_1(...)`               |
| `recalculateMIC(...)`           | `LoraPacket::recalculate_mic_v1_0(...)` / `_v1_1(...)`          |

## Function-by-function

### fromWire

**TypeScript:**

```ts
import loraPacket from "lora-packet";

const packet = loraPacket.fromWire(
  Buffer.from("40f17dbe4900020001954378762b11ff0d", "hex"),
);
```

**Rust:**

```rust
use lora_packet::LoraPacket;

let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
let packet = LoraPacket::from_wire(&bytes)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### fromFields

**TypeScript:**

```ts
const packet = loraPacket.fromFields(
  {
    MType: "Unconfirmed Data Up",
    DevAddr: Buffer.from("49be7df1", "hex"),
    FCnt: Buffer.from("0002", "hex"),
    FPort: Buffer.from("01", "hex"),
    payload: Buffer.from("test"),
  },
  appSKey,
  nwkSKey,
);
```

**Rust:**

```rust
use lora_packet::{LoraPacket, Direction, DevAddr, AppSKey, NwkSKey};

let app_s_key = AppSKey::from_slice(&hex::decode("ec925802ae430ca77fd3dd73cb2cc588")?)?;
let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;

let packet = LoraPacket::builder()
  .data(Direction::Uplink, false)
  .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
  .f_cnt(2)
  .f_port(1)
  .payload(b"test")
  .sign_and_encrypt(&app_s_key, &nwk_s_key)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### decrypt

**TypeScript:**

```ts
const plaintext = loraPacket.decrypt(packet, appSKey, nwkSKey);
```

**Rust:**

```rust
use lora_packet::{LoraPacket, AppSKey, NwkSKey};

# let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
# let packet = LoraPacket::from_wire(&bytes)?;
# let app_s_key = AppSKey::from_slice(&hex::decode("ec925802ae430ca77fd3dd73cb2cc588")?)?;
# let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
let plaintext = packet
  .as_data()
  .unwrap()
  .decrypt_payload(&app_s_key, &nwk_s_key, 0)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### decryptJoin / decryptJoinAccept

**TypeScript:**

```ts
const decrypted = loraPacket.decryptJoinAccept(packet, appKey);
```

**Rust:**

```rust
use lora_packet::{JoinAccept, AppKey};

# let app_key = AppKey::new([0u8; 16]);
# let encrypted = hex::decode("20e3de108795f776b8037610ef7869b5b3")?;
let join_accept = JoinAccept::decrypt_from_wire(&encrypted, &app_key)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### encrypt

**TypeScript:**

```ts
const ciphertext = loraPacket.encrypt(buffer, key);
```

**Rust:**

```rust
use lora_packet::aes_ecb_encrypt;

let block = [0u8; 16];
let key = [0u8; 16];
let ciphertext = aes_ecb_encrypt(&block, &key);
```

### generateSessionKeys / generateSessionKeys10

**TypeScript:**

```ts
const { AppSKey, NwkSKey } = loraPacket.generateSessionKeys(
  appKey,
  netId,
  appNonce,
  devNonce,
);
```

**Rust:**

```rust
use lora_packet::{SessionKeys10, AppKey, NetId, AppNonce, DevNonce};

let keys = SessionKeys10::derive(
  &AppKey::new([0u8; 16]),
  &NetId::new([0, 0, 0]),
  &AppNonce::new([0, 0, 0]),
  &DevNonce::new([0, 0]),
);
let app_s_key = keys.app_s_key;
let nwk_s_key = keys.nwk_s_key;
```

### generateSessionKeys11

**TypeScript:**

```ts
const keys = loraPacket.generateSessionKeys11(
  appKey,
  nwkKey,
  joinEui,
  appNonce,
  devNonce,
);
```

**Rust:**

```rust
use lora_packet::{SessionKeys11, AppKey, NwkKey, AppEui, AppNonce, DevNonce};

let keys = SessionKeys11::derive(
  &AppKey::new([0u8; 16]),
  &NwkKey::new([0u8; 16]),
  &AppEui::new([0u8; 8]),
  &AppNonce::new([0, 0, 0]),
  &DevNonce::new([0, 0]),
);
```

### generateJSKeys

**TypeScript:**

```ts
const { JSIntKey, JSEncKey } = loraPacket.generateJSKeys(nwkKey, devEui);
```

**Rust:**

```rust
use lora_packet::{JoinServerKeys, NwkKey, DevEui};

let js = JoinServerKeys::derive(&NwkKey::new([0u8; 16]), &DevEui::new([0u8; 8]));
let int_key = js.js_int_key;
let enc_key = js.js_enc_key;
```

### generateWORKey

**TypeScript:**

```ts
const rootWorKey = loraPacket.generateWORKey(nwkSKey);
```

**Rust:**

```rust
use lora_packet::{WorKeys, NwkSKey};

let root = WorKeys::root(&NwkSKey::new([0u8; 16]));
```

### generateWORSessionKeys

**TypeScript:**

```ts
const { WorSIntKey, WorSEncKey } = loraPacket.generateWORSessionKeys(
  rootWorKey,
  devAddr,
);
```

**Rust:**

```rust
use lora_packet::{WorKeys, RootWorSKey, DevAddr};

# let root = RootWorSKey::new([0u8; 16]);
let session = WorKeys::session(&root, &DevAddr::new([0, 0, 0, 0]));
let int_key = session.wor_s_int_key;
let enc_key = session.wor_s_enc_key;
```

### calculateMIC

**TypeScript:**

```ts
const mic = loraPacket.calculateMIC(packet, nwkSKey);
```

**Rust:**

```rust
use lora_packet::{LoraPacket, V1_0MicKeys, NwkSKey};

# let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
# let packet = LoraPacket::from_wire(&bytes)?;
let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
let keys = V1_0MicKeys { nwk_s_key: Some(&nwk_s_key), ..Default::default() };
let mic = packet.calculate_mic_v1_0(&keys)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### verifyMIC

**TypeScript:**

```ts
const ok = loraPacket.verifyMIC(packet, nwkSKey);
```

**Rust:**

```rust
use lora_packet::{LoraPacket, V1_0MicKeys, NwkSKey};

# let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
# let packet = LoraPacket::from_wire(&bytes)?;
# let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
let keys = V1_0MicKeys { nwk_s_key: Some(&nwk_s_key), ..Default::default() };
let ok = packet.verify_mic_v1_0(&keys)?;
assert!(ok);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### recalculateMIC

**TypeScript:**

```ts
loraPacket.recalculateMIC(packet, nwkSKey);
const wire = packet.getPHYPayload();
```

**Rust:**

```rust
use lora_packet::{LoraPacket, V1_0MicKeys, NwkSKey};

# let bytes = hex::decode("40f17dbe490002000195437876eeeeeeee")?;
# let mut packet = LoraPacket::from_wire(&bytes)?;
# let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
let keys = V1_0MicKeys { nwk_s_key: Some(&nwk_s_key), ..Default::default() };
packet.recalculate_mic_v1_0(&keys)?;
let wire = packet.to_wire();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Accessor map

| TS                                  | Rust                                |
| ----------------------------------- | ----------------------------------- |
| `packet.getMType()`                 | `packet.m_type()`                   |
| `packet.getDir()`                   | `data.direction`                    |
| `packet.getFCnt()`                  | `data.f_cnt()`                      |
| `packet.getFPort()`                 | `data.f_port`                       |
| `packet.isDataMessage()`            | `packet.is_data()`                  |
| `packet.isConfirmed()`              | `packet.is_confirmed()`             |
| `packet.isJoinRequestMessage()`     | `packet.is_join_request()`          |
| `packet.isJoinAcceptMessage()`      | `packet.is_join_accept()`           |
| `packet.isRejoinRequestMessage()`   | `packet.is_rejoin_request()`        |
| `packet.getBuffers()`               | direct struct field access          |
| `packet.getPHYPayload()`            | `packet.to_wire()`                  |
| `packet.decryptFOpts(...)`          | `data.decrypt_fopts(...)`           |
| `packet.encryptFOpts(...)`          | `data.encrypt_fopts(...)`           |

## Notes

- The TS API works on opaque `Buffer` blobs; the Rust API uses typed newtypes
  (`AppKey`, `DevAddr`, etc.) that prevent mixing up byte-order or key roles at
  compile time.
- All `from_wire`/`from_slice`/MIC functions return `Result<T, Error>`. There
  are no exceptions to catch.
- `f_cnt_msb` is the upper 16 bits of the 32-bit frame counter, tracked by the
  caller (the wire only carries the lower 16 bits). Pass `0` when frame
  counters never wrap.
