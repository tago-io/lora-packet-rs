# lora-packet-rs design

- Date: 2026-05-20
- Author: Felipe Lima
- Status: Approved, ready for implementation plan

## Goal

Build a LoRaWAN 1.0 / 1.1 packet decoder and encoder as a Rust crate, suitable for TagoIO Lambda middleware and other Rust contexts. Publish to crates.io for public use. Cover the full set of LoRaWAN packet operations: wire-format parse and build, AES-ECB FRMPayload and FOpts crypt, AES-CMAC MIC calculation and verification, and key derivation (session, Join Server, Relay/WOR). Idiomatic Rust API with strong newtypes for keys and identifiers, a tagged-union `Payload` enum for compile-time message-type safety, and a builder for construction.

## Scope

### In scope

- Wire-format parse and build (`from_wire`, builder pattern)
- AES-ECB FRMPayload encrypt and decrypt
- FOpts encrypt and decrypt
- Join Accept encrypt and decrypt
- AES-CMAC MIC calculation and verification for Join Request, Join Accept, Data, and Rejoin Request
- LoRaWAN 1.0 and 1.1 support, including 1.1 dual-MIC and OptNeg
- Session key derivation (1.0 and 1.1)
- Join Server key derivation (1.1)
- WOR / Relay key derivation
- no_std + alloc compatibility behind a default `std` feature
- Optional `serde` support
- Optional hex and base64 input helpers

### Out of scope for v1

- CLI binary. Can be added later as a separate workspace member.
- WASM bindings. Can be added later as a separate crate.
- Async APIs. The library does no I/O.
- LoRaWAN 1.2 support.

## Naming

- **Crate name on crates.io**: `lora-packet`
- **Repository / project directory**: `lora-packet-rs`
- **Internal Rust module path**: `lora_packet`

Rationale: clear, short, descriptive name for a LoRaWAN packet library. Rust API guidelines discourage the `-rs` suffix on published crates; the repository keeps the `-rs` suffix to make the git URL self-describing (same pattern as `tokio-rs/tokio` and `serde-rs/serde`).

Cargo.toml package block:

```toml
[package]
name = "lora-packet"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
description = "LoRaWAN 1.0/1.1 packet decoder and encoder with parse, build, MIC, and key derivation."
repository = "https://github.com/tago-io/lora-packet-rs"
license = "MIT"
keywords = ["lora", "lorawan", "packet", "codec", "iot"]
categories = ["encoding", "embedded", "no-std", "parser-implementations"]
```

## Crate layout

Single library crate at the repository root. No workspace until a second crate is needed.

```
lora-packet-rs/
├── Cargo.toml
├── rust-toolchain.toml
├── rustfmt.toml
├── clippy.toml
├── deny.toml
├── LICENSE                              # MIT, copyright TagoIO
├── AGENTS.md                            # repo conventions
├── CLAUDE.md -> AGENTS.md               # symlink
├── README.md
├── docs/                                # internal scaffolding for agents and implementers
│   ├── migration.md                     # TS-to-Rust function map (agent reference, removable post-v1)
│   ├── ts-source-map.md                 # which TS file each Rust module reflects (agent reference)
│   └── superpowers/
│       └── specs/
│           └── 2026-05-20-lora-packet-rs-design.md
├── src/
│   ├── lib.rs                           # crate root, public re-exports
│   ├── error.rs                         # Error enum, Result alias
│   ├── types.rs                         # newtypes, enums, bitfield wrappers
│   ├── codec.rs                         # LoraPacket, Payload, Builder, from_wire, to_wire
│   ├── crypto.rs                        # AES helpers, session and JS and WOR key derivation
│   ├── mic.rs                           # CMAC MIC, V1_0MicKeys, V1_1MicKeys
│   └── util.rs                          # internal byte helpers (pub(crate))
├── tests/
│   ├── parse.rs                         # mirrors __tests__/parse_test.ts
│   ├── decrypt.rs                       # mirrors __tests__/decrypt_test.ts
│   ├── mic.rs                           # mirrors __tests__/mic_test.ts
│   ├── packet.rs                        # mirrors __tests__/packet_test.ts
│   ├── fopts.rs                         # mirrors __tests__/fopts_test.ts
│   ├── join_accept_encrypt.rs           # mirrors __tests__/join_accept_encrypt.ts
│   ├── key_gen.rs                       # mirrors __tests__/key_gen_test.ts
│   └── no_std_smoke.rs                  # builds the crate with std off
└── .github/
    └── workflows/
        └── ci.yml
```

## Features

```toml
[features]
default = ["std"]
std = ["thiserror/std"]
serde = ["dep:serde"]
hex_base64 = ["dep:hex", "dep:base64"]
```

| Feature | Default | Effect |
|---------|---------|--------|
| `std` | yes | Enables `std::error::Error` impl; otherwise `core::error::Error` is used |
| `serde` | no | `Serialize` and `Deserialize` derives on `LoraPacket`, key types, and enums |
| `hex_base64` | no | `from_hex` and `from_base64` constructors on `LoraPacket` and key types |

Embedded users opt out of std with `cargo add lora-packet --no-default-features`.

## Dependencies

Versions checked against crates.io on 2026-05-20.

```toml
[dependencies]
aes = { version = "0.9", default-features = false }
cmac = { version = "0.8", default-features = false }
cipher = "0.5"
subtle = { version = "2.6", default-features = false }
zeroize = { version = "1.8", default-features = false, features = ["derive"] }
thiserror = { version = "2.0", default-features = false }

hex = { version = "0.4", default-features = false, features = ["alloc"], optional = true }
base64 = { version = "0.22", default-features = false, features = ["alloc"], optional = true }
serde = { version = "1.0", default-features = false, features = ["derive", "alloc"], optional = true }

[dev-dependencies]
hex = { version = "0.4", features = ["alloc"] }
proptest = "1"
serde_json = "1"
```

`aes 0.9` and `cmac 0.8` are the paired April 2026 RustCrypto release; both depend on `cipher 0.5`.

## Modules

### `error`

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid wire format: expected at least {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },

    #[error("invalid MType: {0:#05b}")]
    InvalidMType(u8),

    #[error("invalid major version: {0:#04b}")]
    InvalidMajor(u8),

    #[error("invalid rejoin type: {0}")]
    InvalidRejoinType(u8),

    #[error("FOpts and FPort=0 cannot both carry MAC commands")]
    ConflictingMacCommands,

    #[error("FOpts length {0} exceeds maximum of 15")]
    FOptsTooLong(usize),

    #[error("expected key length {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("expected identifier length {expected}, got {got}")]
    InvalidIdentifierLength { expected: usize, got: usize },

    #[error("MIC mismatch")]
    MicMismatch,

    #[error("missing key for operation: {0}")]
    MissingKey(&'static str),

    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(usize),

    #[cfg(feature = "hex_base64")]
    #[error("invalid hex input")]
    Hex(#[from] hex::FromHexError),

    #[cfg(feature = "hex_base64")]
    #[error("invalid base64 input")]
    Base64(#[from] base64::DecodeError),
}

pub type Result<T> = core::result::Result<T, Error>;
```

No panics in library code. All fallible operations return `Result`. Newtype constructors validate length and return `Err`. Internal `unreachable!()` allowed only when the variant set is exhaustive by construction.

### `types`

Strong newtypes for every key and identifier. Each is `Copy`, fixed-size, with redacted `Debug` for key types.

#### Identifiers

```rust
pub struct DevAddr(pub [u8; 4]);
pub struct DevEui(pub [u8; 8]);
pub struct AppEui(pub [u8; 8]);
pub use AppEui as JoinEui;           // 1.1 spec alias

pub struct NetId(pub [u8; 3]);
pub struct DevNonce(pub [u8; 2]);
pub struct AppNonce(pub [u8; 3]);
pub use AppNonce as JoinNonce;       // 1.1 spec alias
```

#### Keys

```rust
pub struct AppKey([u8; 16]);
pub struct NwkKey([u8; 16]);
pub struct AppSKey([u8; 16]);
pub struct NwkSKey([u8; 16]);
pub struct FNwkSIntKey([u8; 16]);
pub struct SNwkSIntKey([u8; 16]);
pub struct NwkSEncKey([u8; 16]);
pub struct JSIntKey([u8; 16]);
pub struct JSEncKey([u8; 16]);
pub struct RootWorSKey([u8; 16]);
pub struct WorSIntKey([u8; 16]);
pub struct WorSEncKey([u8; 16]);
```

Common surface on every key type:

- `pub fn new(bytes: [u8; 16]) -> Self`
- `pub fn from_slice(s: &[u8]) -> Result<Self>`
- `pub fn as_bytes(&self) -> &[u8; 16]`
- `Debug` redacts: prints `AppSKey(***)` instead of the bytes
- `Drop` wipes memory via `zeroize::Zeroize`
- Optional `serde` impl reads and writes hex strings
- Optional `from_hex(s: &str)` constructor when `hex_base64` is enabled

#### Enums

```rust
pub enum MType {
    JoinRequest = 0b000,
    JoinAccept = 0b001,
    UnconfirmedDataUp = 0b010,
    UnconfirmedDataDown = 0b011,
    ConfirmedDataUp = 0b100,
    ConfirmedDataDown = 0b101,
    RejoinRequest = 0b110,
    Proprietary = 0b111,
}

pub enum Direction { Uplink, Downlink }

pub enum LorawanVersion { V1_0, V1_1 }
```

#### Bitfield wrappers

```rust
pub struct Mhdr(pub u8);
impl Mhdr {
    pub fn m_type(&self) -> MType;
    pub fn major(&self) -> u8;
}

pub struct FCtrl(pub u8);
impl FCtrl {
    pub fn adr(&self) -> bool;
    pub fn adr_ack_req(&self) -> bool;
    pub fn ack(&self) -> bool;
    pub fn f_pending(&self) -> bool;        // downlink only
    pub fn class_b(&self) -> bool;          // uplink only (same bit as f_pending)
    pub fn f_opts_len(&self) -> u8;
}

pub struct DlSettings(pub u8);
impl DlSettings {
    pub fn rx1_dr_offset(&self) -> u8;
    pub fn rx2_data_rate(&self) -> u8;
    pub fn opt_neg(&self) -> bool;          // 1.1 only
}
```

### `codec`

`LoraPacket` as a tagged union over message types. Compile-time guarantee that field access matches the message type.

```rust
pub struct LoraPacket {
    pub phy_payload: Vec<u8>,
    pub mhdr: Mhdr,
    pub mic: [u8; 4],
    pub payload: Payload,
}

pub enum Payload {
    JoinRequest(JoinRequest),
    JoinAccept(JoinAccept),
    Data(Data),
    RejoinRequest(RejoinRequest),
    Proprietary(Vec<u8>),
}

pub struct JoinRequest {
    pub join_eui: AppEui,
    pub dev_eui: DevEui,
    pub dev_nonce: DevNonce,
}

pub struct JoinAccept {
    pub join_nonce: AppNonce,
    pub net_id: NetId,
    pub dev_addr: DevAddr,
    pub dl_settings: DlSettings,
    pub rx_delay: u8,
    pub cf_list: Option<[u8; 16]>,
    pub join_req_type: Option<u8>,
}

pub struct Data {
    pub direction: Direction,
    pub confirmed: bool,
    pub dev_addr: DevAddr,
    pub f_ctrl: FCtrl,
    pub f_cnt: [u8; 2],
    pub f_opts: Vec<u8>,
    pub f_port: Option<u8>,
    pub frm_payload: Option<Vec<u8>>,
}

pub enum RejoinRequest {
    Type0 { net_id: NetId, dev_eui: DevEui, rj_count_0: [u8; 2] },
    Type1 { join_eui: AppEui, dev_eui: DevEui, rj_count_1: [u8; 2] },
    Type2 { net_id: NetId, dev_eui: DevEui, rj_count_0: [u8; 2] },
}
```

#### LoraPacket methods

```rust
impl LoraPacket {
    pub fn from_wire(bytes: &[u8]) -> Result<Self>;
    pub fn to_wire(&self) -> Vec<u8>;

    pub fn m_type(&self) -> MType;
    pub fn is_data(&self) -> bool;
    pub fn is_confirmed(&self) -> bool;
    pub fn is_join_request(&self) -> bool;
    pub fn is_join_accept(&self) -> bool;
    pub fn is_rejoin_request(&self) -> bool;

    pub fn as_data(&self) -> Option<&Data>;
    pub fn as_data_mut(&mut self) -> Option<&mut Data>;
    pub fn as_join_request(&self) -> Option<&JoinRequest>;
    pub fn as_join_accept(&self) -> Option<&JoinAccept>;
    pub fn as_rejoin_request(&self) -> Option<&RejoinRequest>;
}

impl Data {
    pub fn f_cnt(&self) -> u16;
    pub fn f_cnt_32(&self, msb: u16) -> u32;
}
```

#### Builder

```rust
pub struct LoraPacketBuilder { /* private state */ }

impl LoraPacket {
    pub fn builder() -> LoraPacketBuilder;
}

impl LoraPacketBuilder {
    // Message-type entry points
    pub fn data(self, direction: Direction, confirmed: bool) -> Self;
    pub fn join_request(self) -> Self;
    pub fn join_accept(self) -> Self;
    pub fn rejoin_request(self, rejoin_type: u8) -> Self;

    // Data fields
    pub fn dev_addr(self, addr: DevAddr) -> Self;
    pub fn f_ctrl(self, f_ctrl: FCtrl) -> Self;
    pub fn f_cnt(self, fcnt: u16) -> Self;
    pub fn f_opts(self, opts: &[u8]) -> Self;
    pub fn f_port(self, port: u8) -> Self;
    pub fn payload(self, payload: &[u8]) -> Self;

    // Join Request fields
    pub fn join_eui(self, eui: AppEui) -> Self;
    pub fn dev_eui(self, eui: DevEui) -> Self;
    pub fn dev_nonce(self, nonce: DevNonce) -> Self;

    // Join Accept fields
    pub fn join_nonce(self, nonce: AppNonce) -> Self;
    pub fn net_id(self, id: NetId) -> Self;
    pub fn dl_settings(self, dl: DlSettings) -> Self;
    pub fn rx_delay(self, rx: u8) -> Self;
    pub fn cf_list(self, cf: [u8; 16]) -> Self;
    pub fn join_req_type(self, t: u8) -> Self;

    // Terminal methods
    pub fn build_unsigned(self) -> Result<LoraPacket>;
    pub fn sign_and_encrypt(self, app_s_key: &AppSKey, nwk_s_key: &NwkSKey) -> Result<LoraPacket>;
    pub fn sign_join_request(self, app_key: &AppKey) -> Result<LoraPacket>;
    pub fn sign_join_accept(self, app_key: &AppKey) -> Result<LoraPacket>;
}
```

### `crypto`

```rust
impl Data {
    pub fn decrypt_payload(&self, app_s_key: &AppSKey, nwk_s_key: &NwkSKey, f_cnt_msb: u16) -> Result<Vec<u8>>;
    pub fn encrypt_payload(&self, plaintext: &[u8], app_s_key: &AppSKey, nwk_s_key: &NwkSKey, f_cnt_msb: u16) -> Result<Vec<u8>>;
    pub fn decrypt_fopts(&self, nwk_s_enc_key: &NwkSEncKey, f_cnt_msb: u16) -> Result<Vec<u8>>;
    pub fn encrypt_fopts(&self, nwk_s_enc_key: &NwkSEncKey, f_cnt_msb: u16) -> Result<Vec<u8>>;
}

impl JoinAccept {
    pub fn encrypt_for_wire(plaintext: &[u8], app_key: &AppKey) -> Result<Vec<u8>>;
    pub fn decrypt_from_wire(ciphertext: &[u8], app_key: &AppKey) -> Result<Vec<u8>>;
}

pub fn aes_ecb_encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16];

pub struct SessionKeys10 {
    pub app_s_key: AppSKey,
    pub nwk_s_key: NwkSKey,
}
impl SessionKeys10 {
    pub fn derive(app_key: &AppKey, net_id: &NetId, app_nonce: &AppNonce, dev_nonce: &DevNonce) -> Self;
}

pub struct SessionKeys11 {
    pub app_s_key: AppSKey,
    pub f_nwk_s_int_key: FNwkSIntKey,
    pub s_nwk_s_int_key: SNwkSIntKey,
    pub nwk_s_enc_key: NwkSEncKey,
}
impl SessionKeys11 {
    pub fn derive(app_key: &AppKey, nwk_key: &NwkKey, join_eui: &AppEui, app_nonce: &AppNonce, dev_nonce: &DevNonce) -> Self;
}

pub struct JoinServerKeys {
    pub js_int_key: JSIntKey,
    pub js_enc_key: JSEncKey,
}
impl JoinServerKeys {
    pub fn derive(nwk_key: &NwkKey, dev_eui: &DevEui) -> Self;
}

pub struct WorSessionKeys {
    pub wor_s_int_key: WorSIntKey,
    pub wor_s_enc_key: WorSEncKey,
}

pub struct WorKeys;
impl WorKeys {
    pub fn root(nwk_s_key: &NwkSKey) -> RootWorSKey;
    pub fn session(root: &RootWorSKey, dev_addr: &DevAddr) -> WorSessionKeys;
}
```

### `mic`

Per-version entry points with typed key bundles.

```rust
pub struct V1_0MicKeys<'a> {
    pub app_key: Option<&'a AppKey>,
    pub nwk_s_key: Option<&'a NwkSKey>,
    pub f_cnt_msb: u16,
}

pub struct V1_1MicKeys<'a> {
    pub nwk_key: Option<&'a NwkKey>,
    pub js_int_key: Option<&'a JSIntKey>,
    pub f_nwk_s_int_key: Option<&'a FNwkSIntKey>,
    pub s_nwk_s_int_key: Option<&'a SNwkSIntKey>,
    pub join_eui: Option<AppEui>,
    pub dev_nonce: Option<DevNonce>,
    pub join_req_type: Option<u8>,
    pub f_cnt_msb: u16,
    pub conf_fcnt_down_tx_dr_tx_ch: Option<[u8; 4]>,
}

impl LoraPacket {
    pub fn verify_mic_v1_0(&self, keys: &V1_0MicKeys<'_>) -> Result<bool>;
    pub fn verify_mic_v1_1(&self, keys: &V1_1MicKeys<'_>) -> Result<bool>;
    pub fn calculate_mic_v1_0(&self, keys: &V1_0MicKeys<'_>) -> Result<[u8; 4]>;
    pub fn calculate_mic_v1_1(&self, keys: &V1_1MicKeys<'_>) -> Result<[u8; 4]>;
    pub fn recalculate_mic_v1_0(&mut self, keys: &V1_0MicKeys<'_>) -> Result<()>;
    pub fn recalculate_mic_v1_1(&mut self, keys: &V1_1MicKeys<'_>) -> Result<()>;
}
```

MIC comparison uses `subtle::ConstantTimeEq` to avoid timing side channels.

A missing required key returns `Error::MissingKey(&'static str)` with the field name. No silent fallback.

### `util`

`pub(crate)` internal helpers. Not part of public API.

```rust
pub(crate) fn reverse_bytes_in_place(buf: &mut [u8]);
pub(crate) fn reversed(buf: &[u8]) -> Vec<u8>;
```

## Data flow

### Receive path (Lambda decoding an uplink)

```text
wire bytes
    -> LoraPacket::from_wire(&bytes)?
    -> match packet.payload { Payload::Data(d) => ..., ... }
    -> packet.verify_mic_v1_0(&keys)?
    -> data.decrypt_payload(&app_s_key, &nwk_s_key, f_cnt_msb)?
    -> plaintext bytes
```

### Send path (building a downlink)

```text
LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(addr)
    .f_cnt(cnt)
    .f_port(port)
    .payload(b"...")
    .sign_and_encrypt(&app_s_key, &nwk_s_key)?
    .to_wire()
    -> wire bytes
```

### OTAA Join (1.1)

```text
SessionKeys11::derive(&app_key, &nwk_key, &join_eui, &app_nonce, &dev_nonce)
    -> { app_s_key, f_nwk_s_int_key, s_nwk_s_int_key, nwk_s_enc_key }
```

## Testing

### Coverage requirements

The test suite must cover, at minimum:

- Parse: every LoRaWAN message type (Join Request, Join Accept, all four Data variants, Rejoin Request types 0/1/2, Proprietary) with realistic byte vectors.
- Build: every message type via the builder, verified by round-trip equivalence with the parser.
- Decrypt: FRMPayload decrypt against known plaintext for both `AppSKey` (FPort > 0) and `NwkSKey` (FPort = 0) cases, 1.0 and 1.1.
- Encrypt: FRMPayload encrypt produces identical ciphertext to the wire vector.
- FOpts: encrypt and decrypt for uplink and downlink direction (1.1 only).
- MIC: calculate and verify for Join Request (1.0 + 1.1), Join Accept (1.0 + 1.1 with `OptNeg`), Data (1.0 + 1.1 uplink dual-MIC and downlink), Rejoin Request types 0/1/2.
- Join Accept crypt: server-side encrypt and on-air decrypt round trip.
- Key derivation: `SessionKeys10`, `SessionKeys11`, `JoinServerKeys`, `WorKeys::root`, `WorKeys::session` with vectors verified against the LoRaWAN specs.

### Parity rule (internal, for implementers)

Every test file under `/Users/felipefdl/Projects/tago/lora-packet/__tests__/` (except CLI-specific tests) must be reflected in the Rust suite with the same input bytes and the same expected outputs. Each Rust test cites its source test in a doc comment for traceability during the build. After v1 ships, these citations can be removed if desired; while building, they let agents cross-check behavior against the reference implementation.

Beyond the parity floor, the Rust suite adds: round-trips, property tests, newtype invariant checks, constant-time MIC compare checks, and a no_std smoke build.

### Test layout

```
src/codec.rs        # #[cfg(test)] mod tests for parser internals
src/crypto.rs       # #[cfg(test)] mod tests for crypto primitives
src/mic.rs          # #[cfg(test)] mod tests for CMAC primitives

tests/
├── parse.rs                  # parse vectors per message type
├── decrypt.rs                # FRMPayload encrypt/decrypt vectors
├── mic.rs                    # MIC calculate/verify vectors per message type
├── packet.rs                 # parse + build round-trips
├── fopts.rs                  # FOpts encrypt/decrypt
├── join_accept_encrypt.rs    # Join Accept server-side encrypt and on-air decrypt
├── key_gen.rs                # session, JS, and WOR key derivation
└── no_std_smoke.rs           # builds the crate with std off
```

### Property and structural tests

- Round-trip: `from_wire(bytes) -> to_wire()` produces identical bytes for every test vector.
- Builder round-trip: `builder().build_unsigned() -> to_wire() -> from_wire()` reconstructs an equivalent struct.
- Property: `from_wire` on arbitrary `Vec<u8>` of length 0..1000 must never panic, only return `Result`. Uses `proptest`.
- Newtype length validation: `*::from_slice(too_short)` and `*::from_slice(too_long)` return `Err`, never panic.
- Constant-time MIC compare: source-level check that `verify_mic_*` uses `subtle::ConstantTimeEq`.
- no_std smoke: `cargo build --target thumbv7em-none-eabihf --no-default-features` in CI.

## Tooling

### Strict lints

Top of `src/lib.rs`:

```rust
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]
```

### Config files

| File | Purpose |
|------|---------|
| `rust-toolchain.toml` | Pin stable channel for reproducible builds |
| `rustfmt.toml` | `max_width = 120`, `tab_spaces = 2`, `edition = "2024"`, `imports_granularity = "Module"` |
| `clippy.toml` | `msrv = "1.85"`, `cognitive-complexity-threshold = 30` |
| `deny.toml` | Forbid GPL and AGPL deps, block yanked crates, fail on security advisories |
| `.cargo/config.toml` | Default test args, doc args |
| `Cargo.toml` `[package.metadata.docs.rs]` | Build docs with `all-features` on docs.rs |

### CI matrix

GitHub Actions, `.github/workflows/ci.yml`:

| Job | Command |
|-----|---------|
| fmt | `cargo fmt --check` |
| clippy | `cargo clippy --all-targets --all-features -- -D warnings` |
| test-stable | `cargo test --all-features` on stable |
| test-msrv | `cargo test --all-features` on 1.85.0 |
| test-no-default | `cargo test --no-default-features` |
| no_std-build | `cargo build --target thumbv7em-none-eabihf --no-default-features` |
| audit | `cargo deny check` |
| docs | `RUSTDOCFLAGS=-D warnings cargo doc --all-features --no-deps` |

## Repository files

### `LICENSE`

MIT, copyright TagoIO. Standard MIT template, with a short attribution block at the end:

```text
MIT License

Copyright (c) 2026 TagoIO

[standard MIT permission grant]

---

Test vectors and protocol-level reference material used during development
were drawn in part from the lora-packet project by Anthony Kirby and
contributors (https://github.com/anthonykirby/lora-packet), MIT License.
```

This is the only place attribution lives.

### `AGENTS.md`

Repo conventions following the tagoio:agents-md skill. Root `AGENTS.md` with `CLAUDE.md` as a symlink so all CLI agents read the same file. Contents include:

- Repo purpose, audience, license stance
- MSRV, edition, formatter, lint expectations
- Test coverage requirements
- Commit and PR conventions (delegated to the tagoio:github skill)
- How to run fmt, clippy, test, and audit locally
- Pointer to this design doc

### `README.md`

- Three-line quickstart showing parse + verify_mic + decrypt
- Five scenario examples: parse uplink, build downlink, OTAA 1.0, OTAA 1.1, rejoin
- Feature flag table
- Pointer to crates.io and docs.rs

No mention of any other library or implementation. `README.md` does not link to anything under `docs/`; those files are internal.

### `docs/migration.md` (internal)

Agent-facing reference that maps each public function in the upstream TS library to its Rust equivalent. Used by implementers during the build to avoid behavioral drift. Removable after v1 ships. Not linked from the README or any public surface.

Contents:

- `fromWire` -> `LoraPacket::from_wire`
- `fromFields` -> `LoraPacket::builder()...`
- `decrypt` -> `Data::decrypt_payload`
- `decryptJoin` / `decryptJoinAccept` -> `JoinAccept::decrypt_from_wire`
- `encrypt` -> `aes_ecb_encrypt`
- `generateSessionKeys` / `generateSessionKeys10` -> `SessionKeys10::derive`
- `generateSessionKeys11` -> `SessionKeys11::derive`
- `generateJSKeys` -> `JoinServerKeys::derive`
- `generateWORKey` -> `WorKeys::root`
- `generateWORSessionKeys` -> `WorKeys::session`
- `calculateMIC` -> `LoraPacket::calculate_mic_v1_0` / `_v1_1`
- `verifyMIC` -> `LoraPacket::verify_mic_v1_0` / `_v1_1`
- `recalculateMIC` -> `LoraPacket::recalculate_mic_v1_0` / `_v1_1`
- Plus a getter map (`packet.getFCnt()` -> `data.f_cnt()`, etc.)

### `docs/ts-source-map.md` (internal)

Agent-facing reference that lists which TS file each Rust module reflects. Lets an agent diff against the upstream behavior when investigating a regression. Removable after v1 ships.

## Decision log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-20 | Single library crate, no workspace | Smallest scaffolding for one library; can be promoted later when CLI or WASM is added |
| 2026-05-20 | no_std + alloc with default `std` feature | Server-side primary use plus embedded compatibility, one crate, no forks |
| 2026-05-20 | Optional `serde` and `hex_base64` features only | Avoid forced deps for users who do not need them |
| 2026-05-20 | Tagged-union `Payload` enum, not flat struct | Compile-time guarantee that field access matches message type |
| 2026-05-20 | Builder pattern for construction | Avoids the 6-param `fromFields` signature, idiomatic Rust |
| 2026-05-20 | Strong newtypes for every key and identifier | Compile-time swap-bug prevention |
| 2026-05-20 | Per-version MIC entry points with key bundles | Explicit version split, no overloaded ambiguous signatures |
| 2026-05-20 | RustCrypto deps (aes 0.9, cmac 0.8) | Audited, no_std, paired April 2026 release sharing `cipher 0.5` |
| 2026-05-20 | MIT license, copyright TagoIO | Standard permissive license for public Rust crates |
| 2026-05-20 | Public surface presents `lora-packet` as a native Rust crate | README, Cargo, code, and inline docs do not reference other implementations |
| 2026-05-20 | Internal `docs/` directory may reference upstream TS lib | Agent-facing scaffolding for the build; removable after v1 ships |

## Open questions

None at the time of approval.
