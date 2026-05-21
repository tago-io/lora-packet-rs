# AGENT_INTEGRATION.md

Guidance for AI coding agents integrating `lora-packet` into a downstream
Rust project (a network server, Lambda middleware, embedded firmware, a
test harness). For repo-internal conventions see `AGENTS.md` at the
project root; for the API reference see [docs.rs/lora-packet](https://docs.rs/lora-packet).

## Where this crate fits

`lora-packet` is a pure codec. It does not own state, sockets, or
allocators beyond what `alloc::vec::Vec` requires. Treat each `LoraPacket`
as a value: parse, verify, decrypt, then hand the plaintext to your
application layer. Build the reverse trip the same way: assemble fields,
sign, emit bytes.

The crate has no async surface. Wrap calls in your runtime as needed.

## Common integration patterns

### Network-server uplink handler

```rust
use lora_packet::{LoraPacket, Error, V1_0MicKeys};

fn handle_uplink(bytes: &[u8], session_keys: &SessionLookup) -> Result<Frame, AppError> {
  let packet = LoraPacket::from_wire(bytes)?;
  let data = packet.as_data().ok_or(AppError::NotADataFrame)?;
  let keys = session_keys.lookup(&data.dev_addr)?;

  let mic_keys = V1_0MicKeys { nwk_s_key: Some(&keys.nwk_s_key), ..Default::default() };
  if !packet.verify_mic_v1_0(&mic_keys)? {
    return Err(AppError::MicMismatch);
  }

  let plaintext = data.decrypt_payload(&keys.app_s_key, &keys.nwk_s_key, keys.f_cnt_msb)?;
  Ok(Frame {
    dev_addr: data.dev_addr,
    f_port: data.f_port,
    f_cnt: data.f_cnt_32(keys.f_cnt_msb),
    payload: plaintext,
  })
}

# struct SessionLookup;
# struct Session { nwk_s_key: lora_packet::NwkSKey, app_s_key: lora_packet::AppSKey, f_cnt_msb: u16 }
# impl SessionLookup {
#   fn lookup(&self, _: &lora_packet::DevAddr) -> Result<Session, AppError> { unimplemented!() }
# }
# struct Frame { dev_addr: lora_packet::DevAddr, f_port: Option<u8>, f_cnt: u32, payload: Vec<u8> }
# #[derive(Debug)] enum AppError { NotADataFrame, MicMismatch, Crypto(lora_packet::Error), Session(String) }
# impl From<lora_packet::Error> for AppError { fn from(e: lora_packet::Error) -> Self { AppError::Crypto(e) } }
```

### Downlink builder (server side)

```rust
use lora_packet::{LoraPacket, Direction, DevAddr, AppSKey, NwkSKey};

fn build_downlink(dev_addr: DevAddr, f_cnt: u16, payload: &[u8], app: &AppSKey, nwk: &NwkSKey)
  -> Result<Vec<u8>, lora_packet::Error>
{
  let packet = LoraPacket::builder()
    .data(Direction::Downlink, false)
    .dev_addr(dev_addr)
    .f_cnt(f_cnt)
    .f_port(1)
    .payload(payload)
    .sign_and_encrypt(app, nwk)?;
  Ok(packet.to_wire())
}
```

### Embedded device-side parser

The `no_std + alloc` mode covers Cortex-M targets with a global allocator.

```toml
[dependencies]
lora-packet = { version = "0.1", default-features = false }
```

```rust,ignore
use lora_packet::{LoraPacket, AppKey, JoinAccept};

fn parse_join_accept(wire: &[u8], app_key: &AppKey) -> Result<JoinAccept, lora_packet::Error> {
  let plain = JoinAccept::decrypt_from_wire(wire, app_key)?;
  JoinAccept::from_plaintext(&plain)
}
```

Avoid `String::from_utf8` and similar on payloads in tight loops; reuse
`Vec<u8>` buffers where possible. The crate itself only allocates inside
parsers and crypt helpers; everything else operates on slices.

## Anti-patterns

- **Do not extract bytes via `as_bytes` and re-wrap.** If you have a
  `NwkSKey` and need an `AppSKey`, derive it with
  [`SessionKeys10`](https://docs.rs/lora-packet/latest/lora_packet/struct.SessionKeys10.html);
  do not call `as_bytes` and `AppSKey::from_slice`. The byte detour throws
  away the role distinction the type system was protecting.
- **Do not match on `Error` string content.** Match on the variant:

  ```rust
  use lora_packet::Error;

  fn classify(err: &Error) -> &'static str {
    match err {
      Error::MicMismatch => "mic_mismatch",
      Error::MissingKey(_) => "missing_key",
      Error::TooShort { .. } => "short_frame",
      Error::InvalidMType(_) => "bad_mtype",
      _ => "other",
    }
  }
  ```

  Display strings are not part of the API contract.
- **Do not roll your own AES-CMAC, AES-ECB, or constant-time compare.**
  The crate uses RustCrypto and `subtle::ConstantTimeEq`. Reach for
  [`aes_ecb_encrypt`](https://docs.rs/lora-packet/latest/lora_packet/fn.aes_ecb_encrypt.html)
  when you really need a raw block.
- **Do not log keys.** Their `Debug` impls already redact, but be careful
  with `as_bytes()` plus a serializer. Wrap any logging in a helper that
  prints only key fingerprints, never raw bytes.
- **Do not skip MIC verification because you trust the gateway.** Compute
  the MIC even on internal traffic; constant-time compare costs almost
  nothing and saves you from a single forged frame ruining a session.
- **Do not feed unbounded `FRMPayload` into `encrypt_payload`.** The 255-block
  / 4080-byte limit is real (1-byte block index in `Ai[15]`). The crate
  returns `Error::PayloadTooLarge` rather than corrupt output; surface
  that error to your caller.

## Error handling

Every fallible API returns
[`Result<T, lora_packet::Error>`](https://docs.rs/lora-packet/latest/lora_packet/error/enum.Error.html).
The variants split into parsing, construction, and crypto buckets; see
the rustdoc on `Error` for the full list. Suggested handling:

| Variant                          | Typical response                           |
| -------------------------------- | ------------------------------------------ |
| `MicMismatch`                    | Drop the frame; surface as a security event |
| `TooShort { .. }`                | Drop the frame; log offending length        |
| `InvalidMType / InvalidMajor / InvalidRejoinType` | Drop the frame; alert on unexpected protocol |
| `MissingKey(role)`               | Programmer error; fix the keyset           |
| `MissingField(name)`             | Programmer error; fix the builder call     |
| `PayloadTooLarge(n)`             | Surface to caller; refuse oversized payloads |
| `InvalidJoinAcceptLength(n)`     | Drop the frame; the message is malformed   |
| `InvalidKeyLength / InvalidIdentifierLength` | Programmer error; validate inputs |
| `FOptsTooLong(n)`                | Builder bug; truncate or split commands    |
| `ConflictingMacCommands`         | Builder bug; pick one location for commands |
| `Hex / Base64` (with `hex_base64`) | Input validation error; surface to user  |
| `Other(_)`                       | Catch-all; should not occur in stable paths |

## Performance characteristics

Approximate, from CPU-bound workloads on x86_64. Treat as ballpark values;
benchmark your own workload.

- **Parsing** a Data frame: ~1 µs, one `Vec<u8>` allocation for
  `phy_payload` plus one for `f_opts` and `frm_payload` (when present).
- **MIC verification**: ~3-5 µs (one or two AES-CMAC computations).
- **`FRMPayload` decrypt**: ~1 µs per 16-byte block (AES-128-ECB). The
  upper bound is 255 blocks = 4080 bytes.
- **OTAA session-key derivation**: ~5 µs total (two or four AES blocks
  depending on version).
- **Builder + sign + encrypt** for a small Data downlink: ~10 µs.

Memory: each `LoraPacket` holds at most ~300 bytes (wire bytes + parsed
fields). Reuse a single `Vec<u8>` buffer for `to_wire()` output if you
emit many frames per second.

Concurrency: every type is `Send` and `Sync` (no interior mutability).
Share `&LoraPacket` across threads freely.

## Feature-flag combinations

| Flags                                            | Purpose                              |
| ------------------------------------------------ | ------------------------------------ |
| (default: `std`)                                 | Server-side Rust app on `std`         |
| `--no-default-features`                          | Embedded firmware (`no_std + alloc`)  |
| `--no-default-features --features serde`         | Embedded + JSON serialisation         |
| `--features hex_base64`                          | Accept hex / base64 input from configs |
| `--all-features`                                 | Everything; used in CI                |

`thiserror` re-exports `std::error::Error` only when the `std` feature is
on. In `no_std` mode, the `Error` enum still works via `core::fmt::Display`
and `core::fmt::Debug`; downstream `?` propagation must rely on `From`
conversions you define yourself.

## Versioning and stability

- Pre-1.0: minor releases may include breaking changes; follow the
  changelog.
- Post-1.0: semver. Field-level breakage triggers a major release.
- MSRV is 1.85 (matches the `rust-toolchain.toml` in this repo). MSRV
  bumps will be flagged in release notes.

## Where to find help

- Crate docs: <https://docs.rs/lora-packet>
- Source: <https://github.com/tago-io/lora-packet-rs>
- File issues for bugs or missing functionality; PRs welcome.
