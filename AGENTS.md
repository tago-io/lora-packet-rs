# AGENTS.md

`LoRaWAN` 1.0 and 1.1 packet codec for Rust. Audience: anyone parsing or
building `PHYPayload` frames from a network server, gateway, embedded
firmware, integration test, or downstream Rust crate. This file is the
single source of truth for repo conventions, layout, and the rules a code
change must respect.

## Quick orientation for AI agents

If you are an AI coding agent landing in this repo, read this section first.

- **What this crate is**: a no-frills, no-`unsafe` codec. It parses and builds
  `LoRaWAN` `PHYPayload` frames, computes AES-CMAC MICs, runs AES-ECB
  `FRMPayload` and `FOpts` crypt, and derives OTAA, Join Server, and Relay
  (WOR) keys. It is a library, not a runtime.
- **What it is not**: no CLI binary, no WASM target, no async or futures, no
  `LoRaWAN` 1.2 (1.0 and 1.1 only), no MAC-layer state machine, no LoRa
  physical-layer modem code, no network-server logic.
- **Where to start reading**: `src/lib.rs` (crate-level guide and
  re-exports) -> `src/codec.rs::LoraPacket::from_wire` and
  `src/codec.rs::LoraPacketBuilder` for the main API surface.
- **Parity floor (non-negotiable)**: every test in
  `/Users/felipefdl/Projects/tago/lora-packet/__tests__/*.ts` (except CLI)
  must have a Rust mirror in `tests/*.rs` with the same inputs and
  expected outputs. The Rust test's doc comment names its TS source for
  traceability.
- **Where the integration guide lives**: `docs/AGENT_INTEGRATION.md` covers
  downstream patterns (Lambda middleware, embedded firmware) and common
  anti-patterns when wiring this crate into a larger system.

## Repository layout

```
.
├── AGENTS.md, CLAUDE.md (symlink)   Repo conventions for AI agents (this file)
├── Cargo.toml                        Crate manifest, MSRV 1.95, edition 2024
├── Cargo.lock                        Committed for reproducible builds
├── README.md                         User-facing intro and quickstart
├── LICENSE                           MIT
├── rust-toolchain.toml               Pinned `stable` + rustfmt + clippy
├── rustfmt.toml                      max_width 120, 2 spaces, Unix newlines
├── clippy.toml                       cognitive-complexity = 30
├── deny.toml                         License + advisory rules for cargo-deny
├── .github/workflows/                CI (fmt, clippy, test, deny, no_std)
├── docs/
│   └── AGENT_INTEGRATION.md          Downstream integration guide
├── src/
│   ├── lib.rs                        Crate-level rustdoc + re-exports
│   ├── error.rs                      Single `Error` enum + `Result<T>` alias
│   ├── types.rs                      Newtypes for keys/IDs, bitfield wrappers
│   ├── codec.rs                      Parse, build, accessors, MIC dispatch
│   ├── crypto.rs                     AES-ECB, FRMPayload crypt, key derivation
│   ├── mic.rs                        CMAC MICs + V1_0MicKeys / V1_1MicKeys
│   └── util.rs                       Private helpers
└── tests/
    ├── parse.rs                      Wire-format parsing parity
    ├── packet.rs                     Round-trip + builder parity
    ├── mic.rs                        MIC vector parity (1.0 and 1.1)
    ├── decrypt.rs                    FRMPayload crypt parity
    ├── fopts.rs                      FOpts crypt parity (1.1)
    ├── key_gen.rs                    OTAA / JS / WOR key derivation parity
    ├── join_accept_encrypt.rs        Join Accept on-air crypt
    ├── hex_base64.rs                 Optional feature constructors
    ├── serde.rs                      Optional serde derive smoke tests
    └── no_std_smoke.rs               Builds with --no-default-features
```

## How the public API is shaped

### Read path: bytes in, typed packet out

```
[u8] bytes ──▶ LoraPacket::from_wire(&bytes) ──▶ LoraPacket {
                                                    phy_payload: Vec<u8>,
                                                    mhdr: Mhdr,
                                                    mic: [u8; 4],
                                                    payload: Payload {
                                                      JoinRequest(JoinRequest)
                                                      JoinAccept(JoinAccept)
                                                      Data(Data)
                                                      RejoinRequest(RejoinRequest)
                                                      Proprietary(Vec<u8>)
                                                    }
                                                  }
                                                       │
                                  ┌────────────────────┼──────────────────┐
                                  ▼                    ▼                  ▼
                       verify_mic_v1_0/_v1_1   decrypt_payload    decrypt_fopts
                       (constant-time CMAC)    (AES-CTR keystream) (1.1 only)
```

### Write path: builder in, bytes out

```
LoraPacket::builder() ──▶ .data() / .join_request() / .join_accept() / .rejoin_request()
                                  │
                                  ▼
                       .dev_addr() / .f_cnt() / .f_port() / .payload() / ...
                                  │
                                  ▼
                       .sign_and_encrypt(&app_s_key, &nwk_s_key)         (Data 1.0)
                       .sign_join_request(&app_key) / _v1_1(&nwk_key)    (Join Req)
                       .sign_join_accept(&app_key)                       (Join Acc)
                       .build_unsigned()                                  (manual)
                                  │
                                  ▼
                       LoraPacket ──▶ .to_wire() ──▶ Vec<u8> bytes
```

## Core invariants

These rules are mechanical. Each one is enforced by a lint, a test, or
both. Code that violates any of them must not be merged.

- **No `unsafe`.** `#![deny(unsafe_code)]` in `src/lib.rs`. There has never
  been a reason to reach for `unsafe` here.
- **All public items documented.** `#![deny(missing_docs)]` enforces this.
  A missing `///` comment is a build error.
- **`no_std + alloc` compatibility.** The crate compiles with
  `--no-default-features`. Do not use `std::` in `src/`; use `alloc::` and
  `core::`. `tests/no_std_smoke.rs` is the smoke test.
- **Strong newtypes everywhere.** `AppKey`, `NwkSKey`, etc. are distinct
  types; raw `[u8; 16]` is never accepted in the public API. This catches
  cross-key bugs at compile time.
- **Constant-time MIC compare.** Use `subtle::ConstantTimeEq` via the
  internal `mic::mic_eq`. Never compare MIC bytes with `==`.
- **Keys auto-zeroize on drop.** Every key newtype derives
  `zeroize::ZeroizeOnDrop`. Do not copy a key (the type intentionally lacks
  `Copy`); borrow with `&` and clone only when ownership is required.
- **Builder fields are all `Option`.** Required-field validation happens in
  `LoraPacketBuilder::build_unsigned` based on the chosen `MType`. Do not
  add bespoke "is this field set?" checks elsewhere.
- **Wire-format byte order is little-endian.** Struct fields store the
  big-endian (display) form. `from_wire` and `to_wire` reverse bytes for
  you; never reverse in callers.

## Stack and conventions

- **Language**: Rust, edition 2024, MSRV 1.95.0.
- **Crypto**: RustCrypto stack (`aes 0.9`, `cmac 0.8`, `cipher 0.5`,
  `subtle 2.6`, `zeroize 1.8`). Errors via `thiserror 2.0`. Optional
  features: `hex 0.4`, `base64 0.22`, `serde 1.0`.
- **Formatting**: `rustfmt` with `max_width = 120`, `tab_spaces = 2`,
  `imports_granularity = "Module"`, `group_imports = "StdExternalCrate"`.
- **Lints**: clippy with `pedantic` and `nursery` warnings on, plus
  `cognitive-complexity-threshold = 30`. CI runs with `-D warnings`.
- **Naming**: `snake_case` for modules and functions, `PascalCase` for
  types, `SCREAMING_SNAKE_CASE` for constants, `kebab-case` for top-level
  repo files (`rust-toolchain.toml`, `deny.toml`).
- **Doc style**: use backticks around acronyms (`AES`, `MIC`, `LoRaWAN`),
  add a `# Errors` section to every `pub fn -> Result`, `# Panics` only if
  there is a real panic. Prefer runnable `\`\`\`rust` blocks over `ignore`.
- **`const fn` where possible.** Getter methods on `FCtrl`, `Mhdr`,
  `DlSettings`, and frame-counter helpers on `Data` are all `const`.

## Commands

| Task                         | Command                                                         |
| ---------------------------- | --------------------------------------------------------------- |
| Format check                 | `cargo fmt --check`                                             |
| Format apply                 | `cargo fmt`                                                     |
| Lint                         | `cargo clippy --all-targets --all-features -- -D warnings`      |
| Full tests                   | `cargo test --all-features`                                     |
| `no_std` smoke               | `cargo test --no-default-features`                              |
| Per-feature tests            | `cargo test --no-default-features --features serde`             |
| Doc tests only               | `cargo test --doc --all-features`                               |
| Build docs (with warnings)   | `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps` |
| Dependency policy            | `cargo deny check`                                              |
| Publish dry-run              | `cargo publish --dry-run --all-features`                        |
| MSRV check                   | `cargo +1.95 check --all-features`                              |

## Test parity rule (critical)

Every TypeScript test in `/Users/felipefdl/Projects/tago/lora-packet/__tests__/`
(except CLI) MUST have a Rust mirror in `tests/*.rs` with the SAME inputs
and SAME expected outputs.

TS file → Rust file:

| TS                              | Rust                                  |
| ------------------------------- | ------------------------------------- |
| `__tests__/parse_test.ts`       | `tests/parse.rs`                      |
| `__tests__/packet_test.ts`      | `tests/packet.rs`                     |
| `__tests__/mic_test.ts`         | `tests/mic.rs`                        |
| `__tests__/decrypt_test.ts`     | `tests/decrypt.rs`                    |
| `__tests__/fopts_test.ts`       | `tests/fopts.rs`                      |
| `__tests__/key_gen_test.ts`     | `tests/key_gen.rs`                    |
| `__tests__/join_accept_encrypt.ts` | `tests/join_accept_encrypt.rs`     |

Each Rust test has a doc comment naming its TS source, e.g.:

```rust
/// Mirror of `__tests__/parse_test.ts`: "parses a Join Request"
#[test]
fn parse_join_request_known_vector() { /* ... */ }
```

If you add a TS-side vector that this crate must also handle, port it to
the matching Rust file in the same PR.

## Working on this crate

### Adding a new public function

1. Define in the right module (`codec`, `crypto`, `mic`, `types`).
2. Re-export from `src/lib.rs` if it belongs in the top-level surface.
3. Add a `///` doc comment with a one-sentence description, a runnable
   example where useful, and a `# Errors` section if it returns `Result`.
4. Add unit tests in the same module under `#[cfg(test)] mod tests`. For
   anything user-visible, also mirror an integration test in `tests/`.
5. If it covers a TS-reference behaviour, name the source TS test in a
   `///` comment on the Rust test.
6. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
   and `cargo test --all-features` before sending for review.

### Modifying the codec

- Wire fields are little-endian; struct fields are big-endian (display
  order). The `*_test.ts` vectors in the TS reference are wire bytes; the
  Rust struct fields display reversed.
- After any change to `from_wire` or `to_wire`, confirm the round-trip
  property holds for every `__tests__/parse_test.ts` vector. The
  proptest in `codec::prop_tests::from_wire_never_panics` guards against
  panics on arbitrary inputs.
- `LoraPacket::phy_payload` is the source of truth for MIC computation
  (every MIC routine slices it). When you mutate fields, regenerate
  `phy_payload` via `to_wire()` before calling a MIC routine.

### Modifying crypto

- Always test against the existing TS vectors first. They are the ground
  truth. Never invent new test vectors without cross-checking the TS
  reference or the `LoRaWAN` spec.
- The XOR keystream construction means encrypt and decrypt share one
  primitive. If you change `payload_crypt`, both directions break or both
  fix together.
- The block-index limit (`Ai[15]` is one byte, so 255 blocks = 4080 bytes
  max) is real, not a defensive check. Going beyond silently corrupts
  output. The guard in `payload_crypt` must stay.
- Key derivation byte layouts come from the `LoRaWAN` 1.0.4 and 1.1
  specifications. When in doubt, read the spec PDF, not blog posts.

### Modifying MIC

- The per-version dispatch table lives in `LoraPacket::calculate_mic_v1_0`
  / `_v1_1`. Add new MIC variants by extending the appropriate match arm
  and adding a `pub(crate) fn calculate_*_mic_*` in `src/mic.rs`.
- The B0 block layout (1.0 and 1.1 downlinks, 1.1 uplink first CMAC) and
  the B1 block layout (1.1 uplink second CMAC) are spec-defined. Do not
  reorder fields.
- For dual-MIC uplinks (1.1), the final MIC is
  `cmac_s[0..2] || cmac_f[0..2]`. Swapping the halves is the most common
  bug; the integration tests in `tests/mic.rs` catch it.

## Common pitfalls

- **Do not pass raw `[u8; 16]` anywhere public.** Wrap in the matching
  newtype (`AppKey::new`, `AppKey::from_slice`, `AppKey::from_hex` with
  `hex_base64` feature). Hand-rolled byte arrays sidestep the
  zeroize-on-drop guarantee.
- **Do not use `std::` in `src/`.** Reach for `alloc::vec::Vec` and
  `alloc::string::String`; `core::` for everything else. CI builds with
  `--no-default-features` and will catch leaks.
- **Do not add `unsafe`.** The `#![deny(unsafe_code)]` lint enforces it;
  if you think you need it, ask first.
- **Do not bypass constant-time compare for MIC.** Use `mic::mic_eq` (which
  wraps `subtle::ConstantTimeEq`). Never write `a.mic == b.mic`.
- **Do not log or `Debug`-print a key expecting raw bytes.** Key newtypes
  have a redacted `Debug` (`AppKey(***)`). Call `as_bytes()` if you really
  need the bytes.
- **Do not match on `Error` `Display` strings.** Match on the variant.
  String wording can change between releases.
- **When in doubt about a byte layout**, open the LoRaWAN spec or read
  the TS reference at `/Users/felipefdl/Projects/tago/lora-packet/src/lib/`
  before guessing.

## Commits and PRs

- **Conventional commits**: `type(scope): subject` (lowercase, no period,
  under 72 chars). Types: `feat`, `fix`, `refactor`, `test`, `docs`,
  `chore`, `perf`. Scopes are usually module names (`codec`, `crypto`,
  `mic`, `types`, `error`) or a wider one (`docs`, `ci`).
- **Branch prefixes**: `feature/`, `fix/`, `chore/`, `refactor/`,
  `docs/`.
- **PR titles**: human-readable summary, not the conventional-commit
  format. Capitalize the first word. Example:
  `Document Join Accept MIC binding for 1.1 OptNeg sessions`.
- **No Co-Authored-By lines.** No mentions of AI tooling anywhere in
  commits, PR descriptions, or code comments.
- **gh CLI for PRs and issues**: `gh pr view`, `gh pr diff`,
  `gh api repos/{owner}/{repo}/pulls/<n>/comments` for review comments,
  `gh api repos/{owner}/{repo}/issues/<n>/comments` for issue comments.

## Releasing a new version

**AI agents drive the entire release end to end.** When the user asks
for a new version (or asks you to ship a bug fix, etc.), you handle the
version bump, the release notes, and the publish. Do not hand the
release back to the user unless trusted publishing is unconfigured or a
secret is missing.

GitHub releases are the source of truth for changelogs. Do **not** push
tags manually - always create a release through GitHub. The release
publish event triggers `.github/workflows/publish-crate.yml`, which
authenticates with crates.io via OIDC trusted publishing and runs
`cargo publish`.

### Agent procedure

```bash
# 1. Confirm main is clean and decide the new version.
git status
git log "v$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)..HEAD" --oneline
# Pick patch / minor / major per semver based on the commits since the
# last tag.

# 2. Bump Cargo.toml version. Use Edit, not sed-in-place, so the change
# is auditable.
# version = "X.Y.Z"

# 3. Commit and push.
git add Cargo.toml
git commit -m "chore(crate): bump version to X.Y.Z"
git push origin main

# 4. Wait for CI to go green before releasing.
gh run watch --exit-status

# 5. Draft release notes from the commit log. Group by:
#   ### Added       - new public functionality
#   ### Changed     - behavior changes that are not breaking
#   ### Fixed       - bug fixes
#   ### Breaking    - public API changes that require a major bump
#   ### Internal    - tooling, refactors, docs that users won't notice
# Be terse. One bullet per change. Drop trivial commits (typos,
# formatting). Write in past tense ("Added X", not "Adds X").

# 6. Create the GitHub release. This triggers the publish workflow.
gh release create vX.Y.Z \
  --title "vX.Y.Z" \
  --target main \
  --notes "$(cat <<'EOF'
### Added
- ...

### Fixed
- ...
EOF
)"

# 7. Watch the publish workflow. Fail loudly if it fails.
gh run watch --workflow=publish-crate.yml --exit-status

# 8. Confirm the version is on crates.io.
curl -s https://crates.io/api/v1/crates/lora-packet | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['crate']['max_stable_version'])"
```

### If the publish fails

- **Verify step fails** (tag does not match Cargo.toml): the release was
  created with the wrong tag. Delete + recreate the release with the
  correct tag.
- **Auth step fails**: crates.io trusted publishing is misconfigured.
  This is the only case where you must stop and ask the user to fix the
  crates.io repo settings.
- **Publish step fails** (network, transient): re-run from
  `gh run rerun --failed`.
- **Workflow YAML had a bug** (e.g., the verify step needs a fix): the
  re-run uses the workflow YAML from the original release commit and
  will still fail. Fix the YAML, push, **then delete and recreate the
  release** so the new release event picks up the fixed YAML.

### Semver rules for this crate

- `Error` variants are public API. Adding a variant is non-breaking
  (a minor bump); removing or renaming one is breaking (major bump).
- Key newtypes, the `Payload` enum variants, and the `LoraPacketBuilder`
  method signatures are public API. Same rule.
- Adding a feature flag is non-breaking. Removing or renaming one is
  breaking.
- Bumping a dependency's major version is breaking if the dep type
  shows up in the public surface (none of ours currently do, so this is
  usually a minor bump).

## Integration guide

- `docs/AGENT_INTEGRATION.md`: downstream patterns (Lambda middleware,
  embedded firmware, error handling, performance notes). Read before
  wiring this crate into a larger system.
