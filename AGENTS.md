# AGENTS.md

LoRaWAN 1.0/1.1 packet codec for Rust.

## Stack
- Rust edition 2024, MSRV 1.85
- `no_std + alloc` with default `std` feature
- RustCrypto: `aes 0.9`, `cmac 0.8`, `subtle 2.6`, `zeroize 1.8`
- `thiserror 2.0` for errors

## Conventions
- Line width 120, 2 spaces, double quotes, trailing commas (ES5 style)
- `snake_case` for files in `src/`, `kebab-case` for repo-level files
- No `unsafe` (`#![deny(unsafe_code)]`)
- All public items documented (`#![deny(missing_docs)]`)
- Clippy: pedantic + nursery, warnings deny in CI
- Test parity rule: every test in `/Users/felipefdl/Projects/tago/lora-packet/__tests__/` (except CLI) has a Rust mirror with the same input and same expected output

## Commits and PRs
- Conventional commits: `type(scope): subject` (lowercase, no period, under 72 chars)
- Branch prefixes: `feature/`, `fix/`, `chore/`, `refactor/`
- PR titles: human-readable, capitalized
- See the tagoio:github skill for the full convention

## Local commands
- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo test --no-default-features`
- `cargo deny check`

## Design and scaffolding docs
- `docs/superpowers/specs/2026-05-20-lora-packet-rs-design.md` (design)
- `docs/superpowers/plans/2026-05-20-lora-packet-implementation.md` (this plan)
- `docs/migration.md` (TS-to-Rust function map, internal)
- `docs/ts-source-map.md` (which TS file each Rust module reflects, internal)
