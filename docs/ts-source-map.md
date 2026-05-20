# TS source map (internal scaffolding)

Which Rust module reflects which TS file. Use this to cross-check behavior during the build.

| Rust module | TS source |
|-------------|-----------|
| `src/error.rs` | (new; TS throws strings/Error) |
| `src/types.rs` | `src/lib/LoraPacket.ts` (enum + constants section, lines 1-90) |
| `src/codec.rs` (parse) | `src/lib/LoraPacket.ts::_initFromWire` and `_parseGroupFields` |
| `src/codec.rs` (build) | `src/lib/LoraPacket.ts::_initFromFields` and `_mergeGroupFields` |
| `src/codec.rs` (accessors) | `src/lib/LoraPacket.ts::getXxx`, `isXxx` methods |
| `src/crypto.rs` (aes, key derivation) | `src/lib/crypto.ts` |
| `src/crypto.rs` (payload, FOpts) | `src/lib/crypto.ts::_metadataBlockAi`, `decrypt`, `encrypt` |
| `src/crypto.rs` (Join Accept crypt) | `src/lib/crypto.ts::decryptJoin*`, `encryptJoin*` |
| `src/mic.rs` | `src/lib/mic.ts` |
| `src/util.rs` | `src/lib/util.ts` |

Removable after v1 ships.
