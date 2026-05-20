# Migration map (internal scaffolding)

This document maps every public function in `/Users/felipefdl/Projects/tago/lora-packet/src/lib.ts` to its Rust equivalent. It exists to help agents and implementers verify behavioral parity during the v1 build. Removable after v1 ships.

## Functions

| TS | Rust |
|----|------|
| `fromWire(buffer)` | `LoraPacket::from_wire(&bytes)` |
| `fromFields(fields, AppSKey?, NwkSKey?, AppKey?, FCntMSBytes?, ConfFCntDownTxDrTxCh?)` | `LoraPacket::builder()...` |
| `decrypt(payload, AppSKey?, NwkSKey?, fCntMSB32?)` | `data.decrypt_payload(&app_s_key, &nwk_s_key, f_cnt_msb)` |
| `decryptJoin(payload, AppKey)` | `JoinAccept::decrypt_from_wire(&bytes, &app_key)` |
| `decryptJoinAccept(payload, appKey)` | `JoinAccept::decrypt_from_wire(&bytes, &app_key)` |
| `encrypt(buffer, key)` | `aes_ecb_encrypt(&block, &key)` |
| `generateSessionKeys(...)` | `SessionKeys10::derive(...)` |
| `generateSessionKeys10(...)` | `SessionKeys10::derive(...)` |
| `generateSessionKeys11(...)` | `SessionKeys11::derive(...)` |
| `generateJSKeys(...)` | `JoinServerKeys::derive(...)` |
| `generateWORKey(NwkSKey)` | `WorKeys::root(&nwk_s_key)` |
| `generateWORSessionKeys(root, devAddr)` | `WorKeys::session(&root, &dev_addr)` |
| `calculateMIC(...)` | `LoraPacket::calculate_mic_v1_0(...)` / `_v1_1(...)` |
| `verifyMIC(...)` | `LoraPacket::verify_mic_v1_0(...)` / `_v1_1(...)` |
| `recalculateMIC(...)` | `LoraPacket::recalculate_mic_v1_0(...)` / `_v1_1(...)` |

## Accessor map

| TS | Rust |
|----|------|
| `packet.getMType()` | `packet.m_type()` |
| `packet.getDir()` | `data.direction` |
| `packet.getFCnt()` | `data.f_cnt()` |
| `packet.getFPort()` | `data.f_port` |
| `packet.isDataMessage()` | `packet.is_data()` |
| `packet.isConfirmed()` | `packet.is_confirmed()` |
| `packet.isJoinRequestMessage()` | `packet.is_join_request()` |
| `packet.isJoinAcceptMessage()` | `packet.is_join_accept()` |
| `packet.isRejoinRequestMessage()` | `packet.is_rejoin_request()` |
| `packet.getBuffers()` | direct struct field access |
| `packet.getPHYPayload()` | `packet.to_wire()` |
| `packet.decryptFOpts(...)` | `data.decrypt_fopts(...)` |
| `packet.encryptFOpts(...)` | `data.encrypt_fopts(...)` |

This file is expanded in Task 13.3 with full call-site translations.
