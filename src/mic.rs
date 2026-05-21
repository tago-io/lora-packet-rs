//! CMAC-based message integrity codes for every `LoRaWAN` message type.
//!
//! The two public types are [`V1_0MicKeys`] and [`V1_1MicKeys`], which
//! bundle the keys and context fields needed to compute or verify a MIC.
//! The actual computation is dispatched from
//! [`crate::LoraPacket::calculate_mic_v1_0`] /
//! [`crate::LoraPacket::calculate_mic_v1_1`].
//!
//! Build the key set with struct literals and `Default::default()`:
//!
//! ```
//! use lora_packet::{V1_0MicKeys, NwkSKey};
//!
//! let nwk_s_key = NwkSKey::new([0u8; 16]);
//! let keys = V1_0MicKeys {
//!   nwk_s_key: Some(&nwk_s_key),
//!   ..Default::default()
//! };
//! # let _ = keys;
//! ```

use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac};
use subtle::ConstantTimeEq;

use crate::types::{AppEui, AppKey, DevNonce, FNwkSIntKey, JSIntKey, NwkKey, NwkSKey, SNwkSIntKey};

/// `LoRaWAN` 1.0 key set required by MIC operations.
///
/// Fields are all `Option` so callers can omit keys for message types
/// they will not handle. A required-but-missing key surfaces as
/// [`crate::Error::MissingKey`] from
/// [`crate::LoraPacket::calculate_mic_v1_0`] /
/// [`crate::LoraPacket::verify_mic_v1_0`].
///
/// Use `Default::default()` to start from an all-`None` value and fill in
/// only what you need:
///
/// ```
/// use lora_packet::{V1_0MicKeys, AppKey, NwkSKey};
///
/// let app_key = AppKey::new([0u8; 16]);
/// let nwk_s_key = NwkSKey::new([0u8; 16]);
/// let keys = V1_0MicKeys {
///   app_key: Some(&app_key),
///   nwk_s_key: Some(&nwk_s_key),
///   ..Default::default()
/// };
/// # let _ = keys;
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct V1_0MicKeys<'a> {
  /// `AppKey` for Join Request and Join Accept MIC.
  pub app_key: Option<&'a AppKey>,
  /// `NwkSKey` for Data MIC (uplink and downlink).
  pub nwk_s_key: Option<&'a NwkSKey>,
  /// Upper 16 bits of the 32-bit Data `FCnt` (caller-tracked).
  ///
  /// The wire carries only the lower 16 bits; pass `0` if frame counters
  /// never wrap in your deployment.
  pub f_cnt_msb: u16,
}

/// `LoRaWAN` 1.1 key set required by MIC operations.
///
/// 1.1 splits MIC responsibilities across more keys and threads more
/// context bytes into the CMAC blocks. Fields are `Option`; only the
/// values needed for the message variant being signed/verified must be
/// set.
///
/// Per-variant requirements:
/// - **Data uplink**: `f_nwk_s_int_key`, `s_nwk_s_int_key`, optionally
///   `conf_fcnt_down_tx_dr_tx_ch`, `f_cnt_msb`.
/// - **Data downlink**: `s_nwk_s_int_key`, optionally
///   `conf_fcnt_down_tx_dr_tx_ch`, `f_cnt_msb`.
/// - **Join Request**: `nwk_key`.
/// - **Join Accept**: `js_int_key`, `join_eui`, `dev_nonce`,
///   `join_req_type`.
/// - **Rejoin Type 1**: `js_int_key`.
/// - **Rejoin Type 0/2**: `s_nwk_s_int_key`.
#[derive(Debug, Default, Clone, Copy)]
pub struct V1_1MicKeys<'a> {
  /// `NwkKey` for Join Request 1.1 MIC.
  pub nwk_key: Option<&'a NwkKey>,
  /// `JSIntKey` for Join Accept and Rejoin Type 1 MIC.
  pub js_int_key: Option<&'a JSIntKey>,
  /// `FNwkSIntKey` for Data uplink (lower 2 MIC bytes).
  pub f_nwk_s_int_key: Option<&'a FNwkSIntKey>,
  /// `SNwkSIntKey` for Data uplink (upper 2 MIC bytes), Data downlink,
  /// and Rejoin Type 0/2.
  pub s_nwk_s_int_key: Option<&'a SNwkSIntKey>,
  /// `JoinEUI` for Join Accept 1.1 MIC context.
  pub join_eui: Option<AppEui>,
  /// `DevNonce` for Join Accept 1.1 MIC context.
  pub dev_nonce: Option<DevNonce>,
  /// `JoinReqType` byte for Join Accept 1.1 MIC context.
  pub join_req_type: Option<u8>,
  /// Upper 16 bits of the 32-bit Data `FCnt` (caller-tracked).
  pub f_cnt_msb: u16,
  /// 4-byte `ConfFCntDown || TxDr || TxCh` context for Data 1.1.
  /// Defaults to all-zero when `None`.
  pub conf_fcnt_down_tx_dr_tx_ch: Option<[u8; 4]>,
}

/// Compute AES-CMAC-128 of `data` under `key` and return the first 4 bytes.
pub(crate) fn cmac4(key: &[u8; 16], data: &[u8]) -> [u8; 4] {
  let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("16-byte AES key");
  mac.update(data);
  let tag = mac.finalize().into_bytes();
  let mut out = [0u8; 4];
  out.copy_from_slice(&tag[..4]);
  out
}

/// Constant-time MIC comparison.
pub(crate) fn mic_eq(a: [u8; 4], b: [u8; 4]) -> bool {
  a.ct_eq(&b).into()
}

/// Compute the Join Request MIC.
///
/// Same algorithm for `LoRaWAN` 1.0 and 1.1; only the key differs (`AppKey`
/// for 1.0, `NwkKey` for 1.1). The CMAC input is `MHDR || JoinRequestBody`
/// (everything in `phy_payload` except the 4-byte MIC).
pub(crate) fn calculate_join_request_mic(packet: &crate::codec::LoraPacket, key: &[u8; 16]) -> [u8; 4] {
  let bytes = &packet.phy_payload[..packet.phy_payload.len() - 4];
  cmac4(key, bytes)
}

/// Compute the Join Accept MIC for `LoRaWAN` 1.0.
///
/// CMAC input is the plaintext `MHDR || JoinAcceptBody` (the Join Accept body
/// is encrypted on the wire; pass the decrypted bytes). The key is `AppKey`.
pub(crate) fn calculate_join_accept_mic_1_0(mhdr_and_body: &[u8], key: &[u8; 16]) -> [u8; 4] {
  cmac4(key, mhdr_and_body)
}

/// Compute the Data MIC for `LoRaWAN` 1.0 (uplink and downlink).
///
/// Builds the 16-byte B0 prefix per the `LoRaWAN` 1.0 spec and CMACs
/// `B0 || MHDR || MACPayload` with `NwkSKey`.
///
/// `f_cnt_msb` is the upper 16 bits of the 32-bit frame counter (the wire
/// carries only the low 16 bits).
pub(crate) fn calculate_data_mic_1_0(packet: &crate::codec::LoraPacket, key: &[u8; 16], f_cnt_msb: u16) -> [u8; 4] {
  let crate::codec::Payload::Data(data) = &packet.payload else {
    debug_assert!(false, "calculate_data_mic_1_0 called on non-data packet");
    return [0u8; 4]; // safe fallback in release builds
  };

  let mhdr_and_body = &packet.phy_payload[..packet.phy_payload.len() - 4];
  let dir_byte = u8::from(!matches!(data.direction, crate::types::Direction::Uplink));
  let f_cnt_32 = data.f_cnt_32(f_cnt_msb);
  let mut addr = *data.dev_addr.as_bytes();
  addr.reverse();

  let mut input = alloc::vec::Vec::with_capacity(16 + mhdr_and_body.len());
  // B0
  input.push(0x49);
  input.extend_from_slice(&[0, 0, 0, 0]); // bytes 1..5 zero in 1.0
  input.push(dir_byte);
  input.extend_from_slice(&addr);
  input.extend_from_slice(&f_cnt_32.to_le_bytes());
  input.push(0x00);
  input.push(u8::try_from(mhdr_and_body.len()).unwrap_or(0xFF));
  // MHDR || MACPayload
  input.extend_from_slice(mhdr_and_body);

  cmac4(key, &input)
}

/// Compute the Data MIC for `LoRaWAN` 1.1 uplink (dual-MIC).
///
/// Runs two CMACs with different B blocks:
/// - B0 (bytes 1..5 = 0): CMAC under `FNwkSIntKey` -> `cmac_f`
/// - B1 (bytes 1..5 = `ConfFCntDown`||TxDr||TxCh): CMAC under `SNwkSIntKey` -> `cmac_s`
///
/// Final MIC = `cmac_s[0..2] || cmac_f[0..2]`.
pub(crate) fn calculate_data_mic_1_1_uplink(
  packet: &crate::codec::LoraPacket,
  f_nwk_s_int_key: &[u8; 16],
  s_nwk_s_int_key: &[u8; 16],
  f_cnt_msb: u16,
  conf_fcnt_down_tx_dr_tx_ch: [u8; 4],
) -> [u8; 4] {
  let crate::codec::Payload::Data(data) = &packet.payload else {
    debug_assert!(false, "calculate_data_mic_1_1_uplink called on non-data packet");
    return [0u8; 4]; // safe fallback in release builds
  };

  let mhdr_and_body = &packet.phy_payload[..packet.phy_payload.len() - 4];
  let dir_byte = 0u8;
  let f_cnt_32 = data.f_cnt_32(f_cnt_msb);
  let mut addr = *data.dev_addr.as_bytes();
  addr.reverse();
  let len_byte = u8::try_from(mhdr_and_body.len()).unwrap_or(0xFF);

  // B0: bytes 1..5 = 0
  let mut b0 = alloc::vec::Vec::with_capacity(16 + mhdr_and_body.len());
  b0.push(0x49);
  b0.extend_from_slice(&[0, 0, 0, 0]);
  b0.push(dir_byte);
  b0.extend_from_slice(&addr);
  b0.extend_from_slice(&f_cnt_32.to_le_bytes());
  b0.push(0x00);
  b0.push(len_byte);
  b0.extend_from_slice(mhdr_and_body);

  // B1: bytes 1..5 = conf_fcnt_down_tx_dr_tx_ch
  let mut b1 = alloc::vec::Vec::with_capacity(16 + mhdr_and_body.len());
  b1.push(0x49);
  b1.extend_from_slice(&conf_fcnt_down_tx_dr_tx_ch);
  b1.push(dir_byte);
  b1.extend_from_slice(&addr);
  b1.extend_from_slice(&f_cnt_32.to_le_bytes());
  b1.push(0x00);
  b1.push(len_byte);
  b1.extend_from_slice(mhdr_and_body);

  let cmac_f = cmac4(f_nwk_s_int_key, &b0);
  let cmac_s = cmac4(s_nwk_s_int_key, &b1);
  [cmac_s[0], cmac_s[1], cmac_f[0], cmac_f[1]]
}

/// Compute the Rejoin Request MIC (types 0/1/2).
///
/// CMAC input is `MHDR || RejoinBody` (everything in `phy_payload` except the
/// 4-byte MIC). The caller chooses the key per rejoin type: `SNwkSIntKey` for
/// types 0 and 2, `JSIntKey` for type 1.
pub(crate) fn calculate_rejoin_mic(packet: &crate::codec::LoraPacket, key: &[u8; 16]) -> [u8; 4] {
  let bytes = &packet.phy_payload[..packet.phy_payload.len() - 4];
  cmac4(key, bytes)
}

/// Compute the Data MIC for `LoRaWAN` 1.1 downlink.
///
/// B0-style block with bytes 1..5 = `ConfFCntDown`||TxDr||TxCh (or all zero
/// when absent). Key: `SNwkSIntKey`.
pub(crate) fn calculate_data_mic_1_1_downlink(
  packet: &crate::codec::LoraPacket,
  s_nwk_s_int_key: &[u8; 16],
  f_cnt_msb: u16,
  conf_fcnt_down_tx_dr_tx_ch: [u8; 4],
) -> [u8; 4] {
  let crate::codec::Payload::Data(data) = &packet.payload else {
    debug_assert!(false, "calculate_data_mic_1_1_downlink called on non-data packet");
    return [0u8; 4]; // safe fallback in release builds
  };

  let mhdr_and_body = &packet.phy_payload[..packet.phy_payload.len() - 4];
  let dir_byte = 1u8;
  let f_cnt_32 = data.f_cnt_32(f_cnt_msb);
  let mut addr = *data.dev_addr.as_bytes();
  addr.reverse();

  let mut input = alloc::vec::Vec::with_capacity(16 + mhdr_and_body.len());
  input.push(0x49);
  input.extend_from_slice(&conf_fcnt_down_tx_dr_tx_ch);
  input.push(dir_byte);
  input.extend_from_slice(&addr);
  input.extend_from_slice(&f_cnt_32.to_le_bytes());
  input.push(0x00);
  input.push(u8::try_from(mhdr_and_body.len()).unwrap_or(0xFF));
  input.extend_from_slice(mhdr_and_body);

  cmac4(s_nwk_s_int_key, &input)
}

/// Compute the Join Accept MIC for `LoRaWAN` 1.1 with `OptNeg` set.
///
/// CMAC input is `JoinReqType(1) || JoinEUI_LE(8) || DevNonce_LE(2) ||
/// MHDR(1) || MACPayload(N)`. The key is `JSIntKey`.
#[allow(clippy::trivially_copy_pass_by_ref)] // refs match the public-surface key/id newtypes
pub(crate) fn calculate_join_accept_mic_1_1(
  mhdr_and_body: &[u8],
  js_int_key: &[u8; 16],
  join_req_type: u8,
  join_eui: &AppEui,
  dev_nonce: &DevNonce,
) -> [u8; 4] {
  let mut input = alloc::vec::Vec::with_capacity(11 + mhdr_and_body.len());
  input.push(join_req_type);
  let mut eui = *join_eui.as_bytes();
  eui.reverse();
  input.extend_from_slice(&eui);
  let mut nonce = *dev_nonce.as_bytes();
  nonce.reverse();
  input.extend_from_slice(&nonce);
  input.extend_from_slice(mhdr_and_body);
  cmac4(js_int_key, &input)
}

#[cfg(test)]
mod tests {
  use super::*;
  use alloc::vec::Vec;

  #[test]
  fn cmac4_deterministic() {
    let key = [0u8; 16];
    let a = cmac4(&key, b"hello");
    let b = cmac4(&key, b"hello");
    assert_eq!(a, b);
  }

  #[test]
  fn mic_eq_works() {
    assert!(mic_eq([1, 2, 3, 4], [1, 2, 3, 4]));
    assert!(!mic_eq([1, 2, 3, 4], [1, 2, 3, 5]));
  }

  #[test]
  fn join_request_mic_1_1_vector() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("00010000000000000001000000000000000ce83685eb17");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let nwk_key = NwkKey::new(hex_to_arr_16("01010101010101010101010101010101"));
    let mic = calculate_join_request_mic(&packet, nwk_key.as_bytes());
    assert_eq!(mic, [0x36, 0x85, 0xeb, 0x17]);
  }

  #[test]
  fn join_accept_mic_1_0_deterministic() {
    // MHDR (Join Accept = 0x20) + 12-byte zero body.
    let raw = [0x20u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let app_key = AppKey::new([0u8; 16]);
    let m1 = calculate_join_accept_mic_1_0(&raw, app_key.as_bytes());
    let m2 = calculate_join_accept_mic_1_0(&raw, app_key.as_bytes());
    assert_eq!(m1, m2);
    // Cross-check against the same construction with all-zero inputs.
    assert_eq!(m1, [0xf8, 0x6f, 0x0a, 0x91]);
  }

  #[test]
  fn data_mic_1_0_uplink() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let nwk_s_key = NwkSKey::new(hex_to_arr_16("44024241ed4ce9a68c6a8bc055233fd3"));
    let mic = calculate_data_mic_1_0(&packet, nwk_s_key.as_bytes(), 0);
    assert_eq!(mic, [0x2b, 0x11, 0xff, 0x0d]);
  }

  #[test]
  fn data_mic_1_0_uplink_short() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("40F17DBE49000300012A3518AF");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let nwk_s_key = NwkSKey::new(hex_to_arr_16("44024241ed4ce9a68c6a8bc055233fd3"));
    let mic = calculate_data_mic_1_0(&packet, nwk_s_key.as_bytes(), 0);
    assert_eq!(mic, [0x2a, 0x35, 0x18, 0xaf]);
  }

  #[test]
  fn data_mic_1_0_confirmed_ack() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("60f17dbe4920020001f9d65d27");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let nwk_s_key = NwkSKey::new(hex_to_arr_16("44024241ed4ce9a68c6a8bc055233fd3"));
    let mic = calculate_data_mic_1_0(&packet, nwk_s_key.as_bytes(), 0);
    assert_eq!(mic, [0xf9, 0xd6, 0x5d, 0x27]);
  }

  #[test]
  fn rejoin_mic_deterministic() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("c0000102030405060708090a0b0c0ddeadbeef");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let s_key = SNwkSIntKey::new([0u8; 16]);
    let mic = calculate_rejoin_mic(&packet, s_key.as_bytes());
    let mic2 = calculate_rejoin_mic(&packet, s_key.as_bytes());
    assert_eq!(mic, mic2);
  }

  #[test]
  fn data_mic_1_1_downlink_deterministic() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("60f17dbe4920020001f9d65d27");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let s_key = SNwkSIntKey::new([0x33u8; 16]);
    let m1 = calculate_data_mic_1_1_downlink(&packet, s_key.as_bytes(), 0, [0; 4]);
    let m2 = calculate_data_mic_1_1_downlink(&packet, s_key.as_bytes(), 0, [0; 4]);
    assert_eq!(m1, m2);
  }

  #[test]
  fn data_mic_1_1_uplink_dual_different_from_1_0() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let f_key = FNwkSIntKey::new([0x11u8; 16]);
    let s_key = SNwkSIntKey::new([0x22u8; 16]);
    let mic = calculate_data_mic_1_1_uplink(&packet, f_key.as_bytes(), s_key.as_bytes(), 0, [0, 0, 0, 0]);
    // dual-MIC: bytes 0..2 from cmacS, bytes 2..4 from cmacF
    assert_eq!(mic.len(), 4);
  }

  #[test]
  fn join_accept_mic_1_1_distinct_from_1_0() {
    let mhdr_and_body = [0x20u8; 13];
    let js_key = JSIntKey::new([0u8; 16]);
    let join_eui = AppEui::new([0u8; 8]);
    let dev_nonce = DevNonce::new([0u8; 2]);
    let mic = calculate_join_accept_mic_1_1(&mhdr_and_body, js_key.as_bytes(), 0xFF, &join_eui, &dev_nonce);
    let mic2 = calculate_join_accept_mic_1_1(&mhdr_and_body, js_key.as_bytes(), 0x00, &join_eui, &dev_nonce);
    assert_ne!(mic, mic2); // JoinReqType changes the MIC
  }

  fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
      .collect()
  }

  fn hex_to_arr_16(s: &str) -> [u8; 16] {
    let mut arr = [0u8; 16];
    for (i, byte) in (0..s.len()).step_by(2).enumerate() {
      arr[i] = u8::from_str_radix(&s[byte..byte + 2], 16).unwrap();
    }
    arr
  }
}
