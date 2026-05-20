//! CMAC-based message integrity codes for every `LoRaWAN` message type.

use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac};
use subtle::ConstantTimeEq;

use crate::types::{AppEui, AppKey, DevNonce, FNwkSIntKey, JSIntKey, NwkKey, NwkSKey, SNwkSIntKey};

/// `LoRaWAN` 1.0 key set required by MIC operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct V1_0MicKeys<'a> {
  /// `AppKey` for Join Request / Join Accept.
  pub app_key: Option<&'a AppKey>,
  /// `NwkSKey` for Data messages.
  pub nwk_s_key: Option<&'a NwkSKey>,
  /// Upper 16 bits of the data-frame `FCnt` (caller-tracked).
  pub f_cnt_msb: u16,
}

/// `LoRaWAN` 1.1 key set required by MIC operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct V1_1MicKeys<'a> {
  /// `NwkKey` for Join Request 1.1.
  pub nwk_key: Option<&'a NwkKey>,
  /// `JSIntKey` for Join Accept 1.1.
  pub js_int_key: Option<&'a JSIntKey>,
  /// `FNwkSIntKey` for Data uplink 1.1 (lower 2 MIC bytes).
  pub f_nwk_s_int_key: Option<&'a FNwkSIntKey>,
  /// `SNwkSIntKey` for Data uplink and downlink 1.1.
  pub s_nwk_s_int_key: Option<&'a SNwkSIntKey>,
  /// `JoinEUI` for Join Accept 1.1.
  pub join_eui: Option<AppEui>,
  /// `DevNonce` for Join Accept 1.1.
  pub dev_nonce: Option<DevNonce>,
  /// `JoinReqType` byte for Join Accept 1.1.
  pub join_req_type: Option<u8>,
  /// Upper 16 bits of the data-frame `FCnt` (caller-tracked).
  pub f_cnt_msb: u16,
  /// 4-byte `ConfFCntDown`||TxDr||TxCh context for Data 1.1.
  pub conf_fcnt_down_tx_dr_tx_ch: Option<[u8; 4]>,
}

/// Compute AES-CMAC-128 of `data` under `key` and return the first 4 bytes.
#[allow(dead_code)] // wired up in later tasks
pub(crate) fn cmac4(key: &[u8; 16], data: &[u8]) -> [u8; 4] {
  let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("16-byte AES key");
  mac.update(data);
  let tag = mac.finalize().into_bytes();
  let mut out = [0u8; 4];
  out.copy_from_slice(&tag[..4]);
  out
}

/// Constant-time MIC comparison.
#[allow(dead_code)] // wired up in later tasks
pub(crate) fn mic_eq(a: [u8; 4], b: [u8; 4]) -> bool {
  a.ct_eq(&b).into()
}

/// Compute the Join Request MIC.
///
/// Same algorithm for `LoRaWAN` 1.0 and 1.1; only the key differs (`AppKey`
/// for 1.0, `NwkKey` for 1.1). The CMAC input is `MHDR || JoinRequestBody`
/// (everything in `phy_payload` except the 4-byte MIC).
#[allow(dead_code)] // wired up in Task 8.8 dispatcher
pub(crate) fn calculate_join_request_mic(packet: &crate::codec::LoraPacket, key: &[u8; 16]) -> [u8; 4] {
  let bytes = &packet.phy_payload[..packet.phy_payload.len() - 4];
  cmac4(key, bytes)
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

  /// Mirror of __tests__/mic_test.ts: "should calculate & verify correct join request packet MIC in 1.1"
  #[test]
  fn join_request_mic_1_1_vector() {
    use crate::codec::LoraPacket;
    let bytes = hex_to_vec("00010000000000000001000000000000000ce83685eb17");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let nwk_key = NwkKey::new(hex_to_arr_16("01010101010101010101010101010101"));
    let mic = calculate_join_request_mic(&packet, nwk_key.as_bytes());
    assert_eq!(mic, [0x36, 0x85, 0xeb, 0x17]);
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
