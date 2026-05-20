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

#[cfg(test)]
mod tests {
  use super::*;

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
}
