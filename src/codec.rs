//! Wire-format codec for `LoRaWAN` packets.
//!
//! Parsing (`from_wire`), building (`builder()` / `to_wire`), and accessors.

use alloc::vec::Vec;

use crate::types::{AppEui, AppNonce, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, Mhdr, NetId};

/// A `LoRaWAN` `PHYPayload`, parsed into structured fields.
///
/// `LoraPacket` is always exactly one of the five message types described by
/// `Payload`. The variant carries every field that is meaningful for that
/// message type; fields that do not apply are not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoraPacket {
  /// Full wire bytes (MHDR + `MACPayload` + MIC).
  pub phy_payload: Vec<u8>,
  /// MAC header byte.
  pub mhdr: Mhdr,
  /// 4-byte message integrity code.
  pub mic: [u8; 4],
  /// Type-specific payload fields.
  pub payload: Payload,
}

/// Discriminated union over `LoRaWAN` message variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
  /// OTAA join request.
  JoinRequest(JoinRequest),
  /// Server-issued join accept.
  JoinAccept(JoinAccept),
  /// Confirmed or unconfirmed data, uplink or downlink.
  Data(Data),
  /// `LoRaWAN` 1.1 rejoin request (any of 3 types).
  RejoinRequest(RejoinRequest),
  /// Proprietary message body.
  Proprietary(Vec<u8>),
}

/// Fields of an OTAA Join Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
  /// Join EUI (`LoRaWAN` 1.1 spec name for `AppEUI`).
  pub join_eui: AppEui,
  /// Device EUI.
  pub dev_eui: DevEui,
  /// Device-generated nonce.
  pub dev_nonce: DevNonce,
}

/// Fields of a Join Accept (plaintext, after decrypt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinAccept {
  /// Server-generated nonce.
  pub join_nonce: AppNonce,
  /// Network ID.
  pub net_id: NetId,
  /// Assigned device address.
  pub dev_addr: DevAddr,
  /// Downlink settings (RX1 offset, RX2 data rate, `OptNeg`).
  pub dl_settings: DlSettings,
  /// RX1 delay in seconds.
  pub rx_delay: u8,
  /// Optional channel frequency list (16 bytes).
  pub cf_list: Option<[u8; 16]>,
  /// `LoRaWAN` 1.1 only: rejoin/join-request distinguisher.
  pub join_req_type: Option<u8>,
}

/// Fields of a Data message (confirmed/unconfirmed, uplink/downlink).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
  /// Direction inferred from `MType`.
  pub direction: Direction,
  /// `true` for `ConfirmedData{Up,Down}`.
  pub confirmed: bool,
  /// Device address.
  pub dev_addr: DevAddr,
  /// Frame control byte.
  pub f_ctrl: FCtrl,
  /// Wire bytes for the lower 16 bits of `FCnt` (caller tracks the upper 16).
  pub f_cnt: [u8; 2],
  /// MAC commands carried in `FOpts` (empty when none).
  pub f_opts: Vec<u8>,
  /// `FPort` byte (0 = MAC commands in `FRMPayload`; >0 = application data).
  pub f_port: Option<u8>,
  /// Encrypted or plaintext payload (encrypted on the wire; plaintext post-decrypt).
  pub frm_payload: Option<Vec<u8>>,
}

/// Rejoin Request body (`LoRaWAN` 1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejoinRequest {
  /// Type 0: `NetID` + `DevEUI` + `RJCount0`.
  Type0 {
    /// Network ID.
    net_id: NetId,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 0.
    rj_count_0: [u8; 2],
  },
  /// Type 1: `JoinEUI` + `DevEUI` + `RJCount1`.
  Type1 {
    /// Join EUI.
    join_eui: AppEui,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 1.
    rj_count_1: [u8; 2],
  },
  /// Type 2: `NetID` + `DevEUI` + `RJCount0`.
  Type2 {
    /// Network ID.
    net_id: NetId,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 0.
    rj_count_0: [u8; 2],
  },
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::types::MType;

  #[test]
  fn lora_packet_constructs_with_join_request_payload() {
    let p = LoraPacket {
      phy_payload: alloc::vec![0x00],
      mhdr: Mhdr::from_parts(MType::JoinRequest, 0),
      mic: [0u8; 4],
      payload: Payload::JoinRequest(JoinRequest {
        join_eui: AppEui::new([0u8; 8]),
        dev_eui: DevEui::new([0u8; 8]),
        dev_nonce: DevNonce::new([0u8; 2]),
      }),
    };
    assert!(matches!(p.payload, Payload::JoinRequest(_)));
  }
}
