//! Wire-format codec for `LoRaWAN` packets.
//!
//! Two halves to the API:
//!
//! - **Parsing**: [`LoraPacket::from_wire`] takes raw bytes and returns a
//!   typed [`LoraPacket`]. Match on [`LoraPacket::payload`] (a [`Payload`]
//!   enum) to dispatch on the message variant.
//! - **Building**: [`LoraPacket::builder`] returns a [`LoraPacketBuilder`]
//!   that finalises with [`LoraPacketBuilder::sign_and_encrypt`] (Data),
//!   [`LoraPacketBuilder::sign_join_request`] (Join Request 1.0),
//!   [`LoraPacketBuilder::sign_join_request_v1_1`] (Join Request 1.1), or
//!   [`LoraPacketBuilder::sign_join_accept`] (Join Accept).
//!
//! All wire bytes are little-endian; struct fields display in big-endian
//! order. The codec reverses bytes for you on both parse and serialise.

use alloc::vec::Vec;

use crate::types::{AppEui, AppNonce, DevAddr, DevEui, DevNonce, Direction, DlSettings, FCtrl, MType, Mhdr, NetId};

/// A `LoRaWAN` `PHYPayload`, parsed into structured fields.
///
/// `LoraPacket` is always exactly one of the five message types described by
/// [`Payload`]. The variant carries every field that is meaningful for that
/// message type; fields that do not apply are not representable.
///
/// Construct from wire bytes with [`from_wire`](Self::from_wire), or compose
/// from fields with [`builder`](Self::builder).
///
/// # Examples
///
/// Parse and dispatch on the message variant:
///
/// ```
/// use lora_packet::{LoraPacket, Payload};
///
/// let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
/// let packet = LoraPacket::from_wire(&bytes)?;
///
/// match &packet.payload {
///   Payload::Data(d) => {
///     assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
///     assert_eq!(d.f_cnt(), 2);
///   }
///   Payload::JoinRequest(_) => unreachable!(),
///   Payload::JoinAccept(_) => unreachable!(),
///   Payload::RejoinRequest(_) => unreachable!(),
///   Payload::Proprietary(_) => unreachable!(),
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoraPacket {
  /// Full wire bytes (MHDR + `MACPayload` + MIC).
  ///
  /// Kept around so that MIC re-computation does not need to re-serialise.
  /// [`to_wire`](Self::to_wire) rebuilds these bytes from the typed fields.
  pub phy_payload: Vec<u8>,
  /// MAC header byte.
  pub mhdr: Mhdr,
  /// 4-byte message integrity code (the last 4 bytes of `phy_payload`).
  pub mic: [u8; 4],
  /// Type-specific payload fields. See [`Payload`].
  pub payload: Payload,
}

/// Discriminated union over the five `LoRaWAN` message variants.
///
/// The variant is always determined by [`LoraPacket::m_type`] / the MHDR.
/// Use the [`LoraPacket::as_data`] / [`LoraPacket::as_join_request`]
/// helpers when you want to peek without an exhaustive match.
///
/// # Examples
///
/// ```
/// use lora_packet::{LoraPacket, Payload};
///
/// let bytes = hex::decode("0039363463336913aa05693574323831338ef1c1d5ec6c")?;
/// let packet = LoraPacket::from_wire(&bytes)?;
///
/// if let Payload::JoinRequest(jr) = &packet.payload {
///   assert_eq!(jr.dev_nonce.as_bytes(), &[0xf1, 0x8e]);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Payload {
  /// OTAA Join Request.
  JoinRequest(JoinRequest),
  /// Server-issued Join Accept (plaintext fields; the wire form is encrypted).
  JoinAccept(JoinAccept),
  /// Confirmed or unconfirmed Data frame, uplink or downlink.
  Data(Data),
  /// `LoRaWAN` 1.1 Rejoin Request (one of three types).
  RejoinRequest(RejoinRequest),
  /// Proprietary message body (opaque bytes).
  Proprietary(Vec<u8>),
}

/// Fields of an OTAA Join Request.
///
/// Returned by [`LoraPacket::from_wire`] when the MHDR indicates
/// [`MType::JoinRequest`]; the MIC is verified separately with
/// [`LoraPacket::verify_mic_v1_0`] (using `AppKey`) or
/// [`LoraPacket::verify_mic_v1_1`] (using `NwkKey`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct JoinRequest {
  /// Join EUI (`AppEUI` in 1.0 nomenclature, `JoinEUI` in 1.1).
  pub join_eui: AppEui,
  /// Device EUI (IEEE EUI-64).
  pub dev_eui: DevEui,
  /// Device-generated random nonce; must not repeat per the spec.
  pub dev_nonce: DevNonce,
}

/// Fields of a Join Accept (plaintext, after decrypt).
///
/// On the wire, the body of a Join Accept is AES-ECB encrypted. Use
/// [`JoinAccept::decrypt_from_wire`] to turn wire bytes into this struct,
/// or [`JoinAccept::encrypt_for_wire`] to go the other direction (server
/// side).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct JoinAccept {
  /// Server-generated random nonce (`AppNonce` in 1.0, `JoinNonce` in 1.1).
  pub join_nonce: AppNonce,
  /// Network ID.
  pub net_id: NetId,
  /// `DevAddr` assigned to the device.
  pub dev_addr: DevAddr,
  /// Downlink settings (RX1 offset, RX2 data rate, `OptNeg`).
  pub dl_settings: DlSettings,
  /// RX1 delay, in seconds.
  pub rx_delay: u8,
  /// Optional Channel-Frequency List (16 bytes); only present in some
  /// regional plans.
  pub cf_list: Option<[u8; 16]>,
  /// 1.1 only: `JoinReqType` byte threaded into the 1.1 Join Accept MIC.
  /// `None` on parsed packets; set explicitly when re-signing a 1.1 frame.
  pub join_req_type: Option<u8>,
}

/// Fields of a Data message (confirmed or unconfirmed, uplink or downlink).
///
/// `FRMPayload` is encrypted on the wire; call
/// [`Data::decrypt_payload`] to recover the plaintext. MAC commands in
/// `FOpts` are encrypted only in `LoRaWAN` 1.1; call
/// [`Data::decrypt_fopts`] when applicable.
///
/// # Frame counters
///
/// The wire carries only the lower 16 bits of the 32-bit `FCnt`. The caller
/// tracks the upper 16 bits and passes it to [`Data::f_cnt_32`] and to
/// every crypt / MIC call. Pass `0` for sessions that never wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Data {
  /// Frame direction, inferred from `MType`.
  pub direction: Direction,
  /// `true` for `ConfirmedData{Up,Down}`.
  pub confirmed: bool,
  /// Device address.
  pub dev_addr: DevAddr,
  /// Frame-control byte.
  pub f_ctrl: FCtrl,
  /// Lower 16 bits of `FCnt` as on the wire (little-endian).
  ///
  /// Use [`Data::f_cnt`] for a `u16` value or [`Data::f_cnt_32`] for the
  /// full 32-bit counter with a caller-supplied upper half.
  pub f_cnt: [u8; 2],
  /// MAC commands carried in `FOpts` (empty when none); up to 15 bytes.
  /// Encrypted with `NwkSEncKey` in 1.1; plaintext in 1.0.
  pub f_opts: Vec<u8>,
  /// `FPort` byte. `Some(0)` means `FRMPayload` carries MAC commands;
  /// `Some(p)` with `p > 0` means application data; `None` when neither
  /// `FPort` nor `FRMPayload` is present.
  pub f_port: Option<u8>,
  /// `FRMPayload`. Encrypted on the wire; replace with plaintext after
  /// [`Data::decrypt_payload`].
  pub frm_payload: Option<Vec<u8>>,
}

/// Rejoin Request body (`LoRaWAN` 1.1).
///
/// Type 0/2 trigger a rejoin to the same network; type 1 triggers a rejoin
/// to a different `JoinEUI` (a roaming hand-off). Each type uses a different
/// MIC key (see [`LoraPacket::calculate_mic_v1_1`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RejoinRequest {
  /// Type 0: `NetID || DevEUI || RJCount0`. MIC key: `SNwkSIntKey`.
  Type0 {
    /// Network ID.
    net_id: NetId,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 0.
    rj_count_0: [u8; 2],
  },
  /// Type 1: `JoinEUI || DevEUI || RJCount1`. MIC key: `JSIntKey`.
  Type1 {
    /// Join EUI.
    join_eui: AppEui,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 1.
    rj_count_1: [u8; 2],
  },
  /// Type 2: `NetID || DevEUI || RJCount0`. MIC key: `SNwkSIntKey`.
  Type2 {
    /// Network ID.
    net_id: NetId,
    /// Device EUI.
    dev_eui: DevEui,
    /// Rejoin counter 0.
    rj_count_0: [u8; 2],
  },
}

impl LoraPacket {
  /// Message type from the MHDR.
  ///
  /// # Panics
  /// Never panics on a `LoraPacket` produced by [`from_wire`](Self::from_wire)
  /// or the builder; both reject invalid `MType` bytes up front. When a
  /// `LoraPacket` is struct-constructed directly with an invalid `Mhdr` byte,
  /// this method will panic. Prefer construction via `from_wire` or
  /// `builder()`.
  pub fn m_type(&self) -> MType {
    self.mhdr.m_type().expect("LoraPacket MHDR always has a valid MType")
  }

  /// `true` for any data frame (confirmed or unconfirmed, uplink or downlink).
  pub const fn is_data(&self) -> bool {
    matches!(self.payload, Payload::Data(_))
  }

  /// `true` for `ConfirmedDataUp` or `ConfirmedDataDown`.
  pub fn is_confirmed(&self) -> bool {
    matches!(self.m_type(), MType::ConfirmedDataUp | MType::ConfirmedDataDown)
  }

  /// `true` for Join Request.
  pub const fn is_join_request(&self) -> bool {
    matches!(self.payload, Payload::JoinRequest(_))
  }

  /// `true` for Join Accept.
  pub const fn is_join_accept(&self) -> bool {
    matches!(self.payload, Payload::JoinAccept(_))
  }

  /// `true` for Rejoin Request.
  pub const fn is_rejoin_request(&self) -> bool {
    matches!(self.payload, Payload::RejoinRequest(_))
  }

  /// Borrow as [`Data`] if this is a data frame, else `None`.
  pub const fn as_data(&self) -> Option<&Data> {
    if let Payload::Data(d) = &self.payload {
      Some(d)
    } else {
      None
    }
  }

  /// Mutably borrow as [`Data`] if this is a data frame.
  pub const fn as_data_mut(&mut self) -> Option<&mut Data> {
    if let Payload::Data(d) = &mut self.payload {
      Some(d)
    } else {
      None
    }
  }

  /// Borrow as [`JoinRequest`] if applicable, else `None`.
  pub const fn as_join_request(&self) -> Option<&JoinRequest> {
    if let Payload::JoinRequest(j) = &self.payload {
      Some(j)
    } else {
      None
    }
  }

  /// Borrow as [`JoinAccept`] if applicable, else `None`.
  pub const fn as_join_accept(&self) -> Option<&JoinAccept> {
    if let Payload::JoinAccept(j) = &self.payload {
      Some(j)
    } else {
      None
    }
  }

  /// Borrow as [`RejoinRequest`] if applicable, else `None`.
  pub const fn as_rejoin_request(&self) -> Option<&RejoinRequest> {
    if let Payload::RejoinRequest(r) = &self.payload {
      Some(r)
    } else {
      None
    }
  }

  /// Verify the MIC using the `LoRaWAN` 1.0 key set.
  ///
  /// Compares against `self.mic` in constant time
  /// (via `subtle::ConstantTimeEq`). Returns `Ok(true)` on match,
  /// `Ok(false)` on mismatch, and an error only if a required key is
  /// missing from `keys`.
  ///
  /// # Errors
  /// [`crate::Error::MissingKey`] if a required key for the message type is
  /// not in `keys` (e.g. `nwk_s_key` for a Data frame).
  ///
  /// # Examples
  ///
  /// ```
  /// use lora_packet::{LoraPacket, NwkSKey, V1_0MicKeys};
  ///
  /// let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
  /// let packet = LoraPacket::from_wire(&bytes)?;
  /// let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
  /// let keys = V1_0MicKeys { nwk_s_key: Some(&nwk_s_key), ..Default::default() };
  /// assert!(packet.verify_mic_v1_0(&keys)?);
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  pub fn verify_mic_v1_0(&self, keys: &crate::mic::V1_0MicKeys<'_>) -> crate::Result<bool> {
    let calculated = self.calculate_mic_v1_0(keys)?;
    Ok(crate::mic::mic_eq(calculated, self.mic))
  }

  /// Verify the MIC using the `LoRaWAN` 1.1 key set.
  ///
  /// 1.1 uplinks use a dual-MIC construction with both `FNwkSIntKey` and
  /// `SNwkSIntKey`; downlinks use `SNwkSIntKey` only. Join Accept frames
  /// also need `join_eui`, `dev_nonce`, and `join_req_type` in the keyset.
  ///
  /// # Errors
  /// [`crate::Error::MissingKey`] if a required key for the message type is
  /// not in `keys`.
  pub fn verify_mic_v1_1(&self, keys: &crate::mic::V1_1MicKeys<'_>) -> crate::Result<bool> {
    let calculated = self.calculate_mic_v1_1(keys)?;
    Ok(crate::mic::mic_eq(calculated, self.mic))
  }

  /// Calculate the MIC under `LoRaWAN` 1.0 without overwriting `self.mic`.
  ///
  /// Useful when you want to compare against an expected value without
  /// running [`Self::verify_mic_v1_0`], or when you need to record both the
  /// computed MIC and the received MIC for debugging.
  ///
  /// # Errors
  /// - [`crate::Error::MissingKey`] if a required key for the message type
  ///   is not in `keys`.
  /// - [`crate::Error::UnsupportedForVersion`] if the payload is a Rejoin
  ///   Request or Proprietary frame (both 1.1-only).
  pub fn calculate_mic_v1_0(&self, keys: &crate::mic::V1_0MicKeys<'_>) -> crate::Result<[u8; 4]> {
    match &self.payload {
      Payload::Data(_) => {
        let key = keys
          .nwk_s_key
          .ok_or(crate::Error::MissingKey("nwk_s_key required for Data MIC"))?;
        Ok(crate::mic::calculate_data_mic_1_0(self, key.as_bytes(), keys.f_cnt_msb))
      }
      Payload::JoinRequest(_) => {
        let key = keys
          .app_key
          .ok_or(crate::Error::MissingKey("app_key required for Join Request MIC"))?;
        Ok(crate::mic::calculate_join_request_mic(self, key.as_bytes()))
      }
      Payload::JoinAccept(_) => {
        let key = keys
          .app_key
          .ok_or(crate::Error::MissingKey("app_key required for Join Accept MIC"))?;
        let mhdr_and_body = &self.phy_payload[..self.phy_payload.len() - 4];
        Ok(crate::mic::calculate_join_accept_mic_1_0(mhdr_and_body, key.as_bytes()))
      }
      Payload::RejoinRequest(_) | Payload::Proprietary(_) => Err(crate::Error::UnsupportedForVersion(
        "Rejoin Request and Proprietary frames are 1.1-only; use calculate_mic_v1_1",
      )),
    }
  }

  /// Calculate the MIC under `LoRaWAN` 1.1 without overwriting `self.mic`.
  ///
  /// Dispatches by `MType` and direction:
  /// - Data uplink: dual-MIC with `FNwkSIntKey` + `SNwkSIntKey`.
  /// - Data downlink: single MIC with `SNwkSIntKey`.
  /// - Join Request: `NwkKey`.
  /// - Join Accept: `JSIntKey` + `JoinEUI` + `DevNonce` + `JoinReqType`.
  /// - Rejoin Type 1: `JSIntKey`.
  /// - Rejoin Type 0/2: `SNwkSIntKey`.
  ///
  /// # Errors
  /// [`crate::Error::MissingKey`] if a required key (or context field) for
  /// the message type is not in `keys`.
  pub fn calculate_mic_v1_1(&self, keys: &crate::mic::V1_1MicKeys<'_>) -> crate::Result<[u8; 4]> {
    match &self.payload {
      Payload::Data(d) => match d.direction {
        Direction::Uplink => {
          let f_key = keys.f_nwk_s_int_key.ok_or(crate::Error::MissingKey(
            "f_nwk_s_int_key required for Data uplink 1.1 MIC",
          ))?;
          let s_key = keys.s_nwk_s_int_key.ok_or(crate::Error::MissingKey(
            "s_nwk_s_int_key required for Data uplink 1.1 MIC",
          ))?;
          let conf = keys.conf_fcnt_down_tx_dr_tx_ch.unwrap_or([0, 0, 0, 0]);
          Ok(crate::mic::calculate_data_mic_1_1_uplink(
            self,
            f_key.as_bytes(),
            s_key.as_bytes(),
            keys.f_cnt_msb,
            conf,
          ))
        }
        Direction::Downlink => {
          let s_key = keys.s_nwk_s_int_key.ok_or(crate::Error::MissingKey(
            "s_nwk_s_int_key required for Data downlink 1.1 MIC",
          ))?;
          let conf = keys.conf_fcnt_down_tx_dr_tx_ch.unwrap_or([0, 0, 0, 0]);
          Ok(crate::mic::calculate_data_mic_1_1_downlink(
            self,
            s_key.as_bytes(),
            keys.f_cnt_msb,
            conf,
          ))
        }
      },
      Payload::JoinRequest(_) => {
        let key = keys
          .nwk_key
          .ok_or(crate::Error::MissingKey("nwk_key required for Join Request 1.1 MIC"))?;
        Ok(crate::mic::calculate_join_request_mic(self, key.as_bytes()))
      }
      Payload::JoinAccept(_) => {
        let js_key = keys
          .js_int_key
          .ok_or(crate::Error::MissingKey("js_int_key required for Join Accept 1.1 MIC"))?;
        let join_eui = keys
          .join_eui
          .ok_or(crate::Error::MissingKey("join_eui required for Join Accept 1.1 MIC"))?;
        let dev_nonce = keys
          .dev_nonce
          .ok_or(crate::Error::MissingKey("dev_nonce required for Join Accept 1.1 MIC"))?;
        let join_req_type = keys.join_req_type.unwrap_or(0xFF);
        let mhdr_and_body = &self.phy_payload[..self.phy_payload.len() - 4];
        Ok(crate::mic::calculate_join_accept_mic_1_1(
          mhdr_and_body,
          js_key.as_bytes(),
          join_req_type,
          &join_eui,
          &dev_nonce,
        ))
      }
      Payload::RejoinRequest(rj) => {
        let key = match rj {
          RejoinRequest::Type1 { .. } => keys
            .js_int_key
            .ok_or(crate::Error::MissingKey("js_int_key required for Rejoin Type 1 MIC"))?
            .as_bytes(),
          _ => keys
            .s_nwk_s_int_key
            .ok_or(crate::Error::MissingKey(
              "s_nwk_s_int_key required for Rejoin Type 0/2 MIC",
            ))?
            .as_bytes(),
        };
        Ok(crate::mic::calculate_rejoin_mic(self, key))
      }
      Payload::Proprietary(_) => Err(crate::Error::MissingKey("Proprietary has no defined MIC")),
    }
  }

  /// Recompute and overwrite the MIC under `LoRaWAN` 1.0.
  ///
  /// Also rewrites `phy_payload` so its trailing 4 bytes match the new MIC.
  /// Use after mutating fields on a parsed packet, or after building an
  /// unsigned packet you want to sign in place.
  ///
  /// # Errors
  /// [`crate::Error::MissingKey`] if a required key for the message type is
  /// not in `keys`.
  pub fn recalculate_mic_v1_0(&mut self, keys: &crate::mic::V1_0MicKeys<'_>) -> crate::Result<()> {
    let mic = self.calculate_mic_v1_0(keys)?;
    self.mic = mic;
    self.phy_payload = self.to_wire();
    Ok(())
  }

  /// Recompute and overwrite the MIC under `LoRaWAN` 1.1.
  ///
  /// Also rewrites `phy_payload` so its trailing 4 bytes match the new MIC.
  ///
  /// # Errors
  /// [`crate::Error::MissingKey`] if a required key for the message type is
  /// not in `keys`.
  pub fn recalculate_mic_v1_1(&mut self, keys: &crate::mic::V1_1MicKeys<'_>) -> crate::Result<()> {
    let mic = self.calculate_mic_v1_1(keys)?;
    self.mic = mic;
    self.phy_payload = self.to_wire();
    Ok(())
  }
}

impl Data {
  /// Lower 16 bits of `FCnt` as read from the wire (little-endian).
  ///
  /// The wire stores only the bottom 16 bits of the actual 32-bit counter.
  /// For the full counter use [`Data::f_cnt_32`] together with a
  /// caller-tracked upper half.
  pub const fn f_cnt(&self) -> u16 {
    u16::from_le_bytes(self.f_cnt)
  }

  /// Full 32-bit `FCnt`, combining the wire LSB16 with a caller-tracked MSB16.
  ///
  /// `msb` is the upper 16 bits the caller has been tracking. Pass `0` if
  /// frame counters never wrap in your deployment; otherwise increment
  /// `msb` each time the wire counter rolls over from `0xFFFF` to `0x0000`.
  pub const fn f_cnt_32(&self, msb: u16) -> u32 {
    ((msb as u32) << 16) | (self.f_cnt() as u32)
  }
}

impl LoraPacket {
  /// Parse a complete `PHYPayload` from wire bytes.
  ///
  /// This is the primary entry point for inbound traffic. The returned
  /// [`LoraPacket`] keeps the full wire bytes in
  /// [`LoraPacket::phy_payload`] so that MIC re-computation is cheap.
  ///
  /// Join Accept frames are encrypted on the wire and cannot be parsed
  /// directly. Use [`JoinAccept::decrypt_from_wire`] first, then either
  /// pass the result to [`JoinAccept::from_plaintext`] or work with the
  /// returned plaintext bytes directly.
  ///
  /// # Errors
  /// - [`crate::Error::TooShort`] if the buffer is shorter than the minimum
  ///   5 bytes (MHDR + MIC), or shorter than the per-variant minimum.
  /// - [`crate::Error::TooLong`] if the buffer exceeds the `LoRaWAN` PHY
  ///   maximum of 256 bytes.
  /// - [`crate::Error::InvalidMType`] if the MHDR encodes an unknown
  ///   `MType` (reserved for forward compatibility).
  /// - [`crate::Error::InvalidRejoinType`] if a Rejoin Request type byte is
  ///   not in {0, 1, 2}.
  /// - [`crate::Error::Other`] for a Join Accept input
  ///   (Join Accept needs `decrypt_from_wire`).
  ///
  /// # Examples
  ///
  /// ```
  /// use lora_packet::{LoraPacket, MType};
  ///
  /// let bytes = hex::decode("40f17dbe4900020001954378762b11ff0d")?;
  /// let packet = LoraPacket::from_wire(&bytes)?;
  ///
  /// assert!(packet.is_data());
  /// assert_eq!(packet.m_type(), MType::UnconfirmedDataUp);
  /// assert_eq!(packet.mic, [0x2b, 0x11, 0xff, 0x0d]);
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  pub fn from_wire(bytes: &[u8]) -> crate::Result<Self> {
    if bytes.len() < 5 {
      return Err(crate::Error::TooShort {
        expected: 5,
        got: bytes.len(),
      });
    }
    // LoRaWAN PHY payload never exceeds 256 bytes in any regional plan.
    // Reject larger buffers so the 1-byte length field in CMAC B0/B1
    // cannot silently wrap and produce a wrong-but-deterministic MIC.
    if bytes.len() > 256 {
      return Err(crate::Error::TooLong { got: bytes.len() });
    }
    let mhdr = Mhdr::new(bytes[0]);
    let mic_offset = bytes.len() - 4;
    let mut mic = [0u8; 4];
    mic.copy_from_slice(&bytes[mic_offset..]);
    let m_type = mhdr.m_type()?;
    let body = &bytes[1..mic_offset];

    let payload = match m_type {
      MType::JoinRequest => Payload::JoinRequest(parse_join_request(body)?),
      MType::JoinAccept => {
        return Err(crate::Error::Other(alloc::string::String::from(
          "JoinAccept parsing requires decrypt; use JoinAccept::decrypt_from_wire",
        )));
      }
      MType::UnconfirmedDataUp | MType::UnconfirmedDataDown | MType::ConfirmedDataUp | MType::ConfirmedDataDown => {
        Payload::Data(parse_data(m_type, body)?)
      }
      MType::RejoinRequest => Payload::RejoinRequest(parse_rejoin_request(body)?),
      MType::Proprietary => Payload::Proprietary(body.to_vec()),
    };

    Ok(Self {
      phy_payload: bytes.to_vec(),
      mhdr,
      mic,
      payload,
    })
  }

  /// Serialise back to wire bytes.
  ///
  /// Re-encodes the typed fields into the little-endian wire layout and
  /// appends `self.mic` unchanged. Call
  /// [`recalculate_mic_v1_0`](Self::recalculate_mic_v1_0) /
  /// [`recalculate_mic_v1_1`](Self::recalculate_mic_v1_1) first if you have
  /// mutated fields and need a fresh MIC.
  ///
  /// For round-trip parsing, the output of `from_wire(bytes).to_wire()`
  /// equals `bytes` (subject to MIC bytes being preserved).
  pub fn to_wire(&self) -> Vec<u8> {
    let mut out = Vec::with_capacity(self.phy_payload.len().max(13));
    out.push(self.mhdr.as_byte());
    match &self.payload {
      Payload::JoinRequest(jr) => {
        let mut tmp = *jr.join_eui.as_bytes();
        tmp.reverse();
        out.extend_from_slice(&tmp);
        let mut tmp = *jr.dev_eui.as_bytes();
        tmp.reverse();
        out.extend_from_slice(&tmp);
        let mut tmp = *jr.dev_nonce.as_bytes();
        tmp.reverse();
        out.extend_from_slice(&tmp);
      }
      Payload::Data(d) => {
        let mut tmp = *d.dev_addr.as_bytes();
        tmp.reverse();
        out.extend_from_slice(&tmp);
        out.push(d.f_ctrl.as_byte());
        out.extend_from_slice(&d.f_cnt);
        out.extend_from_slice(&d.f_opts);
        if let Some(p) = d.f_port {
          out.push(p);
        }
        if let Some(payload) = &d.frm_payload {
          out.extend_from_slice(payload);
        }
      }
      Payload::JoinAccept(ja) => {
        let mut tmp = *ja.join_nonce.as_bytes();
        tmp.reverse();
        out.extend_from_slice(&tmp);
        let mut tmp = *ja.net_id.as_bytes();
        tmp.reverse();
        out.extend_from_slice(&tmp);
        let mut tmp = *ja.dev_addr.as_bytes();
        tmp.reverse();
        out.extend_from_slice(&tmp);
        out.push(ja.dl_settings.as_byte());
        out.push(ja.rx_delay);
        if let Some(cf) = ja.cf_list {
          out.extend_from_slice(&cf);
        }
      }
      Payload::RejoinRequest(rj) => match rj {
        RejoinRequest::Type0 {
          net_id,
          dev_eui,
          rj_count_0,
        } => {
          out.push(0);
          let mut tmp = *net_id.as_bytes();
          tmp.reverse();
          out.extend_from_slice(&tmp);
          let mut tmp = *dev_eui.as_bytes();
          tmp.reverse();
          out.extend_from_slice(&tmp);
          let mut tmp = *rj_count_0;
          tmp.reverse();
          out.extend_from_slice(&tmp);
        }
        RejoinRequest::Type1 {
          join_eui,
          dev_eui,
          rj_count_1,
        } => {
          out.push(1);
          let mut tmp = *join_eui.as_bytes();
          tmp.reverse();
          out.extend_from_slice(&tmp);
          let mut tmp = *dev_eui.as_bytes();
          tmp.reverse();
          out.extend_from_slice(&tmp);
          let mut tmp = *rj_count_1;
          tmp.reverse();
          out.extend_from_slice(&tmp);
        }
        RejoinRequest::Type2 {
          net_id,
          dev_eui,
          rj_count_0,
        } => {
          out.push(2);
          let mut tmp = *net_id.as_bytes();
          tmp.reverse();
          out.extend_from_slice(&tmp);
          let mut tmp = *dev_eui.as_bytes();
          tmp.reverse();
          out.extend_from_slice(&tmp);
          let mut tmp = *rj_count_0;
          tmp.reverse();
          out.extend_from_slice(&tmp);
        }
      },
      Payload::Proprietary(b) => out.extend_from_slice(b),
    }
    out.extend_from_slice(&self.mic);
    out
  }
}

#[cfg(feature = "hex_base64")]
impl LoraPacket {
  /// Parse from a hex-encoded wire frame.
  ///
  /// # Errors
  /// [`crate::Error::Hex`] for invalid hex; otherwise any error from
  /// [`LoraPacket::from_wire`].
  pub fn from_hex(s: &str) -> crate::Result<Self> {
    let bytes = hex::decode(s)?;
    Self::from_wire(&bytes)
  }

  /// Parse from a standard base64-encoded wire frame.
  ///
  /// # Errors
  /// [`crate::Error::Base64`] for invalid base64; otherwise any error from
  /// [`LoraPacket::from_wire`].
  pub fn from_base64(s: &str) -> crate::Result<Self> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
    Self::from_wire(&bytes)
  }
}

impl JoinAccept {
  /// Parse an already-decrypted Join Accept (MHDR + body + MIC).
  ///
  /// Most callers start with encrypted wire bytes; use
  /// [`JoinAccept::decrypt_from_wire`] to decrypt first, then pass the
  /// resulting plaintext bytes here.
  ///
  /// Accepts both single-block (17 bytes total) and `CFList` (33 bytes
  /// total) Join Accept formats.
  ///
  /// # Errors
  /// [`crate::Error::TooShort`] if the total length is below 17 or the body
  /// length is neither 12 (no `CFList`) nor 28 bytes (with `CFList`).
  pub fn from_plaintext(bytes: &[u8]) -> crate::Result<Self> {
    if bytes.len() < 17 {
      return Err(crate::Error::TooShort {
        expected: 17,
        got: bytes.len(),
      });
    }
    let body = &bytes[1..bytes.len() - 4];
    if body.len() != 12 && body.len() != 28 {
      return Err(crate::Error::TooShort {
        expected: 12,
        got: body.len(),
      });
    }

    let mut join_nonce = [0u8; 3];
    join_nonce.copy_from_slice(&body[0..3]);
    join_nonce.reverse();
    let mut net_id = [0u8; 3];
    net_id.copy_from_slice(&body[3..6]);
    net_id.reverse();
    let mut dev_addr = [0u8; 4];
    dev_addr.copy_from_slice(&body[6..10]);
    dev_addr.reverse();
    let dl_settings = DlSettings(body[10]);
    let rx_delay = body[11];

    let cf_list = if body.len() == 28 {
      let mut cf = [0u8; 16];
      cf.copy_from_slice(&body[12..28]);
      Some(cf)
    } else {
      None
    };

    Ok(Self {
      join_nonce: AppNonce::new(join_nonce),
      net_id: NetId::new(net_id),
      dev_addr: DevAddr::new(dev_addr),
      dl_settings,
      rx_delay,
      cf_list,
      join_req_type: None,
    })
  }
}

fn parse_join_request(body: &[u8]) -> crate::Result<JoinRequest> {
  if body.len() != 18 {
    return Err(crate::Error::TooShort {
      expected: 18,
      got: body.len(),
    });
  }
  let mut app_eui = [0u8; 8];
  app_eui.copy_from_slice(&body[0..8]);
  app_eui.reverse();
  let mut dev_eui = [0u8; 8];
  dev_eui.copy_from_slice(&body[8..16]);
  dev_eui.reverse();
  let mut dev_nonce = [0u8; 2];
  dev_nonce.copy_from_slice(&body[16..18]);
  dev_nonce.reverse();

  Ok(JoinRequest {
    join_eui: AppEui::new(app_eui),
    dev_eui: DevEui::new(dev_eui),
    dev_nonce: DevNonce::new(dev_nonce),
  })
}

fn parse_data(m_type: MType, body: &[u8]) -> crate::Result<Data> {
  if body.len() < 7 {
    return Err(crate::Error::TooShort {
      expected: 7,
      got: body.len(),
    });
  }

  let mut dev_addr = [0u8; 4];
  dev_addr.copy_from_slice(&body[0..4]);
  dev_addr.reverse();
  let f_ctrl = FCtrl(body[4]);
  let mut f_cnt = [0u8; 2];
  f_cnt.copy_from_slice(&body[5..7]);

  let f_opts_len = f_ctrl.f_opts_len() as usize;
  if 7 + f_opts_len > body.len() {
    return Err(crate::Error::TooShort {
      expected: 7 + f_opts_len,
      got: body.len(),
    });
  }
  let f_opts = body[7..7 + f_opts_len].to_vec();

  let remainder_start = 7 + f_opts_len;
  let (f_port, frm_payload) = if remainder_start >= body.len() {
    (None, None)
  } else {
    let port = body[remainder_start];
    let payload = if remainder_start + 1 < body.len() {
      Some(body[remainder_start + 1..].to_vec())
    } else {
      Some(Vec::new())
    };
    (Some(port), payload)
  };

  let (direction, confirmed) = match m_type {
    MType::UnconfirmedDataUp => (Direction::Uplink, false),
    MType::ConfirmedDataUp => (Direction::Uplink, true),
    MType::UnconfirmedDataDown => (Direction::Downlink, false),
    MType::ConfirmedDataDown => (Direction::Downlink, true),
    _ => unreachable!("parse_data called with non-data MType"),
  };

  Ok(Data {
    direction,
    confirmed,
    dev_addr: DevAddr::new(dev_addr),
    f_ctrl,
    f_cnt,
    f_opts,
    f_port,
    frm_payload,
  })
}

/// Fluent builder for assembling a [`LoraPacket`] field by field.
///
/// Pick the message variant first with [`data`](Self::data),
/// [`join_request`](Self::join_request), [`join_accept`](Self::join_accept),
/// or [`rejoin_request`](Self::rejoin_request). Then set the per-variant
/// fields. Finalise with one of:
///
/// - [`build_unsigned`](Self::build_unsigned): emit a [`LoraPacket`] with
///   `mic = [0; 4]`. Sign later by calling
///   [`recalculate_mic_v1_0`](LoraPacket::recalculate_mic_v1_0) or
///   [`recalculate_mic_v1_1`](LoraPacket::recalculate_mic_v1_1).
/// - [`sign_and_encrypt`](Self::sign_and_encrypt): encrypt `FRMPayload` and
///   compute the 1.0 Data MIC.
/// - [`sign_join_request`](Self::sign_join_request) /
///   [`sign_join_request_v1_1`](Self::sign_join_request_v1_1): compute the
///   Join Request MIC.
/// - [`sign_join_accept`](Self::sign_join_accept): compute the Join Accept
///   MIC and encrypt the on-air form.
///
/// Every field is optional; required-field validation happens in
/// `build_unsigned` based on the selected variant.
#[derive(Debug, Default, Clone)]
pub struct LoraPacketBuilder {
  m_type: Option<MType>,
  major: u8,
  direction: Option<Direction>,
  confirmed: bool,
  dev_addr: Option<DevAddr>,
  f_ctrl: Option<FCtrl>,
  f_cnt: Option<u16>,
  f_opts: Vec<u8>,
  f_port: Option<u8>,
  payload: Option<Vec<u8>>,
  join_eui: Option<AppEui>,
  dev_eui: Option<DevEui>,
  dev_nonce: Option<DevNonce>,
  join_nonce: Option<AppNonce>,
  net_id: Option<NetId>,
  dl_settings: Option<DlSettings>,
  rx_delay: Option<u8>,
  cf_list: Option<[u8; 16]>,
  join_req_type: Option<u8>,
  rejoin_type: Option<u8>,
  rj_count_0: Option<[u8; 2]>,
  rj_count_1: Option<[u8; 2]>,
}

impl LoraPacket {
  /// Begin building a packet field by field.
  ///
  /// See [`LoraPacketBuilder`] for the full surface and finalisation
  /// methods.
  ///
  /// # Examples
  ///
  /// Build a Data uplink, encrypt, and sign in one expression:
  ///
  /// ```
  /// use lora_packet::{LoraPacket, Direction, DevAddr, AppSKey, NwkSKey};
  ///
  /// let app_s_key = AppSKey::new([0u8; 16]);
  /// let nwk_s_key = NwkSKey::new([0u8; 16]);
  /// let packet = LoraPacket::builder()
  ///   .data(Direction::Uplink, false)
  ///   .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
  ///   .f_cnt(2)
  ///   .f_port(1)
  ///   .payload(b"hi")
  ///   .sign_and_encrypt(&app_s_key, &nwk_s_key)?;
  /// assert!(packet.is_data());
  /// # Ok::<(), lora_packet::Error>(())
  /// ```
  ///
  /// Build and sign a Join Request:
  ///
  /// ```
  /// use lora_packet::{LoraPacket, AppKey, AppEui, DevEui, DevNonce};
  ///
  /// let app_key = AppKey::new([0u8; 16]);
  /// let packet = LoraPacket::builder()
  ///   .join_request()
  ///   .join_eui(AppEui::new([0u8; 8]))
  ///   .dev_eui(DevEui::new([0u8; 8]))
  ///   .dev_nonce(DevNonce::new([0u8; 2]))
  ///   .sign_join_request(&app_key)?;
  /// assert!(packet.is_join_request());
  /// # Ok::<(), lora_packet::Error>(())
  /// ```
  pub fn builder() -> LoraPacketBuilder {
    LoraPacketBuilder::default()
  }
}

impl LoraPacketBuilder {
  /// Set message type and direction for a Data message.
  #[must_use]
  pub const fn data(mut self, direction: Direction, confirmed: bool) -> Self {
    self.direction = Some(direction);
    self.confirmed = confirmed;
    self.m_type = Some(match (confirmed, direction) {
      (false, Direction::Uplink) => MType::UnconfirmedDataUp,
      (false, Direction::Downlink) => MType::UnconfirmedDataDown,
      (true, Direction::Uplink) => MType::ConfirmedDataUp,
      (true, Direction::Downlink) => MType::ConfirmedDataDown,
    });
    self
  }

  /// Begin a Join Request.
  #[must_use]
  pub const fn join_request(mut self) -> Self {
    self.m_type = Some(MType::JoinRequest);
    self
  }

  /// Begin a Join Accept.
  #[must_use]
  pub const fn join_accept(mut self) -> Self {
    self.m_type = Some(MType::JoinAccept);
    self
  }

  /// Begin a Rejoin Request with the given type (0, 1, or 2).
  #[must_use]
  pub const fn rejoin_request(mut self, rejoin_type: u8) -> Self {
    self.m_type = Some(MType::RejoinRequest);
    self.rejoin_type = Some(rejoin_type);
    self
  }

  /// Set `DevAddr` (Data and Join Accept).
  #[must_use]
  pub const fn dev_addr(mut self, addr: DevAddr) -> Self {
    self.dev_addr = Some(addr);
    self
  }

  /// Set `FCtrl` byte (Data).
  #[must_use]
  pub const fn f_ctrl(mut self, c: FCtrl) -> Self {
    self.f_ctrl = Some(c);
    self
  }

  /// Set `FCnt` (Data).
  #[must_use]
  pub const fn f_cnt(mut self, n: u16) -> Self {
    self.f_cnt = Some(n);
    self
  }

  /// Set `FOpts` MAC commands (Data).
  #[must_use]
  pub fn f_opts(mut self, opts: &[u8]) -> Self {
    self.f_opts = opts.to_vec();
    self
  }

  /// Set `FPort` (Data).
  #[must_use]
  pub const fn f_port(mut self, p: u8) -> Self {
    self.f_port = Some(p);
    self
  }

  /// Set `FRMPayload` plaintext (Data).
  #[must_use]
  pub fn payload(mut self, p: &[u8]) -> Self {
    self.payload = Some(p.to_vec());
    self
  }

  /// Set Join EUI (Join Request / Rejoin Type 1).
  #[must_use]
  pub const fn join_eui(mut self, e: AppEui) -> Self {
    self.join_eui = Some(e);
    self
  }

  /// Set Device EUI (Join Request / Rejoin).
  #[must_use]
  pub const fn dev_eui(mut self, e: DevEui) -> Self {
    self.dev_eui = Some(e);
    self
  }

  /// Set `DevNonce` (Join Request).
  #[must_use]
  pub const fn dev_nonce(mut self, n: DevNonce) -> Self {
    self.dev_nonce = Some(n);
    self
  }

  /// Set Join Nonce / `AppNonce` (Join Accept).
  #[must_use]
  pub const fn join_nonce(mut self, n: AppNonce) -> Self {
    self.join_nonce = Some(n);
    self
  }

  /// Set `NetID` (Join Accept / Rejoin Type 0/2).
  #[must_use]
  pub const fn net_id(mut self, id: NetId) -> Self {
    self.net_id = Some(id);
    self
  }

  /// Set `DLSettings` (Join Accept).
  #[must_use]
  pub const fn dl_settings(mut self, s: DlSettings) -> Self {
    self.dl_settings = Some(s);
    self
  }

  /// Set `RxDelay` (Join Accept).
  #[must_use]
  pub const fn rx_delay(mut self, r: u8) -> Self {
    self.rx_delay = Some(r);
    self
  }

  /// Set `CFList` (Join Accept).
  #[must_use]
  pub const fn cf_list(mut self, c: [u8; 16]) -> Self {
    self.cf_list = Some(c);
    self
  }

  /// Set `JoinReqType` (`LoRaWAN` 1.1 Join Accept MIC context).
  #[must_use]
  pub const fn join_req_type(mut self, t: u8) -> Self {
    self.join_req_type = Some(t);
    self
  }

  /// Set `RJcount0` (Rejoin Request Type 0 and Type 2).
  ///
  /// Stored little-endian on the wire. Defaults to 0 when not set.
  #[must_use]
  pub const fn rj_count_0(mut self, count: u16) -> Self {
    self.rj_count_0 = Some(count.to_le_bytes());
    self
  }

  /// Set `RJcount1` (Rejoin Request Type 1).
  ///
  /// Stored little-endian on the wire. Defaults to 0 when not set.
  #[must_use]
  pub const fn rj_count_1(mut self, count: u16) -> Self {
    self.rj_count_1 = Some(count.to_le_bytes());
    self
  }

  /// Build a Join Accept, compute the MIC, and produce the encrypted wire bytes.
  ///
  /// Returns `(plaintext_packet, encrypted_wire)`. The plaintext packet has
  /// MIC populated and `phy_payload` set to the plaintext form. The wire
  /// bytes are what you send over the air; the device will decrypt them back
  /// to the plaintext form.
  ///
  /// # Errors
  /// `Error::MissingField` if required Join Accept fields are missing.
  pub fn sign_join_accept(self, app_key: &crate::types::AppKey) -> crate::Result<(LoraPacket, alloc::vec::Vec<u8>)> {
    let mut packet = self.build_unsigned()?;
    let keys = crate::mic::V1_0MicKeys {
      app_key: Some(app_key),
      ..Default::default()
    };
    packet.recalculate_mic_v1_0(&keys)?;
    let encrypted_wire = JoinAccept::encrypt_for_wire(&packet.phy_payload, app_key)?;
    Ok((packet, encrypted_wire))
  }

  /// Build a Join Request and compute its MIC using `LoRaWAN` 1.0 `AppKey`.
  ///
  /// For `LoRaWAN` 1.1, use [`sign_join_request_v1_1`](Self::sign_join_request_v1_1)
  /// which takes a `NwkKey` directly.
  ///
  /// # Errors
  /// `Error::MissingField` if required fields are missing.
  pub fn sign_join_request(self, app_key: &crate::types::AppKey) -> crate::Result<LoraPacket> {
    let mut packet = self.build_unsigned()?;
    let keys = crate::mic::V1_0MicKeys {
      app_key: Some(app_key),
      ..Default::default()
    };
    packet.recalculate_mic_v1_0(&keys)?;
    Ok(packet)
  }

  /// Build a Join Request and compute its MIC using `LoRaWAN` 1.1 `NwkKey`.
  ///
  /// The CMAC algorithm is identical to 1.0; only the key changes.
  ///
  /// # Errors
  /// `Error::MissingField` if required fields are missing.
  pub fn sign_join_request_v1_1(self, nwk_key: &crate::types::NwkKey) -> crate::Result<LoraPacket> {
    let mut packet = self.build_unsigned()?;
    let keys = crate::mic::V1_1MicKeys {
      nwk_key: Some(nwk_key),
      ..Default::default()
    };
    packet.recalculate_mic_v1_1(&keys)?;
    Ok(packet)
  }

  /// Build a Data packet, encrypt `FRMPayload`, and compute the
  /// `LoRaWAN` 1.0 MIC in one shot.
  ///
  /// The plaintext payload provided via [`payload`](Self::payload) is
  /// encrypted with `AppSKey` (when `FPort > 0`) or `NwkSKey` (when
  /// `FPort == 0`). The MIC is then calculated under `NwkSKey` with the
  /// 1.0 algorithm.
  ///
  /// For 1.1 Data frames, build with [`build_unsigned`](Self::build_unsigned),
  /// encrypt manually with [`Data::encrypt_payload`], and sign with
  /// [`LoraPacket::recalculate_mic_v1_1`].
  ///
  /// # Errors
  /// - [`crate::Error::MissingField`] if required Data fields are missing.
  /// - [`crate::Error::PayloadTooLarge`] if `FRMPayload` exceeds 4080 bytes.
  /// - Any error from [`build_unsigned`](Self::build_unsigned) or
  ///   [`LoraPacket::recalculate_mic_v1_0`].
  ///
  /// # Examples
  ///
  /// ```
  /// use lora_packet::{LoraPacket, Direction, DevAddr, AppSKey, NwkSKey};
  ///
  /// let app_s_key = AppSKey::from_slice(&hex::decode("ec925802ae430ca77fd3dd73cb2cc588")?)?;
  /// let nwk_s_key = NwkSKey::from_slice(&hex::decode("44024241ed4ce9a68c6a8bc055233fd3")?)?;
  ///
  /// let packet = LoraPacket::builder()
  ///   .data(Direction::Uplink, false)
  ///   .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
  ///   .f_cnt(2)
  ///   .f_port(1)
  ///   .payload(b"test")
  ///   .sign_and_encrypt(&app_s_key, &nwk_s_key)?;
  ///
  /// assert_eq!(packet.to_wire(), hex::decode("40f17dbe4900020001954378762b11ff0d")?);
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  pub fn sign_and_encrypt(
    self,
    app_s_key: &crate::types::AppSKey,
    nwk_s_key: &crate::types::NwkSKey,
  ) -> crate::Result<LoraPacket> {
    let mut packet = self.build_unsigned()?;
    // Encrypt FRMPayload if data variant has one
    if let Payload::Data(d) = &mut packet.payload {
      if let Some(plaintext) = d.frm_payload.clone() {
        let encrypted = d.encrypt_payload(&plaintext, app_s_key, nwk_s_key, 0)?;
        d.frm_payload = Some(encrypted);
      }
    }
    // Refresh phy_payload with encrypted contents (no MIC yet)
    packet.phy_payload = packet.to_wire();
    let keys = crate::mic::V1_0MicKeys {
      nwk_s_key: Some(nwk_s_key),
      ..Default::default()
    };
    packet.recalculate_mic_v1_0(&keys)?;
    Ok(packet)
  }

  /// Finalise the builder into a [`LoraPacket`] with MIC set to zero.
  ///
  /// Useful when you want to sign and emit in separate steps (e.g. for test
  /// vectors or when the signing keys arrive asynchronously). Call a
  /// `sign_*` method on the builder, or call
  /// [`recalculate_mic_v1_0`](LoraPacket::recalculate_mic_v1_0) /
  /// [`recalculate_mic_v1_1`](LoraPacket::recalculate_mic_v1_1) on the
  /// resulting packet, to fill in the MIC.
  ///
  /// # Errors
  /// - [`crate::Error::MissingField`] when a required field for the chosen
  ///   `MType` is missing. The field name is in the error.
  /// - [`crate::Error::FOptsTooLong`] when the `FOpts` vector exceeds the
  ///   15-byte wire limit.
  /// - [`crate::Error::InvalidRejoinType`] when the rejoin type is not in
  ///   {0, 1, 2}.
  pub fn build_unsigned(self) -> crate::Result<LoraPacket> {
    let m_type = self.m_type.ok_or(crate::Error::MissingField("m_type"))?;
    let mhdr = Mhdr::from_parts(m_type, self.major);

    let payload = match m_type {
      MType::JoinRequest => Payload::JoinRequest(JoinRequest {
        join_eui: self.join_eui.ok_or(crate::Error::MissingField("join_eui"))?,
        dev_eui: self.dev_eui.ok_or(crate::Error::MissingField("dev_eui"))?,
        dev_nonce: self.dev_nonce.ok_or(crate::Error::MissingField("dev_nonce"))?,
      }),
      MType::JoinAccept => Payload::JoinAccept(JoinAccept {
        join_nonce: self.join_nonce.ok_or(crate::Error::MissingField("join_nonce"))?,
        net_id: self.net_id.ok_or(crate::Error::MissingField("net_id"))?,
        dev_addr: self.dev_addr.ok_or(crate::Error::MissingField("dev_addr"))?,
        dl_settings: self.dl_settings.ok_or(crate::Error::MissingField("dl_settings"))?,
        rx_delay: self.rx_delay.unwrap_or(0),
        cf_list: self.cf_list,
        join_req_type: self.join_req_type,
      }),
      MType::UnconfirmedDataUp | MType::UnconfirmedDataDown | MType::ConfirmedDataUp | MType::ConfirmedDataDown => {
        let direction = self.direction.ok_or(crate::Error::MissingField("direction"))?;
        let f_opts_len = u8::try_from(self.f_opts.len()).map_err(|_| crate::Error::FOptsTooLong(self.f_opts.len()))?;
        if f_opts_len > 15 {
          return Err(crate::Error::FOptsTooLong(self.f_opts.len()));
        }
        // FCtrl.FOptsLen (low nibble) must match the actual FOpts length.
        // If the caller supplied a custom FCtrl, keep its upper nibble (ADR,
        // ADRACKReq, ACK, FPending) but force the low nibble to f_opts_len.
        let f_opts_len_nibble = f_opts_len & 0x0F;
        let f_ctrl = self
          .f_ctrl
          .map_or(FCtrl(f_opts_len_nibble), |fc| FCtrl((fc.0 & 0xF0) | f_opts_len_nibble));
        Payload::Data(Data {
          direction,
          confirmed: self.confirmed,
          dev_addr: self.dev_addr.ok_or(crate::Error::MissingField("dev_addr"))?,
          f_ctrl,
          f_cnt: self.f_cnt.unwrap_or(0).to_le_bytes(),
          f_opts: self.f_opts,
          f_port: self.f_port,
          frm_payload: self.payload,
        })
      }
      MType::RejoinRequest => {
        let dev_eui = self.dev_eui.ok_or(crate::Error::MissingField("dev_eui"))?;
        Payload::RejoinRequest(match self.rejoin_type.unwrap_or(0) {
          0 => RejoinRequest::Type0 {
            net_id: self.net_id.ok_or(crate::Error::MissingField("net_id"))?,
            dev_eui,
            rj_count_0: self.rj_count_0.unwrap_or([0, 0]),
          },
          1 => RejoinRequest::Type1 {
            join_eui: self.join_eui.ok_or(crate::Error::MissingField("join_eui"))?,
            dev_eui,
            rj_count_1: self.rj_count_1.unwrap_or([0, 0]),
          },
          2 => RejoinRequest::Type2 {
            net_id: self.net_id.ok_or(crate::Error::MissingField("net_id"))?,
            dev_eui,
            rj_count_0: self.rj_count_0.unwrap_or([0, 0]),
          },
          other => return Err(crate::Error::InvalidRejoinType(other)),
        })
      }
      MType::Proprietary => Payload::Proprietary(self.payload.unwrap_or_default()),
    };

    let mut pkt = LoraPacket {
      phy_payload: Vec::new(),
      mhdr,
      mic: [0u8; 4],
      payload,
    };
    pkt.phy_payload = pkt.to_wire();
    Ok(pkt)
  }
}

fn parse_rejoin_request(body: &[u8]) -> crate::Result<RejoinRequest> {
  if body.is_empty() {
    return Err(crate::Error::TooShort { expected: 1, got: 0 });
  }
  let rejoin_type = body[0];
  match rejoin_type {
    0 | 2 => {
      if body.len() != 14 {
        return Err(crate::Error::TooShort {
          expected: 14,
          got: body.len(),
        });
      }
      let mut net_id = [0u8; 3];
      net_id.copy_from_slice(&body[1..4]);
      net_id.reverse();
      let mut dev_eui = [0u8; 8];
      dev_eui.copy_from_slice(&body[4..12]);
      dev_eui.reverse();
      let mut rj_count_0 = [0u8; 2];
      rj_count_0.copy_from_slice(&body[12..14]);
      rj_count_0.reverse();
      let dev_eui = DevEui::new(dev_eui);
      let net_id = NetId::new(net_id);
      if rejoin_type == 0 {
        Ok(RejoinRequest::Type0 {
          net_id,
          dev_eui,
          rj_count_0,
        })
      } else {
        Ok(RejoinRequest::Type2 {
          net_id,
          dev_eui,
          rj_count_0,
        })
      }
    }
    1 => {
      if body.len() != 19 {
        return Err(crate::Error::TooShort {
          expected: 19,
          got: body.len(),
        });
      }
      let mut join_eui = [0u8; 8];
      join_eui.copy_from_slice(&body[1..9]);
      join_eui.reverse();
      let mut dev_eui = [0u8; 8];
      dev_eui.copy_from_slice(&body[9..17]);
      dev_eui.reverse();
      let mut rj_count_1 = [0u8; 2];
      rj_count_1.copy_from_slice(&body[17..19]);
      rj_count_1.reverse();
      Ok(RejoinRequest::Type1 {
        join_eui: AppEui::new(join_eui),
        dev_eui: DevEui::new(dev_eui),
        rj_count_1,
      })
    }
    other => Err(crate::Error::InvalidRejoinType(other)),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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

  fn sample_data_packet(confirmed: bool, direction: Direction) -> LoraPacket {
    let m_type = match (confirmed, direction) {
      (false, Direction::Uplink) => MType::UnconfirmedDataUp,
      (false, Direction::Downlink) => MType::UnconfirmedDataDown,
      (true, Direction::Uplink) => MType::ConfirmedDataUp,
      (true, Direction::Downlink) => MType::ConfirmedDataDown,
    };
    LoraPacket {
      phy_payload: alloc::vec![],
      mhdr: Mhdr::from_parts(m_type, 0),
      mic: [0u8; 4],
      payload: Payload::Data(Data {
        direction,
        confirmed,
        dev_addr: DevAddr::new([0u8; 4]),
        f_ctrl: FCtrl(0),
        f_cnt: [0, 0],
        f_opts: alloc::vec![],
        f_port: None,
        frm_payload: None,
      }),
    }
  }

  #[test]
  fn accessor_is_data() {
    let p = sample_data_packet(false, Direction::Uplink);
    assert!(p.is_data());
    assert!(!p.is_confirmed());
    assert!(p.as_data().is_some());
  }

  #[test]
  fn accessor_is_confirmed() {
    let p = sample_data_packet(true, Direction::Downlink);
    assert!(p.is_data());
    assert!(p.is_confirmed());
  }

  #[test]
  fn accessor_is_join_request() {
    let p = LoraPacket {
      phy_payload: alloc::vec![],
      mhdr: Mhdr::from_parts(MType::JoinRequest, 0),
      mic: [0u8; 4],
      payload: Payload::JoinRequest(JoinRequest {
        join_eui: AppEui::new([0u8; 8]),
        dev_eui: DevEui::new([0u8; 8]),
        dev_nonce: DevNonce::new([0u8; 2]),
      }),
    };
    assert!(p.is_join_request());
    assert!(p.as_join_request().is_some());
    assert!(p.as_data().is_none());
  }

  #[test]
  fn data_f_cnt_little_endian() {
    let d = Data {
      direction: Direction::Uplink,
      confirmed: false,
      dev_addr: DevAddr::new([0u8; 4]),
      f_ctrl: FCtrl(0),
      f_cnt: [0x02, 0x00],
      f_opts: alloc::vec![],
      f_port: None,
      frm_payload: None,
    };
    assert_eq!(d.f_cnt(), 2);
    assert_eq!(d.f_cnt_32(0), 2);
    assert_eq!(d.f_cnt_32(1), 0x0001_0002);
  }

  #[test]
  fn from_wire_rejects_empty() {
    let err = LoraPacket::from_wire(&[]).unwrap_err();
    assert!(matches!(err, crate::Error::TooShort { .. }));
  }

  #[test]
  fn from_wire_rejects_too_short() {
    let err = LoraPacket::from_wire(&[1, 2, 3, 4]).unwrap_err();
    assert!(matches!(err, crate::Error::TooShort { .. }));
  }

  /// Mirror of `__tests__/parse_test.ts`: "parses a Join Request"
  #[test]
  fn parse_join_request_known_vector() {
    let bytes = hex_to_vec("0039363463336913aa05693574323831338ef1c1d5ec6c");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    assert_eq!(p.mhdr.as_byte(), 0x00);
    assert_eq!(p.mic, [0xc1, 0xd5, 0xec, 0x6c]);
    let jr = p.as_join_request().expect("expected JoinRequest");
    assert_eq!(
      jr.join_eui.as_bytes(),
      &[0xaa, 0x13, 0x69, 0x33, 0x63, 0x34, 0x36, 0x39]
    );
    assert_eq!(jr.dev_eui.as_bytes(), &[0x33, 0x31, 0x38, 0x32, 0x74, 0x35, 0x69, 0x05]);
    assert_eq!(jr.dev_nonce.as_bytes(), &[0xf1, 0x8e]);
  }

  fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
      .collect()
  }

  #[test]
  fn parse_join_accept_plaintext_minimum() {
    let plaintext = hex_to_vec("20010203040506070809100001deadbeef");
    let ja = JoinAccept::from_plaintext(&plaintext).unwrap();
    assert_eq!(ja.join_nonce.as_bytes(), &[0x03, 0x02, 0x01]);
    assert_eq!(ja.net_id.as_bytes(), &[0x06, 0x05, 0x04]);
    assert_eq!(ja.dev_addr.as_bytes(), &[0x10, 0x09, 0x08, 0x07]);
    assert_eq!(ja.dl_settings.as_byte(), 0x00);
    assert_eq!(ja.rx_delay, 0x01);
    assert!(ja.cf_list.is_none());
    assert!(ja.join_req_type.is_none());
  }

  #[test]
  fn parse_join_accept_plaintext_with_cflist() {
    let plaintext = hex_to_vec(concat!(
      "20",
      "010203040506070809100001",
      "112233445566778899aabbccddeeff00",
      "deadbeef"
    ));
    let ja = JoinAccept::from_plaintext(&plaintext).unwrap();
    assert_eq!(
      ja.cf_list.unwrap(),
      [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
      ]
    );
  }

  /// Mirror of `__tests__/parse_test.ts`: "parses an unconfirmed data up"
  #[test]
  fn parse_data_up_known_vector() {
    let bytes = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    assert_eq!(p.mhdr.as_byte(), 0x40);
    assert_eq!(p.mic, [0x2b, 0x11, 0xff, 0x0d]);
    let d = p.as_data().expect("expected Data");
    assert_eq!(d.direction, Direction::Uplink);
    assert!(!d.confirmed);
    assert_eq!(d.dev_addr.as_bytes(), &[0x49, 0xbe, 0x7d, 0xf1]);
    assert_eq!(d.f_ctrl.as_byte(), 0x00);
    assert_eq!(d.f_cnt(), 2);
    assert!(d.f_opts.is_empty());
    assert_eq!(d.f_port, Some(0x01));
    assert_eq!(d.frm_payload.as_deref(), Some(&[0x95, 0x43, 0x78, 0x76][..]));
  }

  #[test]
  fn parse_rejoin_type_0() {
    let bytes = hex_to_vec("c0000102030405060708090a0b0c0ddeadbeef");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    let rj = p.as_rejoin_request().expect("rejoin");
    match rj {
      RejoinRequest::Type0 {
        net_id,
        dev_eui,
        rj_count_0,
      } => {
        assert_eq!(net_id.as_bytes(), &[0x03, 0x02, 0x01]);
        assert_eq!(dev_eui.as_bytes(), &[0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04]);
        assert_eq!(rj_count_0, &[0x0d, 0x0c]);
      }
      _ => panic!("expected Type0"),
    }
  }

  #[test]
  fn parse_rejoin_type_1() {
    let bytes = hex_to_vec("c001aaaaaaaaaaaaaaaa0405060708090a0b0c0ddeadbeef");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    match p.as_rejoin_request().unwrap() {
      RejoinRequest::Type1 {
        join_eui,
        dev_eui,
        rj_count_1,
      } => {
        assert_eq!(join_eui.as_bytes(), &[0xaa; 8]);
        assert_eq!(dev_eui.as_bytes(), &[0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04]);
        assert_eq!(rj_count_1, &[0x0d, 0x0c]);
      }
      _ => panic!("expected Type1"),
    }
  }

  #[test]
  fn parse_rejoin_type_2() {
    let bytes = hex_to_vec("c0020102030405060708090a0b0c0ddeadbeef");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    assert!(matches!(p.as_rejoin_request().unwrap(), RejoinRequest::Type2 { .. }));
  }

  #[test]
  fn parse_rejoin_invalid_type() {
    let bytes = hex_to_vec("c0030102030405060708090a0b0c0ddeadbeef");
    let err = LoraPacket::from_wire(&bytes).unwrap_err();
    assert!(matches!(err, crate::Error::InvalidRejoinType(3)));
  }

  #[test]
  fn parse_proprietary_keeps_body() {
    let bytes = hex_to_vec("e0deadbeefcafe11223344");
    let p = LoraPacket::from_wire(&bytes).unwrap();
    match &p.payload {
      Payload::Proprietary(body) => assert_eq!(body, &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]),
      _ => panic!("expected Proprietary"),
    }
    assert_eq!(p.mic, [0x11, 0x22, 0x33, 0x44]);
  }

  #[test]
  fn builder_constructs() {
    let _b = LoraPacket::builder().data(Direction::Uplink, false);
  }

  #[test]
  fn builder_chains_fields() {
    let b = LoraPacket::builder()
      .data(Direction::Downlink, false)
      .dev_addr(DevAddr::new([1, 2, 3, 4]))
      .f_cnt(7)
      .f_port(1)
      .payload(b"hi");
    assert_eq!(b.dev_addr.unwrap().as_bytes(), &[1, 2, 3, 4]);
    assert_eq!(b.f_cnt.unwrap(), 7);
    assert_eq!(b.f_port.unwrap(), 1);
    assert_eq!(b.payload.as_deref().unwrap(), b"hi");
  }

  #[test]
  fn build_unsigned_data_round_trip() {
    let pkt = LoraPacket::builder()
      .data(Direction::Uplink, false)
      .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
      .f_ctrl(FCtrl(0))
      .f_cnt(2)
      .f_port(1)
      .payload(&[0x95, 0x43, 0x78, 0x76])
      .build_unsigned()
      .unwrap();

    let wire = pkt.to_wire();
    assert_eq!(&wire[..1], &[0x40]);
    assert_eq!(&wire[1..5], &[0xf1, 0x7d, 0xbe, 0x49]);
    assert_eq!(wire[5], 0x00);
    assert_eq!(&wire[6..8], &[0x02, 0x00]);
    assert_eq!(wire[8], 0x01);
    assert_eq!(&wire[9..13], &[0x95, 0x43, 0x78, 0x76]);
    assert_eq!(&wire[wire.len() - 4..], &[0, 0, 0, 0]);
  }

  #[test]
  fn round_trip_data_up() {
    let wire = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
    let p = LoraPacket::from_wire(&wire).unwrap();
    let emitted = p.to_wire();
    assert_eq!(emitted, wire);
  }

  #[test]
  fn round_trip_join_request() {
    let wire = hex_to_vec("0039363463336913aa05693574323831338ef1c1d5ec6c");
    let p = LoraPacket::from_wire(&wire).unwrap();
    assert_eq!(p.to_wire(), wire);
  }

  #[test]
  fn round_trip_rejoin_type_0() {
    let wire = hex_to_vec("c0000102030405060708090a0b0c0ddeadbeef");
    let p = LoraPacket::from_wire(&wire).unwrap();
    assert_eq!(p.to_wire(), wire);
  }

  #[test]
  fn verify_mic_v1_0_real_vector() {
    use crate::mic::V1_0MicKeys;
    use crate::types::NwkSKey;
    let bytes = hex_to_vec("40F17DBE4900020001954378762B11FF0D");
    let packet = LoraPacket::from_wire(&bytes).unwrap();
    let nwk_s_key = NwkSKey::from_slice(&hex_to_vec("44024241ed4ce9a68c6a8bc055233fd3")).unwrap();
    let keys = V1_0MicKeys {
      nwk_s_key: Some(&nwk_s_key),
      ..Default::default()
    };
    assert!(packet.verify_mic_v1_0(&keys).unwrap());
  }

  #[test]
  fn recalculate_mic_v1_0_updates_mic_and_phypayload() {
    use crate::mic::V1_0MicKeys;
    use crate::types::NwkSKey;
    let bytes = hex_to_vec("40f17dbe490002000195437876eeeeeeee");
    let mut packet = LoraPacket::from_wire(&bytes).unwrap();
    assert_eq!(packet.mic, [0xee, 0xee, 0xee, 0xee]);
    let nwk_s_key = NwkSKey::from_slice(&hex_to_vec("44024241ed4ce9a68c6a8bc055233fd3")).unwrap();
    let keys = V1_0MicKeys {
      nwk_s_key: Some(&nwk_s_key),
      ..Default::default()
    };
    packet.recalculate_mic_v1_0(&keys).unwrap();
    assert_eq!(packet.mic, [0x2b, 0x11, 0xff, 0x0d]);
    assert_eq!(
      &packet.phy_payload[packet.phy_payload.len() - 4..],
      &[0x2b, 0x11, 0xff, 0x0d]
    );
  }

  #[test]
  fn sign_join_accept_zero_key_vector() {
    use crate::types::{AppKey, AppNonce, NetId};

    let app_key = AppKey::new([0u8; 16]);
    let (packet, encrypted_wire) = LoraPacket::builder()
      .join_accept()
      .join_nonce(AppNonce::new([0, 0, 0]))
      .net_id(NetId::new([0, 0, 0]))
      .dev_addr(DevAddr::new([0, 0, 0, 0]))
      .dl_settings(DlSettings(0))
      .rx_delay(0)
      .sign_join_accept(&app_key)
      .unwrap();

    // Plaintext MIC should be f86f0a91
    assert_eq!(packet.mic, [0xf8, 0x6f, 0x0a, 0x91]);
    // Encrypted wire should match the TS join_accept_encrypt vector
    let expected_encrypted = hex_to_vec("20e3de108795f776b8037610ef7869b5b3");
    assert_eq!(encrypted_wire, expected_encrypted);
  }

  #[test]
  fn sign_join_request_produces_verifiable_mic() {
    use crate::mic::V1_0MicKeys;
    use crate::types::AppKey;

    let app_key = AppKey::new([0u8; 16]);
    let packet = LoraPacket::builder()
      .join_request()
      .join_eui(AppEui::new([0u8; 8]))
      .dev_eui(DevEui::new([0u8; 8]))
      .dev_nonce(DevNonce::new([0u8; 2]))
      .sign_join_request(&app_key)
      .unwrap();

    let keys = V1_0MicKeys {
      app_key: Some(&app_key),
      ..Default::default()
    };
    assert!(packet.verify_mic_v1_0(&keys).unwrap());
  }

  #[test]
  fn sign_join_request_v1_1_works() {
    use crate::mic::V1_1MicKeys;
    use crate::types::NwkKey;
    let nwk_key = NwkKey::new([0u8; 16]);
    let packet = LoraPacket::builder()
      .join_request()
      .join_eui(AppEui::new([0; 8]))
      .dev_eui(DevEui::new([0; 8]))
      .dev_nonce(DevNonce::new([0; 2]))
      .sign_join_request_v1_1(&nwk_key)
      .unwrap();
    let keys = V1_1MicKeys {
      nwk_key: Some(&nwk_key),
      ..Default::default()
    };
    assert!(packet.verify_mic_v1_1(&keys).unwrap());
  }

  #[test]
  fn build_unsigned_rejects_fopts_too_long() {
    let too_many = alloc::vec![0u8; 16];
    let result = LoraPacket::builder()
      .data(Direction::Uplink, false)
      .dev_addr(DevAddr::new([0; 4]))
      .f_opts(&too_many)
      .build_unsigned();
    assert!(matches!(result, Err(crate::Error::FOptsTooLong(16))));
  }

  #[test]
  fn from_wire_rejects_oversized_buffer() {
    // 257 bytes exceeds the LoRaWAN PHY maximum of 256; reject before
    // parsing so we cannot produce a wrong-but-deterministic MIC.
    let huge = alloc::vec![0u8; 257];
    let err = LoraPacket::from_wire(&huge).unwrap_err();
    assert!(matches!(err, crate::Error::TooLong { got: 257 }));
  }

  #[test]
  fn from_wire_accepts_max_size_buffer() {
    // Boundary: exactly 256 bytes must still be accepted (or rejected on
    // semantic grounds, but not on the length cap). We pick a Proprietary
    // MType so the parser does not try to interpret the body.
    let mut bytes = alloc::vec![0u8; 256];
    bytes[0] = 0b1110_0000; // Proprietary MType
    let result = LoraPacket::from_wire(&bytes);
    assert!(result.is_ok(), "256-byte buffer should parse, got {result:?}");
  }

  #[test]
  fn builder_rj_count_0_persists_through_rejoin_type_0() {
    use crate::types::NetId;
    let packet = LoraPacket::builder()
      .rejoin_request(0)
      .net_id(NetId::new([0, 0, 0]))
      .dev_eui(DevEui::new([0; 8]))
      .rj_count_0(0x1234)
      .build_unsigned()
      .unwrap();
    match &packet.payload {
      Payload::RejoinRequest(RejoinRequest::Type0 { rj_count_0, .. }) => {
        assert_eq!(rj_count_0, &0x1234u16.to_le_bytes());
      }
      other => panic!("expected Rejoin Type 0, got {other:?}"),
    }
  }

  #[test]
  fn builder_rj_count_1_persists_through_rejoin_type_1() {
    let packet = LoraPacket::builder()
      .rejoin_request(1)
      .join_eui(AppEui::new([0; 8]))
      .dev_eui(DevEui::new([0; 8]))
      .rj_count_1(0xBEEF)
      .build_unsigned()
      .unwrap();
    match &packet.payload {
      Payload::RejoinRequest(RejoinRequest::Type1 { rj_count_1, .. }) => {
        assert_eq!(rj_count_1, &0xBEEFu16.to_le_bytes());
      }
      other => panic!("expected Rejoin Type 1, got {other:?}"),
    }
  }

  #[test]
  fn builder_rj_count_0_persists_through_rejoin_type_2() {
    use crate::types::NetId;
    let packet = LoraPacket::builder()
      .rejoin_request(2)
      .net_id(NetId::new([0, 0, 0]))
      .dev_eui(DevEui::new([0; 8]))
      .rj_count_0(0x00DB)
      .build_unsigned()
      .unwrap();
    match &packet.payload {
      Payload::RejoinRequest(RejoinRequest::Type2 { rj_count_0, .. }) => {
        assert_eq!(rj_count_0, &0x00DBu16.to_le_bytes());
      }
      other => panic!("expected Rejoin Type 2, got {other:?}"),
    }
  }

  #[test]
  fn builder_rejoin_defaults_to_zero_counters() {
    use crate::types::NetId;
    let packet = LoraPacket::builder()
      .rejoin_request(0)
      .net_id(NetId::new([0, 0, 0]))
      .dev_eui(DevEui::new([0; 8]))
      .build_unsigned()
      .unwrap();
    match &packet.payload {
      Payload::RejoinRequest(RejoinRequest::Type0 { rj_count_0, .. }) => {
        assert_eq!(rj_count_0, &[0, 0]);
      }
      other => panic!("expected Rejoin Type 0, got {other:?}"),
    }
  }

  #[test]
  fn builder_overrides_f_ctrl_low_nibble_with_actual_fopts_len() {
    // Caller passes a FCtrl whose low nibble (0) disagrees with the actual
    // f_opts vector length (3). The builder must preserve the upper nibble
    // (0xA = ADR + ACK bits) and rewrite the low nibble to 3.
    let packet = LoraPacket::builder()
      .data(Direction::Uplink, false)
      .dev_addr(DevAddr::new([1, 2, 3, 4]))
      .f_ctrl(FCtrl(0xA0))
      .f_opts(&[0x01, 0x02, 0x03])
      .build_unsigned()
      .unwrap();
    let data = packet.as_data().unwrap();
    assert_eq!(data.f_ctrl.as_byte(), 0xA3, "upper nibble preserved, low nibble = 3");
    assert_eq!(data.f_opts.len(), 3);
  }

  #[test]
  fn sign_and_encrypt_round_trip() {
    use crate::mic::V1_0MicKeys;
    use crate::types::{AppSKey, NwkSKey};

    let app_s_key = AppSKey::from_slice(&hex_to_vec("ec925802ae430ca77fd3dd73cb2cc588")).unwrap();
    let nwk_s_key = NwkSKey::from_slice(&hex_to_vec("44024241ed4ce9a68c6a8bc055233fd3")).unwrap();

    let packet = LoraPacket::builder()
      .data(Direction::Uplink, false)
      .dev_addr(DevAddr::new([0x49, 0xbe, 0x7d, 0xf1]))
      .f_ctrl(FCtrl(0))
      .f_cnt(2)
      .f_port(1)
      .payload(b"test")
      .sign_and_encrypt(&app_s_key, &nwk_s_key)
      .unwrap();

    // The encrypted payload should be the known ciphertext
    let d = packet.as_data().unwrap();
    assert_eq!(d.frm_payload.as_deref(), Some(&[0x95, 0x43, 0x78, 0x76][..]));

    // MIC should match the known value
    assert_eq!(packet.mic, [0x2b, 0x11, 0xff, 0x0d]);

    // PHY payload should be the canonical wire frame
    let expected_wire = hex_to_vec("40f17dbe4900020001954378762b11ff0d");
    assert_eq!(packet.phy_payload, expected_wire);

    // verify_mic_v1_0 succeeds
    let keys = V1_0MicKeys {
      nwk_s_key: Some(&nwk_s_key),
      ..Default::default()
    };
    assert!(packet.verify_mic_v1_0(&keys).unwrap());
  }
}

#[cfg(test)]
mod prop_tests {
  use super::*;
  use proptest::prelude::*;

  proptest! {
    #[test]
    fn from_wire_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..=1000)) {
      // It must return Result, never panic.
      let _ = LoraPacket::from_wire(&bytes);
    }
  }
}
