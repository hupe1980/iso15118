//! One type for "a V2G message", whichever schema set it came from.
//!
//! Above the codecs and below the role drivers there is a job nothing else
//! does: a V2GTP frame carries a payload type and a blob, and turning that pair
//! into a typed message needs a fact the frame does not contain — which
//! protocol generation the session agreed on. Payload type `0x8001` is
//! `supportedAppProtocol` before the handshake, DIN SPEC 70121 after it if DIN
//! won, and ISO 15118-2 after it if -2 won. Sniffing is not an option; the
//! session has to remember.
//!
//! [`Message`] is that dispatch, done once, in one place.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use crate::app_protocol::{SupportedAppProtocolReq, SupportedAppProtocolRes};
use crate::exi::{ExiDocument, ExiError};
use crate::v2gtp::PayloadType;
use crate::{Protocol, session::SessionId};

/// A decoded V2G message.
///
/// The variants are one per schema set, not one per message: which of the
/// thirty-odd messages of a set arrived is the inner `Document`'s business.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Message {
    /// `supportedAppProtocolReq` — the handshake that picks the generation.
    AppProtocolReq(Box<SupportedAppProtocolReq>),
    /// `supportedAppProtocolRes`.
    AppProtocolRes(Box<SupportedAppProtocolRes>),
    /// An ISO 15118-2 message.
    #[cfg(feature = "iso2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso2")))]
    Iso2(Box<crate::iso2::Document>),
    /// An ISO 15118-20 `CommonMessages` message.
    #[cfg(feature = "iso20-common")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
    Iso20(Box<crate::iso20::messages::Document>),
    /// An ISO 15118-20 AC message.
    #[cfg(feature = "iso20-ac")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-ac")))]
    Iso20Ac(Box<crate::iso20::ac::Document>),
    /// An ISO 15118-20 DC message.
    #[cfg(feature = "iso20-dc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-dc")))]
    Iso20Dc(Box<crate::iso20::dc::Document>),
    /// An ISO 15118-20 wireless-power-transfer message.
    #[cfg(feature = "iso20-wpt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-wpt")))]
    Iso20Wpt(Box<crate::iso20::wpt::Document>),
    /// An ISO 15118-20 pantograph message.
    #[cfg(feature = "iso20-acdp")]
    #[cfg_attr(docsrs, doc(cfg(feature = "iso20-acdp")))]
    Iso20Acdp(Box<crate::iso20::acdp::Document>),
}

impl Message {
    /// Decodes the payload of one V2GTP frame.
    ///
    /// `protocol` is what the `supportedAppProtocol` handshake settled on, or
    /// `None` before it has. Passing the wrong one does not produce a wrong
    /// message: the schema sets have different document grammars, so a -20
    /// frame read as -2 fails on its event code rather than decoding to
    /// something plausible.
    pub fn decode(
        protocol: Option<Protocol>,
        payload_type: PayloadType,
        bytes: &[u8],
    ) -> Result<Self, MessageError> {
        if !payload_type.is_exi() {
            return Err(MessageError::NotAMessage(payload_type));
        }
        match (payload_type, protocol) {
            // Before the handshake, `0x8001` is the handshake itself. It has
            // two root elements, so which one is decided by its own document
            // event code rather than by us.
            (PayloadType::ExiEncodedV2gMessage, None) => SupportedAppProtocolReq::from_bytes(bytes)
                .map(|m| Self::AppProtocolReq(Box::new(m)))
                .or_else(|_| {
                    SupportedAppProtocolRes::from_bytes(bytes)
                        .map(|m| Self::AppProtocolRes(Box::new(m)))
                })
                .map_err(MessageError::Exi),
            #[cfg(feature = "iso2")]
            (PayloadType::ExiEncodedV2gMessage, Some(Protocol::Iso2)) => {
                crate::iso2::Document::from_bytes(bytes)
                    .map(|m| Self::Iso2(Box::new(m)))
                    .map_err(MessageError::Exi)
            }
            // The -20 payload types are only legal once -20 has actually been
            // negotiated. Decoding one in an unnegotiated session, or in a -2
            // one, would let a peer step outside the generation it agreed to.
            #[cfg(feature = "iso20-common")]
            (PayloadType::Part20Main, Some(Protocol::Iso20)) => {
                crate::iso20::messages::Document::from_bytes(bytes)
                    .map(|m| Self::Iso20(Box::new(m)))
                    .map_err(MessageError::Exi)
            }
            #[cfg(feature = "iso20-ac")]
            (PayloadType::Part20Ac, Some(Protocol::Iso20)) => {
                crate::iso20::ac::Document::from_bytes(bytes)
                    .map(|m| Self::Iso20Ac(Box::new(m)))
                    .map_err(MessageError::Exi)
            }
            #[cfg(feature = "iso20-dc")]
            (PayloadType::Part20Dc, Some(Protocol::Iso20)) => {
                crate::iso20::dc::Document::from_bytes(bytes)
                    .map(|m| Self::Iso20Dc(Box::new(m)))
                    .map_err(MessageError::Exi)
            }
            #[cfg(feature = "iso20-wpt")]
            (PayloadType::Part20Wpt, Some(Protocol::Iso20)) => {
                crate::iso20::wpt::Document::from_bytes(bytes)
                    .map(|m| Self::Iso20Wpt(Box::new(m)))
                    .map_err(MessageError::Exi)
            }
            #[cfg(feature = "iso20-acdp")]
            (PayloadType::Part20Acdp, Some(Protocol::Iso20)) => {
                crate::iso20::acdp::Document::from_bytes(bytes)
                    .map(|m| Self::Iso20Acdp(Box::new(m)))
                    .map_err(MessageError::Exi)
            }
            // Nothing matched, and the two reasons are not the same fault.
            _ if !payload_type.belongs_to(protocol) => {
                // A message for a session other than this one — a -20 payload
                // type in a -2 session, or any type before negotiation.
                // \[V2G2-800\] has the receiver ignore it.
                Err(MessageError::NotForThisSession { payload_type, protocol })
            }
            // The payload type *is* this session's, and there is no message set
            // compiled in for it — DIN SPEC 70121, or a -20 schema set behind a
            // feature that is off. Ignoring would silently drop a message this
            // session is genuinely part of, so it is reported; the caller's own
            // codec rides `Connection::next_frame`.
            _ => Err(MessageError::NoCodec { payload_type, protocol }),
        }
    }

    /// Encodes the message, returning the V2GTP payload type it belongs under.
    pub fn encode(&self) -> Result<(PayloadType, Vec<u8>), MessageError> {
        let bytes = match self {
            Self::AppProtocolReq(m) => m.to_vec(),
            Self::AppProtocolRes(m) => m.to_vec(),
            #[cfg(feature = "iso2")]
            Self::Iso2(m) => m.to_vec(),
            #[cfg(feature = "iso20-common")]
            Self::Iso20(m) => m.to_vec(),
            #[cfg(feature = "iso20-ac")]
            Self::Iso20Ac(m) => m.to_vec(),
            #[cfg(feature = "iso20-dc")]
            Self::Iso20Dc(m) => m.to_vec(),
            #[cfg(feature = "iso20-wpt")]
            Self::Iso20Wpt(m) => m.to_vec(),
            #[cfg(feature = "iso20-acdp")]
            Self::Iso20Acdp(m) => m.to_vec(),
        }
        .map_err(MessageError::Exi)?;
        Ok((self.payload_type(), bytes))
    }

    /// The V2GTP payload type this message travels under.
    #[must_use]
    pub const fn payload_type(&self) -> PayloadType {
        match self {
            Self::AppProtocolReq(_) | Self::AppProtocolRes(_) => PayloadType::ExiEncodedV2gMessage,
            #[cfg(feature = "iso2")]
            Self::Iso2(_) => PayloadType::ExiEncodedV2gMessage,
            #[cfg(feature = "iso20-common")]
            Self::Iso20(_) => PayloadType::Part20Main,
            #[cfg(feature = "iso20-ac")]
            Self::Iso20Ac(_) => PayloadType::Part20Ac,
            #[cfg(feature = "iso20-dc")]
            Self::Iso20Dc(_) => PayloadType::Part20Dc,
            #[cfg(feature = "iso20-wpt")]
            Self::Iso20Wpt(_) => PayloadType::Part20Wpt,
            #[cfg(feature = "iso20-acdp")]
            Self::Iso20Acdp(_) => PayloadType::Part20Acdp,
        }
    }

    /// The element name of the message, for logs and for telling a request
    /// from a response.
    ///
    /// ISO 15118-2 wraps all thirty-four of its messages in one `V2G_Message`
    /// root, so the document's own name says nothing about which message
    /// arrived — the *body* does. This reports the body's name, which is what
    /// every other layer means by "the message".
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AppProtocolReq(_) => "supportedAppProtocolReq",
            Self::AppProtocolRes(_) => "supportedAppProtocolRes",
            #[cfg(feature = "iso2")]
            Self::Iso2(m) => match &**m {
                crate::iso2::Document::V2GMessage(v) => match &v.body.choice {
                    Some(choice) => choice.name(),
                    // A `V2G_Message` with an empty body is legal EXI and no
                    // message at all; the sequencer refuses it.
                    None => "V2G_Message",
                },
                other => other.name(),
            },
            #[cfg(feature = "iso20-common")]
            Self::Iso20(m) => m.name(),
            #[cfg(feature = "iso20-ac")]
            Self::Iso20Ac(m) => m.name(),
            #[cfg(feature = "iso20-dc")]
            Self::Iso20Dc(m) => m.name(),
            #[cfg(feature = "iso20-wpt")]
            Self::Iso20Wpt(m) => m.name(),
            #[cfg(feature = "iso20-acdp")]
            Self::Iso20Acdp(m) => m.name(),
        }
    }

    /// What this message's `ResponseCode` means for the session.
    ///
    /// `None` for a request, and for the few schema elements that are signed
    /// payloads rather than messages.
    ///
    /// ISO 15118 gives the three classes of code three different consequences,
    /// and only one of them is a judgement call: `OK_*` carries on, `WARNING_*`
    /// carries on and tells somebody, and `FAILED_*` **ends the session** — the
    /// peer may send `SessionStopReq` and nothing else. The session drivers act
    /// on that; see [`session::Flow::failed`](crate::session::Flow::failed).
    #[must_use]
    pub fn outcome(&self) -> Option<Outcome> {
        #[cfg(any(feature = "iso2", feature = "iso20-common"))]
        fn classify(is_ok: bool, is_warning: bool) -> Outcome {
            match (is_ok, is_warning) {
                (true, _) => Outcome::Ok,
                (_, true) => Outcome::Warning,
                _ => Outcome::Failed,
            }
        }
        match self {
            Self::AppProtocolReq(_) => None,
            Self::AppProtocolRes(m) => {
                Some(if m.response_code.is_ok() { Outcome::Ok } else { Outcome::Failed })
            }
            #[cfg(feature = "iso2")]
            Self::Iso2(m) => {
                let crate::iso2::Document::V2GMessage(v) = &**m else { return None };
                let code = v.body.choice.as_ref()?.response_code()?;
                Some(classify(code.is_ok(), code.is_warning()))
            }
            #[cfg(feature = "iso20-common")]
            Self::Iso20(m) => m.response_code().map(|c| classify(c.is_ok(), c.is_warning())),
            #[cfg(feature = "iso20-ac")]
            Self::Iso20Ac(m) => m.response_code().map(|c| classify(c.is_ok(), c.is_warning())),
            #[cfg(feature = "iso20-dc")]
            Self::Iso20Dc(m) => m.response_code().map(|c| classify(c.is_ok(), c.is_warning())),
            #[cfg(feature = "iso20-wpt")]
            Self::Iso20Wpt(m) => m.response_code().map(|c| classify(c.is_ok(), c.is_warning())),
            #[cfg(feature = "iso20-acdp")]
            Self::Iso20Acdp(m) => m.response_code().map(|c| classify(c.is_ok(), c.is_warning())),
        }
    }

    /// What this message says about the vehicle's battery, if anything.
    ///
    /// `None` for a message that carries no battery information at all — every
    /// response, the handshake, and the requests that are pure protocol.
    ///
    /// This is the one question a consumer above the protocol actually has, and
    /// answering it otherwise means knowing both message sets: -2 hides a state of
    /// charge in `DC_EVStatus` on six different requests and its energy figures
    /// in `ChargeParameterDiscoveryReq`, while -20 puts the state of charge in
    /// `DisplayParameters` on the charge loop and the energy figures in
    /// `ScheduleExchangeReq`. See [`EvEnergyStatus`].
    ///
    /// An energy value in a unit that is not watt-hours is dropped rather than
    /// converted, and so is one that cannot be scaled to an exact integer —
    /// both are `None`, on the principle that a wrong number is worse than no
    /// number for a quantity somebody is billed for.
    /// Present only when a build has a message set to read one out of — with
    /// neither generation enabled there is no message that carries a battery.
    #[must_use]
    #[cfg(any(feature = "iso2", feature = "iso20-common"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "iso2", feature = "iso20-common"))))]
    pub fn ev_energy_status(&self) -> Option<EvEnergyStatus> {
        let status = match self {
            #[cfg(feature = "iso2")]
            Self::Iso2(m) => iso2_energy_status(m)?,
            #[cfg(feature = "iso20-common")]
            Self::Iso20(m) => iso20_common_energy_status(m)?,
            #[cfg(feature = "iso20-ac")]
            Self::Iso20Ac(m) => {
                use crate::iso20::ac::ACChargeLoopReqChoice as C;
                let crate::iso20::ac::Document::ACChargeLoopReq(r) = &**m else { return None };
                let mut out = display_energy_status(r.display_parameters.as_ref());
                // The four *dynamic* control modes restate the energy request
                // on every turn of the loop, which is what a load manager
                // tracks. The scheduled ones do not: a vehicle following a
                // schedule is not asking for an amount.
                match &r.choice {
                    C::DynamicACCLReqControlMode(c) => out.take_request(
                        c.departure_time,
                        &c.ev_target_energy_request,
                        &c.ev_minimum_energy_request,
                        &c.ev_maximum_energy_request,
                    ),
                    C::BPTDynamicACCLReqControlMode(c) => out.take_request(
                        c.departure_time,
                        &c.ev_target_energy_request,
                        &c.ev_minimum_energy_request,
                        &c.ev_maximum_energy_request,
                    ),
                    _ => {}
                }
                out
            }
            #[cfg(feature = "iso20-dc")]
            Self::Iso20Dc(m) => {
                use crate::iso20::dc::DCChargeLoopReqChoice as C;
                let crate::iso20::dc::Document::DCChargeLoopReq(r) = &**m else { return None };
                let mut out = display_energy_status(r.display_parameters.as_ref());
                match &r.choice {
                    C::DynamicDCCLReqControlMode(c) => out.take_request(
                        c.departure_time,
                        &c.ev_target_energy_request,
                        &c.ev_minimum_energy_request,
                        &c.ev_maximum_energy_request,
                    ),
                    C::BPTDynamicDCCLReqControlMode(c) => out.take_request(
                        c.departure_time,
                        &c.ev_target_energy_request,
                        &c.ev_minimum_energy_request,
                        &c.ev_maximum_energy_request,
                    ),
                    _ => {}
                }
                out
            }
            #[cfg(feature = "iso20-wpt")]
            Self::Iso20Wpt(m) => match &**m {
                // WPT has no dynamic control mode carrying an energy request,
                // so the display parameters are the whole of what it states.
                crate::iso20::wpt::Document::WPTChargeLoopReq(r) => {
                    display_energy_status(r.display_parameters.as_ref())
                }
                _ => return None,
            },
            _ => return None,
        };
        // A `DisplayParameters` with every field absent is legal EXI and says
        // nothing; reporting it as a status would be reporting an answer.
        if status.is_empty() { None } else { Some(status) }
    }

    /// True for a request — an element whose name ends in `Req`.
    ///
    /// Both generations name every message this way, and the direction decides
    /// which side is allowed to have sent it.
    #[must_use]
    pub fn is_request(&self) -> bool {
        self.name().ends_with("Req")
    }

    /// The session id in the message header, where the message has one.
    ///
    /// The `supportedAppProtocol` handshake predates the session, so it has
    /// none.
    #[must_use]
    pub fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::AppProtocolReq(_) | Self::AppProtocolRes(_) => None,
            #[cfg(feature = "iso2")]
            Self::Iso2(m) => match &**m {
                // -2 wraps every message in one `V2G_Message` root, so there is
                // exactly one place a session id can be.
                crate::iso2::Document::V2GMessage(v) => {
                    SessionId::from_slice(&v.header.session_id).ok()
                }
                _ => None,
            },
            // -20 puts the header on each message rather than on a wrapper.
            #[cfg(feature = "iso20-common")]
            Self::Iso20(m) => header_session_id(m.header()),
            #[cfg(feature = "iso20-ac")]
            Self::Iso20Ac(m) => header_session_id(m.header()),
            #[cfg(feature = "iso20-dc")]
            Self::Iso20Dc(m) => header_session_id(m.header()),
            #[cfg(feature = "iso20-wpt")]
            Self::Iso20Wpt(m) => header_session_id(m.header()),
            #[cfg(feature = "iso20-acdp")]
            Self::Iso20Acdp(m) => header_session_id(m.header()),
        }
    }

    /// True when this message is the answer to the request named `request`.
    ///
    /// Both generations name every exchange `XxxReq`/`XxxRes`, right down to
    /// the `supportedAppProtocol` handshake, so the stems must match exactly.
    /// Which is worth checking on both sides: the ordering graph constrains
    /// requests only, so nothing else stands between a peer and an answer to a
    /// question nobody asked.
    #[must_use]
    pub fn answers(&self, request: &str) -> bool {
        match (request.strip_suffix("Req"), self.name().strip_suffix("Res")) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Writes `id` into the message header, where the message has one.
    ///
    /// Returns `false` for the `supportedAppProtocol` handshake, which predates
    /// the session and has no header.
    ///
    /// Which session a message belongs to is not a per-message choice: the SECC
    /// assigns one id in `SessionSetupRes` and both sides repeat it until the
    /// session ends \[V2G2-747\], \[V2G2-752\]. The session drivers stamp it
    /// through here so
    /// that an application building a response cannot get it wrong, and so that
    /// the id lives in exactly one place — see
    /// [`Secc::respond`](crate::secc::Secc::respond).
    #[allow(unused_variables, reason = "every arm that uses `id` is behind a feature")]
    pub fn set_session_id(&mut self, id: SessionId) -> bool {
        match self {
            Self::AppProtocolReq(_) | Self::AppProtocolRes(_) => false,
            #[cfg(feature = "iso2")]
            Self::Iso2(m) => match &mut **m {
                crate::iso2::Document::V2GMessage(v) => {
                    v.header.session_id = id.as_bytes().to_vec();
                    true
                }
                _ => false,
            },
            #[cfg(feature = "iso20-common")]
            Self::Iso20(m) => set_header_session_id(m.header_mut(), id),
            #[cfg(feature = "iso20-ac")]
            Self::Iso20Ac(m) => set_header_session_id(m.header_mut(), id),
            #[cfg(feature = "iso20-dc")]
            Self::Iso20Dc(m) => set_header_session_id(m.header_mut(), id),
            #[cfg(feature = "iso20-wpt")]
            Self::Iso20Wpt(m) => set_header_session_id(m.header_mut(), id),
            #[cfg(feature = "iso20-acdp")]
            Self::Iso20Acdp(m) => set_header_session_id(m.header_mut(), id),
        }
    }
}

/// Reads the ISO 15118-2 side: a state of charge from any of the six requests
/// that carry `DC_EVStatus`, and the energy figures from the one that carries
/// them.
#[cfg(feature = "iso2")]
fn iso2_energy_status(doc: &crate::iso2::Document) -> Option<EvEnergyStatus> {
    use crate::iso2::{BodyChoice as B, ChargeParameterDiscoveryReqChoice as P};

    let crate::iso2::Document::V2GMessage(v2g) = doc else { return None };
    let mut out = EvEnergyStatus::default();

    // `DC_EVStatus` rides on six different requests, and the state of charge
    // inside it is the same field every time.
    let dc_status = match v2g.body.choice.as_ref()? {
        B::CableCheckReq(r) => Some(&r.dc_ev_status),
        B::PreChargeReq(r) => Some(&r.dc_ev_status),
        B::WeldingDetectionReq(r) => Some(&r.dc_ev_status),
        B::CurrentDemandReq(r) => {
            out.charging_complete = Some(r.charging_complete);
            Some(&r.dc_ev_status)
        }
        B::PowerDeliveryReq(r) => match r.choice.as_ref() {
            Some(crate::iso2::PowerDeliveryReqChoice::DCEVPowerDeliveryParameter(p)) => {
                out.charging_complete = Some(p.charging_complete);
                Some(&p.dc_ev_status)
            }
            _ => None,
        },
        B::ChargeParameterDiscoveryReq(r) => match &r.choice {
            P::DCEVChargeParameter(p) => {
                out.departure_in = p.departure_time;
                out.full_soc = p.full_soc;
                out.bulk_soc = p.bulk_soc;
                out.energy_capacity = p.ev_energy_capacity.as_ref().and_then(energy_mwh);
                out.target_energy_request = p.ev_energy_request.as_ref().and_then(energy_mwh);
                Some(&p.dc_ev_status)
            }
            P::ACEVChargeParameter(p) => {
                out.departure_in = p.departure_time;
                // `EAmount` is AC's only energy figure: what the vehicle wants
                // by the time it leaves. AC states no state of charge at all.
                out.target_energy_request = energy_mwh(&p.e_amount);
                None
            }
            P::EVChargeParameter(_) => None,
        },
        _ => return None,
    };
    if let Some(dc) = dc_status {
        out.present_soc = Some(dc.ev_ress_soc);
    }
    Some(out)
}

/// Reads the ISO 15118-20 `CommonMessages` side, which is where the energy
/// request lives — in whichever of the two control modes the vehicle chose.
#[cfg(feature = "iso20-common")]
fn iso20_common_energy_status(doc: &crate::iso20::messages::Document) -> Option<EvEnergyStatus> {
    use crate::iso20::messages::{Document as D, ScheduleExchangeReqChoice as C};

    let D::ScheduleExchangeReq(req) = doc else { return None };
    let mut out = EvEnergyStatus::default();
    match &req.choice {
        // Dynamic mode states all three energy figures and a departure time;
        // the schema makes them mandatory, which is what "dynamic" means here.
        C::DynamicSEReqControlMode(m) => {
            out.departure_in = Some(m.departure_time);
            out.minimum_soc = m.minimum_soc;
            out.target_soc = m.target_soc;
            out.target_energy_request = rational_mwh(&m.ev_target_energy_request);
            out.minimum_energy_request = rational_mwh(&m.ev_minimum_energy_request);
            out.maximum_energy_request = rational_mwh(&m.ev_maximum_energy_request);
        }
        // Scheduled mode states the same things optionally: the vehicle is
        // following a schedule rather than asking for an amount.
        C::ScheduledSEReqControlMode(m) => {
            out.departure_in = m.departure_time;
            out.target_energy_request = m.ev_target_energy_request.as_ref().and_then(rational_mwh);
            out.minimum_energy_request =
                m.ev_minimum_energy_request.as_ref().and_then(rational_mwh);
            out.maximum_energy_request =
                m.ev_maximum_energy_request.as_ref().and_then(rational_mwh);
        }
    }
    Some(out)
}

/// Reads the ISO 15118-20 charge-loop side, which is the same `DisplayParameters`
/// for AC, DC and WPT.
#[cfg(any(feature = "iso20-ac", feature = "iso20-dc", feature = "iso20-wpt"))]
fn display_energy_status(p: Option<&crate::iso20::common::DisplayParameters>) -> EvEnergyStatus {
    let Some(p) = p else { return EvEnergyStatus::default() };
    EvEnergyStatus {
        present_soc: p.present_soc,
        target_soc: p.target_soc,
        minimum_soc: p.minimum_soc,
        // -20 calls the ceiling `MaximumSOC` where -2 calls it `FullSOC`; they
        // are the same quantity, so they land in the same field.
        full_soc: p.maximum_soc,
        bulk_soc: None,
        energy_capacity: p.battery_energy_capacity.as_ref().and_then(rational_mwh),
        target_energy_request: None,
        minimum_energy_request: None,
        maximum_energy_request: None,
        departure_in: None,
        charging_complete: p.charging_complete,
    }
}

#[cfg(feature = "iso20-common")]
fn header_session_id(header: Option<&crate::iso20::common::MessageHeader>) -> Option<SessionId> {
    SessionId::from_slice(&header?.session_id).ok()
}

#[cfg(feature = "iso20-common")]
fn set_header_session_id(
    header: Option<&mut crate::iso20::common::MessageHeader>,
    id: SessionId,
) -> bool {
    match header {
        Some(header) => {
            header.session_id = id.as_bytes().to_vec();
            true
        }
        None => false,
    }
}

/// Energy in milliwatt-hours.
///
/// Exact integers rather than a float, for the reason
/// [`schedule::Milliwatts`](crate::session::iso2::schedule::Milliwatts) gives:
/// these numbers decide how much energy a vehicle is sold, and a rounding error
/// there is a billing error. Milliwatt-hours hold every value either generation
/// can express — `i16::MAX * 10^6` at the widest — four orders of magnitude
/// inside the type, with no rounding and no floating point anywhere near it.
pub type MilliwattHours = i64;

/// What the vehicle has said about its battery, whichever generation said it.
///
/// The two generations carry this in different places, in different types, in
/// different messages: ISO 15118-2 puts a state of charge in `DC_EVStatus` —
/// which rides on six different requests — and the energy figures in
/// `ChargeParameterDiscoveryReq`, while ISO 15118-20 puts the state of charge
/// in `DisplayParameters` on every charge-loop message and the energy figures
/// in `ScheduleExchangeReq`. A caller that wanted the vehicle's state of
/// charge therefore had to know both message sets, both control modes and both numeric
/// encodings to ask one question.
///
/// This is that question asked once. Every field is `Option` because every one
/// of them is optional *somewhere*: a -2 AC session states no charge level at all, and a
/// -20 charge loop need not carry `DisplayParameters`. `None` means "this
/// message did not say", never "zero".
///
/// ```
/// # #[cfg(feature = "iso2")] {
/// use iso15118::iso2;
/// use iso15118::message::Message;
///
/// # let status = iso2::DCEVStatus {
/// #     ev_ready: true,
/// #     ev_error_code: iso2::DCEVErrorCode::NOERROR,
/// #     ev_ress_soc: 42,
/// # };
/// let message = Message::Iso2(Box::new(iso2::Document::V2GMessage(iso2::V2GMessage {
///     header: iso2::MessageHeader {
///         session_id: vec![0; 8],
///         notification: None,
///         signature: None,
///     },
///     body: iso2::Body {
///         choice: Some(iso2::BodyChoice::CableCheckReq(iso2::CableCheckReq {
///             dc_ev_status: status,
///         })),
///     },
/// })));
///
/// let energy = message.ev_energy_status().expect("a DC request states a SoC");
/// assert_eq!(energy.present_soc, Some(42));
/// assert_eq!(energy.energy_capacity, None, "a cable check says nothing about capacity");
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct EvEnergyStatus {
    /// State of charge right now, as a percentage.
    ///
    /// `EVRESSSOC` in ISO 15118-2, `PresentSOC` in ISO 15118-20.
    pub present_soc: Option<u8>,
    /// The state of charge the vehicle is aiming for.
    ///
    /// ISO 15118-20 only: -2 has no equivalent, and `FullSOC` is not it —
    /// that is the point above which the vehicle considers itself *full*, which
    /// is [`EvEnergyStatus::full_soc`].
    pub target_soc: Option<u8>,
    /// The state of charge below which the vehicle considers itself short.
    ///
    /// ISO 15118-20 only.
    pub minimum_soc: Option<u8>,
    /// The state of charge at which the vehicle is fully charged.
    ///
    /// `FullSOC` in ISO 15118-2, `MaximumSOC` in ISO 15118-20. Not always 100:
    /// a vehicle may declare itself full below the cell chemistry's ceiling.
    pub full_soc: Option<u8>,
    /// The state of charge at which bulk charging ends and the taper begins.
    ///
    /// ISO 15118-2 only.
    pub bulk_soc: Option<u8>,
    /// Usable battery capacity.
    ///
    /// `EVEnergyCapacity` in ISO 15118-2, `BatteryEnergyCapacity` in
    /// ISO 15118-20.
    pub energy_capacity: Option<MilliwattHours>,
    /// The energy the vehicle is asking for.
    ///
    /// `EAmount` (AC) or `EVEnergyRequest` (DC) in ISO 15118-2,
    /// `EVTargetEnergyRequest` in ISO 15118-20.
    pub target_energy_request: Option<MilliwattHours>,
    /// The least the vehicle will accept, in ISO 15118-20's terms.
    pub minimum_energy_request: Option<MilliwattHours>,
    /// The most the vehicle will accept, in ISO 15118-20's terms.
    pub maximum_energy_request: Option<MilliwattHours>,
    /// Seconds from now until the vehicle intends to leave.
    ///
    /// Relative, not absolute, in both generations — which is what makes it
    /// usable without a synchronised clock, and what makes it meaningless if
    /// it is stored rather than acted on.
    pub departure_in: Option<u32>,
    /// True once the vehicle says it has finished charging.
    pub charging_complete: Option<bool>,
}

impl EvEnergyStatus {
    /// Folds in an ISO 15118-20 dynamic control mode's energy request.
    ///
    /// The four dynamic modes — AC and DC, each with and without bidirectional
    /// power transfer — declare these four fields identically, so reading them
    /// is one function rather than four copies of one.
    #[cfg(any(feature = "iso20-ac", feature = "iso20-dc"))]
    fn take_request(
        &mut self,
        departure: Option<u32>,
        target: &crate::iso20::common::RationalNumber,
        minimum: &crate::iso20::common::RationalNumber,
        maximum: &crate::iso20::common::RationalNumber,
    ) {
        self.departure_in = departure;
        self.target_energy_request = rational_mwh(target);
        self.minimum_energy_request = rational_mwh(minimum);
        self.maximum_energy_request = rational_mwh(maximum);
    }

    /// True when nothing at all was stated.
    ///
    /// [`Message::ev_energy_status`] returns `None` rather than an empty status
    /// for a message that carries no battery information, so this is only ever
    /// true for one built by hand.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Converts an ISO 15118-2 `PhysicalValue` energy to [`MilliwattHours`].
///
/// Refuses a value that is not in watt-hours. `EVEnergyCapacity`, `EAmount` and
/// `EVEnergyRequest` are all `Wh` by Table 68, and reading a voltage as an
/// energy because both happen to be integers is the kind of agreement nobody
/// notices until it is on an invoice.
#[cfg(feature = "iso2")]
fn energy_mwh(value: &crate::iso2::PhysicalValue) -> Option<MilliwattHours> {
    if value.unit != crate::iso2::UnitSymbol::Wh {
        return None;
    }
    scale_mwh(i64::from(value.value), i32::from(value.multiplier))
}

/// The same for ISO 15118-20's `RationalNumber`, which carries no unit at all —
/// the schema fixes it per element, and every element read here is energy.
#[cfg(feature = "iso20-common")]
fn rational_mwh(value: &crate::iso20::common::RationalNumber) -> Option<MilliwattHours> {
    scale_mwh(i64::from(value.value), i32::from(value.exponent))
}

/// `value * 10^(exponent + 3)`, or `None` where that is not an exact integer or
/// does not fit.
///
/// Both callers are behind a protocol feature, so this is too.
///
/// A negative result exponent would be a fraction of a milliwatt-hour. Rounding
/// it away would be a silent loss on a billable quantity, so it is refused
/// instead — both schemas' facets keep real values far inside the range where
/// this cannot happen.
#[cfg(any(feature = "iso2", feature = "iso20-common"))]
fn scale_mwh(value: i64, exponent: i32) -> Option<MilliwattHours> {
    let exponent = exponent.checked_add(3)?;
    let scale = 10i64.checked_pow(u32::try_from(exponent).ok()?)?;
    value.checked_mul(scale)
}

/// What a response's `ResponseCode` says about the session.
///
/// The three classes are the standard's own, split by the code's name prefix,
/// and they differ in exactly one thing that matters to a protocol core:
/// whether the session goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Outcome {
    /// An `OK_*` code. Carry on.
    Ok,
    /// A `WARNING_*` code. Carry on, but the application should know.
    Warning,
    /// A `FAILED_*` code. The session is over: the only request either side may
    /// still send is `SessionStopReq`.
    Failed,
}

impl Outcome {
    /// True when the session ends here.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// Why a frame could not be turned into a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageError {
    /// The EXI body was malformed, or was not of the schema set expected.
    Exi(ExiError),
    /// The payload type carries something other than a V2G message — an SDP
    /// datagram, for instance.
    NotAMessage(PayloadType),
    /// The payload type does not belong to this session at all.
    ///
    /// A -20 type in a session that negotiated -2, or any session type before
    /// the handshake. \[V2G2-800\] has a receiver **ignore** such a message, and
    /// [`Connection::next_message`](crate::session::Connection::next_message)
    /// does — so this variant is what that skipping is *made of* rather than
    /// something a session driver ever surfaces.
    NotForThisSession {
        /// The payload type that arrived.
        payload_type: PayloadType,
        /// The protocol the session had agreed, if any.
        protocol: Option<Protocol>,
    },
    /// The payload type belongs to this session, and this build has no message
    /// set for it.
    ///
    /// DIN SPEC 70121, whose schemas are not freely available, or an
    /// ISO 15118-20 schema set behind a feature that is off. Unlike
    /// [`MessageError::NotForThisSession`] this is **not** ignored: the message
    /// is part of the session, and silently dropping it would look like a peer
    /// that had gone quiet. Supply the codec and drive
    /// [`Connection::next_frame`](crate::session::Connection::next_frame).
    NoCodec {
        /// The payload type that arrived.
        payload_type: PayloadType,
        /// The protocol the session had agreed, if any.
        protocol: Option<Protocol>,
    },
}

impl From<ExiError> for MessageError {
    fn from(e: ExiError) -> Self {
        Self::Exi(e)
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exi(e) => write!(f, "EXI: {e}"),
            Self::NotAMessage(t) => {
                write!(f, "V2GTP payload type {:#06x} does not carry a V2G message", t.as_u16())
            }
            Self::NotForThisSession { payload_type, protocol } => write!(
                f,
                "V2GTP payload type {:#06x} does not belong to {}",
                payload_type.as_u16(),
                match protocol {
                    Some(p) => p.as_str(),
                    None => "an unnegotiated session",
                }
            ),
            Self::NoCodec { payload_type, protocol } => write!(
                f,
                "no message set compiled in for V2GTP payload type {:#06x} under {}",
                payload_type.as_u16(),
                match protocol {
                    Some(p) => p.as_str(),
                    None => "an unnegotiated session",
                }
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Exi(e) => Some(e),
            _ => None,
        }
    }
}
