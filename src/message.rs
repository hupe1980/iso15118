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
            _ => Err(MessageError::Unsupported { payload_type, protocol }),
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
    /// session ends \[V2G2-390\]. The session drivers stamp it through here so
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
    /// The payload type belongs to a protocol this build does not have enabled,
    /// or one the session has not negotiated.
    Unsupported {
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
            Self::Unsupported { payload_type, protocol } => write!(
                f,
                "no decoder for V2GTP payload type {:#06x} under {}",
                payload_type.as_u16(),
                match protocol {
                    Some(p) => p.namespace(),
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
