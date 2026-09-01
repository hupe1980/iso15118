//! The `supportedAppProtocol` handshake (ISO 15118-2 §8.2, Annex C).
//!
//! Before either side knows which protocol generation it is speaking, the
//! vehicle sends a list of the application protocols it supports, each with a
//! priority and a schema id. The charger picks one and answers with its schema
//! id. Everything after this point — grammars, payload types, state machines —
//! follows from that choice.
//!
//! The handshake has its own tiny schema (`V2G_CI_AppProtocol.xsd`) shared by
//! all three protocol generations, which is why this module is always compiled
//! regardless of which protocol features are enabled.
//!
//! # Wire format
//!
//! This is the crate's reference implementation of a hand-written
//! schema-informed EXI grammar; generated code for the larger schemas follows
//! exactly this shape. The event-code widths below are not guesses — they are
//! derived from the non-strict schema-informed grammar and pinned by golden
//! vectors in the tests at the bottom of this file.

use alloc::string::String;
use alloc::vec::Vec;

use crate::exi::{Decoder, Encoder, ExiDocument, ExiError, ExiResult, Header, Lengths, ValueCtx};
use crate::{Error, Protocol, Protocols, Result};

/// Maximum number of `AppProtocol` entries a request may carry (`maxOccurs`).
pub const MAX_APP_PROTOCOLS: usize = 20;

/// Maximum length of `ProtocolNamespace` in characters (`maxLength`).
pub const MAX_NAMESPACE_LEN: usize = 100;

/// The length facets of `ProtocolNamespace` — a maximum and no minimum.
const NAMESPACE_LEN: Lengths = Lengths::max(MAX_NAMESPACE_LEN);

/// Lowest (numerically largest) priority value.
pub const MAX_PRIORITY: u8 = 20;

/// String table partition for `ProtocolNamespace`, the schema's only string.
const CTX_PROTOCOL_NAMESPACE: ValueCtx = ValueCtx(0);

// --- Event-code widths, derived from the non-strict schema-informed grammar
// ---
//
// The schema declares two global elements. Non-strict grammars add a generic
// `SE(*)` production at the document level, so the root choice is among three:
// two bits. Inside the document, every state whose schema permits exactly one
// event still costs one bit, because non-strict grammars always carry
// second-level productions for undeclared content.

/// Root element choice: `supportedAppProtocolReq` | `supportedAppProtocolRes` |
/// `SE(*)`.
const W_ROOT: u32 = 2;
/// Event code for `supportedAppProtocolReq` (sorts before `...Res`).
const EC_REQ: u64 = 0;
/// Event code for `supportedAppProtocolRes`.
const EC_RES: u64 = 1;

/// A state with a single declared production (plus second-level productions).
const W_ONE: u32 = 1;
/// A state with two declared productions (plus second-level productions).
const W_TWO: u32 = 2;

/// `responseCodeType` has three enumeration values.
const W_RESPONSE_CODE: u32 = 2;
/// `responseCodeType` has three enumeration values.
///
/// `idType` restricts `xs:unsignedByte`, so a `SchemaID` is an eight-bit
/// restricted integer over 0..=255, and `priorityType` narrows that further to
/// 1..=20 — twenty values, five bits, offset by the minimum. Both go through
/// [`Encoder::restricted`](crate::exi::Encoder::restricted), which enforces the
/// facets on the way in and on the way out.
const SCHEMA_ID_RANGE: (i64, i64) = (0, 255);
/// `priorityType` restricts to 1..=20.
const PRIORITY_RANGE: (i64, i64) = (1, MAX_PRIORITY as i64);

/// One entry of the vehicle's protocol list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppProtocol {
    /// Namespace URI identifying the protocol, e.g.
    /// `urn:iso:15118:2:2013:MsgDef`.
    pub protocol_namespace: String,
    /// Major version of that protocol.
    pub version_number_major: u32,
    /// Minor version of that protocol.
    pub version_number_minor: u32,
    /// Identifier the charger echoes back to select this entry.
    pub schema_id: u8,
    /// Preference, `1` being the vehicle's first choice.
    pub priority: u8,
}

impl AppProtocol {
    /// Builds an entry advertising one of the protocols this crate implements.
    #[must_use]
    pub fn for_protocol(protocol: Protocol, schema_id: u8, priority: u8) -> Self {
        let (major, minor) = protocol.version();
        Self {
            protocol_namespace: String::from(protocol.namespace()),
            version_number_major: major,
            version_number_minor: minor,
            schema_id,
            priority,
        }
    }

    /// The protocol this entry names, if this crate knows it.
    #[must_use]
    pub fn protocol(&self) -> Option<Protocol> {
        Protocol::from_namespace(&self.protocol_namespace)
    }

    /// Checks the entry against its schema facets.
    pub fn validate(&self) -> Result<()> {
        if self.protocol_namespace.chars().count() > MAX_NAMESPACE_LEN {
            return Err(Error::InvalidValue("AppProtocol.ProtocolNamespace"));
        }
        if !(1..=MAX_PRIORITY).contains(&self.priority) {
            return Err(Error::InvalidValue("AppProtocol.Priority"));
        }
        Ok(())
    }

    fn encode(&self, e: &mut Encoder<'_>) -> ExiResult<()> {
        e.enter()?;
        // SE(ProtocolNamespace), CH, value, EE
        e.event(0, W_ONE)?;
        e.event(0, W_ONE)?;
        e.string(CTX_PROTOCOL_NAMESPACE, &self.protocol_namespace, NAMESPACE_LEN)?;
        e.event(0, W_ONE)?;
        // SE(VersionNumberMajor), CH, value, EE
        e.event(0, W_ONE)?;
        e.event(0, W_ONE)?;
        e.uint(u64::from(self.version_number_major))?;
        e.event(0, W_ONE)?;
        // SE(VersionNumberMinor), CH, value, EE
        e.event(0, W_ONE)?;
        e.event(0, W_ONE)?;
        e.uint(u64::from(self.version_number_minor))?;
        e.event(0, W_ONE)?;
        // SE(SchemaID), CH, value, EE
        e.event(0, W_ONE)?;
        e.event(0, W_ONE)?;
        e.restricted(i64::from(self.schema_id), SCHEMA_ID_RANGE.0, SCHEMA_ID_RANGE.1)?;
        e.event(0, W_ONE)?;
        // SE(Priority), CH, value, EE
        e.event(0, W_ONE)?;
        e.event(0, W_ONE)?;
        e.restricted(i64::from(self.priority), PRIORITY_RANGE.0, PRIORITY_RANGE.1)?;
        e.event(0, W_ONE)?;
        // EE(AppProtocol)
        e.event(0, W_ONE)?;
        e.leave();
        Ok(())
    }

    fn decode(d: &mut Decoder<'_>) -> ExiResult<Self> {
        d.enter()?;
        expect(d, W_ONE, 0)?; // SE(ProtocolNamespace)
        expect(d, W_ONE, 0)?; // CH
        let protocol_namespace = d.string(CTX_PROTOCOL_NAMESPACE, NAMESPACE_LEN)?;
        expect(d, W_ONE, 0)?; // EE

        expect(d, W_ONE, 0)?;
        expect(d, W_ONE, 0)?;
        let version_number_major =
            u32::try_from(d.uint()?).map_err(|_| ExiError::IntegerOverflow)?;
        expect(d, W_ONE, 0)?;

        expect(d, W_ONE, 0)?;
        expect(d, W_ONE, 0)?;
        let version_number_minor =
            u32::try_from(d.uint()?).map_err(|_| ExiError::IntegerOverflow)?;
        expect(d, W_ONE, 0)?;

        expect(d, W_ONE, 0)?;
        expect(d, W_ONE, 0)?;
        let schema_id = u8::try_from(d.restricted(SCHEMA_ID_RANGE.0, SCHEMA_ID_RANGE.1)?)
            .map_err(|_| ExiError::ValueOutOfRange)?;
        expect(d, W_ONE, 0)?;

        expect(d, W_ONE, 0)?;
        expect(d, W_ONE, 0)?;
        // Five bits can express 0..=31, but the schema only permits 1..=20;
        // `restricted` rejects the twelve encodings that are out of range.
        let priority = u8::try_from(d.restricted(PRIORITY_RANGE.0, PRIORITY_RANGE.1)?)
            .map_err(|_| ExiError::ValueOutOfRange)?;
        expect(d, W_ONE, 0)?;

        expect(d, W_ONE, 0)?; // EE(AppProtocol)
        d.leave();
        Ok(Self {
            protocol_namespace,
            version_number_major,
            version_number_minor,
            schema_id,
            priority,
        })
    }
}

/// Reads an event code and insists it is the one the grammar requires.
fn expect(d: &mut Decoder<'_>, width: u32, code: u64) -> ExiResult<()> {
    if d.event(width)? == code { Ok(()) } else { Err(ExiError::UnknownEventCode) }
}

/// `supportedAppProtocolReq` — the vehicle's list of protocols.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SupportedAppProtocolReq {
    /// Between one and [`MAX_APP_PROTOCOLS`] entries.
    pub app_protocols: Vec<AppProtocol>,
}

impl SupportedAppProtocolReq {
    /// Builds a request advertising `protocols`, most preferred first.
    ///
    /// Schema ids and priorities are both assigned in order starting at 1, so
    /// the *n*th protocol of the set is schema id *n*. A [`Protocols`] set
    /// holds each protocol once, so no two entries can share a schema id —
    /// which is what makes [`SupportedAppProtocolReq::protocol_for_schema_id`]
    /// an unambiguous lookup on the way back.
    ///
    /// An empty set produces a request with no entries, which
    /// [`SupportedAppProtocolReq::validate`] rejects: the schema requires at
    /// least one.
    #[must_use]
    pub fn advertising(protocols: impl Into<Protocols>) -> Self {
        let app_protocols = protocols
            .into()
            .iter()
            .enumerate()
            .take(MAX_APP_PROTOCOLS)
            .map(|(i, p)| {
                #[allow(clippy::cast_possible_truncation)]
                AppProtocol::for_protocol(p, i as u8 + 1, i as u8 + 1)
            })
            .collect();
        Self { app_protocols }
    }

    /// The protocol the entry with this schema id names.
    ///
    /// The charger's answer echoes a schema id and not a namespace, so this is
    /// how the vehicle learns which protocol was chosen. `None` means no entry
    /// carries that id — a charger answering with one that was never offered —
    /// or that the entry names a protocol this crate does not know.
    ///
    /// Where two entries share an id, the first wins. Schema ids are the
    /// vehicle's to assign and nothing in the schema stops a peer repeating
    /// one; [`SupportedAppProtocolReq::advertising`] never does.
    #[must_use]
    pub fn protocol_for_schema_id(&self, schema_id: u8) -> Option<Protocol> {
        self.app_protocols.iter().find(|e| e.schema_id == schema_id)?.protocol()
    }

    /// Checks cardinality and every entry against the schema.
    pub fn validate(&self) -> Result<()> {
        if self.app_protocols.is_empty() {
            return Err(Error::TooFewItems {
                field: "supportedAppProtocolReq.AppProtocol",
                count: 0,
                min: 1,
            });
        }
        if self.app_protocols.len() > MAX_APP_PROTOCOLS {
            return Err(Error::TooManyItems {
                field: "supportedAppProtocolReq.AppProtocol",
                count: self.app_protocols.len(),
                max: MAX_APP_PROTOCOLS,
            });
        }
        for p in &self.app_protocols {
            p.validate()?;
        }
        Ok(())
    }

    /// Chooses the best protocol this charger and this vehicle share.
    ///
    /// The vehicle's `priority` decides, `1` being its first choice; ties fall
    /// back to list order. `supported` is the station's set, and its own order
    /// is ignored on purpose — \[V2G2-169\] has the SECC select, from its own
    /// list, "the protocol with highest Priority indicated by the EVCC". The
    /// station's preference is not a tie-break; it has no say at all.
    ///
    /// A namespace match with a differing major version is *not* a match — a
    /// major version bump means an incompatible schema — but a differing minor
    /// version is, and must be confirmed rather than refused \[V2G2-170\]. It
    /// is reported as a minor deviation so the caller can send the response
    /// code the spec requires.
    ///
    /// Narrow `supported` to what can actually be spoken *before* calling
    /// this, not after. A protocol that wins here and is then discarded takes
    /// the whole session with it, when a lower-priority entry both sides had in
    /// common was sitting in the same request — see
    /// [`Flow::supports`](crate::session::Flow::supports), which is what the
    /// role drivers use.
    #[must_use]
    pub fn negotiate(&self, supported: impl Into<Protocols>) -> Option<Negotiated> {
        let supported = supported.into();
        // Track the winning priority alongside the winner: schema ids are the
        // vehicle's to choose and nothing stops it repeating one, so looking
        // the priority back up by schema id could find the wrong entry.
        let mut best: Option<(u8, Negotiated)> = None;
        for entry in &self.app_protocols {
            let Some(protocol) = entry.protocol() else { continue };
            if !supported.contains(protocol) {
                continue;
            }
            let (major, minor) = protocol.version();
            // A differing major version means an incompatible schema, so it is
            // not a match at all; a differing minor version is, and is reported
            // so the caller can send `..._WithMinorDeviation`.
            if entry.version_number_major != major {
                continue;
            }
            // Priority 1 is the vehicle's first choice; ties keep the earlier
            // entry, which is list order.
            if best.as_ref().is_some_and(|&(p, _)| entry.priority >= p) {
                continue;
            }
            best = Some((
                entry.priority,
                Negotiated {
                    protocol,
                    schema_id: entry.schema_id,
                    minor_deviation: entry.version_number_minor != minor,
                },
            ));
        }
        best.map(|(_, n)| n)
    }
}

/// The outcome of [`SupportedAppProtocolReq::negotiate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Negotiated {
    /// The protocol both sides will speak.
    pub protocol: Protocol,
    /// The schema id to echo in the response.
    pub schema_id: u8,
    /// True when the minor versions differed.
    pub minor_deviation: bool,
}

impl Negotiated {
    /// The response code this outcome calls for.
    #[must_use]
    pub const fn response_code(self) -> ResponseCode {
        if self.minor_deviation {
            ResponseCode::OkSuccessfulNegotiationWithMinorDeviation
        } else {
            ResponseCode::OkSuccessfulNegotiation
        }
    }
}

/// `responseCodeType`.
///
/// Discriminants are the EXI enumeration indices, which follow the order the
/// values appear in the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ResponseCode {
    /// A protocol was agreed.
    OkSuccessfulNegotiation = 0,
    /// A protocol was agreed, but the minor versions differ.
    OkSuccessfulNegotiationWithMinorDeviation = 1,
    /// No protocol in common; the session cannot continue.
    FailedNoNegotiation = 2,
}

impl ResponseCode {
    /// Parses an EXI enumeration index.
    pub const fn from_index(index: u64) -> ExiResult<Self> {
        Ok(match index {
            0 => Self::OkSuccessfulNegotiation,
            1 => Self::OkSuccessfulNegotiationWithMinorDeviation,
            2 => Self::FailedNoNegotiation,
            _ => return Err(ExiError::UnknownEnumValue),
        })
    }

    /// True when the handshake succeeded.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(
            self,
            Self::OkSuccessfulNegotiation | Self::OkSuccessfulNegotiationWithMinorDeviation
        )
    }
}

/// `supportedAppProtocolRes` — the charger's choice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SupportedAppProtocolRes {
    /// Whether a protocol was agreed.
    pub response_code: ResponseCode,
    /// The chosen entry's schema id. Absent when negotiation failed.
    pub schema_id: Option<u8>,
}

impl SupportedAppProtocolRes {
    /// The response for a successful negotiation.
    #[must_use]
    pub const fn accept(negotiated: Negotiated) -> Self {
        Self { response_code: negotiated.response_code(), schema_id: Some(negotiated.schema_id) }
    }

    /// The response for "we have nothing in common".
    ///
    /// `Failed_NoNegotiation`, and **no schema id** — naming one would name a
    /// protocol that was not agreed \[V2G2-172\]. The vehicle's own reaction is
    /// fixed too: it does not open a communication session \[V2G2-173\].
    #[must_use]
    pub const fn reject() -> Self {
        Self { response_code: ResponseCode::FailedNoNegotiation, schema_id: None }
    }

    /// Checks the response is internally consistent.
    ///
    /// A success without a schema id names no protocol, and a failure with one
    /// contradicts itself; both would leave the vehicle guessing.
    pub fn validate(&self) -> Result<()> {
        match (self.response_code.is_ok(), self.schema_id.is_some()) {
            (true, false) | (false, true) => {
                Err(Error::InvalidValue("supportedAppProtocolRes.SchemaID"))
            }
            _ => Ok(()),
        }
    }
}

impl ExiDocument for SupportedAppProtocolReq {
    fn to_slice(&self, buf: &mut [u8]) -> ExiResult<usize> {
        if self.app_protocols.is_empty() || self.app_protocols.len() > MAX_APP_PROTOCOLS {
            return Err(ExiError::ValueTooLong);
        }
        let mut e = Encoder::new(buf);
        e.write_header(Header::ISO15118)?;
        e.event(EC_REQ, W_ROOT)?;

        for (i, p) in self.app_protocols.iter().enumerate() {
            // The first entry is mandatory, so its state offers only SE; later
            // states also offer EE and therefore need a wider code.
            if i == 0 {
                e.event(0, W_ONE)?;
            } else {
                e.event(0, W_TWO)?;
            }
            p.encode(&mut e)?;
        }
        // EE(supportedAppProtocolReq). After the twentieth entry the grammar
        // permits nothing else, so the code narrows.
        if self.app_protocols.len() == MAX_APP_PROTOCOLS {
            e.event(0, W_ONE)?;
        } else {
            e.event(1, W_TWO)?;
        }
        e.finish()
    }

    fn from_bytes(bytes: &[u8]) -> ExiResult<Self> {
        let mut d = Decoder::new(bytes);
        d.read_header()?;
        if d.event(W_ROOT)? != EC_REQ {
            return Err(ExiError::UnknownEventCode);
        }

        let mut app_protocols = Vec::new();
        // First entry is mandatory.
        expect(&mut d, W_ONE, 0)?;
        app_protocols.push(AppProtocol::decode(&mut d)?);

        loop {
            if app_protocols.len() == MAX_APP_PROTOCOLS {
                expect(&mut d, W_ONE, 0)?; // EE only
                break;
            }
            match d.event(W_TWO)? {
                0 => app_protocols.push(AppProtocol::decode(&mut d)?),
                1 => break, // EE
                _ => return Err(ExiError::UnknownEventCode),
            }
        }

        d.finish()?;
        Ok(Self { app_protocols })
    }
}

impl ExiDocument for SupportedAppProtocolRes {
    fn to_slice(&self, buf: &mut [u8]) -> ExiResult<usize> {
        let mut e = Encoder::new(buf);
        e.write_header(Header::ISO15118)?;
        e.event(EC_RES, W_ROOT)?;

        // SE(ResponseCode), CH, value, EE
        e.event(0, W_ONE)?;
        e.event(0, W_ONE)?;
        e.nbit(self.response_code as u64, W_RESPONSE_CODE)?;
        e.event(0, W_ONE)?;

        match self.schema_id {
            Some(id) => {
                e.event(0, W_TWO)?; // SE(SchemaID)
                e.event(0, W_ONE)?; // CH
                e.restricted(i64::from(id), SCHEMA_ID_RANGE.0, SCHEMA_ID_RANGE.1)?;
                e.event(0, W_ONE)?; // EE(SchemaID)
                e.event(0, W_ONE)?; // EE(supportedAppProtocolRes)
            }
            None => e.event(1, W_TWO)?, // EE(supportedAppProtocolRes)
        }
        e.finish()
    }

    fn from_bytes(bytes: &[u8]) -> ExiResult<Self> {
        let mut d = Decoder::new(bytes);
        d.read_header()?;
        if d.event(W_ROOT)? != EC_RES {
            return Err(ExiError::UnknownEventCode);
        }

        expect(&mut d, W_ONE, 0)?; // SE(ResponseCode)
        expect(&mut d, W_ONE, 0)?; // CH
        let response_code = ResponseCode::from_index(d.nbit(W_RESPONSE_CODE)?)?;
        expect(&mut d, W_ONE, 0)?; // EE

        let schema_id = match d.event(W_TWO)? {
            0 => {
                expect(&mut d, W_ONE, 0)?; // CH
                let id = u8::try_from(d.restricted(SCHEMA_ID_RANGE.0, SCHEMA_ID_RANGE.1)?)
                    .map_err(|_| ExiError::ValueOutOfRange)?;
                expect(&mut d, W_ONE, 0)?; // EE(SchemaID)
                expect(&mut d, W_ONE, 0)?; // EE(root)
                Some(id)
            }
            1 => None, // EE(root)
            _ => return Err(ExiError::UnknownEventCode),
        };

        d.finish()?;
        Ok(Self { response_code, schema_id })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Golden vectors produced by the EXI reference implementation
    /// (`exificient` 1.0.7) from `V2G_CI_AppProtocol.xsd`, schema-informed,
    /// bit-packed, default fidelity options. The same settings reproduce
    /// third-party ISO 15118-20 captures byte for byte; see `tests/golden.rs`.
    mod golden {
        pub(super) const REQ_ISO2: &str =
            "8000ebab9371d34b9b79d189a98989c1d191d191818999d26b9b3a232b30020000040040";
        pub(super) const REQ_TWO: &str = "8000f3ab9371d34b9b79d39ba321d34b9b79d189a98989c1d1699181d22218010000280001d75726e3a69736f3a31353131383a323a323031333a4d73674465660040000a00880";
        pub(super) const RES_OK: &str = "80400040";
        pub(super) const RES_FAILED: &str = "804880";
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    fn iso2_entry() -> AppProtocol {
        AppProtocol {
            protocol_namespace: String::from("urn:iso:15118:2:2013:MsgDef"),
            version_number_major: 2,
            version_number_minor: 0,
            schema_id: 1,
            priority: 1,
        }
    }

    #[test]
    fn request_matches_the_golden_vector() {
        let req = SupportedAppProtocolReq { app_protocols: vec![iso2_entry()] };
        assert_eq!(hex(&req.to_vec().unwrap()), golden::REQ_ISO2);
    }

    #[test]
    fn two_entry_request_matches_the_golden_vector() {
        let req = SupportedAppProtocolReq {
            app_protocols: vec![
                AppProtocol {
                    protocol_namespace: String::from("urn:iso:std:iso:15118:-20:DC"),
                    version_number_major: 1,
                    version_number_minor: 0,
                    schema_id: 10,
                    priority: 1,
                },
                AppProtocol {
                    protocol_namespace: String::from("urn:iso:15118:2:2013:MsgDef"),
                    version_number_major: 2,
                    version_number_minor: 0,
                    schema_id: 20,
                    priority: 2,
                },
            ],
        };
        assert_eq!(hex(&req.to_vec().unwrap()), golden::REQ_TWO);
    }

    #[test]
    fn successful_response_matches_the_golden_vector() {
        let res = SupportedAppProtocolRes {
            response_code: ResponseCode::OkSuccessfulNegotiation,
            schema_id: Some(1),
        };
        assert_eq!(hex(&res.to_vec().unwrap()), golden::RES_OK);
    }

    #[test]
    fn failed_response_matches_the_golden_vector() {
        assert_eq!(hex(&SupportedAppProtocolRes::reject().to_vec().unwrap()), golden::RES_FAILED);
    }

    #[test]
    fn golden_vectors_decode_back() {
        let req = SupportedAppProtocolReq::from_bytes(&unhex(golden::REQ_ISO2)).unwrap();
        assert_eq!(req.app_protocols, vec![iso2_entry()]);

        let req2 = SupportedAppProtocolReq::from_bytes(&unhex(golden::REQ_TWO)).unwrap();
        assert_eq!(req2.app_protocols.len(), 2);
        assert_eq!(req2.app_protocols[1].schema_id, 20);
        assert_eq!(req2.app_protocols[1].priority, 2);

        let res = SupportedAppProtocolRes::from_bytes(&unhex(golden::RES_OK)).unwrap();
        assert_eq!(res.schema_id, Some(1));
        assert_eq!(res.response_code, ResponseCode::OkSuccessfulNegotiation);

        let failed = SupportedAppProtocolRes::from_bytes(&unhex(golden::RES_FAILED)).unwrap();
        assert_eq!(failed, SupportedAppProtocolRes::reject());
    }

    #[test]
    fn maximum_entry_count_roundtrips() {
        // The twentieth entry closes the repetition, which narrows the final
        // event code — the one boundary the grammar changes shape at.
        let app_protocols: Vec<_> = (0..MAX_APP_PROTOCOLS)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                AppProtocol {
                    protocol_namespace: alloc::format!("urn:example:{i}"),
                    version_number_major: 1,
                    version_number_minor: 0,
                    schema_id: i as u8,
                    priority: i as u8 + 1,
                }
            })
            .collect();
        let req = SupportedAppProtocolReq { app_protocols };
        let bytes = req.to_vec().unwrap();
        assert_eq!(SupportedAppProtocolReq::from_bytes(&bytes).unwrap(), req);
    }

    /// Found by `cargo fuzz`: five bits can carry 0..=31, but `priorityType`
    /// only defines 1..=20. The decoder used to pass the surplus twelve values
    /// through, producing an `AppProtocol` that then failed to re-encode.
    #[test]
    fn an_out_of_range_priority_is_rejected_by_the_decoder() {
        const CRASH: &[u8] = &[144, 0, 36, 27, 255, 16, 0, 0, 0, 0, 64, 104, 64];
        assert_eq!(
            SupportedAppProtocolReq::from_bytes(CRASH),
            Err(ExiError::ValueOutOfRange),
            "priority 21..=32 is not representable and must not decode"
        );
    }

    #[test]
    fn every_decodable_request_re_encodes() {
        // The property the fuzz target asserts, pinned as a unit test over the
        // priority range: decode must never yield a value encode rejects.
        for raw in 0u8..32 {
            let mut buf = [0u8; 128];
            let mut e = Encoder::new(&mut buf);
            e.write_header(Header::ISO15118).unwrap();
            e.event(EC_REQ, W_ROOT).unwrap();
            e.event(0, W_ONE).unwrap();
            for _ in 0..2 {
                e.event(0, W_ONE).unwrap();
            }
            e.string(CTX_PROTOCOL_NAMESPACE, "urn:x", NAMESPACE_LEN).unwrap();
            for _ in 0..3 {
                e.event(0, W_ONE).unwrap();
            }
            e.uint(1).unwrap();
            for _ in 0..3 {
                e.event(0, W_ONE).unwrap();
            }
            e.uint(0).unwrap();
            for _ in 0..3 {
                e.event(0, W_ONE).unwrap();
            }
            e.nbit(1, 8).unwrap();
            for _ in 0..3 {
                e.event(0, W_ONE).unwrap();
            }
            e.nbit(u64::from(raw), 5).unwrap();
            e.event(0, W_ONE).unwrap();
            e.event(0, W_ONE).unwrap();
            e.event(1, W_TWO).unwrap();
            let n = e.finish().unwrap();

            match SupportedAppProtocolReq::from_bytes(&buf[..n]) {
                Ok(req) => {
                    assert!(raw < 20, "raw priority index {raw} should not have decoded");
                    req.to_vec().expect("anything that decodes must re-encode");
                }
                Err(e) => assert!(raw >= 20, "raw priority index {raw} should decode, got {e}"),
            }
        }
    }

    #[test]
    fn priority_bounds_are_enforced() {
        let mut p = iso2_entry();
        p.priority = 0;
        assert!(p.validate().is_err());
        p.priority = 21;
        assert!(p.validate().is_err());
        p.priority = 20;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn an_over_long_namespace_is_refused() {
        let p =
            AppProtocol { protocol_namespace: "x".repeat(MAX_NAMESPACE_LEN + 1), ..iso2_entry() };
        assert!(p.validate().is_err());
        let req = SupportedAppProtocolReq { app_protocols: vec![p] };
        assert_eq!(req.to_vec(), Err(ExiError::ValueTooLong));
    }

    #[test]
    fn an_empty_request_is_refused() {
        let req = SupportedAppProtocolReq::default();
        assert!(req.validate().is_err());
        assert!(req.to_vec().is_err());
    }

    #[test]
    fn negotiation_prefers_the_vehicles_priority_not_the_list_order() {
        let req = SupportedAppProtocolReq {
            app_protocols: vec![
                AppProtocol::for_protocol(Protocol::Iso2, 1, 2),
                AppProtocol::for_protocol(Protocol::Iso20, 2, 1),
            ],
        };
        let n = req.negotiate([Protocol::Iso2, Protocol::Iso20]).unwrap();
        assert_eq!(n.protocol, Protocol::Iso20, "priority 1 beats list position");
        assert_eq!(n.schema_id, 2);
        assert!(!n.minor_deviation);
    }

    /// The `supported` set really is a set: the vehicle's priority decides, and
    /// \[V2G2-169\] gives the charger no say. `SeccConfig::protocols` says so in
    /// prose; this is the same claim as a test, because a charger operator who
    /// listed their preferred generation first and got the other one would have
    /// no way to tell prose from a bug.
    #[test]
    fn the_chargers_own_order_does_not_decide_anything() {
        let req = SupportedAppProtocolReq::advertising([Protocol::Iso20, Protocol::Iso2]);
        let forwards = req.negotiate([Protocol::Iso2, Protocol::Iso20]).unwrap();
        let backwards = req.negotiate([Protocol::Iso20, Protocol::Iso2]).unwrap();
        assert_eq!(forwards, backwards);
        assert_eq!(forwards.protocol, Protocol::Iso20, "the vehicle's first choice");
    }

    #[test]
    fn negotiation_skips_protocols_the_charger_lacks() {
        let req = SupportedAppProtocolReq::advertising([Protocol::Iso20, Protocol::Iso2]);
        let n = req.negotiate([Protocol::Iso2]).unwrap();
        assert_eq!(n.protocol, Protocol::Iso2);
    }

    #[test]
    fn negotiation_fails_with_nothing_in_common() {
        let req = SupportedAppProtocolReq::advertising([Protocol::Iso20]);
        assert!(req.negotiate([Protocol::Din70121]).is_none());
        assert_eq!(
            SupportedAppProtocolRes::reject().response_code,
            ResponseCode::FailedNoNegotiation
        );
    }

    #[test]
    fn a_differing_major_version_is_not_a_match() {
        let mut entry = AppProtocol::for_protocol(Protocol::Iso2, 1, 1);
        entry.version_number_major = 3;
        let req = SupportedAppProtocolReq { app_protocols: vec![entry] };
        assert!(req.negotiate([Protocol::Iso2]).is_none());
    }

    #[test]
    fn a_differing_minor_version_is_a_deviation_not_a_failure() {
        let mut entry = AppProtocol::for_protocol(Protocol::Iso2, 7, 1);
        entry.version_number_minor = 9;
        let req = SupportedAppProtocolReq { app_protocols: vec![entry] };
        let n = req.negotiate([Protocol::Iso2]).unwrap();
        assert!(n.minor_deviation);
        assert_eq!(n.response_code(), ResponseCode::OkSuccessfulNegotiationWithMinorDeviation);
        assert_eq!(SupportedAppProtocolRes::accept(n).schema_id, Some(7));
    }

    #[test]
    fn an_inconsistent_response_is_refused() {
        assert!(
            SupportedAppProtocolRes {
                response_code: ResponseCode::OkSuccessfulNegotiation,
                schema_id: None,
            }
            .validate()
            .is_err()
        );
        assert!(
            SupportedAppProtocolRes {
                response_code: ResponseCode::FailedNoNegotiation,
                schema_id: Some(1),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn a_request_is_not_a_response() {
        let bytes = unhex(golden::REQ_ISO2);
        assert_eq!(SupportedAppProtocolRes::from_bytes(&bytes), Err(ExiError::UnknownEventCode));
    }

    #[test]
    fn truncated_input_is_refused_without_panicking() {
        let full = unhex(golden::REQ_ISO2);
        for n in 0..full.len() {
            let _ = SupportedAppProtocolReq::from_bytes(&full[..n]);
        }
    }

    #[test]
    fn every_single_bit_flip_is_either_rejected_or_decodes_cleanly() {
        // Not a correctness claim about which — just that no mutation of a
        // valid message can panic or hang the decoder.
        let full = unhex(golden::REQ_TWO);
        for byte in 0..full.len() {
            for bit in 0..8 {
                let mut m = full.clone();
                m[byte] ^= 1 << bit;
                let _ = SupportedAppProtocolReq::from_bytes(&m);
            }
        }
    }
}
