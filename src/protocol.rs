//! Which generation of the protocol a session speaks — and which set of them a
//! piece of equipment implements.
//!
//! [`Protocol`] is the generation a session settled on. [`Protocols`] is a set in
//! preference order: what an EVCC offers, what an SECC accepts, or what a piece
//! of equipment implements. [`Iso20Set`] is an ISO 15118-20 message set as the
//! handshake names it.
//!
//! # The names are deliberate
//!
//! [`Protocol::as_str`] gives `"din70121"`, `"iso15118-2"` and `"iso15118-20"`,
//! and `FromStr` reads them back. A bare `"iso15118"` is refused, with an error
//! saying why: it names neither generation, and some vocabularies around this
//! protocol — DATEX II's AFIR feed among them — use it ambiguously.

use core::fmt;
use core::str::FromStr;

/// Which generation of the protocol a session is speaking.
///
/// The `supportedAppProtocol` handshake picks one of these, and it determines
/// every grammar, payload type and state machine used afterwards.
///
/// The ordering is by generation — `Iso20 > Iso2 > Din70121` — which is what
/// makes [`Protocols::best`] and an SECC's "most capable in common" mean
/// something. It is deliberately *not* the ordering of [`Protocol::version`],
/// which is the schema's own version number and runs the other way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Protocol {
    /// DIN/TS 70121 (formerly DIN SPEC 70121) — legacy DC charging, EIM only,
    /// no TLS.
    ///
    /// Recognised in the handshake so a charger can decline it by name, but its
    /// message set is **not implemented**: the licence of the DIN schemas does
    /// not clearly permit committing code generated from them. See
    /// [`session::Flow::supports`](crate::session::Flow::supports), which is
    /// how the role drivers know; a caller with its own DIN codec drives
    /// [`session::Connection`](crate::session::Connection) directly.
    Din70121,
    /// ISO 15118-2:2014.
    Iso2,
    /// ISO 15118-20:2022.
    Iso20,
}

impl Protocol {
    /// Every protocol this crate recognises, **newest generation first**.
    ///
    /// The order is the one a set wants — newest is the sensible preference —
    /// so that [`Protocols::ALL`] is literally this list and the two cannot
    /// drift into disagreeing about it.
    ///
    /// Recognising is not implementing:
    /// [`session::Flow::supports`](crate::session::Flow::supports) is the
    /// question of whether a build actually has the message set.
    pub const ALL: &'static [Self] = &[Self::Iso20, Self::Iso2, Self::Din70121];

    /// How many protocols there are — the capacity of a [`Protocols`] set.
    pub const COUNT: usize = Self::ALL.len();

    /// A short stable name: `"din70121"`, `"iso15118-2"`, `"iso15118-20"`.
    ///
    /// This is the token to put in a charge-detail record, a log line, a metric
    /// label or a database column. It is stable API: it will not change for an
    /// existing protocol, and [`FromStr`] reads it back, so a value written to
    /// storage under one version of this crate parses under the next.
    ///
    /// Every name says which generation it means. See the [module
    /// documentation](self) for why that is worth insisting on.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Din70121 => "din70121",
            Self::Iso2 => "iso15118-2",
            Self::Iso20 => "iso15118-20",
        }
    }

    /// The document title, for something a person reads.
    ///
    /// `"DIN SPEC 70121:2014"`, `"ISO 15118-2:2014"`, `"ISO 15118-20:2022"`.
    /// Use [`Protocol::as_str`] for anything a machine reads back.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Din70121 => "DIN SPEC 70121:2014",
            Self::Iso2 => "ISO 15118-2:2014",
            Self::Iso20 => "ISO 15118-20:2022",
        }
    }

    /// The XML namespace this crate advertises for the protocol in the
    /// `supportedAppProtocol` handshake when no message set is named.
    ///
    /// ISO 15118-2 and DIN SPEC 70121 have one namespace each. ISO 15118-20
    /// names a **message set** in the handshake — `…:-20:DC`, `…:-20:AC` and four
    /// more, see [`Iso20Set`] — so it has six, and this returns the DC one.
    /// [`Protocol::from_namespace`] recognises all six. Deployed peers agree on
    /// this and on nothing else: Josev's vehicle offers `…:-20:DC` or `…:-20:AC`,
    /// and `EVerest`'s station accepts the DC, AC and two `AC_DER` namespaces and
    /// no other.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Din70121 => "urn:din:70121:2012:MsgDef",
            Self::Iso2 => "urn:iso:15118:2:2013:MsgDef",
            Self::Iso20 => Iso20Set::Dc.namespace(),
        }
    }

    /// Major/minor version numbers advertised alongside the namespace.
    ///
    /// These are the schema's own numbers, carried in the handshake so that a
    /// major-version mismatch can be refused — see
    /// [`SupportedAppProtocolReq::negotiate`](crate::app_protocol::SupportedAppProtocolReq::negotiate).
    /// They are **not** a generation ordinal and do not sort like one:
    /// ISO 15118-2 advertises `(2, 0)` and the newer ISO 15118-20 advertises
    /// `(1, 0)`. Anything that wants to compare generations wants `Ord`;
    /// anything that wants to *record* one wants [`Protocol::as_str`].
    #[must_use]
    #[allow(clippy::match_same_arms, reason = "one arm per protocol reads as a table")]
    pub const fn version(self) -> (u32, u32) {
        match self {
            Self::Din70121 => (2, 0),
            Self::Iso2 => (2, 0),
            Self::Iso20 => (1, 0),
        }
    }

    /// Recognises a protocol from its handshake namespace — any of the six
    /// ISO 15118-20 message-set namespaces for [`Protocol::Iso20`].
    #[must_use]
    pub fn from_namespace(ns: &str) -> Option<Self> {
        if Iso20Set::from_namespace(ns).is_some() {
            return Some(Self::Iso20);
        }
        [Self::Din70121, Self::Iso2].into_iter().find(|p| p.namespace() == ns)
    }

    /// Whether this protocol requires TLS unconditionally.
    #[must_use]
    pub const fn requires_tls(self) -> bool {
        matches!(self, Self::Iso20)
    }
}

/// An ISO 15118-20 message set, as the `supportedAppProtocol` handshake names it.
///
/// ISO 15118-20 does not advertise one namespace for the whole generation: each
/// entry a vehicle offers names the message set of one energy transfer service,
/// `urn:iso:std:iso:15118:-20:` followed by the set. Every one of them selects
/// [`Protocol::Iso20`]; which service the session then uses is decided later, by
/// `ServiceSelectionReq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Iso20Set {
    /// `urn:iso:std:iso:15118:-20:DC`.
    Dc,
    /// `urn:iso:std:iso:15118:-20:AC`.
    Ac,
    /// `urn:iso:std:iso:15118:-20:WPT`.
    Wpt,
    /// `urn:iso:std:iso:15118:-20:ACDP`.
    Acdp,
    /// `urn:iso:std:iso:15118:-20:AC-DER-IEC` (Amd 1).
    AcDerIec,
    /// `urn:iso:std:iso:15118:-20:AC-DER-SAE` (Amd 1).
    AcDerSae,
}

impl Iso20Set {
    /// Every set, in the order [`Iso20Set::namespace`] lists them.
    pub const ALL: [Self; 6] =
        [Self::Dc, Self::Ac, Self::Wpt, Self::Acdp, Self::AcDerIec, Self::AcDerSae];

    /// The handshake namespace — the schema's own target namespace.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Dc => "urn:iso:std:iso:15118:-20:DC",
            Self::Ac => "urn:iso:std:iso:15118:-20:AC",
            Self::Wpt => "urn:iso:std:iso:15118:-20:WPT",
            Self::Acdp => "urn:iso:std:iso:15118:-20:ACDP",
            Self::AcDerIec => "urn:iso:std:iso:15118:-20:AC-DER-IEC",
            Self::AcDerSae => "urn:iso:std:iso:15118:-20:AC-DER-SAE",
        }
    }

    /// The set a handshake namespace names, exactly as spelled.
    #[must_use]
    pub fn from_namespace(ns: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.namespace() == ns)
    }

    /// Whether this build has the message sets a session of this kind needs.
    ///
    /// A pantograph needs two: ACDP to position and connect, DC for the rest.
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::Dc => cfg!(feature = "iso20-dc"),
            Self::Ac => cfg!(feature = "iso20-ac"),
            Self::Wpt => cfg!(feature = "iso20-wpt"),
            Self::Acdp => cfg!(all(feature = "iso20-acdp", feature = "iso20-dc")),
            Self::AcDerIec => cfg!(feature = "iso20-ac-der-iec"),
            Self::AcDerSae => cfg!(feature = "iso20-ac-der-sae"),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = ParseProtocolError;

    /// Reads a [`Protocol::as_str`] name back, ASCII-case-insensitively.
    ///
    /// A [`Protocol::namespace`] is also accepted, exactly as spelled, so a
    /// record that stored the handshake namespace still parses. Nothing else
    /// is: in particular a bare `"iso15118"` is refused rather than guessed at,
    /// with an error that says why — see the [module documentation](self).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(p) = Self::ALL.iter().copied().find(|p| p.as_str().eq_ignore_ascii_case(s)) {
            return Ok(p);
        }
        if let Some(p) = Self::from_namespace(s) {
            return Ok(p);
        }
        // A namespace no peer sends, which releases before 0.6.0 stored for
        // ISO 15118-20; such a record still reads back.
        if s == "urn:iso:std:iso:15118:-20:CommonMessages" {
            return Ok(Self::Iso20);
        }
        Err(ParseProtocolError::for_input(s))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Protocol {
    /// As the [`Protocol::as_str`] name, not as the Rust variant name.
    ///
    /// A serialised protocol is very often a stored one — a charge-detail
    /// record, a session snapshot — and the point of a stable name is that a
    /// consumer sees the same token whether the value travelled through
    /// `Display`, through serde or through a hand-written `match`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Protocol {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Protocol;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(EXPECTED)
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Protocol, E> {
                s.parse().map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// What a [`Protocol`] or [`Protocols`] name could not be parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParseProtocolError {
    generation_omitted: bool,
}

/// The accepted spellings, in one place, so the parser and both error messages
/// cannot disagree about them.
const EXPECTED: &str = r#"one of "din70121", "iso15118-2", "iso15118-20""#;

impl ParseProtocolError {
    /// The error for `input`, distinguishing the one wrong answer worth naming.
    fn for_input(input: &str) -> Self {
        // Every vocabulary that spells ISO 15118 without a generation means a
        // different generation by it, so this is not a name to guess at. It is
        // common enough — and wrong in a way expensive enough — to be worth its
        // own sentence rather than a flat "unrecognised".
        let generation_omitted = input.eq_ignore_ascii_case("iso15118")
            || input.eq_ignore_ascii_case("iso 15118")
            || input.eq_ignore_ascii_case("iso-15118");
        Self { generation_omitted }
    }

    /// True when the input named ISO 15118 without saying which generation.
    ///
    /// Worth branching on where the input came from a vocabulary that cannot
    /// express the distinction: the caller knows what its own source means by
    /// the bare name, and this crate deliberately does not guess.
    #[must_use]
    pub const fn generation_omitted(self) -> bool {
        self.generation_omitted
    }
}

impl fmt::Display for ParseProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.generation_omitted {
            return write!(f, "\"iso15118\" does not say which generation — expected {EXPECTED}");
        }
        write!(f, "unrecognised protocol name — expected {EXPECTED}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseProtocolError {}

/// A set of protocol generations, in preference order.
///
/// What an EVCC offers, most preferred first
/// ([`EvccConfig::protocols`](crate::evcc::EvccConfig::protocols)); what an SECC
/// accepts, where the vehicle's order decides
/// ([`SeccConfig::protocols`](crate::secc::SeccConfig::protocols)); or what a
/// piece of equipment implements.
///
/// `Copy`, allocation-free and `const`-constructible. Entries are distinct:
/// inserting twice keeps the first position. Equality is **order-sensitive** —
/// the order is a stated priority; use [`Protocols::contains`] for membership.
///
/// ```
/// use iso15118::{Protocol, Protocols};
///
/// const OFFERED: Protocols = Protocols::new().with(Protocol::Iso20).with(Protocol::Iso2);
///
/// assert!(OFFERED.contains(Protocol::Iso2));
/// assert_eq!(OFFERED.first(), Some(Protocol::Iso20));   // most preferred
/// assert_eq!(OFFERED.to_string(), "iso15118-20,iso15118-2");
/// assert_eq!("iso15118-20,iso15118-2".parse(), Ok(OFFERED));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Protocols {
    /// Preference order, most preferred first, `None`-padded at the end.
    ///
    /// Capacity is [`Protocol::COUNT`] and the entries are distinct, so an
    /// insert can never overflow and there is no length to keep in step.
    entries: [Option<Protocol>; Protocol::COUNT],
}

impl Protocols {
    /// The empty set — no protocol at all.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; Protocol::COUNT] }
    }

    /// Every protocol this crate recognises, newest generation first.
    ///
    /// Recognising is not implementing: with this as an
    /// [`EvccConfig`](crate::evcc::EvccConfig) or
    /// [`SeccConfig`](crate::secc::SeccConfig) set, the role driver still
    /// offers or accepts only the generations the build has a message set for.
    pub const ALL: Self = Self::from_slice(Protocol::ALL);

    /// The two ISO generations, newest first — the usual thing to speak.
    pub const ISO: Self = Self::new().with(Protocol::Iso20).with(Protocol::Iso2);

    /// A set holding just `protocol`.
    #[must_use]
    pub const fn only(protocol: Protocol) -> Self {
        Self::new().with(protocol)
    }

    /// The set with `protocol` added, in `const` context.
    ///
    /// Appends at the least-preferred end, so chained calls read in preference
    /// order. Adding one that is already present changes nothing — it keeps its
    /// earlier, more-preferred position.
    #[must_use]
    pub const fn with(mut self, protocol: Protocol) -> Self {
        if self.contains(protocol) {
            return self;
        }
        let mut i = 0;
        while i < Protocol::COUNT {
            if self.entries[i].is_none() {
                self.entries[i] = Some(protocol);
                return self;
            }
            i += 1;
        }
        // Unreachable: the entries are distinct and there are `COUNT` slots.
        self
    }

    /// The set built from a slice, most preferred first.
    ///
    /// Duplicates collapse to their first occurrence, so the result never
    /// overflows however long the slice is.
    #[must_use]
    pub const fn from_slice(protocols: &[Protocol]) -> Self {
        let mut set = Self::new();
        let mut i = 0;
        while i < protocols.len() {
            set = set.with(protocols[i]);
            i += 1;
        }
        set
    }

    /// Adds `protocol` at the least-preferred end. True if it was not already
    /// there.
    pub const fn insert(&mut self, protocol: Protocol) -> bool {
        if self.contains(protocol) {
            return false;
        }
        *self = self.with(protocol);
        true
    }

    /// Removes `protocol`, closing the gap. True if it was there.
    pub fn remove(&mut self, protocol: Protocol) -> bool {
        let before = self.len();
        self.retain(|p| p != protocol);
        self.len() != before
    }

    /// Whether `protocol` is in the set.
    #[must_use]
    pub const fn contains(&self, protocol: Protocol) -> bool {
        let mut i = 0;
        while i < Protocol::COUNT {
            if let Some(p) = self.entries[i]
                && p as u8 == protocol as u8
            {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Keeps only the protocols `f` returns true for, preserving order.
    ///
    /// This is how a role driver narrows a configured set to what the build can
    /// actually speak — `set.retain(Flow::supports)`.
    pub fn retain(&mut self, mut f: impl FnMut(Protocol) -> bool) {
        let kept = *self;
        *self = Self::new();
        for p in kept {
            if f(p) {
                *self = self.with(p);
            }
        }
    }

    /// How many protocols are in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < Protocol::COUNT {
            if self.entries[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// True when the set holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries[0].is_none()
    }

    /// The most preferred protocol — the first one added.
    ///
    /// This is *preference*, which is not the same question as
    /// [`Protocols::best`]: a vehicle is free to prefer the older generation.
    #[must_use]
    pub const fn first(&self) -> Option<Protocol> {
        self.entries[0]
    }

    /// The newest generation in the set, whatever the preference order.
    ///
    /// [`Protocol`]'s `Ord` is by generation, so this is "the most capable one
    /// this equipment implements" — the answer to a datasheet question rather
    /// than a handshake one.
    #[must_use]
    pub fn best(&self) -> Option<Protocol> {
        self.iter().max()
    }

    /// The protocols, in preference order.
    #[must_use]
    pub const fn iter(&self) -> Iter {
        Iter { entries: self.entries, next: 0 }
    }
}

impl IntoIterator for Protocols {
    type Item = Protocol;
    type IntoIter = Iter;

    fn into_iter(self) -> Iter {
        self.iter()
    }
}

impl IntoIterator for &Protocols {
    type Item = Protocol;
    type IntoIter = Iter;

    fn into_iter(self) -> Iter {
        self.iter()
    }
}

impl FromIterator<Protocol> for Protocols {
    fn from_iter<I: IntoIterator<Item = Protocol>>(iter: I) -> Self {
        let mut set = Self::new();
        for p in iter {
            set.insert(p);
        }
        set
    }
}

impl From<Protocol> for Protocols {
    fn from(protocol: Protocol) -> Self {
        Self::only(protocol)
    }
}

impl From<&[Protocol]> for Protocols {
    fn from(protocols: &[Protocol]) -> Self {
        Self::from_slice(protocols)
    }
}

impl<const N: usize> From<[Protocol; N]> for Protocols {
    fn from(protocols: [Protocol; N]) -> Self {
        Self::from_slice(&protocols)
    }
}

impl<const N: usize> From<&[Protocol; N]> for Protocols {
    fn from(protocols: &[Protocol; N]) -> Self {
        Self::from_slice(protocols)
    }
}

/// Iterator over a [`Protocols`] set, in preference order.
#[derive(Debug, Clone)]
pub struct Iter {
    entries: [Option<Protocol>; Protocol::COUNT],
    next: usize,
}

impl Iterator for Iter {
    type Item = Protocol;

    fn next(&mut self) -> Option<Protocol> {
        while self.next < Protocol::COUNT {
            let entry = self.entries[self.next];
            self.next += 1;
            if entry.is_some() {
                return entry;
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.entries[self.next..].iter().flatten().count();
        (n, Some(n))
    }
}

impl ExactSizeIterator for Iter {}
impl core::iter::FusedIterator for Iter {}

impl fmt::Debug for Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter().map(Protocol::as_str)).finish()
    }
}

impl fmt::Display for Protocols {
    /// The [`Protocol::as_str`] names, comma-separated, in preference order.
    ///
    /// No spaces, so the result is a configuration token or a metric label as
    /// it stands. The empty set is the empty string, and `FromStr` reads that
    /// back.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(p.as_str())?;
        }
        Ok(())
    }
}

impl FromStr for Protocols {
    type Err = ParseProtocolError;

    /// Reads a comma-separated list of [`Protocol::as_str`] names.
    ///
    /// Whitespace around a name is ignored, the empty string is the empty set,
    /// and a repeated name keeps its first position. Every name must parse:
    /// silently dropping one would turn a typo into a station that quietly
    /// speaks less than its operator thinks it does.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut set = Self::new();
        for token in s.split(',') {
            if token.trim().is_empty() {
                continue;
            }
            set.insert(token.parse()?);
        }
        Ok(set)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Protocols {
    /// As a sequence of [`Protocol::as_str`] names, in preference order.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter().map(Protocol::as_str))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Protocols {
    /// From a sequence of names, or from one comma-separated string.
    ///
    /// The string form is not decoration: a set very often arrives as an
    /// environment variable or a single TOML value, and a format that can only
    /// express a sequence would push the splitting back onto every caller.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Protocols;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a sequence of protocol names, or one comma-separated string")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Protocols, E> {
                s.parse().map_err(serde::de::Error::custom)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Protocols, A::Error> {
                let mut set = Protocols::new();
                while let Some(p) = seq.next_element::<Protocol>()? {
                    set.insert(p);
                }
                Ok(set)
            }
        }
        deserializer.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn namespaces_round_trip() {
        for &p in Protocol::ALL {
            assert_eq!(Protocol::from_namespace(p.namespace()), Some(p));
        }
        assert_eq!(Protocol::from_namespace("urn:nope"), None);
    }

    #[test]
    fn only_dash_20_mandates_tls() {
        assert!(Protocol::Iso20.requires_tls());
        assert!(!Protocol::Iso2.requires_tls());
        assert!(!Protocol::Din70121.requires_tls());
    }

    #[test]
    fn newer_protocols_sort_higher() {
        // The SECC picks the most capable protocol both sides support, so the
        // ordering here is load-bearing.
        assert!(Protocol::Iso20 > Protocol::Iso2);
        assert!(Protocol::Iso2 > Protocol::Din70121);
    }

    #[test]
    fn short_names_round_trip() {
        for &p in Protocol::ALL {
            assert_eq!(p.as_str().parse(), Ok(p));
            assert_eq!(p.to_string().parse(), Ok(p));
            // A record that stored the namespace instead still parses.
            assert_eq!(p.namespace().parse(), Ok(p));
        }
    }

    #[test]
    fn short_names_say_which_generation() {
        assert_eq!(Protocol::Din70121.as_str(), "din70121");
        assert_eq!(Protocol::Iso2.as_str(), "iso15118-2");
        assert_eq!(Protocol::Iso20.as_str(), "iso15118-20");

        // `iso15118-2` is a *prefix* of `iso15118-20`, which is the trap in
        // this naming and the reason parsing is an exact match rather than a
        // `starts_with`. Both directions are checked because a consumer that
        // got it wrong would silently read the newer generation as the older.
        assert!(Protocol::Iso20.as_str().starts_with(Protocol::Iso2.as_str()));
        assert_eq!("iso15118-2".parse(), Ok(Protocol::Iso2));
        assert_eq!("iso15118-20".parse(), Ok(Protocol::Iso20));
        assert!("iso15118-200".parse::<Protocol>().is_err());
    }

    #[test]
    fn a_name_without_a_generation_is_refused_by_name() {
        for input in ["iso15118", "ISO15118", "iso 15118", "ISO-15118"] {
            let err = input.parse::<Protocol>().expect_err("ambiguous");
            assert!(err.generation_omitted(), "{input}");
            assert!(err.to_string().contains("which generation"), "{input}");
        }
        let err = "nonsense".parse::<Protocol>().expect_err("unknown");
        assert!(!err.generation_omitted());
    }

    #[test]
    fn parsing_ignores_ascii_case_and_surrounding_space() {
        assert_eq!("  ISO15118-20 ".parse(), Ok(Protocol::Iso20));
        assert_eq!("DIN70121".parse(), Ok(Protocol::Din70121));
    }

    #[test]
    fn a_set_keeps_preference_order_and_drops_duplicates() {
        let set = Protocols::from_slice(&[
            Protocol::Iso2,
            Protocol::Iso20,
            Protocol::Iso2,
            Protocol::Din70121,
        ]);
        assert_eq!(set.len(), 3);
        assert_eq!(
            set.iter().collect::<alloc::vec::Vec<_>>(),
            [Protocol::Iso2, Protocol::Iso20, Protocol::Din70121],
            "a repeat keeps the first, more-preferred position"
        );
        assert_eq!(set.first(), Some(Protocol::Iso2), "preference");
        assert_eq!(set.best(), Some(Protocol::Iso20), "generation");
    }

    #[test]
    fn the_two_all_constants_cannot_disagree() {
        assert_eq!(Protocols::from_slice(Protocol::ALL), Protocols::ALL);
        assert_eq!(Protocols::ALL.len(), Protocol::COUNT);
        for &p in Protocol::ALL {
            assert!(Protocols::ALL.contains(p));
        }
    }

    #[test]
    fn equality_is_order_sensitive_because_the_order_is_a_priority() {
        let prefers_new = Protocols::from_slice(&[Protocol::Iso20, Protocol::Iso2]);
        let prefers_old = Protocols::from_slice(&[Protocol::Iso2, Protocol::Iso20]);
        assert_ne!(prefers_new, prefers_old, "these two vehicles are asking for different things");
        // ...but they implement the same generations.
        assert!(Protocol::ALL.iter().all(|&p| prefers_new.contains(p) == prefers_old.contains(p)));
        assert_eq!(prefers_new.best(), prefers_old.best());
    }

    #[test]
    fn a_set_cannot_overflow_however_long_the_slice() {
        let long = [Protocol::Iso2; 64];
        assert_eq!(Protocols::from_slice(&long).len(), 1);
    }

    #[test]
    fn set_membership_and_removal() {
        let mut set = Protocols::ISO;
        assert!(set.contains(Protocol::Iso20));
        assert!(!set.contains(Protocol::Din70121));
        assert!(set.remove(Protocol::Iso20));
        assert!(!set.remove(Protocol::Iso20));
        assert_eq!(set.iter().collect::<alloc::vec::Vec<_>>(), [Protocol::Iso2]);
        assert!(set.insert(Protocol::Din70121));
        assert!(!set.insert(Protocol::Din70121));
        assert_eq!(
            set.iter().collect::<alloc::vec::Vec<_>>(),
            [Protocol::Iso2, Protocol::Din70121],
            "an insert appends at the least-preferred end"
        );
    }

    #[test]
    fn retain_preserves_order() {
        let mut set = Protocols::ALL;
        set.retain(|p| p != Protocol::Iso2);
        assert_eq!(
            set.iter().collect::<alloc::vec::Vec<_>>(),
            [Protocol::Iso20, Protocol::Din70121]
        );
    }

    #[test]
    fn the_empty_set_is_empty_in_every_direction() {
        let set = Protocols::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.first(), None);
        assert_eq!(set.best(), None);
        assert_eq!(set.to_string(), "");
        assert_eq!("".parse(), Ok(set));
        assert_eq!(set.iter().count(), 0);
    }

    #[test]
    fn a_set_round_trips_through_its_own_text() {
        for set in
            [Protocols::new(), Protocols::ISO, Protocols::ALL, Protocols::only(Protocol::Iso2)]
        {
            assert_eq!(set.to_string().parse(), Ok(set), "{set:?}");
        }
        assert_eq!(Protocols::ISO.to_string(), "iso15118-20,iso15118-2");
        assert_eq!(
            " iso15118-2 , din70121 ".parse(),
            Ok(Protocols::from_slice(&[Protocol::Iso2, Protocol::Din70121]))
        );
    }

    #[test]
    fn one_bad_name_fails_the_whole_set() {
        // Dropping it silently would leave a station speaking less than its
        // operator configured, with nothing in the log to say so.
        assert!("iso15118-20,nonsense".parse::<Protocols>().is_err());
        assert!("iso15118-20,iso15118".parse::<Protocols>().is_err());
    }

    #[test]
    fn iter_reports_its_own_length() {
        let mut it = Protocols::ISO.iter();
        assert_eq!(it.len(), 2);
        assert_eq!(it.next(), Some(Protocol::Iso20));
        assert_eq!(it.len(), 1);
        assert_eq!(it.collect::<alloc::vec::Vec<_>>(), [Protocol::Iso2]);
    }

    #[test]
    fn a_set_debugs_as_its_stable_names() {
        assert_eq!(format!("{:?}", Protocols::ISO), r#"["iso15118-20", "iso15118-2"]"#);
    }

    #[test]
    fn collecting_builds_a_set() {
        let set: Protocols =
            [Protocol::Iso20, Protocol::Iso2, Protocol::Iso20].into_iter().collect();
        assert_eq!(set, Protocols::ISO);
        assert_eq!(Protocols::from([Protocol::Iso20, Protocol::Iso2]), Protocols::ISO);
        assert_eq!(Protocols::from(Protocol::Iso2), Protocols::only(Protocol::Iso2));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_the_stable_name_not_the_variant_name() {
        assert_eq!(serde_json::to_string(&Protocol::Iso20).unwrap(), r#""iso15118-20""#);
        assert_eq!(serde_json::from_str::<Protocol>(r#""iso15118-20""#).unwrap(), Protocol::Iso20);
        // The variant name is *not* accepted: one spelling, not two.
        assert!(serde_json::from_str::<Protocol>(r#""Iso20""#).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_set_deserialises_from_a_sequence_or_a_string() {
        assert_eq!(
            serde_json::to_string(&Protocols::ISO).unwrap(),
            r#"["iso15118-20","iso15118-2"]"#
        );
        assert_eq!(
            serde_json::from_str::<Protocols>(r#"["iso15118-20","iso15118-2"]"#).unwrap(),
            Protocols::ISO
        );
        assert_eq!(
            serde_json::from_str::<Protocols>(r#""iso15118-20,iso15118-2""#).unwrap(),
            Protocols::ISO
        );
    }
}
