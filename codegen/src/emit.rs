//! Emits Rust message types and EXI codecs from a verified [`Layout`].
//!
//! # Shape of the output
//!
//! One module per schema set. For each XSD type:
//!
//! * a `simpleType` with an `enumeration` facet becomes a Rust enum whose
//!   discriminants are the EXI indices;
//! * every other `simpleType` collapses to a built-in Rust type plus the facets
//!   the codec has to enforce;
//! * a `complexType` becomes a struct, with a `Shape` of the event-code
//!   arithmetic and `encode_body` / `decode_body` driving
//!   [`SeqWriter`](iso15118::exi::SeqWriter) and `SeqReader`.
//!
//! Generated code carries no state table. The `Shape` is five short integer
//! slices; the loops that a state table would unroll stay loops.
//!
//! # What is not generated
//!
//! The `xmldsig` namespace. Its types use wildcards, mixed content and nested
//! choices, none of which map onto a typed struct, and none of which any V2G
//! message needs except through `Signature` — which is Plug & Charge, and not
//! implemented. Elements referring to it become a field the codec refuses,
//! rather than one it silently drops.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::layout::{Branch, Field, Item, Layout};
use crate::xsd::{QName, Schema, SimpleType, TypeDef, TypeRef, UNBOUNDED, XMLDSIG_NS, XSD_NS};

/// How a value is carried on the wire and in Rust.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scalar {
    Bool,
    /// An unsigned integer coded as an EXI Unsigned Integer.
    Uint(&'static str),
    /// A signed integer coded as an EXI Integer.
    Int(&'static str),
    /// A bounded integer coded as an index into its range.
    Restricted {
        rust: &'static str,
        min: i128,
        max: i128,
    },
    /// A generated enumeration.
    Enum(String),
    /// A string, coded through the value string table.
    Str {
        lengths: String,
        ctx: u32,
    },
    /// `hexBinary` or `base64Binary`.
    Binary {
        lengths: String,
    },
    Decimal,
    Float,
    DateTime,
}

impl Scalar {
    fn rust_type(&self) -> String {
        match self {
            Self::Bool => "bool".into(),
            Self::Uint(t) | Self::Int(t) => (*t).into(),
            Self::Restricted { rust, .. } => (*rust).into(),
            Self::Enum(name) => name.clone(),
            Self::Str { .. } => "String".into(),
            Self::Binary { .. } => "Vec<u8>".into(),
            Self::Decimal => "Decimal".into(),
            Self::Float => "Float".into(),
            Self::DateTime => "DateTime".into(),
        }
    }

    /// Expression writing `value` with encoder `e`.
    ///
    /// `value` is a place expression for a borrowed field. Scalars are `Copy`
    /// and get dereferenced; `String` and `Vec<u8>` are passed by reference,
    /// so they must not be.
    fn encode(&self, value: &str) -> String {
        match self {
            Self::Bool => format!("e.boolean({value})?"),
            Self::Uint(_) => format!("e.uint(u64::from({value}))?"),
            Self::Int(_) => format!("e.int(i64::from({value}))?"),
            Self::Restricted { min, max, .. } => {
                format!("e.restricted(i64::from({value}), {min}, {max})?")
            }
            // A method call auto-dereferences, so the caller's `*` would bind
            // to the result instead of the receiver.
            Self::Enum(name) => {
                format!("e.nbit({}.as_index(), {name}::WIDTH)?", value.trim_start_matches('*'))
            }
            // These two are already references; the rest are `Copy` scalars
            // that the caller dereferenced.
            Self::Str { lengths, ctx } => {
                format!("e.string(ValueCtx({ctx}), {}, {lengths})?", value.trim_start_matches('*'))
            }
            Self::Binary { lengths } => {
                format!("e.binary({}, {lengths})?", value.trim_start_matches('*'))
            }
            Self::Decimal => format!("e.decimal({value})?"),
            Self::Float => format!("e.float({value})?"),
            Self::DateTime => format!("e.datetime({value})?"),
        }
    }

    /// Expression reading a value with decoder `d`.
    fn decode(&self) -> String {
        match self {
            Self::Bool => "d.boolean()?".into(),
            Self::Uint(t) => {
                format!("{t}::try_from(d.uint()?).map_err(|_| ExiError::IntegerOverflow)?")
            }
            Self::Int(t) => {
                format!("{t}::try_from(d.int()?).map_err(|_| ExiError::IntegerOverflow)?")
            }
            Self::Restricted { rust, min, max } => format!(
                "{rust}::try_from(d.restricted({min}, {max})?).map_err(|_| ExiError::ValueOutOfRange)?"
            ),
            Self::Enum(name) => format!("{name}::from_index(d.nbit({name}::WIDTH)?)?"),
            Self::Str { lengths, ctx } => format!("d.string(ValueCtx({ctx}), {lengths})?"),
            Self::Binary { lengths } => format!("d.binary({lengths})?"),
            Self::Decimal => "d.decimal()?".into(),
            Self::Float => "d.float()?".into(),
            Self::DateTime => "d.datetime()?".into(),
        }
    }
}

/// What a child element's type resolves to.
#[derive(Debug, Clone)]
enum Kind {
    /// A simple value.
    Scalar(Scalar),
    /// Another generated struct.
    Struct(String),
    /// An `xmldsig` type, which is not generated.
    Unsupported,
}

/// Emits one module for a schema set.
pub(crate) struct Emitter<'a> {
    schema: &'a Schema,
    /// XSD type name to generated Rust type name.
    type_names: BTreeMap<QName, String>,
    /// Generated enum name for each enumerated simple type.
    enum_names: BTreeMap<QName, String>,
    /// String-table context id per element or attribute qualified name.
    contexts: BTreeMap<QName, u32>,
    /// Complex types that reduce to a Rust struct.
    generatable: BTreeSet<QName>,
    /// Anonymous complex types that a global element declares inline, named
    /// after that element. ISO 15118-2's `V2G_Message` root is the only one.
    anonymous_roots: BTreeMap<usize, (QName, String)>,
    /// Namespaces whose types are generated.
    module: String,
    /// When set, only types in these namespaces are written out.
    emit_namespaces: BTreeSet<String>,
    /// Namespaces whose types live in another Rust module, and its path.
    ///
    /// Every ISO 15118-20 schema imports `CommonTypes`, so without this the
    /// shared types would be duplicated into five modules and a
    /// `RationalNumber` from one would not be the same Rust type as a
    /// `RationalNumber` from another.
    extern_modules: BTreeMap<String, String>,
    /// Rust type name to the Rust type of its `Header` child, for the types
    /// that have one. Every V2G message carries a header; letting a receiver
    /// reach it without matching on thirty variants is worth generating.
    header_types: BTreeMap<String, String>,
    /// The same for `ResponseCode`. ISO 15118 makes a `FAILED_*` response
    /// terminal for the session, so a session core has to read the code of
    /// whichever of the thirty-odd responses went past — without knowing which.
    response_code_types: BTreeMap<String, String>,
    /// Why each complex type that is *not* generated was left out.
    ///
    /// A type that quietly vanishes is the worst failure mode this tool has —
    /// the codec still compiles and still round-trips against itself, and only
    /// a real peer notices. `--why` prints this table.
    excluded: BTreeMap<QName, String>,
}

impl<'a> Emitter<'a> {
    pub(crate) fn new(
        schema: &'a Schema,
        module: &str,
        emit_namespaces: BTreeSet<String>,
        extern_modules: BTreeMap<String, String>,
    ) -> Self {
        let mut this = Self {
            schema,
            type_names: BTreeMap::new(),
            enum_names: BTreeMap::new(),
            contexts: BTreeMap::new(),
            generatable: BTreeSet::new(),
            anonymous_roots: BTreeMap::new(),
            module: module.to_owned(),
            emit_namespaces,
            extern_modules,
            excluded: BTreeMap::new(),
            header_types: BTreeMap::new(),
            response_code_types: BTreeMap::new(),
        };
        this.name_anonymous_roots();
        this.find_generatable();
        this.assign_names();
        this.assign_contexts();
        this.find_headers();
        this.find_response_codes();
        this
    }

    /// The complex types that reduce to a Rust struct.
    pub(crate) fn generatable(&self) -> &BTreeSet<QName> {
        &self.generatable
    }

    /// One line per complex type that could not be generated, and why.
    pub(crate) fn exclusions(&self) -> impl Iterator<Item = (&QName, &str)> {
        self.excluded
            .iter()
            .filter(|(name, _)| !self.generatable.contains(*name))
            .map(|(name, why)| (name, why.as_str()))
    }

    /// Records which generated types have a `Header` child, and of what type.
    fn find_headers(&mut self) {
        let mut found = BTreeMap::new();
        for (name, def) in &self.schema.types {
            let (TypeDef::Complex(ct), Some(rust)) = (def, self.type_names.get(name)) else {
                continue;
            };
            if !self.generatable.contains(name) {
                continue;
            }
            let Ok(layout) = Layout::of(self.schema, ct) else { continue };
            for item in &layout.items {
                let Item::Element(f) = item else { continue };
                if f.name.local != "Header" || f.min != 1 || f.max != 1 {
                    continue;
                }
                if let Kind::Struct(header) = self.kind(f) {
                    found.insert(format!("{}{rust}", self.prefix(name)), header);
                }
            }
        }
        self.header_types = found;
    }

    /// Records which generated types have a `ResponseCode` child, and of what
    /// enumeration.
    ///
    /// `responseCodeType` is the name ISO 15118 gives it in every generation,
    /// which is why matching on it here is a fact about the standard rather
    /// than a guess about the schema.
    fn find_response_codes(&mut self) {
        let mut found = BTreeMap::new();
        for (name, def) in &self.schema.types {
            let (TypeDef::Complex(ct), Some(rust)) = (def, self.type_names.get(name)) else {
                continue;
            };
            if !self.generatable.contains(name) {
                continue;
            }
            let Ok(layout) = Layout::of(self.schema, ct) else { continue };
            for item in &layout.items {
                let Item::Element(f) = item else { continue };
                if f.name.local != "ResponseCode" || f.min != 1 || f.max != 1 {
                    continue;
                }
                if let Kind::Scalar(Scalar::Enum(code)) = self.kind(f) {
                    found.insert(format!("{}{rust}", self.prefix(name)), code);
                }
            }
        }
        self.response_code_types = found;
    }

    /// Gives every anonymous complex type declared by a global element the
    /// element's own name, so the root of ISO 15118-2 — whose type is inline —
    /// is generated like any other.
    fn name_anonymous_roots(&mut self) {
        for element in &self.schema.global_elements {
            if let TypeRef::Anonymous(i) = element.type_ref
                && matches!(self.schema.anonymous.get(i), Some(TypeDef::Complex(_)))
            {
                self.anonymous_roots.insert(i, (element.name.clone(), pascal(&element.name.local)));
            }
        }
    }

    /// True for types this emitter produces Rust for, or can refer to in
    /// another module.
    fn generated(&self, name: &QName) -> bool {
        self.generatable.contains(name)
    }

    /// True for types this module writes out, as opposed to importing.
    fn local(&self, name: &QName) -> bool {
        self.emit_namespaces.is_empty() || self.emit_namespaces.contains(&name.namespace)
    }

    /// The path prefix a reference to `name` needs from this module.
    fn prefix(&self, name: &QName) -> String {
        if self.local(name) {
            String::new()
        } else {
            self.extern_modules.get(&name.namespace).map_or_else(String::new, |p| format!("{p}::"))
        }
    }

    /// Works out which complex types can be expressed as Rust structs.
    ///
    /// A type qualifies when its own content model reduces to a [`Layout`] and
    /// every child it names also qualifies. That is a fixpoint, because a type
    /// can be disqualified by a child that is itself disqualified — so start
    /// with everything that reduces and remove until nothing changes.
    ///
    /// Most of what drops out is `xmldsig`, whose signature machinery uses
    /// wildcards and mixed content. Not all of it: `X509IssuerSerialType` is an
    /// ordinary pair of fields, and ISO 15118-2 references it directly from
    /// `ListOfRootCertificateIDsType`, so excluding the namespace wholesale
    /// would have made the -2 certificate types ungeneratable too.
    fn find_generatable(&mut self) {
        let mut candidates: BTreeSet<QName> = BTreeSet::new();
        let mut children: BTreeMap<QName, Vec<QName>> = BTreeMap::new();
        for (name, def) in &self.schema.types {
            let TypeDef::Complex(ct) = def else { continue };
            let layout = match Layout::of(self.schema, ct) {
                Ok(layout) => layout,
                Err(e) => {
                    self.excluded.insert(name.clone(), e.to_string());
                    continue;
                }
            };
            if let Err(e) = layout.verify(self.schema, ct) {
                self.excluded.insert(name.clone(), e.to_string());
                continue;
            }
            let mut referenced = Vec::new();
            let mut ok = true;
            for item in &layout.items {
                // Undeclared content — `xs:any`, or a choice with a wildcard
                // branch — has no Rust form. Optional, it becomes a phantom
                // that keeps the event codes lined up; required, it makes the
                // whole type ungeneratable.
                if item.min() > 0
                    && match item {
                        Item::Wildcard { .. } => true,
                        Item::Choice { branches, .. } => {
                            branches.iter().any(|b| b.field().is_none())
                        }
                        _ => false,
                    }
                {
                    ok = false;
                    self.excluded.insert(
                        name.clone(),
                        "a required xs:any or wildcard choice branch has no Rust form".to_owned(),
                    );
                }
                let fields: Vec<&Field> = match item {
                    Item::Attribute(f) | Item::Element(f) => alloc_one(f),
                    Item::Choice { branches, .. } if item.min() > 0 => {
                        branches.iter().filter_map(Branch::field).collect()
                    }
                    // An optional choice may be dropped whole if any branch is
                    // not generatable, so its branches impose no requirement.
                    Item::Choice { .. } | Item::Characters(_) | Item::Wildcard { .. } => Vec::new(),
                };
                for f in fields {
                    match &f.type_ref {
                        TypeRef::Named(q) => {
                            // An optional child may be a phantom, so it does
                            // not have to be generatable itself.
                            if f.min > 0
                                && matches!(self.schema.types.get(q), Some(TypeDef::Complex(_)))
                            {
                                referenced.push(q.clone());
                            }
                        }
                        TypeRef::Anonymous(i) => {
                            // An inline complex type is usable only when it is a
                            // named root; otherwise there is no Rust item to
                            // point at.
                            if matches!(self.schema.anonymous.get(*i), Some(TypeDef::Complex(_)))
                                && !self.anonymous_roots.contains_key(i)
                            {
                                ok = false;
                                self.excluded.insert(
                                    name.clone(),
                                    format!(
                                        "inline complex type of {} is not a named root",
                                        f.name
                                    ),
                                );
                            }
                        }
                    }
                }
            }
            if ok {
                candidates.insert(name.clone());
                children.insert(name.clone(), referenced);
            }
        }

        loop {
            let doomed: Vec<QName> = candidates
                .iter()
                .filter(|n| children[*n].iter().any(|c| !candidates.contains(c)))
                .cloned()
                .collect();
            if doomed.is_empty() {
                break;
            }
            for name in doomed {
                let blocker = children[&name]
                    .iter()
                    .find(|c| !candidates.contains(c))
                    .map_or_else(String::new, ToString::to_string);
                self.excluded.insert(
                    name.clone(),
                    format!("required child type {blocker} is not generated"),
                );
                candidates.remove(&name);
            }
        }
        self.generatable = candidates;
    }

    /// Chooses a Rust name for every generated type, resolving collisions
    /// deterministically.
    ///
    /// ISO 15118-2 declares both `EMAIDType` and `eMAIDType`, which differ only
    /// in the case of the first letter and would otherwise produce the same
    /// Rust identifier.
    fn assign_names(&mut self) {
        let mut taken: BTreeSet<String> = BTreeSet::new();
        for (name, def) in &self.schema.types {
            let is_enum = matches!(def, TypeDef::Simple(s) if !s.enumeration.is_empty());
            if !is_enum && matches!(def, TypeDef::Simple(_)) {
                // Non-enumerated simple types collapse into their base; they get
                // no Rust item of their own.
                continue;
            }
            let base = pascal(name.local.trim_end_matches("Type"));
            let mut candidate = base.clone();
            if taken.contains(&candidate) {
                candidate = pascal(&name.local);
            }
            let mut n = 2;
            while taken.contains(&candidate) {
                candidate = format!("{base}{n}");
                n += 1;
            }
            taken.insert(candidate.clone());
            if is_enum {
                self.enum_names.insert(name.clone(), candidate.clone());
            }
            self.type_names.insert(name.clone(), candidate);
        }
    }

    /// Assigns a string-table partition id to every element and attribute name
    /// that can carry a string value.
    ///
    /// The partition is keyed by qualified name and shared across the whole
    /// document, so the ids must be global to the module rather than per type.
    fn assign_contexts(&mut self) {
        let mut names: BTreeSet<QName> = BTreeSet::new();
        for (name, def) in &self.schema.types {
            let TypeDef::Complex(ct) = def else { continue };
            if !self.generated(name) {
                continue;
            }
            let Ok(layout) = Layout::of(self.schema, ct) else { continue };
            for item in &layout.items {
                match item {
                    Item::Attribute(f) | Item::Element(f) => {
                        names.insert(f.name.clone());
                    }
                    Item::Choice { branches, .. } => {
                        for b in branches.iter().filter_map(Branch::field) {
                            names.insert(b.name.clone());
                        }
                    }
                    // Simple content shares the enclosing element's partition,
                    // which the parent already registered. A wildcard is never
                    // written and refused on decode, so it has no partition.
                    Item::Characters(_) | Item::Wildcard { .. } => {}
                }
            }
        }
        for (i, name) in names.into_iter().enumerate() {
            self.contexts.insert(name, u32::try_from(i).unwrap_or(u32::MAX));
        }
    }

    /// Resolves a simple type to its wire representation, following the base
    /// chain and accumulating facets.
    fn scalar(&self, type_ref: &TypeRef, owner: Option<&QName>) -> Option<Scalar> {
        let mut max_length: Option<usize> = None;
        let mut min_length: Option<usize> = None;
        let mut min_inclusive: Option<i128> = None;
        let mut max_inclusive: Option<i128> = None;
        let mut current = type_ref.clone();

        for _ in 0..16 {
            // A named enumerated type becomes a Rust enum rather than a value.
            if let TypeRef::Named(q) = &current
                && let Some(rust) = self.enum_names.get(q)
            {
                if !self.reachable(q) {
                    return None;
                }
                return Some(Scalar::Enum(format!("{}{rust}", self.prefix(q))));
            }
            if let TypeRef::Named(q) = &current
                && q.namespace == XSD_NS
            {
                let facets = Facets { max_length, min_length, min_inclusive, max_inclusive };
                return Some(builtin(&q.local, facets, || {
                    owner.and_then(|o| self.contexts.get(o)).copied().unwrap_or(0)
                }));
            }
            let Some(TypeDef::Simple(st)) = self.schema.resolve(&current) else { return None };
            absorb(st, &mut max_length, &mut min_length, &mut min_inclusive, &mut max_inclusive);
            current = TypeRef::Named(st.base.clone()?);
        }
        None
    }

    /// Classifies a child element's or attribute's type.
    fn kind(&self, f: &Field) -> Kind {
        if let TypeRef::Named(q) = &f.type_ref
            && let Some(TypeDef::Complex(_)) = self.schema.types.get(q)
        {
            if !self.generated(q) || !self.reachable(q) {
                return Kind::Unsupported;
            }
            return self
                .type_names
                .get(q)
                .map_or(Kind::Unsupported, |n| Kind::Struct(format!("{}{n}", self.prefix(q))));
        }
        if let TypeRef::Anonymous(i) = &f.type_ref
            && matches!(self.schema.resolve(&f.type_ref), Some(TypeDef::Complex(_)))
        {
            return self
                .anonymous_roots
                .get(i)
                .map_or(Kind::Unsupported, |(_, name)| Kind::Struct(name.clone()));
        }
        self.scalar(&f.type_ref, Some(&f.name)).map_or(Kind::Unsupported, Kind::Scalar)
    }
}

/// The facets a restriction chain accumulates, in one bundle.
#[derive(Debug, Clone, Copy, Default)]
struct Facets {
    max_length: Option<usize>,
    min_length: Option<usize>,
    min_inclusive: Option<i128>,
    max_inclusive: Option<i128>,
}

impl Facets {
    /// The `Lengths` expression a generated call site takes.
    ///
    /// `xs:length` reaches here as an equal minimum and maximum, which is the
    /// distinction that matters: `Lengths::exact` refuses a short value where
    /// `Lengths::max` would take it and re-encode it into a message no peer
    /// will accept.
    fn lengths(self) -> String {
        let max = self.max_length.unwrap_or(65_536);
        match self.min_length {
            None | Some(0) => format!("Lengths::max({max})"),
            Some(min) if min == max => format!("Lengths::exact({min})"),
            Some(min) => format!("Lengths::new({min}, {max})"),
        }
    }
}

/// Folds one restriction step's facets into the accumulated ones.
fn absorb(
    st: &SimpleType,
    max_length: &mut Option<usize>,
    min_length: &mut Option<usize>,
    min_inclusive: &mut Option<i128>,
    max_inclusive: &mut Option<i128>,
) {
    if let Some(v) = st.max_length {
        *max_length = Some(max_length.map_or(v, |cur: usize| cur.min(v)));
    }
    // Facets can only narrow, so a derived minimum is the larger of the two.
    if let Some(v) = st.min_length {
        *min_length = Some(min_length.map_or(v, |cur: usize| cur.max(v)));
    }
    if let Some(v) = st.min_inclusive {
        *min_inclusive = Some(min_inclusive.map_or(v, |cur: i128| cur.max(v)));
    }
    if let Some(v) = st.max_inclusive {
        *max_inclusive = Some(max_inclusive.map_or(v, |cur: i128| cur.min(v)));
    }
}

/// Maps a built-in XSD type, narrowed by any facets, to a wire representation.
fn builtin(local: &str, facets: Facets, ctx: impl Fn() -> u32) -> Scalar {
    let Facets { min_inclusive, max_inclusive, .. } = facets;
    // EXI 1.0 §7.1.5 decides an integer's representation from its *effective*
    // bounds, so a built-in's implicit range and any narrowing facet have to be
    // folded together before the rule is applied:
    //
    //   * a bounded range of 4096 values or fewer -> n-bit index from the min;
    //   * otherwise a lower bound of zero or more -> Unsigned Integer;
    //   * otherwise                               -> sign plus magnitude.
    //
    // `xs:integer` and the two `*Integer` derivations are unbounded above, so
    // they land in the second or third case unless a facet bounds them.
    let implicit: Option<(Option<i128>, Option<i128>)> = match local {
        "byte" => Some((Some(-128), Some(127))),
        "unsignedByte" => Some((Some(0), Some(255))),
        "short" => Some((Some(-32_768), Some(32_767))),
        "unsignedShort" => Some((Some(0), Some(65_535))),
        "int" => Some((Some(i128::from(i32::MIN)), Some(i128::from(i32::MAX)))),
        "unsignedInt" => Some((Some(0), Some(i128::from(u32::MAX)))),
        "long" => Some((Some(i128::from(i64::MIN)), Some(i128::from(i64::MAX)))),
        "unsignedLong" => Some((Some(0), Some(i128::from(u64::MAX)))),
        "nonNegativeInteger" => Some((Some(0), None)),
        "positiveInteger" => Some((Some(1), None)),
        "integer" => Some((None, None)),
        _ => None,
    };

    if let Some((implicit_lo, implicit_hi)) = implicit {
        // Facets can only narrow, never widen.
        let lo = match (implicit_lo, min_inclusive) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let hi = match (implicit_hi, max_inclusive) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        // EXI codes a range of 4096 values or fewer as an index into it.
        if let (Some(lo), Some(hi)) = (lo, hi)
            && hi >= lo
            && (hi - lo) < 4096
        {
            return Scalar::Restricted { rust: int_type(lo, hi), min: lo, max: hi };
        }
        return if lo.is_some_and(|lo| lo >= 0) {
            Scalar::Uint(uint_type(hi.unwrap_or(i128::from(u64::MAX))))
        } else {
            Scalar::Int(int_type(
                lo.unwrap_or(i128::from(i64::MIN)),
                hi.unwrap_or(i128::from(i64::MAX)),
            ))
        };
    }

    match local {
        "boolean" => Scalar::Bool,
        "decimal" => Scalar::Decimal,
        "float" | "double" => Scalar::Float,
        "dateTime" | "date" | "time" => Scalar::DateTime,
        "hexBinary" | "base64Binary" => Scalar::Binary { lengths: facets.lengths() },
        // Everything else — string, anyURI, token, NMTOKEN, ID, QName, lists —
        // travels as a string through the value partition.
        _ => Scalar::Str { lengths: facets.lengths(), ctx: ctx() },
    }
}

fn uint_type(hi: i128) -> &'static str {
    if hi <= i128::from(u8::MAX) {
        "u8"
    } else if hi <= i128::from(u16::MAX) {
        "u16"
    } else if hi <= i128::from(u32::MAX) {
        "u32"
    } else {
        "u64"
    }
}

fn int_type(lo: i128, hi: i128) -> &'static str {
    if lo >= 0 {
        uint_type(hi)
    } else if lo >= i128::from(i8::MIN) && hi <= i128::from(i8::MAX) {
        "i8"
    } else if lo >= i128::from(i16::MIN) && hi <= i128::from(i16::MAX) {
        "i16"
    } else if lo >= i128::from(i32::MIN) && hi <= i128::from(i32::MAX) {
        "i32"
    } else {
        "i64"
    }
}

/// `SessionSetupReq` from `sessionSetupReq`, `EVSE_ID` and so on.
fn pascal(name: &str) -> String {
    let mut out = String::new();
    let mut upper_next = true;
    for ch in name.chars() {
        if ch == '_' || ch == '-' || ch == '.' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// `session_id` from `SessionID`, `evse_processing` from `EVSEProcessing`.
///
/// A boundary is inserted before an uppercase letter that follows a lowercase
/// one, and before the last uppercase of a run that is followed by a lowercase
/// — so an acronym stays together but does not swallow the word after it.
/// The V2G acronyms, longest first.
///
/// Without these, a name that is nothing but acronyms has no case boundaries to
/// split on and collapses into one run: `EVCCID` becomes `evccid`, `EVRESSSOC`
/// becomes `evresssoc`. Splitting greedily against this list instead gives
/// `evcc_id` and `ev_ress_soc`, which is what a reader of the standard would
/// write. The list is the standard's own vocabulary; anything not in it falls
/// back to case boundaries as before.
const ACRONYMS: &[&str] = &[
    "ACDP", "ECDSA", "EMAID", "EVCC", "EVSE", "HMAC", "MAID", "PWM", "RESS", "SECC", "SLAC", "AC",
    "BPT", "CP", "DC", "DH", "EIM", "EV", "EXI", "ID", "PNC", "RSA", "SA", "SDP", "SHA", "SOC",
    "TLS", "URI", "URL", "WPT", "XML",
];

/// Names the schemas spell in a way no rule recovers.
///
/// `DHpublickey` is `DH` + `publickey`, but `ACharge` is `A` + `Charge`: a
/// two-letter acronym followed by a lowercase letter is ambiguous, and only a
/// dictionary tells the two apart. There is exactly one such name in the V2G
/// schemas, so it gets an entry rather than a heuristic.
const IRREGULAR: &[(&str, &str)] = &[("DHpublickey", "dh_public_key")];

/// Splits an identifier into lower-case words.
fn words(name: &str) -> Vec<String> {
    if let Some((_, fixed)) = IRREGULAR.iter().find(|(from, _)| *from == name) {
        return fixed.split('_').map(str::to_owned).collect();
    }
    let chars: Vec<char> = name.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '_' || ch == '-' || ch == '.' {
            if !current.is_empty() {
                out.push(core::mem::take(&mut current));
            }
            i += 1;
            continue;
        }
        // An uppercase run is where a known acronym can hide. Match the longest
        // one that fits, so `EVSEID` splits as EVSE + ID rather than as one
        // opaque run.
        if ch.is_uppercase()
            // Longest match wins, so `HMACOutputLength` splits on `HMAC` and not
            // on the `AC` inside it. Order in the table is then irrelevant,
            // which is one fewer invariant to keep by hand.
            && let Some(acronym) = ACRONYMS
                .iter()
                .filter(|a| {
                    a.len() <= chars.len() - i
                        && chars[i..i + a.len()].iter().collect::<String>().eq_ignore_ascii_case(a)
                        // Do not eat the leading capital of a following word:
                        // `ACharge` is not `AC` + `harge`.
                        && chars.get(i + a.len()).is_none_or(|c| !c.is_lowercase())
                })
                .max_by_key(|a| a.len())
        {
            if !current.is_empty() {
                out.push(core::mem::take(&mut current));
            }
            out.push(acronym.to_lowercase());
            i += acronym.len();
            continue;
        }
        if ch.is_uppercase() && !current.is_empty() {
            let next_lower = chars.get(i + 1).is_some_and(char::is_ascii_lowercase);
            let prev_upper = current.chars().next_back().is_some_and(char::is_uppercase);
            if !prev_upper || next_lower {
                out.push(core::mem::take(&mut current));
            }
        }
        current.push(ch);
        i += 1;
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.into_iter().map(|w| w.to_lowercase()).collect()
}

/// `sessionID` and `SessionID` and `Session_ID` all become `session_id`.
pub(crate) fn snake(name: &str) -> String {
    escape_keyword(&words(name).join("_"))
}

fn escape_keyword(name: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
        "where", "while", "async", "await", "dyn", "abstract", "final", "override", "priv",
        "typeof", "unsized", "virtual", "yield", "box", "try",
    ];
    if KEYWORDS.contains(&name) || name.is_empty() || name.starts_with(|c: char| c.is_numeric()) {
        format!("r#{name}")
    } else {
        name.to_owned()
    }
}

/// Renders `maxOccurs` for a doc comment.
pub(crate) fn occurs(min: u32, max: u32) -> String {
    let max = if max == UNBOUNDED { "unbounded".to_owned() } else { max.to_string() };
    format!("{min}..{max}")
}

impl Emitter<'_> {
    /// Renders the whole module.
    pub(crate) fn render(&self) -> Result<String, String> {
        let mut out = String::new();
        self.header(&mut out);

        for (name, def) in &self.schema.types {
            if !self.local(name) {
                continue;
            }
            match def {
                TypeDef::Simple(st) if !st.enumeration.is_empty() => {
                    self.enumeration(&mut out, name, st);
                }
                TypeDef::Complex(ct) if self.generated(name) => {
                    let layout = Layout::of(self.schema, ct).map_err(|e| format!("{name}: {e}"))?;
                    self.complex(&mut out, name, &layout)?;
                }
                TypeDef::Complex(_) => {}
                TypeDef::Simple(_) => {}
            }
        }

        // Anonymous root types, named after the element that declares them.
        for (slot, (_, rust)) in &self.anonymous_roots {
            let Some(TypeDef::Complex(ct)) = self.schema.anonymous.get(*slot) else { continue };
            let layout = Layout::of(self.schema, ct).map_err(|e| format!("{rust}: {e}"))?;
            let mut fields = Vec::new();
            let choices = layout.items.iter().filter(|i| matches!(i, Item::Choice { .. })).count();
            for (index, item) in layout.items.iter().enumerate() {
                fields.push(self.field_of(rust, index, item, choices <= 1)?);
            }
            let name = QName::new(String::new(), rust.clone());
            self.struct_decl(&mut out, &name, rust, &fields);
            self.shape_decl(&mut out, rust, &layout);
            self.encode_impl(&mut out, rust, &fields);
            self.decode_impl(&mut out, rust, &fields);
        }

        self.documents(&mut out);
        Ok(out)
    }

    /// The two fragment tables this schema set needs, and their widths.
    ///
    /// EXI 1.0 §8.5.2 indexes fragments by *every element qname declared in the
    /// schema*, global and local alike — a different and much longer list than
    /// the document grammar's. ISO 15118 signatures are computed over
    /// fragments, so these numbers are as load-bearing as any byte on the wire.
    fn fragment_tables(&self) -> (Vec<QName>, Vec<QName>) {
        let all = self.schema.declared_element_qnames();
        // ISO 15118-2 Annex J: `SignedInfo` is encoded against the **xmldsig
        // schema alone**, not the V2G schema set it is embedded in. Its
        // fragment table is therefore the xmldsig elements on their own.
        let xmldsig: Vec<QName> =
            all.iter().filter(|q| q.namespace == XMLDSIG_NS).cloned().collect();
        (all, xmldsig)
    }

    fn fragment_header(&self, out: &mut String) {
        let (all, xmldsig) = self.fragment_tables();
        let width = crate::grammar::bit_width(all.len() as u64 + 3);
        let _ = writeln!(out, "/// Width of an EXI *fragment* event code (EXI 1.0 §8.5.2).");
        let _ = writeln!(out, "///");
        let _ = writeln!(out, "/// A fragment is indexed by every element qname the schema set");
        let _ = writeln!(
            out,
            "/// *declares*, local declarations included — {} here, against the {}",
            all.len(),
            self.schema.global_elements.len()
        );
        let _ = writeln!(out, "/// global elements a document is indexed by — plus `SE(*)`, `ED`");
        let _ = writeln!(out, "/// and the second-level group.");
        let _ = writeln!(out, "///");
        let _ = writeln!(out, "/// Plug & Charge signs fragments, not documents; see");
        let _ = writeln!(out, "/// [`crate::pnc`].");
        let _ = writeln!(out, "pub const FRAGMENT_WIDTH: u32 = {width};");
        let _ = writeln!(out);
        let _ = writeln!(out, "/// `ED` event code in this schema set's fragment grammar.");
        let _ = writeln!(out, "///");
        let _ = writeln!(out, "/// It sits one past the generic `SE(*)`, which is itself one past");
        let _ = writeln!(out, "/// the last declared element.");
        let _ = writeln!(out, "pub const FRAGMENT_ED_CODE: u64 = {};", all.len() + 1);
        let _ = writeln!(out);
        if !xmldsig.is_empty() {
            let ds_width = crate::grammar::bit_width(xmldsig.len() as u64 + 3);
            let _ = writeln!(out, "/// Fragment event-code width of the **xmldsig schema alone**.");
            let _ = writeln!(out, "///");
            let _ = writeln!(out, "/// ISO 15118-2 Annex J: `SignedInfo` — the element an XML");
            let _ = writeln!(out, "/// signature actually signs — is EXI-encoded against the");
            let _ =
                writeln!(out, "/// xmldsig schema on its own, *not* against the V2G schema set");
            let _ =
                writeln!(out, "/// that imports it. Using the wrong table produces a signature");
            let _ = writeln!(out, "/// no other implementation can verify, which is exactly the");
            let _ = writeln!(out, "/// interop bug this constant exists to prevent.");
            let _ = writeln!(out, "pub const XMLDSIG_FRAGMENT_WIDTH: u32 = {ds_width};");
            let _ = writeln!(out);
            let _ = writeln!(out, "/// `ED` event code in the xmldsig-only fragment grammar.");
            let _ =
                writeln!(out, "pub const XMLDSIG_FRAGMENT_ED_CODE: u64 = {};", xmldsig.len() + 1);
            let _ = writeln!(out);
        }
    }

    /// Emits fragment codecs for every element whose type is generated and
    /// which no other element shares a Rust type with.
    ///
    /// Every type gets the schema-set encoding. The handful of xmldsig types
    /// additionally get the xmldsig-only one, under its own name — see
    /// [`Emitter::fragment_header`] for why that second encoding exists and why
    /// conflating the two would be a silent interoperability failure.
    fn fragments(&self, out: &mut String) {
        let (all, xmldsig) = self.fragment_tables();
        let elements = self.schema.declared_elements();
        let mut users: BTreeMap<String, usize> = BTreeMap::new();
        let mut named: Vec<(QName, String)> = Vec::new();
        for (q, type_ref) in &elements {
            let Some(rust) = self.rust_of(type_ref) else { continue };
            // A type another module owns cannot carry this module's codes.
            if rust.contains("::") {
                continue;
            }
            *users.entry(rust.clone()).or_default() += 1;
            named.push((q.clone(), rust));
        }
        for (q, rust) in named {
            // One Rust type reached by two element names has no single code;
            // it is encoded through whichever named element the caller means.
            if users[&rust] != 1 {
                continue;
            }
            let Some(code) = all.iter().position(|x| *x == q) else { continue };
            self.fragment_impl(out, &rust, &q.local, code as u64, "FRAGMENT", "this schema set");
            if let Some(ds) = xmldsig.iter().position(|x| *x == q) {
                self.fragment_impl(
                    out,
                    &rust,
                    &q.local,
                    ds as u64,
                    "XMLDSIG_FRAGMENT",
                    "the xmldsig schema alone (ISO 15118-2 Annex J)",
                );
            }
        }
    }

    /// One fragment codec: a code constant plus encode/decode against the
    /// `{prefix}_WIDTH` / `{prefix}_ED_CODE` pair.
    fn fragment_impl(
        &self,
        out: &mut String,
        rust: &str,
        local: &str,
        code: u64,
        prefix: &str,
        table: &str,
    ) {
        let xmldsig = prefix.starts_with("XMLDSIG");
        let suffix = if xmldsig { "_xmldsig_fragment" } else { "_fragment" };
        let width = format!("{prefix}_WIDTH");
        let ed = format!("{prefix}_ED_CODE");
        let _ = writeln!(out, "impl {rust} {{");
        let _ = writeln!(out, "    /// Fragment event code of `{local}` in {table}.");
        let _ = writeln!(out, "    pub const {prefix}_CODE: u64 = {code};");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Encodes this element as a standalone EXI *fragment*");
        let _ = writeln!(out, "    /// (EXI 1.0 §8.5.2) against {table}.");
        let _ = writeln!(out, "    ///");
        let _ = writeln!(out, "    /// A fragment is `SD SE({local}) … EE ED`: the same element");
        let _ = writeln!(out, "    /// body as a document, under a different root table. This is");
        let _ = writeln!(out, "    /// the form an ISO 15118 signature is computed over.");
        let _ = writeln!(
            out,
            "    pub fn encode{suffix}(&self, buf: &mut [u8]) -> ExiResult<usize> {{"
        );
        let _ = writeln!(out, "        let mut e = Encoder::new(buf);");
        let _ = writeln!(out, "        e.write_header(crate::exi::Header::ISO15118)?;");
        let _ = writeln!(out, "        e.event(Self::{prefix}_CODE, {width})?;");
        let _ = writeln!(out, "        self.encode_body(&mut e)?;");
        let _ = writeln!(out, "        e.event({ed}, {width})?;");
        let _ = writeln!(out, "        e.finish()");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Encodes this element as an EXI fragment into a vector.");
        let _ = writeln!(out, "    pub fn to{suffix}(&self) -> ExiResult<Vec<u8>> {{");
        let _ = writeln!(out, "        crate::exi::encode_growing(|buf| self.encode{suffix}(buf))");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Parses this element from a standalone EXI fragment.");
        let _ = writeln!(out, "    pub fn from{suffix}(bytes: &[u8]) -> ExiResult<Self> {{");
        let _ = writeln!(out, "        let mut d = Decoder::new(bytes);");
        let _ = writeln!(out, "        d.read_header()?;");
        let _ = writeln!(out, "        d.expect_event(Self::{prefix}_CODE, {width})?;");
        let _ = writeln!(out, "        let value = Self::decode_body(&mut d)?;");
        let _ = writeln!(out, "        d.expect_event({ed}, {width})?;");
        let _ = writeln!(out, "        d.finish()?;");
        let _ = writeln!(out, "        Ok(value)");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    /// Emits a document-level codec for every global element whose type maps to
    /// a Rust struct that no other global element shares.
    ///
    /// The event code is the element's position in the schema set's sorted
    /// global element list, which is what the document grammar indexes.
    fn documents(&self, out: &mut String) {
        // EXI 1.0 §8.5.1: `DocContent` has one production per global element
        // (codes 0..n-1), then `SE(*)` at n, then DT/CM/PI as one second-level
        // group at n+1 — so n+2 alternatives have to be distinguishable.
        let globals = self.schema.global_elements.len() as u64;
        let width = crate::grammar::bit_width(globals + 2);
        let _ = writeln!(out, "/// Width of a document-level event code.");
        let _ = writeln!(out, "///");
        let _ = writeln!(
            out,
            "/// One alternative per global element in the schema set — {globals} of them,"
        );
        let _ =
            writeln!(out, "/// counting the imported schemas — plus the generic `SE(*)` and the");
        let _ = writeln!(out, "/// second-level group non-strict fidelity adds.");
        let _ = writeln!(out, "pub const DOCUMENT_WIDTH: u32 = {width};");
        let _ = writeln!(out);
        self.fragment_header(out);

        // A type shared by several global elements cannot carry one root code.
        let mut users: BTreeMap<String, usize> = BTreeMap::new();
        for element in &self.schema.global_elements {
            if let Some(rust) = self.rust_of(&element.type_ref) {
                *users.entry(rust).or_default() += 1;
            }
        }

        // Every global element this module can name is a document, whether or
        // not it has a type to itself.
        let mut roots: Vec<(usize, QName, String)> = Vec::new();
        for (code, element) in self.schema.global_elements.iter().enumerate() {
            let Some(rust) = self.rust_of(&element.type_ref) else { continue };
            // A type another module owns cannot carry this module's root code.
            if rust.contains("::") {
                continue;
            }
            roots.push((code, element.name.clone(), rust.clone()));
            // The ergonomic `T::from_bytes` needs one code per type. ISO
            // 15118-20 gives `ACDP_DisconnectReq` the same type as
            // `ACDP_ConnectReq`, so a shared type gets no inherent code and is
            // reached through `Document` instead — which is right, because the
            // two are different messages that merely look alike.
            if users[&rust] != 1 {
                continue;
            }
            let _ = writeln!(out, "impl {rust} {{");
            let _ = writeln!(
                out,
                "    /// Document event code of `{}` in this schema set.",
                element.name.local
            );
            let _ = writeln!(out, "    pub const DOCUMENT_CODE: u64 = {code};");
            let _ = writeln!(out, "}}");
            let _ = writeln!(out);
            let _ = writeln!(out, "impl crate::exi::ExiDocument for {rust} {{");
            let _ = writeln!(out, "    fn to_slice(&self, buf: &mut [u8]) -> ExiResult<usize> {{");
            let _ = writeln!(out, "        let mut e = Encoder::new(buf);");
            let _ = writeln!(out, "        e.write_header(crate::exi::Header::ISO15118)?;");
            let _ = writeln!(out, "        e.event(Self::DOCUMENT_CODE, DOCUMENT_WIDTH)?;");
            let _ = writeln!(out, "        self.encode_body(&mut e)?;");
            let _ = writeln!(out, "        e.finish()");
            let _ = writeln!(out, "    }}");
            let _ = writeln!(out);
            let _ = writeln!(out, "    fn from_bytes(bytes: &[u8]) -> ExiResult<Self> {{");
            let _ = writeln!(out, "        let mut d = Decoder::new(bytes);");
            let _ = writeln!(out, "        d.read_header()?;");
            let _ = writeln!(out, "        d.expect_event(Self::DOCUMENT_CODE, DOCUMENT_WIDTH)?;");
            let _ = writeln!(out, "        let value = Self::decode_body(&mut d)?;");
            let _ = writeln!(out, "        d.finish()?;");
            let _ = writeln!(out, "        Ok(value)");
            let _ = writeln!(out, "    }}");
            let _ = writeln!(out, "}}");
            let _ = writeln!(out);
        }

        self.document_enum(out, &roots);
        self.fragments(out);
    }

    /// Emits an enum over every document this schema set defines.
    ///
    /// A receiver has bytes and a V2GTP payload type, not a message name — the
    /// document event code is the only thing that says which message arrived.
    /// This is the type that reads it.
    fn document_enum(&self, out: &mut String, roots: &[(usize, QName, String)]) {
        if roots.is_empty() {
            return;
        }
        let _ = writeln!(out, "/// Any document this schema set defines.");
        let _ = writeln!(out, "///");
        let _ = writeln!(out, "/// The document event code says which message a stream holds, so");
        let _ = writeln!(out, "/// this is what a peer decodes into before it knows what it got.");
        let _ = writeln!(out, "#[derive(Debug, Clone, PartialEq)]");
        let _ = writeln!(
            out,
            "#[cfg_attr(feature = \"serde\", derive(serde::Serialize, serde::Deserialize))]"
        );
        let _ = writeln!(out, "#[non_exhaustive]");
        let _ = writeln!(out, "pub enum Document {{");
        for (_, name, rust) in roots {
            let local = &name.local;
            let _ = writeln!(out, "    /// `{local}`");
            let _ = writeln!(out, "    {}({rust}),", pascal(local));
        }
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "impl Document {{");
        let _ = writeln!(out, "    /// The element name of this document.");
        let _ = writeln!(out, "    #[must_use]");
        let _ = writeln!(out, "    pub const fn name(&self) -> &'static str {{");
        let _ = writeln!(out, "        match self {{");
        for (_, name, _) in roots {
            let local = &name.local;
            let _ = writeln!(out, "            Self::{}(_) => {local:?},", pascal(local));
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// The document event code of this message.");
        let _ = writeln!(out, "    #[must_use]");
        let _ = writeln!(out, "    pub const fn code(&self) -> u64 {{");
        let _ = writeln!(out, "        match self {{");
        for (code, name, _) in roots {
            let _ = writeln!(out, "            Self::{}(_) => {code},", pascal(&name.local));
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "impl crate::exi::ExiDocument for Document {{");
        let _ = writeln!(out, "    fn to_slice(&self, buf: &mut [u8]) -> ExiResult<usize> {{");
        let _ = writeln!(out, "        let mut e = Encoder::new(buf);");
        let _ = writeln!(out, "        e.write_header(crate::exi::Header::ISO15118)?;");
        let _ = writeln!(out, "        e.event(self.code(), DOCUMENT_WIDTH)?;");
        let _ = writeln!(out, "        match self {{");
        for (_, name, _) in roots {
            let _ = writeln!(
                out,
                "            Self::{}(m) => m.encode_body(&mut e)?,",
                pascal(&name.local)
            );
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "        e.finish()");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    fn from_bytes(bytes: &[u8]) -> ExiResult<Self> {{");
        let _ = writeln!(out, "        let mut d = Decoder::new(bytes);");
        let _ = writeln!(out, "        d.read_header()?;");
        let _ = writeln!(out, "        let value = match d.event(DOCUMENT_WIDTH)? {{");
        for (code, name, rust) in roots {
            let _ = writeln!(
                out,
                "            {code} => Self::{}({rust}::decode_body(&mut d)?),",
                pascal(&name.local)
            );
        }
        let _ = writeln!(out, "            _ => return Err(ExiError::UnknownEventCode),");
        let _ = writeln!(out, "        }};");
        let _ = writeln!(out, "        d.finish()?;");
        let _ = writeln!(out, "        Ok(value)");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);

        // The same messages under the *fragment* grammar. ISO 15118 signs
        // fragments, and the fragment table is indexed differently from the
        // document table, so the two encodings of one message differ from the
        // first event code on.
        // Every message that carries a header, reachable without a match.
        let headers: Vec<(&QName, &String)> = roots
            .iter()
            .filter_map(|(_, name, rust)| Some((name, self.header_types.get(rust)?)))
            .collect();
        if let Some((_, header_type)) = headers.first() {
            let header_type = (*header_type).clone();
            // Every message in a schema set shares one header type; anything
            // else would mean the set has two headers, which none does.
            if headers.iter().all(|(_, t)| **t == header_type) {
                let _ = writeln!(out, "impl Document {{");
                let _ =
                    writeln!(out, "    /// The message header, for the messages that have one.");
                let _ = writeln!(out, "    ///");
                let _ =
                    writeln!(out, "    /// `None` only for the few schema elements that are not");
                let _ = writeln!(out, "    /// messages in their own right.");
                let _ = writeln!(out, "    #[must_use]");
                let _ =
                    writeln!(out, "    pub const fn header(&self) -> Option<&{header_type}> {{");
                let _ = writeln!(out, "        match self {{");
                for (name, _) in &headers {
                    let _ = writeln!(
                        out,
                        "            Self::{}(m) => Some(&m.header),",
                        pascal(&name.local)
                    );
                }
                if headers.len() != roots.len() {
                    let _ = writeln!(out, "            _ => None,");
                }
                let _ = writeln!(out, "        }}");
                let _ = writeln!(out, "    }}");
                let _ = writeln!(out);
                // The mutable twin. A session driver stamps the negotiated
                // session id into every outgoing message rather than trusting
                // the application to remember it, and this is what it stamps
                // through.
                let _ = writeln!(out, "    /// The message header, mutably.");
                let _ = writeln!(out, "    ///");
                let _ =
                    writeln!(out, "    /// The counterpart to [`Document::header`], for a caller");
                let _ =
                    writeln!(out, "    /// that has to set a header field a layer above it owns —");
                let _ = writeln!(
                    out,
                    "    /// the session id, which the SECC assigns and neither side"
                );
                let _ = writeln!(out, "    /// chooses per message.");
                let _ = writeln!(
                    out,
                    "    pub const fn header_mut(&mut self) -> Option<&mut {header_type}> {{"
                );
                let _ = writeln!(out, "        match self {{");
                for (name, _) in &headers {
                    let _ = writeln!(
                        out,
                        "            Self::{}(m) => Some(&mut m.header),",
                        pascal(&name.local)
                    );
                }
                if headers.len() != roots.len() {
                    let _ = writeln!(out, "            _ => None,");
                }
                let _ = writeln!(out, "        }}");
                let _ = writeln!(out, "    }}");
                let _ = writeln!(out, "}}");
                let _ = writeln!(out);
            }
        }

        // The response code, for the sets whose messages are documents in
        // their own right. ISO 15118 makes a `FAILED_*` code terminal, so a
        // session core reads this on every response that goes past.
        let coded: Vec<(&QName, &String)> = roots
            .iter()
            .filter_map(|(_, name, rust)| Some((name, self.response_code_types.get(rust)?)))
            .collect();
        if let Some((_, code_type)) = coded.first() {
            let code_type = (*code_type).clone();
            if coded.iter().all(|(_, t)| **t == code_type) {
                let _ = writeln!(out, "impl Document {{");
                let _ = writeln!(out, "    /// The `ResponseCode`, for the messages that are");
                let _ = writeln!(out, "    /// responses.");
                let _ = writeln!(out, "    ///");
                let _ = writeln!(out, "    /// `None` for a request, which carries no code.");
                let _ = writeln!(out, "    #[must_use]");
                let _ = writeln!(
                    out,
                    "    pub const fn response_code(&self) -> Option<{code_type}> {{"
                );
                let _ = writeln!(out, "        match self {{");
                for (name, _) in &coded {
                    let _ = writeln!(
                        out,
                        "            Self::{}(m) => Some(m.response_code),",
                        pascal(&name.local)
                    );
                }
                if coded.len() != roots.len() {
                    let _ = writeln!(out, "            _ => None,");
                }
                let _ = writeln!(out, "        }}");
                let _ = writeln!(out, "    }}");
                let _ = writeln!(out, "}}");
                let _ = writeln!(out);
            }
        }

        // The schema-set table, and only that one: a fragment stream is coded
        // against a single grammar, and `Document` spans the whole set.
        let (all, _) = self.fragment_tables();
        let codes: Vec<(u64, &QName, &String)> = roots
            .iter()
            .filter_map(|(_, name, rust)| {
                all.iter().position(|x| x == name).map(|code| (code as u64, name, rust))
            })
            .collect();
        if codes.is_empty() {
            return;
        }
        let _ = writeln!(out, "impl Document {{");
        let _ = writeln!(out, "    /// The *fragment* event code of this message.");
        let _ = writeln!(out, "    ///");
        let _ = writeln!(out, "    /// See [`FRAGMENT_WIDTH`] for why this differs from");
        let _ = writeln!(out, "    /// [`Document::code`].");
        let _ = writeln!(out, "    #[must_use]");
        let _ = writeln!(out, "    pub const fn fragment_code(&self) -> u64 {{");
        let _ = writeln!(out, "        match self {{");
        for (code, name, _) in &codes {
            let _ = writeln!(out, "            Self::{}(_) => {code},", pascal(&name.local));
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Encodes this message as a standalone EXI fragment.");
        let _ = writeln!(
            out,
            "    pub fn encode_fragment(&self, buf: &mut [u8]) -> ExiResult<usize> {{"
        );
        let _ = writeln!(out, "        let mut e = Encoder::new(buf);");
        let _ = writeln!(out, "        e.write_header(crate::exi::Header::ISO15118)?;");
        let _ = writeln!(out, "        e.event(self.fragment_code(), FRAGMENT_WIDTH)?;");
        let _ = writeln!(out, "        match self {{");
        for (_, name, _) in &codes {
            let _ = writeln!(
                out,
                "            Self::{}(m) => m.encode_body(&mut e)?,",
                pascal(&name.local)
            );
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "        e.event(FRAGMENT_ED_CODE, FRAGMENT_WIDTH)?;");
        let _ = writeln!(out, "        e.finish()");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Encodes this message as an EXI fragment into a vector.");
        let _ = writeln!(out, "    pub fn to_fragment(&self) -> ExiResult<Vec<u8>> {{");
        let _ =
            writeln!(out, "        crate::exi::encode_growing(|buf| self.encode_fragment(buf))");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Parses a message from a standalone EXI fragment.");
        let _ = writeln!(out, "    pub fn from_fragment(bytes: &[u8]) -> ExiResult<Self> {{");
        let _ = writeln!(out, "        let mut d = Decoder::new(bytes);");
        let _ = writeln!(out, "        d.read_header()?;");
        let _ = writeln!(out, "        let value = match d.event(FRAGMENT_WIDTH)? {{");
        for (code, name, rust) in &codes {
            let _ = writeln!(
                out,
                "            {code} => Self::{}({rust}::decode_body(&mut d)?),",
                pascal(&name.local)
            );
        }
        let _ = writeln!(out, "            _ => return Err(ExiError::UnknownEventCode),");
        let _ = writeln!(out, "        }};");
        let _ = writeln!(out, "        d.expect_event(FRAGMENT_ED_CODE, FRAGMENT_WIDTH)?;");
        let _ = writeln!(out, "        d.finish()?;");
        let _ = writeln!(out, "        Ok(value)");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    /// The Rust type a reference maps to, if this module can name it.
    fn rust_of(&self, type_ref: &TypeRef) -> Option<String> {
        match type_ref {
            TypeRef::Named(q) if self.generated(q) && self.reachable(q) => {
                self.type_names.get(q).map(|n| format!("{}{n}", self.prefix(q)))
            }
            TypeRef::Anonymous(i) => self.anonymous_roots.get(i).map(|(_, n)| n.clone()),
            TypeRef::Named(_) => None,
        }
    }

    /// True when this module either writes the type out or knows where it lives.
    fn reachable(&self, name: &QName) -> bool {
        self.local(name) || self.extern_modules.contains_key(&name.namespace)
    }

    fn header(&self, out: &mut String) {
        let sources: Vec<String> = self
            .schema
            .sources
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        let _ = writeln!(out, "// @generated by iso15118-codegen. Do not edit.");
        let _ = writeln!(out, "//");
        let _ = writeln!(out, "// Source schemas: {}", sources.join(", "));
        let _ = writeln!(out, "//");
        let _ = writeln!(
            out,
            "// Every event-code width and enumeration index below is derived from those"
        );
        let _ = writeln!(
            out,
            "// schemas and cross-checked against the EXI reference implementation; see"
        );
        let _ = writeln!(out, "// scripts/verify-grammars.sh.");
        let _ = writeln!(out);
        // Machine-written code is held to the compiler's correctness bar, not a
        // style bar: these lints all fire on shapes the generator emits
        // uniformly, and bending the emitter around each would make it harder
        // to reason about than the code it produces.
        let _ = writeln!(out, "#![allow(");
        for lint in [
            "unused_imports",
            "clippy::doc_markdown",
            "clippy::too_many_lines",
            "clippy::needless_range_loop",
            "clippy::similar_names",
            "clippy::upper_case_acronyms",
            "clippy::struct_excessive_bools",
            "clippy::module_name_repetitions",
            "clippy::enum_variant_names",
            "clippy::never_loop",
            "clippy::cast_possible_truncation",
            "clippy::cast_lossless",
            "clippy::manual_range_contains",
            "clippy::useless_conversion",
            "clippy::unnecessary_cast",
            "clippy::redundant_closure_for_method_calls",
            "clippy::wildcard_imports",
            "clippy::match_same_arms",
            "clippy::single_match_else",
            "clippy::large_enum_variant",
            "clippy::result_large_err",
            "clippy::unreadable_literal",
        ] {
            let _ = writeln!(out, "    {lint},");
        }
        let _ = writeln!(out, ")]");
        let _ = writeln!(out);
        let _ = writeln!(out, "use alloc::string::String;");
        let _ = writeln!(out, "use alloc::vec::Vec;");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "use crate::exi::seq::{{SIMPLE_WIDTH, SeqReader, SeqWriter, Shape, Step}};"
        );
        let _ = writeln!(
            out,
            "use crate::exi::{{DateTime, Decimal, Decoder, Encoder, ExiError, ExiResult, Float, Lengths, ValueCtx}};"
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "/// Name of the schema set this module was generated from.");
        let _ = writeln!(out, "pub const SCHEMA: &str = {:?};", self.module);
        let _ = writeln!(out);
    }

    fn enumeration(&self, out: &mut String, name: &QName, st: &SimpleType) {
        let rust = &self.enum_names[name];
        let width = crate::grammar::bit_width(st.enumeration.len() as u64);
        let _ = writeln!(out, "/// `{}`.", name.local);
        let _ = writeln!(out, "///");
        let _ = writeln!(
            out,
            "/// {} values, so {width} bits. Discriminants are the EXI indices, which",
            st.enumeration.len()
        );
        let _ = writeln!(out, "/// follow schema document order rather than sort order.");
        let _ =
            writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]");
        let _ = writeln!(
            out,
            "#[cfg_attr(feature = \"serde\", derive(serde::Serialize, serde::Deserialize))]"
        );
        let _ = writeln!(out, "#[repr(u16)]");
        let _ = writeln!(out, "pub enum {rust} {{");
        let mut variants = Vec::new();
        let mut taken = BTreeSet::new();
        for (i, value) in st.enumeration.iter().enumerate() {
            let mut variant = pascal(&sanitise(value));
            while !taken.insert(variant.clone()) {
                variant.push('_');
            }
            let _ = writeln!(out, "    /// `{value}`");
            let _ = writeln!(out, "    {variant} = {i},");
            variants.push(variant);
        }
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "impl {rust} {{");
        let _ = writeln!(out, "    /// Event-code width of this enumeration.");
        let _ = writeln!(out, "    pub const WIDTH: u32 = {width};");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Every value, in EXI index order.");
        let _ = writeln!(out, "    pub const ALL: [Self; {}] = [", variants.len());
        for v in &variants {
            let _ = writeln!(out, "        Self::{v},");
        }
        let _ = writeln!(out, "    ];");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// The EXI index of this value.");
        let _ = writeln!(out, "    #[must_use]");
        let _ = writeln!(out, "    pub const fn as_index(self) -> u64 {{");
        let _ = writeln!(out, "        self as u64");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Parses an EXI index.");
        let _ = writeln!(out, "    pub const fn from_index(index: u64) -> ExiResult<Self> {{");
        let _ = writeln!(out, "        Ok(match index {{");
        for (i, v) in variants.iter().enumerate() {
            let _ = writeln!(out, "            {i} => Self::{v},");
        }
        let _ = writeln!(out, "            _ => return Err(ExiError::UnknownEnumValue),");
        let _ = writeln!(out, "        }})");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out);
        let _ = writeln!(out, "    /// The lexical form this value has in the schema.");
        let _ = writeln!(out, "    #[must_use]");
        let _ = writeln!(out, "    pub const fn as_str(self) -> &'static str {{");
        let _ = writeln!(out, "        match self {{");
        for (v, value) in variants.iter().zip(&st.enumeration) {
            let _ = writeln!(out, "            Self::{v} => {value:?},");
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        if name.local == "responseCodeType" {
            response_code_classes(out, rust, &variants, &st.enumeration);
        }
    }

    fn complex(&self, out: &mut String, name: &QName, layout: &Layout) -> Result<(), String> {
        let rust = &self.type_names[name];

        // Resolve every item to a Rust field first, so an unsupported one can
        // fail the whole type rather than half-generate it.
        let mut fields = Vec::new();
        let choices = layout.items.iter().filter(|i| matches!(i, Item::Choice { .. })).count();
        for (index, item) in layout.items.iter().enumerate() {
            fields.push(self.field_of(rust, index, item, choices <= 1)?);
        }

        self.struct_decl(out, name, rust, &fields);
        self.shape_decl(out, rust, layout);
        self.encode_impl(out, rust, &fields);
        self.decode_impl(out, rust, &fields);
        Ok(())
    }

    fn field_of(
        &self,
        owner: &str,
        index: usize,
        item: &Item,
        sole_choice: bool,
    ) -> Result<Emitted, String> {
        match item {
            Item::Attribute(f) | Item::Element(f) => {
                let kind = self.kind(f);
                // A child whose type cannot be expressed as a struct — in
                // practice only `ds:Signature` — still occupies its event
                // codes, so it stays in the layout and keeps every later width
                // correct. It gets no struct field: encoding never emits it,
                // and decoding refuses it rather than dropping it silently.
                // That is Plug & Charge, which this crate does not implement.
                let phantom = matches!(kind, Kind::Unsupported);
                if phantom && f.min > 0 {
                    return Err(format!(
                        "{owner}: required child {} has a type that is not generated",
                        f.name
                    ));
                }
                Ok(Emitted {
                    index,
                    name: snake(&f.name.local),
                    doc: f.name.local.clone(),
                    kind: FieldKind::Single(kind),
                    min: f.min,
                    max: f.max,
                    attribute: matches!(item, Item::Attribute(_)),
                    phantom,
                })
            }
            Item::Characters(type_ref) => {
                let kind = self.scalar(type_ref, None).map_or(Kind::Unsupported, Kind::Scalar);
                if matches!(kind, Kind::Unsupported) {
                    return Err(format!("{owner}: simple content is not a scalar"));
                }
                Ok(Emitted {
                    index,
                    name: "value".to_owned(),
                    doc: "character data".to_owned(),
                    kind: FieldKind::Single(kind),
                    min: 1,
                    max: 1,
                    // Simple content is written like an attribute value: the
                    // event carries it directly, with no CH/EE of its own.
                    attribute: true,
                    phantom: false,
                })
            }
            Item::Wildcard { min, max } => {
                // `xs:any` has no Rust representation, but it occupies event
                // codes: leaving it out would shift every later code in the
                // type. It is a phantom — never written, refused on decode.
                if *min > 0 {
                    return Err(format!("{owner}: a required xs:any cannot be represented"));
                }
                Ok(Emitted {
                    index,
                    name: format!("any_{index}"),
                    doc: "xs:any wildcard".to_owned(),
                    kind: FieldKind::Single(Kind::Unsupported),
                    min: *min,
                    max: *max,
                    attribute: false,
                    phantom: true,
                })
            }
            Item::Choice { branches, min, max } => {
                let mut variants = Vec::new();
                let mut representable = true;
                for b in branches {
                    let Some(b) = b.field() else {
                        // A wildcard branch: the whole choice loses its typed
                        // form, because one of its codes names nothing.
                        representable = false;
                        break;
                    };
                    let kind = self.kind(b);
                    if matches!(kind, Kind::Unsupported) {
                        representable = false;
                        break;
                    }
                    variants.push((pascal(&b.name.local), b.name.local.clone(), kind));
                }
                if !representable {
                    if *min > 0 {
                        return Err(format!(
                            "{owner}: a required choice has a branch that is not generated"
                        ));
                    }
                    // Optional and unrepresentable: keep the codes, drop the
                    // field. `ds:TransformType` is exactly this — its
                    // `(XPath | any)*` content is never present in an
                    // ISO 15118 signature.
                    return Ok(Emitted {
                        index,
                        name: format!("choice_{index}"),
                        doc: format!("choice of {}", branches.len()),
                        kind: FieldKind::Single(Kind::Unsupported),
                        min: *min,
                        max: *max,
                        attribute: false,
                        phantom: true,
                    });
                }
                // A choice has no name of its own in the schema. Numbering it
                // only when a type has more than one keeps the common case
                // readable.
                let suffix = if sole_choice { String::new() } else { index.to_string() };
                Ok(Emitted {
                    index,
                    name: format!(
                        "choice{}",
                        if suffix.is_empty() { String::new() } else { format!("_{suffix}") }
                    ),
                    doc: format!("choice of {}", branches.len()),
                    kind: FieldKind::Choice {
                        enum_name: format!("{owner}Choice{suffix}"),
                        variants,
                    },
                    min: *min,
                    max: *max,
                    attribute: false,
                    phantom: false,
                })
            }
        }
    }
}

/// A resolved field, ready to be written out.
struct Emitted {
    index: usize,
    name: String,
    doc: String,
    kind: FieldKind,
    min: u32,
    max: u32,
    attribute: bool,
    /// The item occupies event codes but has no Rust field.
    phantom: bool,
}

enum FieldKind {
    Single(Kind),
    Choice { enum_name: String, variants: Vec<(String, String, Kind)> },
}

impl Emitted {
    /// The Rust type of the field, including its `Option` or `Vec` wrapper.
    fn rust_type(&self) -> String {
        let inner = match &self.kind {
            FieldKind::Single(Kind::Scalar(s)) => s.rust_type(),
            FieldKind::Single(Kind::Struct(name)) => name.clone(),
            FieldKind::Single(Kind::Unsupported) => "()".into(),
            FieldKind::Choice { enum_name, .. } => enum_name.clone(),
        };
        if self.max > 1 {
            format!("Vec<{inner}>")
        } else if self.min == 0 {
            format!("Option<{inner}>")
        } else {
            inner
        }
    }
}

fn sanitise(value: &str) -> String {
    let mut out: String =
        value.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect();
    if out.starts_with(|c: char| c.is_numeric()) {
        out.insert(0, 'V');
    }
    out
}

/// Writes the three classifiers every ISO 15118 `responseCodeType` needs.
///
/// The standard splits the codes by prefix and gives each class a consequence:
/// `OK_*` means carry on, `WARNING_*` means carry on and tell somebody, and
/// `FAILED_*` ends the session — the EVCC is then expected to send
/// `SessionStopReq` and nothing else. Deriving the classes from the prefixes
/// rather than listing them keeps the two generations' differing code sets from
/// having to be maintained by hand.
fn response_code_classes(out: &mut String, rust: &str, variants: &[String], values: &[String]) {
    let group = |prefix: &str| -> Vec<&String> {
        variants
            .iter()
            .zip(values)
            .filter(|(_, value)| value.starts_with(prefix))
            .map(|(variant, _)| variant)
            .collect()
    };
    let ok = group("OK");
    let warning = group("WARNING");
    let failed = group("FAILED");
    // Every value must land in exactly one class, or the classification is a
    // guess. ISO 15118 has never used another prefix; if it ever does, this
    // stops rather than silently calling it a failure.
    assert_eq!(
        ok.len() + warning.len() + failed.len(),
        values.len(),
        "{rust}: a response code outside the OK/WARNING/FAILED classes",
    );
    let arm = |group: &[&String]| -> String {
        if group.is_empty() {
            "false".to_owned()
        } else {
            let arms = group
                .iter()
                .map(|v| format!("Self::{v}"))
                .collect::<Vec<_>>()
                .join("\n                | ");
            format!("matches!(self, {arms})")
        }
    };
    let _ = writeln!(out, "impl {rust} {{");
    let _ = writeln!(out, "    /// True for an `OK_*` code: the request succeeded.");
    let _ = writeln!(out, "    #[must_use]");
    let _ = writeln!(out, "    pub const fn is_ok(self) -> bool {{");
    let _ = writeln!(out, "        {}", arm(&ok));
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out);
    let _ = writeln!(out, "    /// True for a `WARNING_*` code: the request succeeded, with a");
    let _ = writeln!(out, "    /// caveat the application should surface. The session continues.");
    let _ = writeln!(out, "    #[must_use]");
    let _ = writeln!(out, "    pub const fn is_warning(self) -> bool {{");
    let _ = writeln!(out, "        {}", arm(&warning));
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out);
    let _ = writeln!(out, "    /// True for a `FAILED_*` code, which **ends the session**.");
    let _ = writeln!(out, "    ///");
    let _ = writeln!(out, "    /// ISO 15118 leaves no discretion here: after a failure response");
    let _ = writeln!(out, "    /// the only request left is `SessionStopReq`. The session cores");
    let _ = writeln!(out, "    /// enforce that; see `session::Flow::failed`.");
    let _ = writeln!(out, "    #[must_use]");
    let _ = writeln!(out, "    pub const fn is_failure(self) -> bool {{");
    let _ = writeln!(out, "        {}", arm(&failed));
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
}

impl Emitter<'_> {
    /// Writes `response_code()` for a choice enum whose branches are messages.
    ///
    /// ISO 15118-2 routes all thirty-four of its messages through one
    /// `V2G_Message` root, so the response code of whatever arrived hangs off
    /// the *branch*. A session core has to read it without knowing which of the
    /// seventeen response types it is holding.
    fn choice_response_code(
        &self,
        out: &mut String,
        enum_name: &str,
        variants: &[(String, String, Kind)],
    ) {
        let coded: Vec<(&String, &String)> = variants
            .iter()
            .filter_map(|(variant, _, kind)| match kind {
                Kind::Struct(inner) => Some((variant, self.response_code_types.get(inner)?)),
                _ => None,
            })
            .collect();
        let Some((_, code_type)) = coded.first() else { return };
        let code_type = (*code_type).clone();
        if !coded.iter().all(|(_, t)| **t == code_type) {
            return;
        }
        let _ = writeln!(out, "impl {enum_name} {{");
        let _ = writeln!(out, "    /// The `ResponseCode`, for the branches that are responses.");
        let _ = writeln!(out, "    ///");
        let _ = writeln!(out, "    /// `None` for a request, which carries no code.");
        let _ = writeln!(out, "    #[must_use]");
        let _ = writeln!(out, "    pub const fn response_code(&self) -> Option<{code_type}> {{");
        let _ = writeln!(out, "        match self {{");
        for (variant, _) in &coded {
            let _ = writeln!(out, "            Self::{variant}(m) => Some(m.response_code),");
        }
        if coded.len() != variants.len() {
            let _ = writeln!(out, "            _ => None,");
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    /// Writes the struct, and any enum a choice item needs.
    fn struct_decl(&self, out: &mut String, name: &QName, rust: &str, fields: &[Emitted]) {
        for f in fields {
            let FieldKind::Choice { enum_name, variants } = &f.kind else { continue };
            let _ = writeln!(out, "/// The `{}` alternatives of [`{rust}`].", f.doc);
            let _ = writeln!(out, "#[derive(Debug, Clone, PartialEq)]");
            let _ = writeln!(
                out,
                "#[cfg_attr(feature = \"serde\", derive(serde::Serialize, serde::Deserialize))]"
            );
            let _ = writeln!(out, "pub enum {enum_name} {{");
            for (variant, doc, kind) in variants {
                let inner = match kind {
                    Kind::Scalar(s) => s.rust_type(),
                    Kind::Struct(n) => n.clone(),
                    Kind::Unsupported => "()".into(),
                };
                let _ = writeln!(out, "    /// `{doc}`");
                let _ = writeln!(out, "    {variant}({inner}),");
            }
            let _ = writeln!(out, "}}");
            let _ = writeln!(out);
            // ISO 15118-2 routes all thirty-four of its messages through one
            // `V2G_Message` root, so the name of the message that actually
            // arrived is the name of the *branch*, not of the document.
            let _ = writeln!(out, "impl {enum_name} {{");
            let _ = writeln!(out, "    /// The element name of the alternative taken.");
            let _ = writeln!(out, "    #[must_use]");
            let _ = writeln!(out, "    pub const fn name(&self) -> &'static str {{");
            let _ = writeln!(out, "        match self {{");
            for (variant, doc, _) in variants {
                let _ = writeln!(out, "            Self::{variant}(_) => {doc:?},");
            }
            let _ = writeln!(out, "        }}");
            let _ = writeln!(out, "    }}");
            let _ = writeln!(out, "}}");
            let _ = writeln!(out);
            self.choice_response_code(out, enum_name, variants);
        }

        let _ = writeln!(out, "/// `{}`.", name.local);
        let _ = writeln!(out, "#[derive(Debug, Clone, PartialEq)]");
        let _ = writeln!(
            out,
            "#[cfg_attr(feature = \"serde\", derive(serde::Serialize, serde::Deserialize))]"
        );
        if fields.iter().all(|f| f.phantom) {
            let _ = writeln!(out, "pub struct {rust};");
            let _ = writeln!(out);
            return;
        }
        let _ = writeln!(out, "pub struct {rust} {{");
        for f in fields {
            if f.phantom {
                let _ = writeln!(
                    out,
                    "    // `{}` is not modelled: its type needs XML signature machinery this",
                    f.doc
                );
                let _ = writeln!(out, "    // crate does not implement. Decoding one is refused.");
                continue;
            }
            let what = if f.attribute { "attribute" } else { "element" };
            let _ = writeln!(out, "    /// `{}` {what}, {}.", f.doc, occurs(f.min, f.max));
            let _ = writeln!(out, "    pub {}: {},", f.name, f.rust_type());
        }
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    /// Writes the event-code arithmetic as static data.
    fn shape_decl(&self, out: &mut String, rust: &str, layout: &Layout) {
        let list = |v: &[u64]| v.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
        let list32 = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
        let mins: Vec<u32> = layout.items.iter().map(Item::min).collect();
        let maxs: Vec<u32> = layout.items.iter().map(Item::max).collect();
        let repeat: Vec<u32> = layout.repeat_width.iter().map(|w| w.unwrap_or(0)).collect();

        let _ = writeln!(out, "impl {rust} {{");
        let _ = writeln!(out, "    /// Event-code arithmetic of this type's content model.");
        let _ = writeln!(out, "    const SHAPE: Shape = Shape {{");
        let _ = writeln!(out, "        prod_before: &[{}],", list(&layout.prod_before));
        let _ = writeln!(out, "        width: &[{}],", list32(&layout.width));
        let _ = writeln!(out, "        repeat_width: &[{}],", list32(&repeat));
        let _ = writeln!(out, "        min: &[{}],", list32(&mins));
        let _ = writeln!(out, "        max: &[{}],", list32(&maxs));
        let _ = writeln!(out, "    }};");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    fn encode_impl(&self, out: &mut String, rust: &str, fields: &[Emitted]) {
        let _ = writeln!(out, "impl {rust} {{");
        let _ = writeln!(out, "    /// Writes this element's content and its end event.");
        let _ = writeln!(out, "    ///");
        let _ = writeln!(out, "    /// The parent writes the start event; this writes everything");
        let _ = writeln!(out, "    /// inside it, so the two compose without either knowing the");
        let _ = writeln!(out, "    /// other's grammar.");
        let _ =
            writeln!(out, "    pub fn encode_body(&self, e: &mut Encoder<'_>) -> ExiResult<()> {{");
        let _ = writeln!(out, "        e.enter()?;");
        let _ = writeln!(out, "        let mut w = SeqWriter::new(Self::SHAPE);");
        for f in fields {
            self.encode_field(out, f);
        }
        let _ = writeln!(out, "        w.end(e)?;");
        let _ = writeln!(out, "        e.leave();");
        let _ = writeln!(out, "        Ok(())");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    fn encode_field(&self, out: &mut String, f: &Emitted) {
        if f.phantom {
            let _ = writeln!(out, "        // {} is never written.", f.doc);
            return;
        }
        let j = f.index;
        let _ = writeln!(out, "        // {} ({})", f.doc, occurs(f.min, f.max));
        if f.max > 1 {
            let _ = writeln!(out, "        {{");
            let _ = writeln!(out, "            let items = &self.{};", f.name);
            let _ = writeln!(out, "            let count = items.len() as u32;");
            // `count` is a u32, so a `minOccurs` of zero needs no lower bound
            // and an unbounded `maxOccurs` needs no upper one.
            let lower = (f.min > 0).then(|| format!("count < {}", f.min));
            let upper = (f.max != UNBOUNDED).then(|| format!("count > {}", f.max));
            let checks: Vec<String> = lower.into_iter().chain(upper).collect();
            if !checks.is_empty() {
                let _ = writeln!(
                    out,
                    "            if {} {{ return Err(ExiError::ValueOutOfRange); }}",
                    checks.join(" || ")
                );
            }
            let _ = writeln!(out, "            for (c, item) in items.iter().enumerate() {{");
            self.encode_value(out, f, "item", "                ", j, "c as u32");
            let _ = writeln!(out, "            }}");
            let _ = writeln!(out, "            if count > 0 {{ w.finish({j}, count); }}");
            let _ = writeln!(out, "        }}");
        } else if f.min == 0 {
            let _ = writeln!(out, "        if let Some(item) = &self.{} {{", f.name);
            self.encode_value(out, f, "item", "            ", j, "0");
            let _ = writeln!(out, "            w.finish({j}, 1);");
            let _ = writeln!(out, "        }}");
        } else {
            let _ = writeln!(out, "        {{");
            let _ = writeln!(out, "            let item = &self.{};", f.name);
            self.encode_value(out, f, "item", "            ", j, "0");
            let _ = writeln!(out, "            w.finish({j}, 1);");
            let _ = writeln!(out, "        }}");
        }
    }

    /// Writes the start event and the value of one occurrence.
    fn encode_value(
        &self,
        out: &mut String,
        f: &Emitted,
        binding: &str,
        pad: &str,
        j: usize,
        c: &str,
    ) {
        match &f.kind {
            FieldKind::Single(kind) => {
                let _ = writeln!(out, "{pad}w.start(e, {j}, {c})?;");
                self.encode_kind(out, kind, binding, pad, f.attribute);
            }
            FieldKind::Choice { enum_name, variants } => {
                let _ = writeln!(out, "{pad}match {binding} {{");
                for (branch, (variant, _, kind)) in variants.iter().enumerate() {
                    let _ = writeln!(out, "{pad}    {enum_name}::{variant}(value) => {{");
                    let _ = writeln!(out, "{pad}        w.start_branch(e, {j}, {c}, {branch})?;");
                    self.encode_kind(out, kind, "value", &format!("{pad}        "), false);
                    let _ = writeln!(out, "{pad}    }}");
                }
                let _ = writeln!(out, "{pad}}}");
            }
        }
    }

    fn encode_kind(
        &self,
        out: &mut String,
        kind: &Kind,
        binding: &str,
        pad: &str,
        attribute: bool,
    ) {
        match kind {
            Kind::Struct(_) => {
                let _ = writeln!(out, "{pad}{binding}.encode_body(e)?;");
            }
            Kind::Scalar(s) => {
                if attribute {
                    // An attribute's value follows its AT event directly.
                    let _ = writeln!(out, "{pad}{};", s.encode(&format!("*{binding}")));
                } else {
                    let _ = writeln!(out, "{pad}e.event(0, SIMPLE_WIDTH)?; // CH");
                    let _ = writeln!(out, "{pad}{};", s.encode(&format!("*{binding}")));
                    let _ = writeln!(out, "{pad}e.event(0, SIMPLE_WIDTH)?; // EE");
                }
            }
            Kind::Unsupported => {
                let _ = writeln!(out, "{pad}return Err(ExiError::UnsupportedOption);");
            }
        }
    }

    fn decode_impl(&self, out: &mut String, rust: &str, fields: &[Emitted]) {
        let _ = writeln!(out, "impl {rust} {{");
        let _ = writeln!(out, "    /// Reads this element's content, up to and including its end");
        let _ = writeln!(out, "    /// event. The parent has already read the start event.");
        let _ = writeln!(out, "    pub fn decode_body(d: &mut Decoder<'_>) -> ExiResult<Self> {{");
        let _ = writeln!(out, "        d.enter()?;");
        let _ = writeln!(out, "        let mut r = SeqReader::new(Self::SHAPE);");
        for f in fields.iter().filter(|f| !f.phantom) {
            let init = if f.max > 1 { "Vec::new()".to_owned() } else { "None".to_owned() };
            // Indexed rather than named: a field called `type` escapes to
            // `r#type`, and `f_r#type` is not an identifier.
            let _ = writeln!(out, "        let mut f_{} = {init};", f.index);
        }
        let _ = writeln!(out, "        loop {{");
        let _ = writeln!(out, "            match r.next(d)? {{");
        let _ = writeln!(out, "                Step::End => break,");
        for f in fields {
            self.decode_field(out, f);
        }
        let _ = writeln!(
            out,
            "                Step::Item {{ .. }} => return Err(ExiError::UnknownEventCode),"
        );
        let _ = writeln!(out, "            }}");
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "        d.leave();");
        let _ = writeln!(out, "        Ok(Self {{");
        for f in fields.iter().filter(|f| !f.phantom) {
            if f.max > 1 {
                if f.min > 0 {
                    let _ = writeln!(
                        out,
                        "            {name}: {{ if (f_{i}.len() as u32) < {min} {{ return Err(ExiError::MissingElement); }} f_{i} }},",
                        name = f.name,
                        i = f.index,
                        min = f.min
                    );
                } else {
                    let _ = writeln!(out, "            {name}: f_{i},", name = f.name, i = f.index);
                }
            } else if f.min == 0 {
                let _ = writeln!(out, "            {name}: f_{i},", name = f.name, i = f.index);
            } else {
                let _ = writeln!(
                    out,
                    "            {name}: f_{i}.ok_or(ExiError::MissingElement)?,",
                    name = f.name,
                    i = f.index
                );
            }
        }
        let _ = writeln!(out, "        }})");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    fn decode_field(&self, out: &mut String, f: &Emitted) {
        let j = f.index;
        if f.phantom {
            let _ = writeln!(out, "                // `{}` is refused, not skipped.", f.doc);
            let _ = writeln!(
                out,
                "                Step::Item {{ index: {j}, .. }} => return Err(ExiError::UnsupportedOption),"
            );
            return;
        }
        let pad = "                    ";
        match &f.kind {
            FieldKind::Single(kind) => {
                let _ = writeln!(out, "                Step::Item {{ index: {j}, .. }} => {{");
                let expr = self.decode_kind(kind, pad, f.attribute);
                let _ = writeln!(out, "{expr}");
                if f.max > 1 {
                    let _ = writeln!(out, "{pad}f_{}.push(value);", f.index);
                } else {
                    let _ = writeln!(out, "{pad}f_{} = Some(value);", f.index);
                }
                let _ = writeln!(out, "                }}");
            }
            FieldKind::Choice { enum_name, variants } => {
                let _ =
                    writeln!(out, "                Step::Item {{ index: {j}, branch, .. }} => {{");
                let _ = writeln!(out, "{pad}let value = match branch {{");
                for (branch, (variant, _, kind)) in variants.iter().enumerate() {
                    let inner_pad = format!("{pad}        ");
                    let _ = writeln!(out, "{pad}    {branch} => {{");
                    let expr = self.decode_kind(kind, &inner_pad, false);
                    let _ = writeln!(out, "{expr}");
                    let _ = writeln!(out, "{inner_pad}{enum_name}::{variant}(value)");
                    let _ = writeln!(out, "{pad}    }}");
                }
                let _ = writeln!(out, "{pad}    _ => return Err(ExiError::UnknownEventCode),");
                let _ = writeln!(out, "{pad}}};");
                if f.max > 1 {
                    let _ = writeln!(out, "{pad}f_{}.push(value);", f.index);
                } else {
                    let _ = writeln!(out, "{pad}f_{} = Some(value);", f.index);
                }
                let _ = writeln!(out, "                }}");
            }
        }
    }

    /// Statements binding `value` to the decoded content of one occurrence.
    fn decode_kind(&self, kind: &Kind, pad: &str, attribute: bool) -> String {
        match kind {
            Kind::Struct(name) => format!("{pad}let value = {name}::decode_body(d)?;"),
            Kind::Scalar(s) if attribute => format!("{pad}let value = {};", s.decode()),
            Kind::Scalar(s) => format!(
                "{pad}d.expect_event(0, SIMPLE_WIDTH)?; // CH\n\
                 {pad}let value = {};\n\
                 {pad}d.expect_event(0, SIMPLE_WIDTH)?; // EE",
                s.decode()
            ),
            Kind::Unsupported => format!("{pad}return Err(ExiError::UnsupportedOption);"),
        }
    }
}

/// A one-element borrow list, so the two arms of a field scan have one type.
fn alloc_one(f: &Field) -> Vec<&Field> {
    vec![f]
}

#[cfg(test)]
mod tests {
    use super::snake;

    #[test]
    fn ordinary_names_split_on_case() {
        assert_eq!(snake("SessionSetupReq"), "session_setup_req");
        assert_eq!(snake("chargeProgress"), "charge_progress");
        assert_eq!(snake("Selected_Service_List"), "selected_service_list");
    }

    /// The names that motivated the acronym table: without it these collapse
    /// into one unreadable run.
    #[test]
    fn acronym_runs_split_where_the_standard_does() {
        assert_eq!(snake("EVCCID"), "evcc_id");
        assert_eq!(snake("EVSEID"), "evse_id");
        assert_eq!(snake("EVRESSSOC"), "ev_ress_soc");
        assert_eq!(snake("DC_EVSEStatus"), "dc_evse_status");
        assert_eq!(snake("EVSEProcessing"), "evse_processing");
        // `eMAID` keeps its leading lowercase word: `e` is not an acronym.
        assert_eq!(snake("eMAID"), "e_maid");
    }

    /// An acronym must not be taken out of the front of a longer word.
    #[test]
    fn a_word_that_starts_with_an_acronym_is_left_alone() {
        assert_eq!(snake("Address"), "address");
        assert_eq!(snake("Identification"), "identification");
        assert_eq!(snake("SOCLimit"), "soc_limit");
        assert_eq!(snake("DHpublickey"), "dh_public_key", "the one name that needs a table");
    }

    /// A longer acronym must win over one nested inside it.
    #[test]
    fn the_longest_acronym_wins() {
        assert_eq!(snake("HMACOutputLength"), "hmac_output_length", "not hm_ac_...");
        assert_eq!(snake("ACDPSystemStatusReq"), "acdp_system_status_req", "not ac_dp_...");
    }

    #[test]
    fn rust_keywords_are_escaped() {
        assert_eq!(snake("Type"), "r#type");
        assert_eq!(snake("Match"), "r#match");
    }
}
