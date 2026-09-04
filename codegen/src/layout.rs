//! The structural view of a content model that code generation works from.
//!
//! # Why not generate from the DFA
//!
//! [`grammar`](crate::grammar) derives a deterministic state machine, and it is
//! verified against the EXI reference implementation. It is the wrong thing to
//! *generate code from*, though: a particle unrolls to one state per permitted
//! occurrence, and these schemas have a `maxOccurs="2048"` (ISO 15118-20's
//! `CommonMessages`), seven at 1024, and sixteen at `unbounded` — which does
//! not unroll at all. Emitting those tables would put hundreds of kilobytes of
//! static data in a crate meant to run on a microcontroller, and for the
//! unbounded ones there is no table to emit.
//!
//! The DFA is regular, so the same information fits in a handful of integers
//! per sequence position. This module computes those, and the generated code
//! loops where the DFA unrolls.
//!
//! # The arithmetic
//!
//! A content model is a flat list of items (an element, or a choice of
//! elements). For position `i` in that list:
//!
//! * the **first set** is the items from `i` onward up to and including the
//!   first required one — everything before it may be skipped;
//! * `EE` is possible exactly when every item from `i` on is optional;
//! * an item's **event code** is the number of productions declared before it,
//!   which is why [`Layout::prod_before`] is a prefix sum rather than an index.
//!
//! A repetition adds one more state shape: after `c` occurrences of item `j`,
//! with `min <= c < max`, the grammar offers that item again at code 0 and then
//! the first set of `j + 1` shifted up by one. That shift is the `base` the
//! generated coders carry.
//!
//! Every number this module computes is cross-checked against the derived DFA
//! by [`Layout::verify`], so a mistake here fails loudly instead of producing a
//! codec that disagrees with the wire.

use crate::grammar::{Builder, Event, bit_width};
use crate::xsd::{ComplexType, Derivation, Particle, Schema, TypeDef, TypeRef};

/// One item of a flattened content model.
///
/// Attributes are items too. EXI puts their productions in the same first-level
/// event-code space as the content, ahead of it and sorted by qualified name,
/// and an optional attribute may be skipped exactly the way an optional element
/// may. Modelling them as leading items makes the first-set arithmetic below
/// handle both without a special case.
#[derive(Debug, Clone)]
pub(crate) enum Item {
    /// An attribute of the element.
    Attribute(Field),
    /// A single child element.
    Element(Field),
    /// The character data of a simple-content type.
    Characters(TypeRef),
    /// An `xs:any` wildcard.
    ///
    /// It occupies event codes exactly like a declared element, so it has to
    /// stay in the list even though nothing can be generated for it: drop it
    /// and every later code in the type shifts down by one.
    Wildcard {
        /// Minimum occurrences.
        min: u32,
        /// Maximum occurrences.
        max: u32,
    },
    /// A choice between child elements.
    Choice {
        /// The alternatives, in event-code order.
        branches: Vec<Branch>,
        /// Minimum occurrences of the choice as a whole.
        min: u32,
        /// Maximum occurrences of the choice as a whole.
        max: u32,
    },
}

/// One alternative of a choice.
#[derive(Debug, Clone)]
pub(crate) enum Branch {
    /// A declared child element.
    Element(Field),
    /// An `xs:any` wildcard branch.
    Wildcard,
}

impl Branch {
    pub(crate) fn field(&self) -> Option<&Field> {
        match self {
            Self::Element(f) => Some(f),
            Self::Wildcard => None,
        }
    }
}

impl Item {
    /// How many event codes this item occupies.
    pub(crate) fn productions(&self) -> u64 {
        match self {
            Self::Attribute(_) | Self::Element(_) | Self::Characters(_) | Self::Wildcard { .. } => {
                1
            }
            Self::Choice { branches, .. } => branches.len() as u64,
        }
    }

    pub(crate) fn min(&self) -> u32 {
        match self {
            Self::Attribute(f) | Self::Element(f) => f.min,
            // Simple content is the element's value; it is always there.
            Self::Characters(_) => 1,
            Self::Wildcard { min, .. } | Self::Choice { min, .. } => *min,
        }
    }

    pub(crate) fn max(&self) -> u32 {
        match self {
            Self::Attribute(f) | Self::Element(f) => f.max,
            Self::Characters(_) => 1,
            Self::Wildcard { max, .. } | Self::Choice { max, .. } => *max,
        }
    }

    /// True when the item may be absent, so the position after it is reachable
    /// without consuming anything.
    pub(crate) fn optional(&self) -> bool {
        self.min() == 0
    }
}

/// One child element of a content model.
#[derive(Debug, Clone)]
pub(crate) struct Field {
    /// The element's name, as it appears in the schema.
    pub(crate) name: crate::xsd::QName,
    /// The element's type.
    pub(crate) type_ref: TypeRef,
    /// Minimum occurrences.
    pub(crate) min: u32,
    /// Maximum occurrences.
    pub(crate) max: u32,
}

/// A content model reduced to what code generation needs.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    /// The items, in schema order.
    pub(crate) items: Vec<Item>,
    /// `prod_before[i]` is the number of event codes items `0..i` occupy.
    /// `prod_before[items.len()]` is the total, which is also the event code
    /// `EE` takes wherever it is allowed.
    pub(crate) prod_before: Vec<u64>,
    /// Event-code width at each position `0..=items.len()`.
    pub(crate) width: Vec<u32>,
    /// Event-code width after an occurrence of item `j` once its `minOccurs`
    /// is satisfied and more are still permitted. `None` for items that cannot
    /// repeat.
    ///
    /// Below `minOccurs` the width is always [`BELOW_MIN_WIDTH`] instead: the
    /// grammar permits nothing but another occurrence, so there is exactly one
    /// production. `WPT_TxRxPackageSpecDataType` has `minOccurs="2"` and is the
    /// reason this distinction exists.
    pub(crate) repeat_width: Vec<Option<u32>>,
}

/// Width of a repetition's event code while its `minOccurs` is unmet.
///
/// Only "one more occurrence" is possible, so it is one declared production
/// plus the non-strict second level.
pub(crate) const BELOW_MIN_WIDTH: u32 = 1;

impl Layout {
    /// Flattens a complex type, resolving extensions.
    pub(crate) fn of(schema: &Schema, ct: &ComplexType) -> Result<Self, Error> {
        let mut items = Vec::new();
        for attribute in collect_attributes(schema, ct, 0)? {
            items.push(Item::Attribute(Field {
                name: attribute.name,
                type_ref: attribute.type_ref,
                min: u32::from(attribute.required),
                max: 1,
            }));
        }
        // Where the content region begins: only content states carry the
        // untyped character data a `mixed` type contributes, never the
        // attribute prefix.
        let content_start = items.len();
        if let Some(simple) = &ct.simple_content {
            // A simple-content type carries a value rather than children, and
            // that value is one production in the same code space.
            items.push(Item::Characters(TypeRef::Named(simple.clone())));
        } else {
            collect(schema, ct, &mut items, 0)?;
        }
        let n = items.len();
        let mut prod_before = Vec::with_capacity(n + 1);
        let mut total = 0u64;
        prod_before.push(0);
        for item in &items {
            total += item.productions();
            prod_before.push(total);
        }

        // `end_ok[i]` and the first-set bound both follow from where the next
        // required item is.
        let mut end_ok = vec![false; n + 1];
        let mut first_set_end = vec![0usize; n + 1];
        for i in 0..=n {
            let mut k = i;
            while k < n && items[k].optional() {
                k += 1;
            }
            // `k` is the first required item, or `n` if there is none.
            first_set_end[i] = if k < n { k + 1 } else { n };
            end_ok[i] = k == n;
        }

        // A `mixed` type adds one untyped character-data production to every
        // *content* state, after `EE`. It costs no code of its own to anything
        // this codec writes, but it widens every event code in the region.
        let mixed_extra = |i: usize| u64::from(ct.mixed && i >= content_start);

        let mut width = Vec::with_capacity(n + 1);
        for i in 0..=n {
            let declared = prod_before[first_set_end[i]] - prod_before[i];
            let productions = declared + u64::from(end_ok[i]) + mixed_extra(i);
            // The `+ 1` is the non-strict second level; see `grammar`.
            width.push(bit_width(productions + 1));
        }

        let mut repeat_width = vec![None; n];
        for (j, item) in items.iter().enumerate() {
            if item.max() > 1 {
                // After an occurrence the grammar offers the item again at the
                // low codes — *every* code it occupies, so a repeated choice
                // re-offers all of its branches — and then the first set of the
                // position after it, shifted up by that many.
                let again = item.productions();
                let follow = prod_before[first_set_end[j + 1]] - prod_before[j + 1];
                let productions = again + follow + u64::from(end_ok[j + 1]) + mixed_extra(j + 1);
                repeat_width[j] = Some(bit_width(productions + 1));
            }
        }

        // `BELOW_MIN_WIDTH` is a constant, and it is only a constant because
        // "another occurrence" is one production. A repeated *choice* with a
        // minimum above one would offer a production per branch and need a
        // wider code, and nothing downstream would notice: the generated
        // encoder would write the branch index at one bit and the decoder would
        // read it back as something else. No V2G schema has one; if one ever
        // does, this stops the generator instead of shipping the mis-encoding.
        for item in &items {
            if item.min() >= 2 && item.productions() > 1 {
                return Err(Error::Unsupported(
                    "a repeated choice with minOccurs >= 2 (see BELOW_MIN_WIDTH)",
                ));
            }
        }

        Ok(Self { items, prod_before, width, repeat_width })
    }

    /// Event code of item `j` when the coder is at position `pos`.
    pub(crate) fn code_of(&self, pos: usize, j: usize) -> u64 {
        self.prod_before[j] - self.prod_before[pos]
    }

    /// Cross-checks every width and code against the derived DFA.
    ///
    /// The DFA is verified against the EXI reference implementation, so
    /// agreement here transitively ties the generated code to it. Positions
    /// inside a repetition are checked through the repeat width; the DFA's
    /// unrolled chain is walked only far enough to reach each distinct shape.
    pub(crate) fn verify(&self, schema: &Schema, ct: &ComplexType) -> Result<(), Error> {
        let grammar = Builder::new(schema).complex_type(ct).map_err(Error::Grammar)?;
        // Walk the DFA along the "every item present exactly once" path and
        // compare widths and codes at each step.
        let mut state = 0usize;
        // `base` is the shift a still-open repetition imposes on later codes.
        let mut base = 0u64;
        let mut previous_repeat: Option<u32> = None;
        for (j, item) in self.items.iter().enumerate() {
            // Walk the path where every item appears exactly `minOccurs` times,
            // or once when it is optional.
            let occurrences = item.min().max(1);
            for c in 0..occurrences {
                let expected = if c > 0 {
                    // Inside this item's own repetition.
                    if c < item.min() { BELOW_MIN_WIDTH } else { self.repeat_width[j].unwrap() }
                } else if base == 0 {
                    self.width[j]
                } else {
                    previous_repeat.unwrap()
                };
                let actual = grammar.states[state].event_width();
                if expected != actual {
                    return Err(Error::WidthMismatch { position: j, expected, actual });
                }
                let code = if c > 0 { 0 } else { base + self.code_of(j, j) };
                // Every alternative of a choice is checked, not just the one
                // the walk follows: the generated encoder addresses them by
                // consecutive codes, so a single misplaced branch would send
                // the wrong element under a plausible-looking event code.
                for (offset, expected_event) in expected_events(item).into_iter().enumerate() {
                    let at = code + offset as u64;
                    let Some(production) = grammar.states[state].productions.get(at as usize)
                    else {
                        return Err(Error::MissingProduction { position: j, code: at });
                    };
                    if !event_matches(&expected_event, &production.event) {
                        return Err(Error::ProductionMismatch { position: j, code: at });
                    }
                }
                let production = &grammar.states[state].productions[code as usize];
                state = production.target;
            }
            // If more occurrences are still permitted we are in the repeat
            // state, which shifts every later code up by one.
            let more_allowed = occurrences < item.max();
            base = u64::from(more_allowed);
            previous_repeat = more_allowed.then(|| self.repeat_width[j].unwrap());
        }
        // At the end only `EE` may remain.
        let last = self.items.len();
        let expected = if base == 0 { self.width[last] } else { previous_repeat.unwrap() };
        let actual = grammar.states[state].event_width();
        if expected != actual {
            return Err(Error::WidthMismatch { position: last, expected, actual });
        }
        Ok(())
    }
}

/// What an item expects to find at its event code, one entry per production it
/// occupies.
enum Expected<'a> {
    Named(&'a crate::xsd::QName),
    Attribute(&'a crate::xsd::QName),
    Characters,
    Wildcard,
}

fn expected_events(item: &Item) -> Vec<Expected<'_>> {
    match item {
        Item::Element(f) => vec![Expected::Named(&f.name)],
        Item::Attribute(f) => vec![Expected::Attribute(&f.name)],
        Item::Characters(_) => vec![Expected::Characters],
        Item::Wildcard { .. } => vec![Expected::Wildcard],
        Item::Choice { branches, .. } => branches
            .iter()
            .map(|b| match b {
                Branch::Element(f) => Expected::Named(&f.name),
                Branch::Wildcard => Expected::Wildcard,
            })
            .collect(),
    }
}

fn event_matches(expected: &Expected<'_>, actual: &Event) -> bool {
    match (expected, actual) {
        (Expected::Named(q), Event::StartElement { name, .. })
        | (Expected::Attribute(q), Event::Attribute { name, .. }) => *q == name,
        (Expected::Characters, Event::Characters { .. }) => true,
        (Expected::Wildcard, Event::Wildcard) => true,
        _ => false,
    }
}

/// Collects declared attributes, including inherited ones, in qualified-name
/// order — which is the order EXI assigns their event codes in.
fn collect_attributes(
    schema: &Schema,
    ct: &ComplexType,
    depth: u32,
) -> Result<Vec<crate::xsd::Attribute>, Error> {
    if depth > 16 {
        return Err(Error::Unsupported("cyclic type derivation"));
    }
    let mut out = Vec::new();
    if let Some(base) = &ct.base
        && let Some(TypeDef::Complex(base_ct)) = schema.types.get(base)
    {
        out.extend(collect_attributes(schema, base_ct, depth + 1)?);
    }
    out.extend(ct.attributes.iter().cloned());
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    Ok(out)
}

/// Flattens a type's content model, prepending its base's when it extends.
fn collect(
    schema: &Schema,
    ct: &ComplexType,
    out: &mut Vec<Item>,
    depth: u32,
) -> Result<(), Error> {
    if depth > 16 {
        return Err(Error::Unsupported("cyclic type derivation"));
    }
    if ct.derivation == Derivation::Extension
        && let Some(base) = &ct.base
        && let Some(TypeDef::Complex(base_ct)) = schema.types.get(base)
    {
        collect(schema, base_ct, out, depth + 1)?;
    }
    if let Some(particle) = &ct.particle {
        flatten(particle, out, depth)?;
    }
    Ok(())
}

fn flatten(particle: &Particle, out: &mut Vec<Item>, depth: u32) -> Result<(), Error> {
    match particle {
        Particle::Element(e) => {
            out.push(Item::Element(Field {
                name: e.name.clone(),
                type_ref: e.type_ref.clone(),
                min: e.min,
                max: e.max,
            }));
            Ok(())
        }
        Particle::Sequence(group) => {
            if group.min != 1 || group.max != 1 {
                // A repeated or optional sequence group would need its own
                // state shape; the V2G schemas contain two optional groups and
                // no repeated ones, so this is refused rather than guessed at.
                return Err(Error::Unsupported("sequence group with occurrence bounds"));
            }
            for item in &group.items {
                flatten(item, out, depth + 1)?;
            }
            Ok(())
        }
        Particle::Choice(group) => {
            let mut branches = Vec::new();
            for item in &group.items {
                match item {
                    Particle::Element(e) => branches.push(Branch::Element(Field {
                        name: e.name.clone(),
                        type_ref: e.type_ref.clone(),
                        min: e.min,
                        max: e.max,
                    })),
                    Particle::Any { .. } => branches.push(Branch::Wildcard),
                    _ => return Err(Error::Unsupported("choice branch that is not an element")),
                }
            }
            // Declared alternatives take the low codes whatever order the
            // schema wrote them in; `ds:TransformType` lists `<any>` before
            // `<element name="XPath">` and EXI still codes `XPath` as zero.
            branches.sort_by_key(|b| matches!(b, Branch::Wildcard));
            out.push(Item::Choice { branches, min: group.min, max: group.max });
            Ok(())
        }
        Particle::All(_) => Err(Error::Unsupported("xs:all")),
        Particle::Any { min, max } => {
            out.push(Item::Wildcard { min: *min, max: *max });
            Ok(())
        }
    }
}

/// Why a content model could not be reduced to a [`Layout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    /// A construct code generation does not model.
    Unsupported(&'static str),
    /// Grammar derivation itself failed.
    Grammar(crate::grammar::Error),
    /// The structural width disagrees with the derived DFA.
    WidthMismatch {
        /// Position in the content model.
        position: usize,
        /// What the layout computed.
        expected: u32,
        /// What the DFA says.
        actual: u32,
    },
    /// The DFA has no production where the layout expects one.
    MissingProduction {
        /// Position in the content model.
        position: usize,
        /// The event code.
        code: u64,
    },
    /// The DFA's production at that code names a different element.
    ProductionMismatch {
        /// Position in the content model.
        position: usize,
        /// The event code.
        code: u64,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported for code generation: {what}"),
            Self::Grammar(e) => write!(f, "grammar: {e}"),
            Self::WidthMismatch { position, expected, actual } => write!(
                f,
                "width at position {position}: layout says {expected}, grammar says {actual}"
            ),
            Self::MissingProduction { position, code } => {
                write!(f, "no production at position {position} code {code}")
            }
            Self::ProductionMismatch { position, code } => {
                write!(f, "production at position {position} code {code} names another element")
            }
        }
    }
}

impl std::error::Error for Error {}
