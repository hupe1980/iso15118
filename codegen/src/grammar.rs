//! Deriving EXI schema-informed grammars from a content model (EXI 1.0 §8.5).
//!
//! # Method
//!
//! A content model is compiled to an NFA with epsilon transitions, then made
//! deterministic by subset construction. XML Schema's Unique Particle
//! Attribution rule guarantees the result is deterministic on element names, so
//! no ambiguity can survive; what the subset construction really buys is
//! correct handling of optional particles, where the "first set" at a position
//! spans several particles ahead.
//!
//! Transitions carry the document order in which they were created, and
//! productions are emitted in that order, because EXI assigns first-level event
//! codes positionally. `EE` always sorts last.
//!
//! # The non-strict adjustment
//!
//! ISO 15118 uses default fidelity options, so `strict` is false. Non-strict
//! grammars gain productions for undeclared content (`SE(*)`, `CH`, `AT(*)`,
//! `ER`). Those live at the **second** event-code level and cost no bits of
//! their own — but their existence adds one to the number of alternatives the
//! first-level code has to distinguish. That is why a state with a single
//! declared production still costs one bit here and would cost zero under
//! strict rules, and it is the single most consequential line in this file:
//!
//! ```text
//! width = ceil(log2(first_level_productions + 1))
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crate::xsd::{
    ComplexType, Derivation, Group, Particle, QName, Schema, TypeDef, TypeRef, UNBOUNDED,
};

/// How far a bounded repetition is unrolled.
///
/// A `maxOccurs="N"` particle becomes a chain of N states, because the grammar
/// has to stop offering the element after the Nth one. Only
/// `maxOccurs="unbounded"` becomes a loop.
///
/// The V2G schemas go up to `maxOccurs="2048"` (ISO 15118-20 price rule
/// stacks), so the cap has to clear that: treating a large bound as unbounded
/// would keep offering the element past its limit and desynchronise from any
/// conforming peer. 4096 leaves headroom and matches EXI's own threshold for
/// coding a bounded integer as an index.
const MAX_UNROLL: u32 = 4096;

/// One thing that can happen at a point in a grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// A declared child element.
    StartElement {
        /// The element's name.
        name: QName,
        /// The element's type.
        type_ref: TypeRef,
        /// Whether `xsi:nil` is permitted.
        nillable: bool,
    },
    /// A declared attribute.
    Attribute {
        /// The attribute's name.
        name: QName,
        /// The attribute's type.
        type_ref: TypeRef,
    },
    /// Character data with a schema type: the value of a simple-content
    /// element.
    Characters {
        /// The type of the value.
        type_ref: TypeRef,
    },
    /// Untyped character data, contributed by a `mixed` content model.
    ///
    /// EXI treats text in mixed content as *undeclared* content that happens to
    /// be permitted, so it is a generic production and it sorts **after** `EE`
    /// — unlike every other production, which sorts before it.
    CharactersGeneric,
    /// An `xs:any` wildcard.
    Wildcard,
    /// End of the element.
    EndElement,
}

/// A first-level production: an event and the state it leads to.
#[derive(Debug, Clone)]
pub(crate) struct Production {
    /// What happens.
    pub(crate) event: Event,
    /// The state this leads to. Meaningless for [`Event::EndElement`].
    pub(crate) target: usize,
}

/// One grammar state.
#[derive(Debug, Clone, Default)]
pub(crate) struct State {
    /// First-level productions, in event-code order.
    pub(crate) productions: Vec<Production>,
}

impl State {
    /// Width in bits of this state's event code.
    ///
    /// The `+ 1` is the non-strict second level; see the module docs.
    pub(crate) fn event_width(&self) -> u32 {
        bit_width(self.productions.len() as u64 + 1)
    }
}

/// The grammar of one complex type: a state machine over its content.
#[derive(Debug, Clone, Default)]
pub(crate) struct Grammar {
    /// States; state 0 is the start (`StartTagContent`).
    pub(crate) states: Vec<State>,
}

/// `ceil(log2(count))` — the EXI width for a choice among `count` alternatives.
pub(crate) fn bit_width(count: u64) -> u32 {
    match count {
        0 | 1 => 0,
        n => u64::BITS - (n - 1).leading_zeros(),
    }
}

// ---------------------------------------------------------------------------
// NFA
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct NfaState {
    /// Labelled transitions: `(document order, event, target)`.
    edges: Vec<(usize, Event, usize)>,
    /// Epsilon transitions.
    epsilon: Vec<usize>,
    /// True for states inside the content model, as opposed to the attribute
    /// prefix. Only content states carry mixed-content character data.
    content: bool,
}

struct Nfa {
    states: Vec<NfaState>,
    order: usize,
    /// Set once attribute productions are done, so that states created after
    /// it belong to the content region.
    in_content: bool,
}

impl Nfa {
    fn new() -> Self {
        Self { states: vec![NfaState::default()], order: 0, in_content: false }
    }

    fn add_state(&mut self) -> usize {
        let content = self.in_content;
        self.states.push(NfaState { content, ..NfaState::default() });
        self.states.len() - 1
    }

    fn edge(&mut self, from: usize, event: Event, to: usize) {
        let order = self.order;
        self.order += 1;
        self.states[from].edges.push((order, event, to));
    }

    fn epsilon(&mut self, from: usize, to: usize) {
        self.states[from].epsilon.push(to);
    }

    /// Every state reachable from `states` through epsilon transitions alone.
    fn closure(&self, states: &BTreeSet<usize>) -> BTreeSet<usize> {
        let mut out = states.clone();
        let mut stack: Vec<usize> = states.iter().copied().collect();
        while let Some(s) = stack.pop() {
            for &next in &self.states[s].epsilon {
                if out.insert(next) {
                    stack.push(next);
                }
            }
        }
        out
    }
}

/// Builds the grammar for a complex type, resolving its base types.
pub(crate) struct Builder<'a> {
    schema: &'a Schema,
}

impl<'a> Builder<'a> {
    pub(crate) fn new(schema: &'a Schema) -> Self {
        Self { schema }
    }

    /// Builds the grammar of a complex type.
    pub(crate) fn complex_type(&self, ct: &ComplexType) -> Result<Grammar, Error> {
        let mut nfa = Nfa::new();
        let entry = 0;

        // Attributes come first in `StartTagContent`, sorted by qualified name,
        // and each optional one may be skipped.
        let attributes = self.collect_attributes(ct, 0)?;
        let mut cursor = entry;
        for attribute in &attributes {
            let next = nfa.add_state();
            nfa.edge(
                cursor,
                Event::Attribute {
                    name: attribute.name.clone(),
                    type_ref: attribute.type_ref.clone(),
                },
                next,
            );
            if !attribute.required {
                nfa.epsilon(cursor, next);
            }
            cursor = next;
        }

        // Everything from here on is content rather than attributes.
        nfa.in_content = true;
        nfa.states[cursor].content = true;

        // Then the content model.
        let content_exit = if let Some(simple) = &ct.simple_content {
            let next = nfa.add_state();
            nfa.edge(cursor, Event::Characters { type_ref: TypeRef::Named(simple.clone()) }, next);
            next
        } else {
            let particles = self.effective_particles(ct, 0)?;
            let mut cur = cursor;
            for particle in &particles {
                cur = self.build_particle(&mut nfa, particle, cur)?;
            }
            cur
        };

        Ok(Self::determinise(&nfa, entry, content_exit, ct.mixed))
    }

    /// Builds the grammar of an element whose type is simple: a single typed
    /// character-data event, then the end of the element.
    #[allow(clippy::unused_self, reason = "mirrors complex_type so callers can treat them alike")]
    pub(crate) fn simple_type(&self, type_ref: &TypeRef) -> Grammar {
        let mut nfa = Nfa::new();
        let exit = nfa.add_state();
        nfa.edge(0, Event::Characters { type_ref: type_ref.clone() }, exit);
        Self::determinise(&nfa, 0, exit, false)
    }

    /// Flattens a type's content model, prepending its base's when it extends.
    fn effective_particles(&self, ct: &ComplexType, depth: u32) -> Result<Vec<Particle>, Error> {
        if depth > 16 {
            return Err(Error::CyclicDerivation);
        }
        let mut out = Vec::new();
        // An extension's content is the base's content followed by its own; a
        // restriction's content replaces the base's entirely.
        if ct.derivation == Derivation::Extension
            && let Some(base) = &ct.base
            && let Some(TypeDef::Complex(base_ct)) = self.schema.types.get(base)
        {
            out.extend(self.effective_particles(base_ct, depth + 1)?);
        }
        if let Some(p) = &ct.particle {
            out.push(p.clone());
        }
        Ok(out)
    }

    /// Collects declared attributes, including inherited ones, in qname order.
    fn collect_attributes(
        &self,
        ct: &ComplexType,
        depth: u32,
    ) -> Result<Vec<crate::xsd::Attribute>, Error> {
        if depth > 16 {
            return Err(Error::CyclicDerivation);
        }
        let mut out = Vec::new();
        if let Some(base) = &ct.base
            && let Some(TypeDef::Complex(base_ct)) = self.schema.types.get(base)
        {
            out.extend(self.collect_attributes(base_ct, depth + 1)?);
        }
        out.extend(ct.attributes.iter().cloned());
        // EXI orders attribute productions by qualified name, not by the order
        // they appear in the schema.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out.dedup_by(|a, b| a.name == b.name);
        Ok(out)
    }

    /// Compiles one particle, returning the state the content continues from.
    fn build_particle(
        &self,
        nfa: &mut Nfa,
        particle: &Particle,
        entry: usize,
    ) -> Result<usize, Error> {
        let (min, max) = (particle.min(), particle.max());

        match particle {
            Particle::Element(e) => {
                let event = Event::StartElement {
                    name: e.name.clone(),
                    type_ref: e.type_ref.clone(),
                    nillable: e.nillable,
                };
                Ok(Self::repeat(nfa, entry, min, max, |nfa, from| {
                    let to = nfa.add_state();
                    nfa.edge(from, event.clone(), to);
                    to
                }))
            }
            Particle::Any { .. } => Ok(Self::repeat(nfa, entry, min, max, |nfa, from| {
                let to = nfa.add_state();
                nfa.edge(from, Event::Wildcard, to);
                to
            })),
            Particle::Sequence(group) => self.build_group_repeated(nfa, group, entry, true),
            Particle::Choice(group) => self.build_group_repeated(nfa, group, entry, false),
            Particle::All(group) => {
                // `xs:all` members may appear in any order. EXI models this as
                // a choice repeated once per member, with each member optional.
                // The V2G schemas do not use it; refuse rather than approximate.
                if group.items.is_empty() { Ok(entry) } else { Err(Error::Unsupported("xs:all")) }
            }
        }
    }

    fn build_group_repeated(
        &self,
        nfa: &mut Nfa,
        group: &Group,
        entry: usize,
        sequence: bool,
    ) -> Result<usize, Error> {
        // Groups with occurrence bounds of their own are rare; unroll them the
        // same way an element repetition is unrolled.
        let (min, max) = (group.min, group.max);
        let items = group.items.clone();
        let mut error = None;
        let exit = Self::repeat(nfa, entry, min, max, |nfa, from| {
            if sequence {
                let mut cur = from;
                for item in &items {
                    match self.build_particle(nfa, item, cur) {
                        Ok(next) => cur = next,
                        Err(e) => {
                            error.get_or_insert(e);
                            return cur;
                        }
                    }
                }
                cur
            } else {
                let to = nfa.add_state();
                for item in &items {
                    match self.build_particle(nfa, item, from) {
                        Ok(branch_exit) => nfa.epsilon(branch_exit, to),
                        Err(e) => {
                            error.get_or_insert(e);
                        }
                    }
                }
                to
            }
        });
        match error {
            Some(e) => Err(e),
            None => Ok(exit),
        }
    }

    /// Applies occurrence bounds around a body builder.
    fn repeat(
        nfa: &mut Nfa,
        entry: usize,
        min: u32,
        max: u32,
        mut body: impl FnMut(&mut Nfa, usize) -> usize,
    ) -> usize {
        let exit = nfa.add_state();

        // The mandatory occurrences, in a chain.
        let mut cur = entry;
        let required = min.min(MAX_UNROLL);
        for _ in 0..required {
            cur = body(nfa, cur);
        }

        if max == UNBOUNDED || max > MAX_UNROLL {
            // A loop rather than a chain: the grammar state after one
            // occurrence is the same one that accepts the next.
            let loop_entry = cur;
            let loop_exit = body(nfa, loop_entry);
            nfa.epsilon(loop_exit, loop_entry);
            nfa.epsilon(loop_entry, exit);
        } else {
            // The optional occurrences, each able to stop early.
            nfa.epsilon(cur, exit);
            for _ in required..max {
                cur = body(nfa, cur);
                nfa.epsilon(cur, exit);
            }
        }
        exit
    }

    /// Subset construction, then ordering of productions.
    fn determinise(nfa: &Nfa, entry: usize, accept: usize, mixed: bool) -> Grammar {
        let mut grammar = Grammar::default();
        let mut index: BTreeMap<BTreeSet<usize>, usize> = BTreeMap::new();
        let start = nfa.closure(&BTreeSet::from([entry]));
        let mut queue = vec![start.clone()];
        index.insert(start, 0);
        grammar.states.push(State::default());

        let mut head = 0;
        while head < queue.len() {
            let set = queue[head].clone();
            head += 1;
            let id = index[&set];

            // Gather every labelled transition leaving the set, keeping the
            // document order EXI assigns event codes by.
            let mut edges: Vec<(usize, Event, BTreeSet<usize>)> = Vec::new();
            for &state in &set {
                for (order, event, target) in &nfa.states[state].edges {
                    match edges.iter_mut().find(|(_, e, _)| e == event) {
                        // The same event from two NFA states merges into one
                        // production whose target is the union.
                        Some((existing_order, _, targets)) => {
                            *existing_order = (*existing_order).min(*order);
                            targets.insert(*target);
                        }
                        None => {
                            edges.push((*order, event.clone(), BTreeSet::from([*target])));
                        }
                    }
                }
            }
            // Declared productions come first, in content order; the `xs:any`
            // wildcard follows them however early it appeared in the schema.
            // `TransformType` declares `<any>` before `<element name="XPath">`,
            // yet EXI codes `XPath` as 0 and the wildcard as 1.
            edges.sort_by_key(|(order, event, _)| (matches!(event, Event::Wildcard), *order));

            let mut productions = Vec::new();
            for (_, event, targets) in edges {
                let closed = nfa.closure(&targets);
                let target = if let Some(&existing) = index.get(&closed) {
                    existing
                } else {
                    let new_id = grammar.states.len();
                    grammar.states.push(State::default());
                    index.insert(closed.clone(), new_id);
                    queue.push(closed);
                    new_id
                };
                productions.push(Production { event, target });
            }

            // `EE` is the last *declared* production of a state.
            if set.contains(&accept) {
                productions.push(Production { event: Event::EndElement, target: usize::MAX });
            }
            // Mixed content adds untyped character data after everything else,
            // including after `EE`. Only the content region carries it: the
            // attribute prefix of a mixed type does not.
            if mixed && set.iter().any(|&s| nfa.states[s].content) {
                productions.push(Production { event: Event::CharactersGeneric, target: id });
            }
            grammar.states[id].productions = productions;
        }

        grammar
    }
}

/// Failures while deriving a grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// A construct outside the supported subset.
    Unsupported(&'static str),
    /// Type derivation formed a cycle.
    CyclicDerivation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported content model construct: {what}"),
            Self::CyclicDerivation => f.write_str("cyclic type derivation"),
        }
    }
}

impl std::error::Error for Error {}
