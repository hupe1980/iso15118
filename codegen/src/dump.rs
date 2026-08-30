//! A canonical, flat rendering of a derived grammar.
//!
//! The point of this format is that an *independent* EXI implementation can be
//! made to emit the same thing, so the two can be diffed state by state and
//! production by production. `tools/compare_grammars.py` does exactly that
//! against the EXI reference implementation; see `scripts/verify-grammars.sh`.
//!
//! Grammars are flattened: every `(type, state)` pair becomes one node with a
//! global id, so the output is a plain graph rather than a set of nested state
//! machines. That is the shape the reference implementation exposes, and
//! matching it removes a whole class of "the structures differ but only in how
//! they are grouped" false positives.
//!
//! ```text
//! #element {ns}LocalName G12
//! G12 events=2
//!   0 SE {ns}Child body=G13 -> G14
//!   1 EE
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::grammar::{Builder, Event, Grammar};
use crate::xsd::{QName, Schema, TypeDef, TypeRef};

/// `{namespace}local`, always with the braces so that an unqualified name
/// renders as `{}local` — the form the reference implementation uses.
fn canonical(q: &QName) -> String {
    format!("{{{}}}{}", q.namespace, q.local)
}

/// Flattens every grammar reachable from the schema's global elements.
pub(crate) struct Flattener<'a> {
    schema: &'a Schema,
    builder: Builder<'a>,
    /// Node id of each `(type key, state index)` pair.
    nodes: BTreeMap<(String, usize), usize>,
    /// Node id to its productions, once rendered.
    rendered: BTreeMap<usize, String>,
    /// Grammars already expanded, by type key.
    grammars: BTreeMap<String, Grammar>,
    next_id: usize,
}

impl<'a> Flattener<'a> {
    pub(crate) fn new(schema: &'a Schema) -> Self {
        Self {
            schema,
            builder: Builder::new(schema),
            nodes: BTreeMap::new(),
            rendered: BTreeMap::new(),
            grammars: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// A stable key for a type reference. Anonymous types are keyed by their
    /// slot, which is stable for a given schema load.
    fn key(type_ref: &TypeRef) -> String {
        match type_ref {
            TypeRef::Named(q) => q.to_string(),
            TypeRef::Anonymous(i) => format!("#anon{i}"),
        }
    }

    fn grammar_for(&mut self, type_ref: &TypeRef) -> &Grammar {
        let key = Self::key(type_ref);
        if !self.grammars.contains_key(&key) {
            let grammar = match self.schema.resolve(type_ref) {
                Some(TypeDef::Complex(ct)) => self.builder.complex_type(ct).unwrap_or_default(),
                // A simple or built-in type: one typed character-data event.
                _ => self.builder.simple_type(type_ref),
            };
            self.grammars.insert(key.clone(), grammar);
        }
        &self.grammars[&key]
    }

    fn node_id(&mut self, key: &str, state: usize) -> usize {
        if let Some(&id) = self.nodes.get(&(key.to_owned(), state)) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert((key.to_owned(), state), id);
        id
    }

    /// Renders every grammar reachable from the global elements.
    pub(crate) fn render(&mut self) -> String {
        let mut out = String::new();
        let elements: Vec<(QName, TypeRef)> = self
            .schema
            .global_elements
            .iter()
            .map(|e| (e.name.clone(), e.type_ref.clone()))
            .collect();

        let mut index = String::new();
        let mut queue: Vec<TypeRef> = Vec::new();
        for (name, type_ref) in &elements {
            let key = Self::key(type_ref);
            self.grammar_for(type_ref);
            let start = self.node_id(&key, 0);
            let _ = writeln!(index, "#element {} G{start}", canonical(name));
            queue.push(type_ref.clone());
        }

        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        while let Some(type_ref) = queue.pop() {
            let key = Self::key(&type_ref);
            if !seen.insert(key.clone()) {
                continue;
            }
            let grammar = self.grammar_for(&type_ref).clone();
            for (state_index, state) in grammar.states.iter().enumerate() {
                let id = self.node_id(&key, state_index);
                let mut body = String::new();
                let _ = writeln!(body, "G{id} events={}", state.productions.len());
                for (code, production) in state.productions.iter().enumerate() {
                    let _ = write!(body, "  {code} ");
                    match &production.event {
                        Event::StartElement { name, type_ref: child, .. } => {
                            let child_key = Self::key(child);
                            self.grammar_for(child);
                            let child_start = self.node_id(&child_key, 0);
                            queue.push(child.clone());
                            let next = self.node_id(&key, production.target);
                            let _ = writeln!(
                                body,
                                "SE {} body=G{child_start} -> G{next}",
                                canonical(name)
                            );
                        }
                        Event::Attribute { name, .. } => {
                            let next = self.node_id(&key, production.target);
                            let _ = writeln!(body, "AT {} -> G{next}", canonical(name));
                        }
                        Event::Characters { .. } => {
                            let next = self.node_id(&key, production.target);
                            let _ = writeln!(body, "CH -> G{next}");
                        }
                        Event::CharactersGeneric => {
                            let next = self.node_id(&key, production.target);
                            let _ = writeln!(body, "CHGEN -> G{next}");
                        }
                        Event::Wildcard => {
                            let next = self.node_id(&key, production.target);
                            let _ = writeln!(body, "SEGEN -> G{next}");
                        }
                        Event::EndElement => {
                            let _ = writeln!(body, "EE");
                        }
                    }
                }
                self.rendered.insert(id, body);
            }
        }

        out.push_str(&index);
        for body in self.rendered.values() {
            out.push_str(body);
        }
        out
    }
}
