//! Generates a schema-valid XML instance for every global element.
//!
//! These exist to be fed to an independent EXI implementation. That produces
//! bytes for a message this crate has never seen, which the generated codec
//! must then decode and re-encode byte for byte — see
//! `scripts/verify-messages.sh`.
//!
//! Golden vectors cover a handful of messages. This covers all of them, and
//! covers the parts of each that no captured trace happens to exercise.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::layout::{Branch, Field, Item, Layout};
use crate::xsd::{QName, Schema, SimpleType, TypeDef, TypeRef, XSD_NS};

/// Builds instances of a schema set's global elements.
pub(crate) struct Sampler<'a> {
    schema: &'a Schema,
    /// When non-empty, only elements in these namespaces are sampled.
    namespaces: std::collections::BTreeSet<String>,
    /// Prefix assigned to each namespace in the emitted documents.
    prefixes: BTreeMap<String, String>,
    /// The complex types the emitter can express in Rust.
    ///
    /// Anything else is left out of the samples: the generated codec refuses
    /// undeclared content by design, so an instance containing it would test
    /// nothing but that refusal.
    generatable: std::collections::BTreeSet<QName>,
}

impl<'a> Sampler<'a> {
    pub(crate) fn new(
        schema: &'a Schema,
        namespaces: std::collections::BTreeSet<String>,
        generatable: std::collections::BTreeSet<QName>,
    ) -> Self {
        let mut seen: Vec<String> = Vec::new();
        for element in &schema.global_elements {
            if !seen.contains(&element.name.namespace) {
                seen.push(element.name.namespace.clone());
            }
        }
        for name in schema.types.keys() {
            if !seen.contains(&name.namespace) {
                seen.push(name.namespace.clone());
            }
        }
        let prefixes = seen.into_iter().enumerate().map(|(i, ns)| (ns, format!("n{i}"))).collect();
        Self { schema, namespaces, prefixes, generatable }
    }

    /// Renders one instance per global element, keyed by local name.
    pub(crate) fn render_all(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for element in &self.schema.global_elements {
            if !self.namespaces.is_empty() && !self.namespaces.contains(&element.name.namespace) {
                continue;
            }
            // An abstract head never appears in an instance.
            let Some(TypeDef::Complex(ct)) = self.schema.resolve(&element.type_ref) else {
                continue;
            };
            if ct.is_abstract {
                continue;
            }
            let mut body = String::new();
            if self.element(&mut body, &element.name, &element.type_ref, 0).is_err() {
                continue;
            }
            let mut declarations = String::new();
            for (ns, prefix) in self.prefixes.iter().filter(|(ns, _)| !ns.is_empty()) {
                let _ = write!(declarations, " xmlns:{prefix}=\"{ns}\"");
            }
            // The namespace declarations go on the root, which `element` wrote
            // without them; splice them in after the root's name.
            let insert = body.find('>').unwrap_or(0);
            let mut document = body.clone();
            document.insert_str(insert, &declarations);
            out.insert(element.name.local.clone(), document);
        }
        out
    }

    fn qualified(&self, name: &QName) -> String {
        if name.namespace.is_empty() {
            name.local.clone()
        } else {
            format!("{}:{}", self.prefixes[&name.namespace], name.local)
        }
    }

    /// Writes one element and everything under it.
    fn element(
        &self,
        out: &mut String,
        name: &QName,
        type_ref: &TypeRef,
        depth: u32,
    ) -> Result<(), ()> {
        if depth > 12 {
            return Err(());
        }
        let tag = self.qualified(name);
        if let Some(TypeDef::Complex(ct)) = self.schema.resolve(type_ref) {
            if let TypeRef::Named(q) = type_ref
                && !self.generatable.contains(q)
            {
                return Err(());
            }
            let Ok(layout) = Layout::of(self.schema, ct) else { return Err(()) };
            let mut attributes = String::new();
            for item in &layout.items {
                if let Item::Attribute(f) = item
                    && f.min > 0
                {
                    let value = self.value_of(&f.type_ref)?;
                    let _ = write!(attributes, " {}=\"{value}\"", self.qualified(&f.name));
                }
            }
            let _ = write!(out, "<{tag}{attributes}>");
            for item in &layout.items {
                match item {
                    Item::Attribute(_) => {}
                    Item::Characters(t) => {
                        let _ = write!(out, "{}", self.value_of(t)?);
                    }
                    Item::Element(f) => self.occurrences(out, f, depth)?,
                    // A wildcard is never sampled: the crate's codecs refuse
                    // undeclared content, which is what the samples must show.
                    Item::Wildcard { min, .. } if *min == 0 => {}
                    Item::Wildcard { .. } => return Err(()),
                    Item::Choice { branches, min, .. } => {
                        if *min > 0 {
                            // One branch is enough to exercise the choice;
                            // take the first that renders.
                            let mut done = false;
                            for b in branches.iter().filter_map(Branch::field) {
                                let mut attempt = String::new();
                                if self.occurrences(&mut attempt, b, depth).is_ok() {
                                    out.push_str(&attempt);
                                    done = true;
                                    break;
                                }
                            }
                            if !done {
                                return Err(());
                            }
                        }
                    }
                }
            }
            let _ = write!(out, "</{tag}>");
            Ok(())
        } else {
            let value = self.value_of(type_ref)?;
            let _ = write!(out, "<{tag}>{value}</{tag}>");
            Ok(())
        }
    }

    /// Writes an element `minOccurs` times, or once when it is optional, so
    /// that optional slots are exercised too.
    ///
    /// An optional child that cannot be rendered is simply left out — that is
    /// how `ds:Signature`, whose content model has wildcards, stays out of the
    /// samples without taking every message that has a header with it.
    fn occurrences(&self, out: &mut String, f: &Field, depth: u32) -> Result<(), ()> {
        let count = f.min.max(1).min(f.max.max(1));
        let mut attempt = String::new();
        for _ in 0..count {
            if self.element(&mut attempt, &f.name, &f.type_ref, depth + 1).is_err() {
                // Required children must render; optional ones may be dropped.
                return if f.min == 0 { Ok(()) } else { Err(()) };
            }
        }
        out.push_str(&attempt);
        Ok(())
    }

    /// A lexical value that satisfies a simple type's facets.
    fn value_of(&self, type_ref: &TypeRef) -> Result<String, ()> {
        let mut max_length: Option<usize> = None;
        let mut min_length: Option<usize> = None;
        let mut min_inclusive: Option<i128> = None;
        let mut max_inclusive: Option<i128> = None;
        let mut current = type_ref.clone();

        for _ in 0..16 {
            match self.schema.resolve(&current) {
                Some(TypeDef::Simple(st)) => {
                    if !st.enumeration.is_empty() {
                        return Ok(st.enumeration[0].clone());
                    }
                    absorb(
                        st,
                        &mut max_length,
                        &mut min_length,
                        &mut min_inclusive,
                        &mut max_inclusive,
                    );
                    let Some(base) = st.base.clone() else { return Err(()) };
                    current = TypeRef::Named(base);
                }
                _ => break,
            }
        }

        let TypeRef::Named(q) = &current else { return Err(()) };
        if q.namespace != XSD_NS {
            return Err(());
        }
        Ok(literal(&q.local, max_length, min_length, min_inclusive, max_inclusive))
    }
}

fn absorb(
    st: &SimpleType,
    max_length: &mut Option<usize>,
    min_length: &mut Option<usize>,
    min_inclusive: &mut Option<i128>,
    max_inclusive: &mut Option<i128>,
) {
    if let Some(v) = st.max_length {
        *max_length = Some(max_length.map_or(v, |c: usize| c.min(v)));
    }
    if let Some(v) = st.min_length {
        *min_length = Some(min_length.map_or(v, |c: usize| c.max(v)));
    }
    if let Some(v) = st.min_inclusive {
        *min_inclusive = Some(min_inclusive.map_or(v, |c: i128| c.max(v)));
    }
    if let Some(v) = st.max_inclusive {
        *max_inclusive = Some(max_inclusive.map_or(v, |c: i128| c.min(v)));
    }
}

/// A lexical form for a built-in type that respects the accumulated facets.
fn literal(
    local: &str,
    max_length: Option<usize>,
    min_length: Option<usize>,
    min_inclusive: Option<i128>,
    max_inclusive: Option<i128>,
) -> String {
    let clamp = |preferred: i128| -> i128 {
        let mut v = preferred;
        if let Some(lo) = min_inclusive {
            v = v.max(lo);
        }
        if let Some(hi) = max_inclusive {
            v = v.min(hi);
        }
        v
    };

    match local {
        "boolean" => "true".into(),
        "hexBinary" => {
            // Two hex digits per byte; honour both length facets.
            let bytes = min_length.unwrap_or(1).max(1).min(max_length.unwrap_or(8));
            "A5".repeat(bytes.max(1))
        }
        "base64Binary" => {
            // The facets on `base64Binary` count *bytes*, not base64
            // characters, and several of them are exact: `genChallengeType` is
            // sixteen bytes and `dhPublicKeyType` is a hundred and thirty-three.
            // A three-byte stand-in for all of them produced samples the schema
            // forbids — which the codec only started rejecting once it learned
            // to enforce a minimum.
            let bytes = min_length.unwrap_or(3).clamp(1, max_length.unwrap_or(usize::MAX).max(1));
            base64(&vec![0xA5; bytes])
        }
        "decimal" => "1.5".into(),
        "float" | "double" => "1.5".into(),
        "dateTime" => "2024-09-04T13:25:43Z".into(),
        "date" => "2024-09-04".into(),
        "time" => "13:25:43".into(),
        "anyURI" => {
            let text = "urn:example:sample";
            truncate(text, max_length, min_length)
        }
        "byte" | "short" | "int" | "long" | "integer" | "unsignedByte" | "unsignedShort"
        | "unsignedInt" | "unsignedLong" | "nonNegativeInteger" | "positiveInteger" => {
            clamp(i128::from(local == "positiveInteger")).to_string()
        }
        _ => truncate("Sample", max_length, min_length),
    }
}

fn truncate(text: &str, max_length: Option<usize>, min_length: Option<usize>) -> String {
    let mut value: String = match max_length {
        Some(max) => text.chars().take(max).collect(),
        None => text.to_owned(),
    };
    if let Some(min) = min_length {
        while value.chars().count() < min {
            value.push('x');
        }
        if let Some(max) = max_length
            && value.chars().count() > max
        {
            value = value.chars().take(max).collect();
        }
    }
    value
}

/// Standard base64 with padding, for `base64Binary` sample values.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_matches_rfc_4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    /// The facets count bytes, so the sample has to decode back to that many.
    #[test]
    fn a_sixteen_byte_challenge_encodes_to_a_full_block() {
        assert_eq!(base64(&[0xA5; 16]).len(), 24, "ceil(16/3)*4");
    }
}
