//! An XML Schema model covering the constructs the V2G schemas actually use.
//!
//! This is deliberately not a general XSD implementation. The V2G schemas are
//! machine-generated, restricted and frozen, so the subset below is complete
//! *for them* and anything outside it is reported as an error rather than
//! silently mishandled — a grammar that is quietly wrong produces a stream that
//! looks plausible and decodes to nonsense.
//!
//! Supported: global and local elements, `sequence`, `choice`, `all`,
//! `complexContent` extension and restriction, `simpleContent`, attributes,
//! simple-type restrictions with enumeration / range / length facets, `list`,
//! `union` (as its first member), and `any`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use roxmltree::Node;

/// The W3C XML Signature namespace.
///
/// ISO 15118 imports it for `ds:Signature` and treats it specially when
/// encoding the signed `SignedInfo` fragment; see ISO 15118-2 Annex J.
pub(crate) const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// The XML Schema namespace.
pub(crate) const XSD_NS: &str = "http://www.w3.org/2001/XMLSchema";

/// A qualified name, ordered the way EXI orders them.
///
/// The [`Ord`] impl is load-bearing: EXI sorts qualified names **by local name
/// first, then by namespace**, and event codes are positions in that order.
/// Sorting by namespace first — the intuitive choice — yields a completely
/// different, silently wrong wire format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) struct QName {
    /// Local name. Compared first.
    pub(crate) local: String,
    /// Namespace URI. Compared second.
    pub(crate) namespace: String,
}

impl QName {
    pub(crate) fn new(namespace: impl Into<String>, local: impl Into<String>) -> Self {
        Self { namespace: namespace.into(), local: local.into() }
    }
}

impl fmt::Display for QName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.namespace.is_empty() {
            f.write_str(&self.local)
        } else {
            write!(f, "{{{}}}{}", self.namespace, self.local)
        }
    }
}

/// `maxOccurs="unbounded"`.
pub(crate) const UNBOUNDED: u32 = u32::MAX;

/// A content-model particle.
#[derive(Debug, Clone)]
pub(crate) enum Particle {
    /// An element declaration or reference.
    Element(ElementParticle),
    /// An ordered sequence of particles.
    Sequence(Group),
    /// A choice between particles.
    Choice(Group),
    /// An `xs:all` group. EXI treats it as a sequence of optional particles.
    All(Group),
    /// A wildcard.
    Any {
        /// Minimum occurrences.
        min: u32,
        /// Maximum occurrences.
        max: u32,
    },
}

impl Particle {
    pub(crate) fn min(&self) -> u32 {
        match self {
            Self::Element(e) => e.min,
            Self::Sequence(g) | Self::Choice(g) | Self::All(g) => g.min,
            Self::Any { min, .. } => *min,
        }
    }

    pub(crate) fn max(&self) -> u32 {
        match self {
            Self::Element(e) => e.max,
            Self::Sequence(g) | Self::Choice(g) | Self::All(g) => g.max,
            Self::Any { max, .. } => *max,
        }
    }
}

/// A group particle with its own occurrence bounds.
#[derive(Debug, Clone)]
pub(crate) struct Group {
    /// The member particles.
    pub(crate) items: Vec<Particle>,
    /// Minimum occurrences.
    pub(crate) min: u32,
    /// Maximum occurrences.
    pub(crate) max: u32,
}

/// A local or referenced element inside a content model.
#[derive(Debug, Clone)]
pub(crate) struct ElementParticle {
    /// The element's qualified name.
    pub(crate) name: QName,
    /// The element's type.
    pub(crate) type_ref: TypeRef,
    /// Minimum occurrences.
    pub(crate) min: u32,
    /// Maximum occurrences.
    pub(crate) max: u32,
    /// Whether `xsi:nil` is permitted.
    pub(crate) nillable: bool,
}

/// A reference to a named type, or an inline anonymous one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypeRef {
    /// A named global type, or a built-in.
    Named(QName),
    /// An anonymous type declared inline; the payload is its index in
    /// [`Schema::anonymous`].
    Anonymous(usize),
}

/// An attribute declaration.
#[derive(Debug, Clone)]
pub(crate) struct Attribute {
    /// The attribute's qualified name.
    pub(crate) name: QName,
    /// Its type.
    pub(crate) type_ref: TypeRef,
    /// Whether it must be present.
    pub(crate) required: bool,
}

/// How a complex type derives from its base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Derivation {
    /// No base type.
    #[default]
    None,
    /// `complexContent`/`simpleContent` extension: base content, then ours.
    Extension,
    /// `complexContent` restriction: our content replaces the base's.
    Restriction,
}

/// A complex type definition.
#[derive(Debug, Clone, Default)]
pub(crate) struct ComplexType {
    /// Name, absent for anonymous types.
    pub(crate) name: Option<QName>,
    /// Base type, when derived.
    pub(crate) base: Option<QName>,
    /// How it derives.
    pub(crate) derivation: Derivation,
    /// The content model.
    pub(crate) particle: Option<Particle>,
    /// Declared attributes.
    pub(crate) attributes: Vec<Attribute>,
    /// `mixed="true"`.
    pub(crate) mixed: bool,
    /// `abstract="true"`; such a type is never instantiated directly.
    #[allow(dead_code, reason = "part of the schema model; EXI ignores abstractness")]
    pub(crate) is_abstract: bool,
    /// Set when the type has simple content: the base simple type carrying the
    /// character data.
    pub(crate) simple_content: Option<QName>,
}

/// A simple type definition, reduced to the facets EXI cares about.
#[derive(Debug, Clone, Default)]
pub(crate) struct SimpleType {
    /// Name, absent for anonymous types.
    pub(crate) name: Option<QName>,
    /// The type it restricts, or the built-in it bottoms out at.
    pub(crate) base: Option<QName>,
    /// `xs:enumeration` values, in schema document order — which is the order
    /// EXI assigns enumeration indices in, *not* lexicographic order.
    pub(crate) enumeration: Vec<String>,
    /// `minInclusive` / `minExclusive`, normalised to inclusive.
    pub(crate) min_inclusive: Option<i128>,
    /// `maxInclusive` / `maxExclusive`, normalised to inclusive.
    pub(crate) max_inclusive: Option<i128>,
    /// `maxLength`, or `length` when fixed.
    pub(crate) max_length: Option<usize>,
    /// `minLength`, or `length` when fixed.
    pub(crate) min_length: Option<usize>,
    /// For `xs:list`, the item type.
    pub(crate) list_item: Option<QName>,
}

/// A type definition of either kind.
#[derive(Debug, Clone)]
pub(crate) enum TypeDef {
    /// A simple type.
    Simple(SimpleType),
    /// A complex type.
    Complex(ComplexType),
}

/// A global element declaration.
#[derive(Debug, Clone)]
pub(crate) struct GlobalElement {
    /// Its qualified name.
    pub(crate) name: QName,
    /// Its type.
    pub(crate) type_ref: TypeRef,
    /// Whether `xsi:nil` is permitted. Recorded for completeness; the
    /// grammar does not branch on it, because non-strict fidelity already
    /// admits `xsi:nil` through a second-level production.
    #[allow(dead_code, reason = "part of the schema model, not consulted by the grammar")]
    pub(crate) nillable: bool,
}

/// A loaded schema set: an entry schema plus everything it imports.
#[derive(Debug, Default)]
pub(crate) struct Schema {
    /// Global elements, sorted into EXI order by [`Schema::finish`].
    pub(crate) global_elements: Vec<GlobalElement>,
    /// Named global types.
    pub(crate) types: BTreeMap<QName, TypeDef>,
    /// Anonymous inline types, referenced by index.
    pub(crate) anonymous: Vec<TypeDef>,
    /// Files read, sorted.
    pub(crate) sources: Vec<PathBuf>,
    /// Global attribute declarations, by name.
    pub(crate) global_attributes: BTreeMap<QName, TypeRef>,
    /// Every global element's name and declared type, collected before any
    /// content model is parsed so that `element ref` always resolves.
    declarations: BTreeMap<QName, Declaration>,
    /// Substitution group head to its members, each sorted into EXI order.
    substitution_groups: BTreeMap<QName, Vec<QName>>,
}

impl Schema {
    /// Every element qname declared anywhere in the schema set — global and
    /// local — sorted the way EXI orders them: by local name, then namespace.
    ///
    /// This is the table the *fragment* grammar indexes (EXI 1.0 §8.5.2), and
    /// it is a different, larger list than [`Schema::global_elements`], which
    /// the document grammar indexes. Plug & Charge signatures are computed over
    /// fragments, so getting this list wrong makes every signature this crate
    /// produces unverifiable by anyone else.
    pub(crate) fn declared_element_qnames(&self) -> Vec<QName> {
        // Every qname counts toward the table, ambiguous or not: the fragment
        // codes are positions in it, so leaving one out shifts all the rest.
        // `QName` already orders by local name then namespace — EXI's order.
        self.walk_declarations().into_keys().collect()
    }

    /// Every declared element qname with the type it was declared with, where
    /// that is unambiguous.
    ///
    /// XML Schema allows one local name to be declared with different types in
    /// different content models. EXI evaluates such an element under the
    /// relaxed *element fragment* grammar (§8.5.3), which this crate does not
    /// implement — so the qname keeps its place in the table but gets no Rust
    /// binding, rather than being bound to whichever declaration was seen last.
    pub(crate) fn declared_elements(&self) -> BTreeMap<QName, TypeRef> {
        self.walk_declarations().into_iter().filter_map(|(k, v)| Some((k, v?))).collect()
    }

    /// The raw table: every declared qname, mapped to its type when the schema
    /// set agrees on one and to `None` when it does not.
    fn walk_declarations(&self) -> BTreeMap<QName, Option<TypeRef>> {
        let mut seen: BTreeMap<QName, Option<TypeRef>> = BTreeMap::new();
        let mut record = |name: QName, type_ref: TypeRef| match seen.entry(name) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(Some(type_ref));
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                if e.get().as_ref() != Some(&type_ref) {
                    e.insert(None);
                }
            }
        };
        for element in &self.global_elements {
            record(element.name.clone(), element.type_ref.clone());
        }
        for def in self.types.values().chain(self.anonymous.iter()) {
            if let TypeDef::Complex(ct) = def
                && let Some(particle) = &ct.particle
            {
                collect_elements(particle, &mut record);
            }
        }
        seen
    }
}

fn collect_elements(particle: &Particle, record: &mut impl FnMut(QName, TypeRef)) {
    match particle {
        Particle::Element(e) => record(e.name.clone(), e.type_ref.clone()),
        Particle::Sequence(g) | Particle::Choice(g) | Particle::All(g) => {
            for item in &g.items {
                collect_elements(item, record);
            }
        }
        Particle::Any { .. } => {}
    }
}

/// What pass one records about a global element.
#[derive(Debug, Clone)]
struct Declaration {
    /// The `type` attribute, if the declaration has one. A global element with
    /// an inline anonymous type cannot be the target of a `ref`.
    declared_type: Option<QName>,
    nillable: bool,
    /// The head of the substitution group this element joins, if any.
    substitution_group: Option<QName>,
    /// `abstract="true"`: schema-invalid to use directly, but EXI still gives
    /// it an event code — see `substitutes_for`.
    #[allow(dead_code, reason = "kept to document why abstractness is ignored")]
    is_abstract: bool,
}

impl Schema {
    /// Loads `entry` and every schema it imports, transitively.
    pub(crate) fn load(entry: &Path) -> Result<Self, Error> {
        let mut schema = Self::default();
        let mut pending = vec![entry.to_path_buf()];
        let mut seen = std::collections::BTreeSet::new();
        // roxmltree borrows from its input, so every document's text has to
        // outlive the parse; collect them first.
        let mut loaded: Vec<(PathBuf, String)> = Vec::new();

        while let Some(path) = pending.pop() {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
            if !seen.insert(canonical) {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|source| Error::Read { path: path.clone(), source })?;
            // `xmldsig-core-schema.xsd` carries an internal DTD subset.
            let options = roxmltree::ParsingOptions {
                allow_dtd: true,
                ..roxmltree::ParsingOptions::default()
            };
            let doc = roxmltree::Document::parse_with_options(&text, options)
                .map_err(|source| Error::Parse { path: path.clone(), source })?;
            for child in doc.root_element().children().filter(Node::is_element) {
                if matches!(child.tag_name().name(), "import" | "include" | "redefine")
                    && let Some(location) = child.attribute("schemaLocation")
                {
                    let dir = path.parent().unwrap_or_else(|| Path::new("."));
                    pending.push(dir.join(location));
                }
            }
            loaded.push((path, text));
        }

        // Pass one records the name and declared type of every global element
        // across the whole set. An `element ref` may point into a schema that
        // has not been absorbed yet — xmldsig's `Signature` is referenced from
        // ISO 15118-20 `CommonTypes`, for instance — so the declarations have to
        // exist before any content model is parsed.
        let options =
            roxmltree::ParsingOptions { allow_dtd: true, ..roxmltree::ParsingOptions::default() };
        for (path, text) in &loaded {
            let doc = roxmltree::Document::parse_with_options(text, options)
                .map_err(|source| Error::Parse { path: path.clone(), source })?;
            let root = doc.root_element();
            let target_namespace = root.attribute("targetNamespace").unwrap_or_default();
            for child in root.children().filter(Node::is_element) {
                if child.tag_name().name() != "element" {
                    continue;
                }
                let Some(name) = child.attribute("name") else { continue };
                let declared_type =
                    child.attribute("type").map(|t| resolve_qname_in(child, t, target_namespace));
                schema.declarations.insert(
                    QName::new(target_namespace, name),
                    Declaration {
                        declared_type,
                        nillable: child.attribute("nillable") == Some("true"),
                        substitution_group: child
                            .attribute("substitutionGroup")
                            .map(|g| resolve_qname_in(child, g, target_namespace)),
                        is_abstract: child.attribute("abstract") == Some("true"),
                    },
                );
            }
        }

        // Substitution groups must be indexed between the two passes: pass two
        // expands `element ref` into a choice over the group's members, so the
        // membership has to be known before any content model is parsed.
        schema.index_substitution_groups();

        for (path, text) in &loaded {
            let doc = roxmltree::Document::parse_with_options(text, options)
                .map_err(|source| Error::Parse { path: path.clone(), source })?;
            schema.absorb(doc.root_element(), path)?;
            schema.sources.push(path.clone());
        }

        schema.sources.sort();
        schema.finish();
        Ok(schema)
    }

    /// Indexes substitution groups: head element to its substitutable members.
    ///
    /// ISO 15118-2 puts every one of its 34 body messages in one group headed
    /// by an abstract `BodyElement`, so `<element ref="BodyElement"/>` in
    /// `BodyType` is really a 34-way choice. Missing this would give `BodyType`
    /// a one-production grammar and make every -2 message undecodable.
    fn index_substitution_groups(&mut self) {
        let mut groups: BTreeMap<QName, Vec<QName>> = BTreeMap::new();
        for (name, decl) in &self.declarations {
            if let Some(head) = &decl.substitution_group {
                groups.entry(head.clone()).or_default().push(name.clone());
            }
        }
        // EXI orders the branches of the expanded choice by qualified name.
        for members in groups.values_mut() {
            members.sort();
        }
        self.substitution_groups = groups;
    }

    /// Every element that may appear where `head` is referenced: the head
    /// itself plus its members, transitively.
    ///
    /// The head is included **even when it is declared `abstract`**. Schema
    /// validity says an abstract element never appears in an instance, but EXI
    /// grammar generation does not consult `abstract`, and the branch still
    /// occupies an event code. ISO 15118-2's `BodyElement` is abstract and
    /// sorts third of the thirty-five branches in `BodyType`; dropping it
    /// shifts every later message's event code down by one and makes the whole
    /// protocol undecodable. Confirmed against an `exificient`-encoded
    /// `SessionSetupReq`, which uses code 29 rather than 28.
    fn substitutes_for(&self, head: &QName) -> Vec<QName> {
        let mut out = Vec::new();
        if self.declarations.contains_key(head) {
            out.push(head.clone());
        }
        let mut stack: Vec<QName> = self.substitution_groups.get(head).cloned().unwrap_or_default();
        while let Some(member) = stack.pop() {
            if out.contains(&member) {
                continue;
            }
            // A member may itself head a nested group.
            if let Some(nested) = self.substitution_groups.get(&member) {
                stack.extend(nested.iter().cloned());
            }
            out.push(member);
        }
        out.sort();
        out.dedup();
        out
    }

    /// Sorts global elements into EXI order. Called once loading is complete.
    fn finish(&mut self) {
        self.global_elements.sort_by(|a, b| a.name.cmp(&b.name));
        self.global_elements.dedup_by(|a, b| a.name == b.name);
    }

    /// Reads one `xs:schema` element into the set.
    fn absorb(&mut self, root: Node<'_, '_>, path: &Path) -> Result<(), Error> {
        let ctx = Context {
            target_namespace: root.attribute("targetNamespace").unwrap_or_default().to_owned(),
            // Absent means "unqualified", which is what the AppProtocol schema
            // relies on: only its two global elements are namespaced.
            element_form_qualified: root.attribute("elementFormDefault") == Some("qualified"),
            attribute_form_qualified: root.attribute("attributeFormDefault") == Some("qualified"),
            path: path.to_path_buf(),
        };

        for child in root.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "element" => {
                    let name = child.attribute("name").ok_or_else(|| {
                        Error::Unsupported("global element without a name".into())
                    })?;
                    let type_ref = self.type_ref_of(child, &ctx)?;
                    self.global_elements.push(GlobalElement {
                        // Global elements are always in the target namespace,
                        // whatever `elementFormDefault` says.
                        name: QName::new(ctx.target_namespace.clone(), name),
                        type_ref,
                        nillable: child.attribute("nillable") == Some("true"),
                    });
                }
                "complexType" => {
                    let name = child.attribute("name").ok_or_else(|| {
                        Error::Unsupported("global complexType without a name".into())
                    })?;
                    let qname = QName::new(ctx.target_namespace.clone(), name);
                    let mut ct = self.parse_complex_type(child, &ctx)?;
                    ct.name = Some(qname.clone());
                    self.types.insert(qname, TypeDef::Complex(ct));
                }
                "simpleType" => {
                    let name = child.attribute("name").ok_or_else(|| {
                        Error::Unsupported("global simpleType without a name".into())
                    })?;
                    let qname = QName::new(ctx.target_namespace.clone(), name);
                    let mut st = Self::parse_simple_type(child, &ctx)?;
                    st.name = Some(qname.clone());
                    self.types.insert(qname, TypeDef::Simple(st));
                }
                "attribute" => {
                    if let Some(name) = child.attribute("name") {
                        let type_ref = self.type_ref_of(child, &ctx)?;
                        self.global_attributes
                            .insert(QName::new(ctx.target_namespace.clone(), name), type_ref);
                    }
                }
                // Named model groups and attribute groups are not used by the
                // V2G schemas; refuse rather than skip.
                "group" | "attributeGroup" => {
                    return Err(Error::Unsupported(format!(
                        "named {} in {}",
                        child.tag_name().name(),
                        path.display()
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Resolves the type of an element or attribute declaration: either the
    /// `type` attribute, or an inline anonymous definition.
    fn type_ref_of(&mut self, node: Node<'_, '_>, ctx: &Context) -> Result<TypeRef, Error> {
        if let Some(t) = node.attribute("type") {
            return Ok(TypeRef::Named(resolve_qname(node, t, ctx)));
        }
        for child in node.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "complexType" => {
                    let ct = self.parse_complex_type(child, ctx)?;
                    self.anonymous.push(TypeDef::Complex(ct));
                    return Ok(TypeRef::Anonymous(self.anonymous.len() - 1));
                }
                "simpleType" => {
                    let st = Self::parse_simple_type(child, ctx)?;
                    self.anonymous.push(TypeDef::Simple(st));
                    return Ok(TypeRef::Anonymous(self.anonymous.len() - 1));
                }
                _ => {}
            }
        }
        // No type and no inline definition means xs:anyType.
        Ok(TypeRef::Named(QName::new(XSD_NS, "anyType")))
    }

    fn parse_complex_type(
        &mut self,
        node: Node<'_, '_>,
        ctx: &Context,
    ) -> Result<ComplexType, Error> {
        let mut ct = ComplexType {
            mixed: node.attribute("mixed") == Some("true"),
            is_abstract: node.attribute("abstract") == Some("true"),
            ..ComplexType::default()
        };

        for child in node.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "complexContent" => {
                    ct.mixed |= child.attribute("mixed") == Some("true");
                    let body = child
                        .children()
                        .filter(Node::is_element)
                        .find(|n| matches!(n.tag_name().name(), "extension" | "restriction"))
                        .ok_or_else(|| {
                            Error::Unsupported(
                                "complexContent without extension/restriction".into(),
                            )
                        })?;
                    ct.derivation = if body.tag_name().name() == "extension" {
                        Derivation::Extension
                    } else {
                        Derivation::Restriction
                    };
                    ct.base = Some(resolve_qname(
                        body,
                        body.attribute("base").ok_or_else(|| {
                            Error::Unsupported("derivation without a base".into())
                        })?,
                        ctx,
                    ));
                    ct.particle = self.parse_particle_children(body, ctx)?;
                    self.parse_attributes(body, ctx, &mut ct.attributes)?;
                }
                "simpleContent" => {
                    let body = child
                        .children()
                        .filter(Node::is_element)
                        .find(|n| matches!(n.tag_name().name(), "extension" | "restriction"))
                        .ok_or_else(|| {
                            Error::Unsupported("simpleContent without extension/restriction".into())
                        })?;
                    ct.derivation = if body.tag_name().name() == "extension" {
                        Derivation::Extension
                    } else {
                        Derivation::Restriction
                    };
                    let base = resolve_qname(
                        body,
                        body.attribute("base").ok_or_else(|| {
                            Error::Unsupported("derivation without a base".into())
                        })?,
                        ctx,
                    );
                    ct.simple_content = Some(base.clone());
                    ct.base = Some(base);
                    self.parse_attributes(body, ctx, &mut ct.attributes)?;
                }
                "sequence" | "choice" | "all" => {
                    ct.particle = Some(self.parse_particle(child, ctx)?);
                }
                "attribute" | "anyAttribute" => {
                    self.parse_attribute_node(child, ctx, &mut ct.attributes)?;
                }
                _ => {}
            }
        }
        Ok(ct)
    }

    /// Parses whichever of `sequence`/`choice`/`all` appears among `node`'s
    /// children, if any.
    fn parse_particle_children(
        &mut self,
        node: Node<'_, '_>,
        ctx: &Context,
    ) -> Result<Option<Particle>, Error> {
        for child in node.children().filter(Node::is_element) {
            if matches!(child.tag_name().name(), "sequence" | "choice" | "all") {
                return Ok(Some(self.parse_particle(child, ctx)?));
            }
        }
        Ok(None)
    }

    fn parse_particle(&mut self, node: Node<'_, '_>, ctx: &Context) -> Result<Particle, Error> {
        let min = occurs(node, "minOccurs", 1)?;
        let max = occurs(node, "maxOccurs", 1)?;

        match node.tag_name().name() {
            "element" => {
                if let Some(reference) = node.attribute("ref") {
                    let target = resolve_qname(node, reference, ctx);
                    if !self.declarations.contains_key(&target) {
                        return Err(Error::UnresolvedRef(target));
                    }
                    // A reference to a substitution group head stands for any
                    // of its members, which EXI models as a choice.
                    let substitutes = self.substitutes_for(&target);
                    if substitutes.len() != 1 || substitutes[0] != target {
                        let mut items = Vec::new();
                        for member in substitutes {
                            let decl = &self.declarations[&member];
                            let declared = decl.declared_type.clone().ok_or_else(|| {
                                Error::Unsupported(format!("{member} has an inline type"))
                            })?;
                            items.push(Particle::Element(ElementParticle {
                                name: member,
                                type_ref: TypeRef::Named(declared),
                                min: 1,
                                max: 1,
                                nillable: decl.nillable,
                            }));
                        }
                        // The occurrence bounds belong to the choice, not to
                        // any single branch.
                        return Ok(Particle::Choice(Group { items, min, max }));
                    }
                }

                let (name, type_ref, nillable) = if let Some(reference) = node.attribute("ref") {
                    // A plain reference keeps the target's name and type.
                    let target = resolve_qname(node, reference, ctx);
                    let decl = self
                        .declarations
                        .get(&target)
                        .ok_or_else(|| Error::UnresolvedRef(target.clone()))?;
                    let declared = decl.declared_type.clone().ok_or_else(|| {
                        Error::Unsupported(format!("ref to {target}, which has an inline type"))
                    })?;
                    (target.clone(), TypeRef::Named(declared), decl.nillable)
                } else {
                    let local = node
                        .attribute("name")
                        .ok_or_else(|| Error::Unsupported("element without name or ref".into()))?;
                    // A local element is in the target namespace only when the
                    // schema says element forms are qualified.
                    let namespace = if ctx.element_form_qualified {
                        ctx.target_namespace.clone()
                    } else {
                        String::new()
                    };
                    let type_ref = self.type_ref_of(node, ctx)?;
                    (
                        QName::new(namespace, local),
                        type_ref,
                        node.attribute("nillable") == Some("true"),
                    )
                };
                Ok(Particle::Element(ElementParticle { name, type_ref, min, max, nillable }))
            }
            "sequence" | "choice" | "all" => {
                let mut items = Vec::new();
                for child in node.children().filter(Node::is_element) {
                    if matches!(
                        child.tag_name().name(),
                        "element" | "sequence" | "choice" | "all" | "any"
                    ) {
                        items.push(self.parse_particle(child, ctx)?);
                    }
                }
                let group = Group { items, min, max };
                Ok(match node.tag_name().name() {
                    "sequence" => Particle::Sequence(group),
                    "choice" => Particle::Choice(group),
                    _ => Particle::All(group),
                })
            }
            "any" => Ok(Particle::Any { min, max }),
            other => Err(Error::Unsupported(format!("particle <{other}>"))),
        }
    }

    fn parse_attributes(
        &mut self,
        node: Node<'_, '_>,
        ctx: &Context,
        out: &mut Vec<Attribute>,
    ) -> Result<(), Error> {
        for child in node.children().filter(Node::is_element) {
            if matches!(child.tag_name().name(), "attribute" | "anyAttribute") {
                self.parse_attribute_node(child, ctx, out)?;
            }
        }
        Ok(())
    }

    fn parse_attribute_node(
        &mut self,
        node: Node<'_, '_>,
        ctx: &Context,
        out: &mut Vec<Attribute>,
    ) -> Result<(), Error> {
        if node.tag_name().name() == "anyAttribute" {
            // Wildcard attributes only add second-level productions under
            // non-strict fidelity, which are already accounted for globally.
            return Ok(());
        }
        let required = node.attribute("use") == Some("required");
        let (name, type_ref) = if let Some(reference) = node.attribute("ref") {
            let target = resolve_qname(node, reference, ctx);
            let type_ref = self
                .global_attributes
                .get(&target)
                .cloned()
                .unwrap_or(TypeRef::Named(QName::new(XSD_NS, "string")));
            (target, type_ref)
        } else {
            let local = node
                .attribute("name")
                .ok_or_else(|| Error::Unsupported("attribute without name or ref".into()))?;
            let namespace = if ctx.attribute_form_qualified {
                ctx.target_namespace.clone()
            } else {
                String::new()
            };
            let type_ref = self.type_ref_of(node, ctx)?;
            (QName::new(namespace, local), type_ref)
        };
        out.push(Attribute { name, type_ref, required });
        Ok(())
    }

    /// Parses a simple type. Takes no receiver: unlike a complex type, a simple
    /// type never introduces anonymous child types, so nothing has to be
    /// registered on the schema.
    fn parse_simple_type(node: Node<'_, '_>, ctx: &Context) -> Result<SimpleType, Error> {
        let mut st = SimpleType::default();
        for child in node.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "restriction" => {
                    if let Some(base) = child.attribute("base") {
                        st.base = Some(resolve_qname(child, base, ctx));
                    } else if let Some(inner) = child
                        .children()
                        .filter(Node::is_element)
                        .find(|n| n.tag_name().name() == "simpleType")
                    {
                        // An anonymous base: flatten it, then let this level's
                        // facets narrow it further.
                        let inner = Self::parse_simple_type(inner, ctx)?;
                        st.base = inner.base;
                        st.enumeration = inner.enumeration;
                        st.min_inclusive = inner.min_inclusive;
                        st.max_inclusive = inner.max_inclusive;
                        st.max_length = inner.max_length;
                        st.min_length = inner.min_length;
                    }
                    for facet in child.children().filter(Node::is_element) {
                        let value = facet.attribute("value").unwrap_or_default();
                        match facet.tag_name().name() {
                            "enumeration" => st.enumeration.push(value.to_owned()),
                            "minInclusive" => st.min_inclusive = parse_int(value),
                            "minExclusive" => st.min_inclusive = parse_int(value).map(|v| v + 1),
                            "maxInclusive" => st.max_inclusive = parse_int(value),
                            "maxExclusive" => st.max_inclusive = parse_int(value).map(|v| v - 1),
                            "maxLength" => st.max_length = value.parse().ok(),
                            "minLength" => st.min_length = value.parse().ok(),
                            "length" => {
                                st.max_length = value.parse().ok();
                                st.min_length = st.max_length;
                            }
                            _ => {}
                        }
                    }
                }
                "list" => {
                    st.list_item = match child.attribute("itemType") {
                        Some(item) => Some(resolve_qname(child, item, ctx)),
                        None => Some(QName::new(XSD_NS, "string")),
                    };
                    st.base = Some(QName::new(XSD_NS, "string"));
                }
                "union" => {
                    // EXI codes a union as a string; the member types only
                    // matter for validation, which is not this codec's job.
                    st.base = Some(QName::new(XSD_NS, "string"));
                }
                _ => {}
            }
        }
        Ok(st)
    }

    /// Looks up a type by reference.
    pub(crate) fn resolve(&self, type_ref: &TypeRef) -> Option<&TypeDef> {
        match type_ref {
            TypeRef::Named(q) => self.types.get(q),
            TypeRef::Anonymous(i) => self.anonymous.get(*i),
        }
    }

    /// Name of a type reference, for diagnostics and for naming generated
    /// Rust items.
    pub(crate) fn name_of<'r>(&'r self, type_ref: &'r TypeRef) -> Option<&'r QName> {
        match type_ref {
            TypeRef::Named(q) => Some(q),
            TypeRef::Anonymous(i) => match self.anonymous.get(*i)? {
                TypeDef::Simple(s) => s.name.as_ref(),
                TypeDef::Complex(c) => c.name.as_ref(),
            },
        }
    }
}

/// Per-schema-document parsing context.
struct Context {
    target_namespace: String,
    element_form_qualified: bool,
    attribute_form_qualified: bool,
    #[allow(dead_code, reason = "kept for future diagnostics")]
    path: PathBuf,
}

/// Resolves a `prefix:local` value against the namespace scope at `node`,
/// falling back to `fallback_ns` for an unprefixed name.
fn resolve_qname_in(node: Node<'_, '_>, value: &str, fallback_ns: &str) -> QName {
    let (prefix, local) = match value.split_once(':') {
        Some((p, l)) => (Some(p), l),
        None => (None, value),
    };
    let namespace =
        node.lookup_namespace_uri(prefix).map_or_else(|| fallback_ns.to_owned(), str::to_owned);
    QName::new(namespace, local)
}

/// Resolves a `prefix:local` value against the namespace scope at `node`.
///
/// An unprefixed reference falls back to the target namespace, which is how the
/// `AppProtocol` schema names its own types.
fn resolve_qname(node: Node<'_, '_>, value: &str, ctx: &Context) -> QName {
    resolve_qname_in(node, value, &ctx.target_namespace)
}

fn occurs(node: Node<'_, '_>, attribute: &str, default: u32) -> Result<u32, Error> {
    match node.attribute(attribute) {
        None => Ok(default),
        Some("unbounded") => Ok(UNBOUNDED),
        Some(v) => v.parse().map_err(|_| Error::Unsupported(format!("{attribute}=\"{v}\""))),
    }
}

fn parse_int(value: &str) -> Option<i128> {
    value.trim().parse().ok()
}

/// Failures while reading a schema set.
#[derive(Debug)]
pub(crate) enum Error {
    /// A schema file could not be read.
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// A schema file was not well-formed XML.
    Parse {
        /// The file.
        path: PathBuf,
        /// Why.
        source: roxmltree::Error,
    },
    /// A construct outside the supported subset.
    Unsupported(String),
    /// An `element ref` or `type` named something the set does not declare.
    UnresolvedRef(QName),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::Parse { path, source } => write!(f, "parsing {}: {source}", path.display()),
            Self::Unsupported(what) => write!(f, "unsupported schema construct: {what}"),
            Self::UnresolvedRef(q) => write!(f, "unresolved reference to {q}"),
        }
    }
}

impl std::error::Error for Error {}
