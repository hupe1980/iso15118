//! Derives EXI schema-informed grammars for the `iso15118` crate from the V2G
//! XSDs.
//!
//! # What it does
//!
//! Loads a schema and everything it imports, then derives:
//!
//! * the **document grammar** — the table of global elements in EXI order,
//!   their event codes and the code width;
//! * an **element grammar** per complex type — states, first-level productions
//!   in event-code order, and each state's code width.
//!
//! Two rules dominate the result and neither is obvious from reading a schema:
//!
//! * the document table spans the whole schema **set**, including transitively
//!   imported schemas (for ISO 15118-20 `CommonMessages` that means
//!   `CommonTypes` and `xmldsig-core` too — 54 elements, not the 28 the file
//!   itself declares);
//! * qualified names sort by **local name first, then namespace**.
//!
//! Get either wrong and every message encodes under the wrong event code.
//!
//! # Trusting the output
//!
//! `--check` re-derives facts that are independently pinned by the `iso15118`
//! crate's golden vectors — bytes produced by other implementations — and fails
//! if this tool disagrees with them. It is the difference between a grammar
//! that is self-consistent and one that is right.
//!
//! # Usage
//!
//! ```text
//! cargo run -p iso15118-codegen -- <schema.xsd> [--check] [--type NAME] [--out FILE]
//! ```
//!
//! The schemas are not in this repository; fetch them with
//! `scripts/fetch-schemas.sh` first. See `specs/README.md`.

// A build tool rather than a published API: these pedantic lints fire on
// shapes that read better as written — a long but flat argument parser, match
// arms kept apart because they mean different things, and recursion that
// threads context through `self`.
#![allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    clippy::only_used_in_recursion,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::unused_self
)]

mod dump;
mod emit;
mod grammar;
mod layout;
mod sample;
mod xsd;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use grammar::{Builder, Event, Grammar, bit_width};
use xsd::{QName, Schema, TypeDef, TypeRef};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let mut entry: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut only_type: Option<String> = None;
    let mut check = false;
    let mut dump = false;
    let mut emit = false;
    let mut samples = false;
    let mut why = false;
    let mut emit_namespaces: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut extern_modules: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--out" | "-o" => match args.next() {
                Some(path) => out = Some(PathBuf::from(path)),
                None => return fail("--out needs a path"),
            },
            "--type" | "-t" => match args.next() {
                Some(name) => only_type = Some(name.to_string_lossy().into_owned()),
                None => return fail("--type needs a name"),
            },
            "--check" => check = true,
            "--dump" => dump = true,
            "--emit" => emit = true,
            "--samples" => samples = true,
            "--why" => why = true,
            "--emit-ns" => match args.next() {
                Some(ns) => {
                    emit_namespaces.insert(ns.to_string_lossy().into_owned());
                }
                None => return fail("--emit-ns needs a namespace"),
            },
            "--extern" => match args.next() {
                Some(spec) => {
                    let spec = spec.to_string_lossy().into_owned();
                    match spec.split_once('=') {
                        Some((ns, path)) => {
                            extern_modules.insert(ns.to_owned(), path.to_owned());
                        }
                        None => return fail("--extern wants <namespace>=<rust::path>"),
                    }
                }
                None => return fail("--extern needs a mapping"),
            },
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            flag if flag.starts_with('-') => return fail(&format!("unknown flag {flag}")),
            _ => entry = Some(PathBuf::from(arg)),
        }
    }

    let Some(entry) = entry else {
        print_usage();
        return fail("no schema given");
    };

    let schema = match Schema::load(&entry) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };

    eprintln!(
        "{}: {} global elements and {} named types across {} schema(s); \
         document event code is {} bits",
        entry.display(),
        schema.global_elements.len(),
        schema.types.len(),
        schema.sources.len(),
        document_event_width(&schema),
    );

    if check {
        return run_checks(&schema);
    }

    if why {
        let emitter = emit::Emitter::new(&schema, "", emit_namespaces, extern_modules);
        let mut any = false;
        for (name, reason) in emitter.exclusions() {
            println!("{name}: {reason}");
            any = true;
        }
        if !any {
            println!("every complex type in this schema set is generated");
        }
        return ExitCode::SUCCESS;
    }

    if samples {
        let Some(dir) = out else { return fail("--samples needs --out <dir>") };
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return fail(&format!("creating {}: {e}", dir.display()));
        }
        // The sampler must agree with the emitter about what has a Rust form,
        // or it writes instances the generated codec is bound to refuse.
        let emitter = emit::Emitter::new(&schema, "", emit_namespaces.clone(), extern_modules);
        let sampler = sample::Sampler::new(&schema, emit_namespaces, emitter.generatable().clone());
        let mut written = 0usize;
        for (name, xml) in sampler.render_all() {
            let path = dir.join(format!("{name}.xml"));
            if let Err(e) = std::fs::write(&path, xml) {
                return fail(&format!("writing {}: {e}", path.display()));
            }
            written += 1;
        }
        eprintln!("wrote {written} sample instances to {}", dir.display());
        return ExitCode::SUCCESS;
    }

    if emit {
        let module = entry.file_stem().unwrap_or_default().to_string_lossy().into_owned();
        let emitter = emit::Emitter::new(&schema, &module, emit_namespaces, extern_modules);
        let text = match emitter.render() {
            Ok(t) => t,
            Err(e) => return fail(&e),
        };
        match out {
            Some(path) => {
                if let Err(e) = std::fs::write(&path, text) {
                    return fail(&format!("writing {}: {e}", path.display()));
                }
                eprintln!("wrote {}", path.display());
            }
            None => print!("{text}"),
        }
        return ExitCode::SUCCESS;
    }

    if dump {
        let text = dump::Flattener::new(&schema).render();
        match out {
            Some(path) => {
                if let Err(e) = std::fs::write(&path, text) {
                    return fail(&format!("writing {}: {e}", path.display()));
                }
            }
            None => print!("{text}"),
        }
        return ExitCode::SUCCESS;
    }

    let report = match render(&schema, only_type.as_deref()) {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, report) {
                return fail(&format!("writing {}: {e}", path.display()));
            }
            eprintln!("wrote {}", path.display());
        }
        None => print!("{report}"),
    }
    ExitCode::SUCCESS
}

/// Width of a document-level event code: one alternative per global element,
/// plus the `SE(*)` production non-strict fidelity adds.
fn document_event_width(schema: &Schema) -> u32 {
    bit_width(schema.global_elements.len() as u64 + 1)
}

/// Event code of a global element, by local name.
fn event_code(schema: &Schema, local: &str) -> Option<usize> {
    schema.global_elements.iter().position(|e| e.name.local == local)
}

/// Derives the grammar of the type a global element declares.
fn grammar_of_element(schema: &Schema, local: &str) -> Option<Grammar> {
    let element = schema.global_elements.iter().find(|e| e.name.local == local)?;
    grammar_of(schema, &element.type_ref)
}

fn grammar_of(schema: &Schema, type_ref: &TypeRef) -> Option<Grammar> {
    let builder = Builder::new(schema);
    match schema.resolve(type_ref) {
        Some(TypeDef::Complex(ct)) => builder.complex_type(ct).ok(),
        // A built-in or simple type: one typed character-data event.
        _ => Some(builder.simple_type(type_ref)),
    }
}

/// The first-level event-code widths of a grammar, state by state.
fn widths(grammar: &Grammar) -> Vec<u32> {
    grammar.states.iter().map(grammar::State::event_width).collect()
}

/// Re-derives facts the `iso15118` crate's golden vectors pin independently.
///
/// Every expectation here was established from bytes produced by other
/// implementations, not from this tool, so agreement is evidence rather than a
/// tautology.
fn run_checks(schema: &Schema) -> ExitCode {
    let mut ok = true;
    let mut check = |what: &str, got: &dyn std::fmt::Debug, want: &dyn std::fmt::Debug| {
        let (got, want) = (format!("{got:?}"), format!("{want:?}"));
        if got == want {
            eprintln!("  ok   {what} = {got}");
        } else {
            eprintln!("  FAIL {what}\n         got  {got}\n         want {want}");
            ok = false;
        }
    };

    if event_code(schema, "supportedAppProtocolReq").is_some() {
        eprintln!("checking the supportedAppProtocol schema against src/app_protocol.rs");
        check("global elements", &schema.global_elements.len(), &2);
        check(
            "supportedAppProtocolReq event code",
            &event_code(schema, "supportedAppProtocolReq"),
            &Some(0),
        );
        check(
            "supportedAppProtocolRes event code",
            &event_code(schema, "supportedAppProtocolRes"),
            &Some(1),
        );
        // Two elements plus SE(*) is three alternatives: two bits, not one.
        check("document event width", &document_event_width(schema), &2);

        // supportedAppProtocolReq: AppProtocol{1,20}. One bit while only SE is
        // possible, two while SE and EE both are, one again once twenty have
        // been seen and only EE remains.
        if let Some(g) = grammar_of_element(schema, "supportedAppProtocolReq") {
            let w = widths(&g);
            check("Req state count", &w.len(), &21);
            check("Req state 0 width", &w.first().copied(), &Some(1));
            check("Req state 1 width", &w.get(1).copied(), &Some(2));
            check("Req state 19 width", &w.get(19).copied(), &Some(2));
            check("Req state 20 width", &w.get(20).copied(), &Some(1));
        } else {
            check("Req grammar", &"missing", &"present");
        }

        // supportedAppProtocolRes: ResponseCode then an optional SchemaID.
        if let Some(g) = grammar_of_element(schema, "supportedAppProtocolRes") {
            check("Res state widths", &widths(&g), &vec![1u32, 2, 1]);
        } else {
            check("Res grammar", &"missing", &"present");
        }

        // AppProtocolType: five required children, then the end.
        if let Some(TypeDef::Complex(ct)) =
            schema.types.get(&QName::new("urn:iso:15118:2:2010:AppProtocol", "AppProtocolType"))
        {
            let g = Builder::new(schema).complex_type(ct).expect("AppProtocolType should derive");
            check("AppProtocolType state widths", &widths(&g), &vec![1u32, 1, 1, 1, 1, 1]);
        }

        // priorityType restricts to 1..=20: twenty values, five bits.
        if let Some(TypeDef::Simple(st)) =
            schema.types.get(&QName::new("urn:iso:15118:2:2010:AppProtocol", "priorityType"))
        {
            let span = st.max_inclusive.unwrap_or(0) - st.min_inclusive.unwrap_or(0) + 1;
            check("priorityType range", &span, &20i128);
            let width = u64::try_from(span).map(bit_width).unwrap_or_default();
            check("priorityType width", &width, &5);
        }
    }

    let is_iso20_common = schema
        .global_elements
        .iter()
        .any(|e| e.name.namespace == "urn:iso:std:iso:15118:-20:CommonMessages");
    if is_iso20_common {
        eprintln!("checking ISO 15118-20 CommonMessages against tests/golden.rs");
        check("global elements", &schema.global_elements.len(), &54);
        check("SessionStopReq event code", &event_code(schema, "SessionStopReq"), &Some(37));
        check("SessionStopRes event code", &event_code(schema, "SessionStopRes"), &Some(38));
        check("document event width", &document_event_width(schema), &6);

        // Header, ChargingSession, then two optional children. The golden
        // vector only visits the first three states, because it takes EE out of
        // state 2; states 3 and 4 are the paths where the optional
        // EVTermination* children are present.
        if let Some(g) = grammar_of_element(schema, "SessionStopReq") {
            check("SessionStopReq state widths", &widths(&g), &vec![1u32, 1, 2, 2, 1]);
        } else {
            check("SessionStopReq grammar", &"missing", &"present");
        }
        // SessionStopRes: Header then ResponseCode, nothing optional after.
        if let Some(g) = grammar_of_element(schema, "SessionStopRes") {
            check("SessionStopRes state widths", &widths(&g), &vec![1u32, 1, 1]);
        }
        // MessageHeaderType: SessionID, TimeStamp, optional Signature.
        if let Some(TypeDef::Complex(ct)) = schema
            .types
            .get(&QName::new("urn:iso:std:iso:15118:-20:CommonTypes", "MessageHeaderType"))
        {
            let g = Builder::new(schema).complex_type(ct).expect("MessageHeaderType should derive");
            check("MessageHeaderType state widths", &widths(&g), &vec![1u32, 1, 2, 1]);
        }
    }

    // The structural layout that code generation uses must agree with the DFA
    // at every position, for every type. The DFA is verified against the EXI
    // reference implementation, so this ties the emitter to it transitively.
    {
        let mut layout_failures = Vec::new();
        let mut checked = 0usize;
        let mut skipped = 0usize;
        for (name, def) in &schema.types {
            let TypeDef::Complex(ct) = def else { continue };
            // xmldsig uses wildcards, mixed content and nested choices, none of
            // which map to a typed Rust struct. Its grammar is still derived and
            // verified; only code generation skips it.
            if name.namespace == "http://www.w3.org/2000/09/xmldsig#" {
                skipped += 1;
                continue;
            }
            match layout::Layout::of(schema, ct) {
                Ok(l) => {
                    checked += 1;
                    if let Err(e) = l.verify(schema, ct) {
                        layout_failures.push(format!("{name}: {e}"));
                    }
                }
                Err(e) => layout_failures.push(format!("{name}: {e}")),
            }
        }
        if layout_failures.is_empty() {
            eprintln!(
                "  ok   all {checked} layouts agree with the derived grammar                  ({skipped} xmldsig types not code-generated)"
            );
        } else {
            for f in &layout_failures {
                eprintln!("  FAIL {f}");
            }
            ok = false;
        }
    }

    // Whatever the schema, every type in it must derive without error.
    let builder = Builder::new(schema);
    let mut failures = Vec::new();
    for (name, def) in &schema.types {
        if let TypeDef::Complex(ct) = def
            && let Err(e) = builder.complex_type(ct)
        {
            failures.push(format!("{name}: {e}"));
        }
    }
    if failures.is_empty() {
        eprintln!("  ok   all {} named types derive a grammar", schema.types.len());
    } else {
        for f in &failures {
            eprintln!("  FAIL {f}");
        }
        ok = false;
    }

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// Renders a human-readable grammar report.
fn render(schema: &Schema, only_type: Option<&str>) -> Result<String, String> {
    let mut s = String::new();
    let _ = writeln!(s, "# Document grammar");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "{} global elements + SE(*) = {} alternatives, {} bits",
        schema.global_elements.len(),
        schema.global_elements.len() + 1,
        document_event_width(schema)
    );
    let _ = writeln!(s);
    for (i, element) in schema.global_elements.iter().enumerate() {
        let _ = writeln!(s, "{i:5}  {}", element.name);
    }

    let _ = writeln!(s);
    let _ = writeln!(s, "# Element grammars");
    let builder = Builder::new(schema);
    for (name, def) in &schema.types {
        let TypeDef::Complex(ct) = def else { continue };
        if let Some(filter) = only_type
            && name.local != filter
        {
            continue;
        }
        let g = builder.complex_type(ct).map_err(|e| format!("{name}: {e}"))?;
        let _ = writeln!(s);
        let _ = writeln!(s, "## {name}");
        for (i, state) in g.states.iter().enumerate() {
            let _ = writeln!(s, "  state {i} ({} bits)", state.event_width());
            for (code, p) in state.productions.iter().enumerate() {
                let _ = writeln!(s, "    {code} {}", describe(schema, &p.event, p.target));
            }
        }
    }
    Ok(s)
}

fn describe(schema: &Schema, event: &Event, target: usize) -> String {
    match event {
        Event::StartElement { name, type_ref, .. } => {
            let ty = schema.name_of(type_ref).map_or_else(|| "?".into(), QName::to_string);
            format!("SE({name}) : {ty} -> {target}")
        }
        Event::Attribute { name, .. } => format!("AT({name}) -> {target}"),
        Event::Characters { type_ref } => {
            let ty = schema.name_of(type_ref).map_or_else(|| "?".into(), QName::to_string);
            format!("CH : {ty} -> {target}")
        }
        Event::CharactersGeneric => format!("CH(*) -> {target}"),
        Event::Wildcard => format!("SE(*) -> {target}"),
        Event::EndElement => "EE".to_owned(),
    }
}

fn print_usage() {
    eprintln!("usage: iso15118-codegen <schema.xsd> [--check] [--type NAME] [--out FILE]");
    eprintln!();
    eprintln!("  --check      re-derive facts pinned by the crate's golden vectors");
    eprintln!("  --dump       emit the flat grammar graph for differential comparison");
    eprintln!("  --emit       emit Rust message types and codecs");
    eprintln!("  --emit-ns    restrict --emit to one namespace (repeatable)");
    eprintln!("  --samples    write one XML instance per global element into --out <dir>");
    eprintln!("  --why        list every complex type that is not generated, and why");
    eprintln!("  --extern     <namespace>=<rust::path> for types another module owns");
    eprintln!("  --type, -t   report only the named complex type");
    eprintln!("  --out, -o    write the report here instead of stdout");
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(relative)
    }

    /// The schemas are gitignored, so tests that need them skip on a fresh
    /// clone rather than failing.
    fn load(relative: &str) -> Option<Schema> {
        let path = spec(relative);
        if !path.exists() {
            eprintln!("skipping: run scripts/fetch-schemas.sh first");
            return None;
        }
        Some(Schema::load(&path).expect("the schema set should load"))
    }

    #[test]
    fn qnames_sort_by_local_name_before_namespace() {
        // The rule the whole document grammar hangs on. Under a namespace-first
        // ordering these three would come out in a different order and every
        // event code would shift.
        let mut names = [
            QName::new("urn:b", "SessionStopRes"),
            QName::new("urn:z", "SessionStopReq"),
            QName::new("urn:z", "AuthorizationReq"),
        ];
        names.sort();
        let order: Vec<_> = names.iter().map(|q| q.local.as_str()).collect();
        assert_eq!(order, ["AuthorizationReq", "SessionStopReq", "SessionStopRes"]);
    }

    #[test]
    fn same_local_name_falls_back_to_namespace() {
        let mut names = [QName::new("urn:z", "Signature"), QName::new("urn:a", "Signature")];
        names.sort();
        assert_eq!(names[0].namespace, "urn:a");
    }

    #[test]
    fn bit_width_matches_the_crates_definition() {
        assert_eq!(bit_width(0), 0);
        assert_eq!(bit_width(1), 0);
        assert_eq!(bit_width(2), 1);
        assert_eq!(bit_width(55), 6, "54 ISO 15118-20 globals plus SE(*)");
        assert_eq!(bit_width(65), 7);
    }

    /// The derived grammar must reproduce the event-code widths that
    /// `src/app_protocol.rs` hand-derived and its golden vectors confirm.
    #[test]
    fn app_protocol_grammar_matches_the_hand_written_codec() {
        let Some(schema) = load("specs/iso15118-2/V2G_CI_AppProtocol.xsd") else { return };

        assert_eq!(schema.global_elements.len(), 2);
        assert_eq!(event_code(&schema, "supportedAppProtocolReq"), Some(0));
        assert_eq!(event_code(&schema, "supportedAppProtocolRes"), Some(1));
        assert_eq!(document_event_width(&schema), 2, "W_ROOT");

        let req = grammar_of_element(&schema, "supportedAppProtocolReq").unwrap();
        let w = widths(&req);
        assert_eq!(w.len(), 21, "one state per AppProtocol count, 0..=20");
        assert_eq!(w[0], 1, "only SE(AppProtocol) is possible before the first one");
        assert_eq!(&w[1..20], &[2u32; 19], "SE or EE while more are allowed");
        assert_eq!(w[20], 1, "only EE once twenty have been seen");

        let res = grammar_of_element(&schema, "supportedAppProtocolRes").unwrap();
        assert_eq!(widths(&res), vec![1, 2, 1]);

        let ct = schema
            .types
            .get(&QName::new("urn:iso:15118:2:2010:AppProtocol", "AppProtocolType"))
            .unwrap();
        let TypeDef::Complex(ct) = ct else { panic!("AppProtocolType is a complex type") };
        let g = Builder::new(&schema).complex_type(ct).unwrap();
        assert_eq!(widths(&g), vec![1, 1, 1, 1, 1, 1], "five children then EE");
    }

    /// The derived grammar must reproduce the widths `tests/golden.rs` walks
    /// real third-party ISO 15118-20 bytes with.
    #[test]
    fn iso20_grammar_matches_the_golden_vectors() {
        let Some(schema) = load("specs/iso15118-20/V2G_CI_CommonMessages.xsd") else { return };

        assert_eq!(schema.global_elements.len(), 54);
        assert_eq!(event_code(&schema, "SessionStopReq"), Some(37));
        assert_eq!(event_code(&schema, "SessionStopRes"), Some(38));
        assert_eq!(document_event_width(&schema), 6);

        // States 0..2 are the path the golden vector walks: SE(Header) at one
        // bit, SE(ChargingSession) at one bit, then a three-way choice between
        // the two optional EVTermination children and EE at two bits — exactly
        // W_ONE, W_ONE and W_THREE in tests/golden.rs. States 3 and 4 cover the
        // optional children actually being present, which no vector exercises.
        assert_eq!(
            widths(&grammar_of_element(&schema, "SessionStopReq").unwrap()),
            vec![1, 1, 2, 2, 1]
        );
        assert_eq!(widths(&grammar_of_element(&schema, "SessionStopRes").unwrap()), vec![1, 1, 1]);

        let header = schema
            .types
            .get(&QName::new("urn:iso:std:iso:15118:-20:CommonTypes", "MessageHeaderType"))
            .unwrap();
        let TypeDef::Complex(header) = header else { panic!("MessageHeaderType is complex") };
        let g = Builder::new(&schema).complex_type(header).unwrap();
        assert_eq!(widths(&g), vec![1, 1, 2, 1], "SessionID, TimeStamp, optional Signature");
    }

    /// Regression: mixed content contributes an **untyped** character-data
    /// production that sorts *after* `EE`, and only in the content region — the
    /// attribute prefix of a mixed type does not carry it. Found by diffing
    /// against the reference implementation; see scripts/verify-grammars.sh.
    #[test]
    fn mixed_content_appends_generic_characters_last() {
        let Some(schema) = load("specs/iso15118-20/V2G_CI_CommonMessages.xsd") else { return };
        let name = QName::new("http://www.w3.org/2000/09/xmldsig#", "CanonicalizationMethodType");
        let Some(TypeDef::Complex(ct)) = schema.types.get(&name) else {
            panic!("xmldsig should be part of the schema set")
        };
        let g = Builder::new(&schema).complex_type(ct).unwrap();

        // The start state offers only the required Algorithm attribute.
        let start = &g.states[0].productions;
        assert_eq!(start.len(), 1, "a required attribute must be taken first");
        assert!(matches!(start[0].event, Event::Attribute { .. }));

        // The content state that follows offers the wildcard, then EE, then
        // untyped characters — in that order.
        let content = &g.states[start[0].target].productions;
        let kinds: Vec<_> = content
            .iter()
            .map(|p| match p.event {
                Event::Wildcard => "SEGEN",
                Event::EndElement => "EE",
                Event::CharactersGeneric => "CHGEN",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, ["SEGEN", "EE", "CHGEN"]);
    }

    /// Regression: declared element productions precede the `xs:any` wildcard
    /// even when the schema declares the wildcard first. `TransformType` puts
    /// `<any>` before `<element name="XPath">`, yet `XPath` gets event code 0.
    #[test]
    fn declared_elements_sort_before_the_wildcard() {
        let Some(schema) = load("specs/iso15118-20/V2G_CI_CommonMessages.xsd") else { return };
        let name = QName::new("http://www.w3.org/2000/09/xmldsig#", "TransformType");
        let Some(TypeDef::Complex(ct)) = schema.types.get(&name) else { return };
        let g = Builder::new(&schema).complex_type(ct).unwrap();

        let content = g
            .states
            .iter()
            .find(|s| s.productions.iter().any(|p| matches!(p.event, Event::Wildcard)))
            .expect("TransformType has a wildcard");
        let wildcard =
            content.productions.iter().position(|p| matches!(p.event, Event::Wildcard)).unwrap();
        let declared =
            content.productions.iter().position(|p| matches!(p.event, Event::StartElement { .. }));
        if let Some(declared) = declared {
            assert!(declared < wildcard, "declared elements come first");
        }
    }

    /// Regression: a bounded repetition is unrolled to its exact `maxOccurs`,
    /// not approximated by a loop. ISO 15118-20 goes up to 2048; treating that
    /// as unbounded would keep offering the element past its limit.
    #[test]
    fn large_bounded_repetitions_are_unrolled_exactly() {
        let Some(schema) = load("specs/iso15118-2/V2G_CI_MsgDef.xsd") else { return };
        let name = QName::new("urn:iso:15118:2:2013:MsgDataTypes", "PMaxScheduleType");
        let Some(TypeDef::Complex(ct)) = schema.types.get(&name) else { return };
        let g = Builder::new(&schema).complex_type(ct).unwrap();

        // maxOccurs="1024" means 1024 chances to send the entry and then a
        // final state offering only EE.
        assert_eq!(g.states.len(), 1025, "one state per count, 0..=1024");
        let last = g.states.last().unwrap();
        assert_eq!(last.productions.len(), 1);
        assert!(matches!(last.productions[0].event, Event::EndElement));
    }

    /// Nothing in any V2G schema may fail to derive; a schema this tool cannot
    /// model is a gap, not something to skip past.
    #[test]
    fn every_v2g_type_derives_a_grammar() {
        for relative in [
            "specs/iso15118-2/V2G_CI_AppProtocol.xsd",
            "specs/iso15118-2/V2G_CI_MsgDef.xsd",
            "specs/iso15118-20/V2G_CI_CommonMessages.xsd",
            "specs/iso15118-20/V2G_CI_AC.xsd",
            "specs/iso15118-20/V2G_CI_DC.xsd",
            "specs/iso15118-20/V2G_CI_WPT.xsd",
            "specs/iso15118-20/V2G_CI_ACDP.xsd",
        ] {
            let Some(schema) = load(relative) else { continue };
            let builder = Builder::new(&schema);
            for (name, def) in &schema.types {
                if let TypeDef::Complex(ct) = def {
                    builder.complex_type(ct).unwrap_or_else(|e| panic!("{relative}: {name}: {e}"));
                }
            }
        }
    }
}
