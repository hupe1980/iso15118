//! This crate against Josev, live: our vehicle at Josev's station and Josev's
//! vehicle at ours, ISO 15118-2 and -20, AC and DC.
//!
//! A capture says what one peer accepted once; a live peer says what it
//! accepts now. Josev — the community edition of the Python stack, Apache-2.0,
//! pinned to its `PyPI` release — runs in a Linux container beside this crate's
//! `examples/v2g_node`, joined by a veth pair, because SDP is link-local
//! multicast and needs a real link. `tests/interop/josev/matrix.sh` runs every
//! row and prints the report this test reads.
//!
//! What it is evidence of, exactly: Josev's EXI codec is `EXICodec.jar`, which
//! is `exificient` — the same reference the grammar and message checks
//! already use. So this adds **session** evidence — ordering, timing, the
//! values a real stack checks — and not codec evidence.
//!
//! Without a Docker daemon the test **skips by name**: a live-peer check that
//! quietly passes with no peer reads exactly like one that ran.

// The node is built inside the image; this test needs nothing from the
// crate but its default environment.
#![cfg(feature = "std")]

mod interop;

use std::path::Path;

use testcontainers::runners::{SyncBuilder, SyncRunner};
use testcontainers::{GenericBuildableImage, ImageExt};

#[test]
fn live_peer_josev_sessions_complete_in_both_roles() {
    if !interop::docker_available() {
        println!("josev: skipped: docker unavailable");
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let image = GenericBuildableImage::new("iso15118-interop-josev", "0.31.2")
        .with_dockerfile(root.join("tests/interop/josev/Dockerfile"))
        .with_file(root.join("Cargo.toml"), "Cargo.toml")
        .with_file(root.join("Cargo.lock"), "Cargo.lock")
        .with_file(root.join("src"), "src")
        .with_file(root.join("examples"), "examples")
        .with_file(root.join("tests/interop/josev/matrix.sh"), "tests/interop/josev/matrix.sh")
        .build_image()
        .expect("the Josev image builds");

    // NET_ADMIN for the veth pair, nothing broader.
    let container = image.with_cap_add("NET_ADMIN").start().expect("the container starts");
    let mut stdout = String::new();
    std::io::Read::read_to_string(&mut container.stdout(true), &mut stdout)
        .expect("the container's output");
    print!("{}", interop::without_report(&stdout));

    let rows = interop::parse_report(&stdout).unwrap_or_else(|e| panic!("josev: {e}"));
    interop::print_table(&rows);
    interop::assert_all_passed("josev", &rows);
}
