//! This crate's vehicle at `EVerest`'s station, live: ISO 15118-2 and -20 DC,
//! over TCP and TLS, by external identification and by Plug & Charge.
//!
//! `EVerest`'s software-in-the-loop station — the everest-demo manager image,
//! Apache-2.0, at the tag everest-demo pins — runs in a Linux container with
//! `examples/v2g_node` on the other end of a veth pair. `EVerest`'s own car
//! simulator drives the control pilot and SLAC; our node runs the ISO 15118
//! session. `tests/interop/everest/matrix.sh` runs every row and prints the
//! report this test reads.
//!
//! What it is evidence of: `EVerest`'s codec is `libcbv2g`, not `exificient`, so
//! this is codec evidence as well as session evidence — and in the Plug & Charge
//! row `EVerest` verifies a signature this crate made.
//!
//! Without a Docker daemon the test **skips by name**. The base image is
//! 20 GB unpacked.

// The node is built inside the image; this test needs nothing from the
// crate but its default environment.
#![cfg(feature = "std")]

mod interop;

use std::path::Path;

use testcontainers::runners::{SyncBuilder, SyncRunner};
use testcontainers::{GenericBuildableImage, ImageExt};

#[test]
fn live_peer_everest_sessions_complete_at_its_station() {
    if !interop::docker_available() {
        println!("everest: skipped: docker unavailable");
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let everest = root.join("tests/interop/everest");
    let image = GenericBuildableImage::new("iso15118-interop-everest", "2025.10.0")
        .with_dockerfile(everest.join("Dockerfile"))
        .with_file(root.join("Cargo.toml"), "Cargo.toml")
        .with_file(root.join("Cargo.lock"), "Cargo.lock")
        .with_file(root.join("src"), "src")
        .with_file(root.join("examples"), "examples")
        .with_file(everest, "tests/interop/everest")
        .build_image()
        .expect("the EVerest image builds");

    // NET_ADMIN for the veth pair, nothing broader.
    let container = image.with_cap_add("NET_ADMIN").start().expect("the container starts");
    let mut stdout = String::new();
    std::io::Read::read_to_string(&mut container.stdout(true), &mut stdout)
        .expect("the container's output");
    print!("{}", interop::without_report(&stdout));

    let rows = interop::parse_report(&stdout).unwrap_or_else(|e| panic!("everest: {e}"));
    interop::print_table(&rows);
    interop::assert_all_passed("everest", &rows);
}
