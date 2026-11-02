# EVerest's software-in-the-loop station — the everest-demo manager image,
# Apache-2.0 — and this crate's `v2g_node`, in one Linux container joined by a
# veth pair. `tests/everest.rs` builds it with the crate's sources as the
# context.

# --- this crate's node -------------------------------------------------------
FROM rust:1.88-slim-bookworm AS node
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
# The node needs neither the code generator nor the test-only Docker client,
# and building an example compiles every dev-dependency.
RUN sed -i -e 's/^members = \["codegen"\]/members = []/' -e '/^testcontainers = /d' Cargo.toml \
 && cargo build --example v2g_node --features std,iso2,iso20-ac,iso20-dc,sdp,evcc,secc,pnc-rustcrypto \
 && cp target/debug/examples/v2g_node /usr/local/bin/v2g_node

# --- EVerest, pinned to the tag everest-demo pins ----------------------------
FROM ghcr.io/everest/everest-demo/manager:2025.10.0-single-phase
# A broker for EVerest's modules, an OpenSSL proxy for TLS (ISO 15118-2's
# CBC suite, which nothing in the crate's dependency tree speaks), `ip`.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends mosquitto socat iproute2 >/dev/null \
 && rm -rf /var/lib/apt/lists/*
# EVerest's own test PKI, shipped in the image: the -20 station will not start
# without a V2G certificate, and TLS and Plug & Charge use the rest.
RUN cd /ext/source/tests/ocpp_tests/test_sets/everest-aux && bash install_certs.sh /ext/dist
COPY --from=node /usr/local/bin/v2g_node /usr/local/bin/v2g_node
COPY tests/interop/everest/config-sil-dc-ours.yaml tests/interop/everest/config-sil-dc-pnc-ours.yaml /ext/source/config/
COPY tests/interop/everest/matrix.sh /matrix.sh
ENTRYPOINT ["sh", "/matrix.sh"]
