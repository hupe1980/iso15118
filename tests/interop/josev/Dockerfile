# Josev — the community edition of the Python ISO 15118 stack, Apache-2.0 —
# and this crate's `v2g_node`, in one Linux container joined by a veth pair.
# `tests/josev.rs` builds it with the crate's sources as the context.

# --- Josev, pinned to its PyPI release ---------------------------------------
FROM python:3.11-slim-bookworm AS josev
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends default-jre-headless iproute2 openssl procps \
 && rm -rf /var/lib/apt/lists/*
# 0.31.2 imports `aiofile` without declaring it.
RUN pip install --no-cache-dir -q iso15118==0.31.2 aiofile==3.9.0
# The simulated station's power module stands at 1 V and never ramps, so no
# vehicle that waits for pre-charge to match its battery ever closes its
# contactors. Set it to the 400 V the vehicle asks for, as a bench sets a
# simulated supply; the protocol stack is untouched.
RUN sed -i 's/evse_data_context.present_voltage = 1$/evse_data_context.present_voltage = 400/' \
      /usr/local/lib/python3.11/site-packages/iso15118/secc/controller/simulator.py \
 && grep -q 'present_voltage = 400' /usr/local/lib/python3.11/site-packages/iso15118/secc/controller/simulator.py
# Its -20 vehicle reads contract certificates even for EIM; the wheel ships the
# script that makes them, not the certificates.
RUN cd /usr/local/lib/python3.11/site-packages/iso15118/shared/pki \
 && bash ./create_certs.sh -v iso-2 >/dev/null \
 && bash ./create_certs.sh -v iso-20 >/dev/null

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

# --- the two together --------------------------------------------------------
FROM josev
COPY --from=node /usr/local/bin/v2g_node /usr/local/bin/v2g_node
COPY tests/interop/josev/matrix.sh /matrix.sh
ENTRYPOINT ["sh", "/matrix.sh"]
