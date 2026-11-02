+++
title = "Verification"
description = "How iso15118 is verified: 3760 real captured messages replayed byte for byte, 395 grammars and 166 messages differed against the EXI reference implementation, layouts pinned, ten fuzz targets, live sessions against Josev and EVerest, and every spec citation checked against the text."
weight = 100
+++

Round-tripping your own encoder through your own decoder proves only that the two
agree. So the codec is checked against other implementations, and against
equipment: a reference implementation says whether it is *right*, a captured
session whether the field can *read* it, a live peer whether a session
*completes*.

| Layer | What it proves |
|---|---|
| **Property tests** | `decode(encode(m)) == m` and bit reader/writer duality — self-consistency only. |
| **Layout pins** | Every SLAC message encoded with a distinct byte per field and asserted verbatim: field order, offsets, widths, reserved gaps. |
| **Golden vectors** | Real ISO 15118-20 frames from an independent C++ implementation, re-encoded byte for byte. |
| **Differential grammars** | Every derived state and production compared against `exificient`, the EXI reference implementation, for all **395** element grammars — both generations and Amd 1's `AC_DER` sets. |
| **Differential messages** | A schema-valid instance of every message type, encoded by the reference implementation as a document **and** as a fragment, re-encoded byte for byte. **166 × 2.** |
| **Requirement register** | Every `[V2G2-nnn]` cited anywhere in the repository checked against the text of ISO 15118-2:2014 itself — **101** cited, against the standard's **852**. `scripts/requirement-coverage.sh`: 47 implemented and tested, 46 implemented only, 4 cited only by tests, 4 only in documentation. |
| **Differential certificates** | Chains and the contract-key envelope minted by **OpenSSL** (`scripts/make-test-pki.sh`); all ten OEM provisioning leaves of **Hubject's published test PKI** validate to its real V2G Root (`tests/pki_pool.rs`). |
| **Captured sessions** | **3 760** messages from sixteen captures — dSPACE DS5366 hardware against **Josev** and **RiseV2G** — re-encoded byte for byte: ISO 15118-2 AC and DC, pause, renegotiation, sales tariff, multi-EVSE SLAC, ISO 15118-20 AC bidirectional and DC over TLS 1.3 and mutual TLS, four Plug & Charge sessions whose signatures verify, and a DIN session declined by name. |
| **Live peers** | This crate's engines on a real link: **Josev** 8 of 8 rows, both roles; **EVerest** 4 of 4, Plug & Charge included — see [below](#live-peers). |

```text
scripts/verify-grammars.sh   all 2 / 80 / 54 / 42 / 48 / 38 / 34 / 48 / 49 element
                             grammars agree with the reference  (395 total)
scripts/verify-messages.sh   all 166 documents round-trip against the reference
                             all 166 fragments round-trip against the reference
scripts/verify-captures.sh   3760 messages decoded, 3760 re-encoded byte-identical,
                             198 DIN frames declined by name,
                             4/4 Plug & Charge authorizations verify
```

- A fragment is indexed over every declared element, a document over global
  elements only, so the fragment half is a separate claim — and the bytes Plug &
  Charge signs.
- The scripts need a JDK and the licensed schemas, so they run locally, not in CI.
  Each checks every schema against a pinned SHA-256 (`scripts/schemas.sha256`) and
  fails if the totals above differ from what it measured.
- The capture corpus is GPL and is fetched, never committed. The replay also checks
  that string-table coding would change some captured messages, so it can see that
  regression.
- `scripts/generate.sh` followed by `git diff` checks the committed codec still
  matches its generator.

## Live peers

`examples/v2g_node` runs this crate's engines on a real link — SDP over a veth
pair, then TCP — in a Linux container beside a peer nobody here wrote.

| Peer | Rows | Passing |
|---|---|---|
| **Josev** 0.31.2 (Python, Apache-2.0, `tests/josev.rs`) | Our EVCC at its SECC and its EVCC at ours; -2 and -20, AC and DC; EIM over TCP | 8 of 8 |
| **EVerest** SIL station, everest-demo `2025.10.0` (C++, Apache-2.0, `tests/everest.rs`) | Our EVCC at its station; -2 and -20 DC over TCP, -2 over TLS 1.2, -2 Plug & Charge | 4 of 4 |

- Josev's EXI codec is `exificient`, so its rows are session evidence.
  EVerest's is `libcbv2g`, so its rows are codec evidence too.
- In the Plug & Charge row EVerest verifies the `AuthorizationReq` signature
  this crate made.
- TLS is the harness's: `socat` with OpenSSL, since ISO 15118-2's TLS suite is
  CBC. The crate links no TLS code.
- Without a Docker daemon running Linux containers each test is skipped by
  name. Each runs in its own CI job on every pull request.
- What the sessions found, and whose it was:
  [`tests/interop/PEERS.md`](https://github.com/hupe1980/iso15118/blob/main/tests/interop/PEERS.md).

## What the grammar layers catch

Things a round trip cannot see, because encoder and decoder agree on them:

- **substitution groups** — the abstract head of ISO 15118-2's body choice
  occupies an event code of its own;
- **mixed content** — an untyped character-data production sorted after `EE`;
- **wildcard ordering** — declared elements precede `xs:any`;
- **bounded repetition** — `maxOccurs="2048"` unrolled exactly;
- **repeated choices** — every branch re-offered after an occurrence;
- **string-table partitions** — a value found in the global partition is not added
  to the local one.

Length facets are enforced both ways: six V2G types have an exact length
(`GenChallenge`, ISO 15118-20's `SessionID`, the ECDH key, the contract-key
envelopes), and a truncated one does not decode. See
[EXI](@/docs/exi.md#bounded-everything-in-both-directions).

## Rules above the encoding

Each is a test:

- the ordering graphs of both generations, including the DC renegotiation exits;
- half-duplex in both directions;
- session ids checked against the assigned id; ISO 15118-20 service ids mapped as
  EVerest's `ServiceCategory` assigns them, and a request refused if it comes from
  a message set the session did not select;
- loop budgets armed, so an `Ongoing` loop that repeats promptly still ends;
- the Plug & Charge challenge and metering-receipt bindings.

## Unauthenticated peers

A frame on SDP or SLAC cannot be authenticated, so it must set neither a deadline
nor a queue length:

- a refused SDP answer does not end discovery, and an answer cannot redirect the
  vehicle off the link;
- a forged SLAC attenuation report can move the choice earlier, never later;
- every collection a peer can reach is bounded; terminal events are never dropped;
- a malformed SLAC frame is ignored — `handle_frame` returns no `Result`. See
  [SLAC](@/docs/slac.md).

SLAC has no reference implementation. `tests/slac_layout.rs` pins all thirteen
layouts field by field, checked against
[EVerest's `libslac`](https://github.com/EVerest/libslac); a same-width field swap
in encoder and decoder passes a round trip and fails this.

## Citations

```text
scripts/verify-citations.sh  every [V2G2-nnn] cited in this repository names a
                             requirement ISO 15118-2:2014 defines  (101 of 852)
```

The script fetches ISO 15118-2:2014(E) from a US FHWA rulemaking docket, which
publishes it in full, and fails on a citation that names no requirement. It writes
nothing into the repository. Whether a requirement says what the code claims is
checked by reading. Timing constants match ISO 15118-2 Tables 109 and 111; the
ISO 15118-20 loop budgets are labelled as this crate's policy.
`[V2G2-ED2-1664]`/`[V2G2-ED2-1667]` cite the unpublished second edition and are
outside the script's pattern.

## Beyond the wire format

| Concern | Approach |
|---|---|
| **Fuzzing** | Ten `cargo-fuzz` targets: EXI primitives, every message decoder, fragments, V2GTP, SDP, SLAC frames, SLAC matching, X.509 certificates, and the station's front door from raw TCP bytes at arbitrary read boundaries. The certificate target asserts every borrowed field lies inside the input; the session target that any error from `handle_input` has already closed the session. |
| **Session tests** | A whole DC session per generation through byte vectors with a mock clock; sequence violations, failures, pauses, timer expiry and protocol mismatch each tested. |
| **Hostile peers** | Pipelined bursts, unsolicited responses, forged SLAC key handover, replayed signatures. |
| **Examples** | `evcc_tcp` and `secc_tcp` complete an AC session over a real socket. `v2g_node` plays either role after SDP, every generation and service of the live-peer matrix; `tests/v2g_node_loopback.rs` completes each against itself. |
| **Unsafe** | `#![forbid(unsafe_code)]` crate-wide. |
| **Feature matrix** | `cargo hack check --feature-powerset --depth 2`, 160 combinations. |
| **`no_std`** | CI builds for `thumbv7em-none-eabihf` with `iso2`, `iso20`, `sdp`, `slac`, `evcc`, `secc` and `pnc`. |
| **MSRV** | `cargo check --all-targets` on 1.88 in CI. |

## What is not claimed

- **Not conformance-tested.** The test plans (EN ISO 15118-4/-5, ISO 15118-21,
  ISO/PAS 15118-23) are paid documents run on a bench; "verified against third
  implementations" is the accurate claim.
- **Not tested against production vehicles.** Captures and reference stacks, live
  or not, are not a vehicle population.
- **Two of three certificate profiles** (`SeccCertificate`, `ContractCertificate`)
  are tested only on OpenSSL-minted chains: the public pool has no real leaf for
  them.

## Running it yourself

```sh
cargo test --workspace --all-features
cargo hack check -p iso15118 --feature-powerset --depth 2 --no-dev-deps
cargo +nightly fuzz run session fuzz/corpus/session fuzz/seeds/session
cargo test --test josev --test everest -- --nocapture       # needs Docker

scripts/generate.sh && git diff --exit-code src/generated   # codegen has not drifted
scripts/verify-grammars.sh              # every grammar vs. the reference
scripts/verify-messages.sh              # every message, as document and fragment
scripts/verify-citations.sh             # every [V2G2-nnn] vs. the standard's text
scripts/verify-captures.sh              # every captured message, replayed
```

`scripts/fetch-schemas.sh` downloads the XSDs, which ISO publishes freely. The
citation check needs `pdftotext` and network access; the capture replay `tshark`;
the live peer Docker.
None of this is needed to build or use the crate — `src/generated/` is committed.
