+++
title = "Verification"
description = "How the iso15118 wire format is checked against the EXI reference implementation: 298 grammars, 121 messages as documents and fragments, nine fuzz targets, and what each layer found."
weight = 100
+++

Round-tripping your own encoder through your own decoder proves that they agree
with each other. It proves nothing about whether a charger will understand you.

This crate is checked in four layers, in increasing strength. Only the last two
say anything about other implementations.

| Layer | What it proves |
|---|---|
| **Property tests** | `decode(encode(m)) == m`, and bit reader/writer duality. Self-consistency, and nothing more. |
| **Layout pins** | Every SLAC message encoded with a distinct byte per field and asserted verbatim, because SLAC has no reference implementation to differ against. Pins field order, offsets, widths and reserved gaps — the things a round trip cannot see. |
| **Golden vectors** | Real ISO 15118-20 frames from an independent C++ implementation, walked event by event and re-encoded byte for byte — including a negative test showing strict-mode widths *cannot* decode the same bytes. |
| **Differential grammars** | Every derived state and production compared against `exificient`, the EXI reference implementation, for all **298** element grammars. Golden vectors cover the paths they take; this covers the whole grammar. |
| **Differential messages** | A schema-valid instance of **every** message type, encoded by the reference implementation as a document **and** as a fragment, decoded and re-encoded byte for byte by the generated codec. **121 × 2.** |

```text
scripts/verify-grammars.sh   all 2 / 80 / 54 / 42 / 48 / 38 / 34 element
                             grammars agree with the reference  (298 total)
scripts/verify-messages.sh   all 121 documents round-trip against the reference
                             all 121 fragments round-trip against the reference
```

The fragment half is a separate claim, not a restatement: a fragment is indexed by
every element qname the schema *declares* rather than by its global elements, so
the same message encodes differently from its very first event code. Those are the
bytes Plug & Charge signs.

Both scripts need a JDK and the ISO schemas, so they are scripts rather than CI
jobs — the schemas are licensed and are not redistributed. `scripts/generate.sh`
followed by `git diff` is the third check: that the committed codec still matches
its generator.

## What the differential layers found

Nine defects that no round-trip test could:

- **substitution groups** — ISO 15118-2 routes all 34 body messages through one
  choice, and the *abstract* head occupies an event code of its own. Dropping it
  shifts every later message down by one;
- **mixed content** — contributes an untyped character-data production that sorts
  **after** `EE`, and only inside the content region;
- **wildcard ordering** — declared elements precede `xs:any` regardless of schema
  order;
- **bounded repetition** — `maxOccurs="2048"` must be unrolled exactly, not
  approximated by a loop;
- **repeated choices** — after one occurrence the grammar re-offers *every* branch,
  not one event code;
- **string-table partitions** — a value found in the *global* partition must not be
  added to the local one. Getting this wrong desynchronises the moment one string
  appears under two element names, which is most real messages;
- an **out-of-range restricted integer** that decoded but could not re-encode;
- an **integer overflow** adding the epoch back to a date-time year;
- a **SLAC frame buffer one byte too small**, silently swallowed by a send path
  that dropped errors.

## What the scripts cannot check

They prove the encoding. They say nothing about whether the flow above it is the
one ISO wrote, or about what an unauthenticated peer can make the engines do.
Reading the layers against the standards and against both live open-source
implementations found five more, each now a test:

- **DC renegotiation deadlocked** — the graph demanded the isolation test before
  every `PowerDeliveryReq(Start)`, including the one after a renegotiation, which
  arrives with the contactors closed and no cable check coming. Both generations
  had it;
- **ISO 15118-20 conflated schedule renegotiation with service renegotiation**,
  sending `PowerDeliveryReq(ScheduleRenegotiation)` back to service selection;
- **the engines read ahead of the protocol** — V2G is half-duplex, and several
  requests are legal repeatedly, so a peer could queue events without bound. The
  vehicle side was worse: it took *any* response to any request, because the
  ordering graph constrains requests only;
- **SLAC took the network key from whoever answered first** — the run id is
  broadcast in the clear, so a forged handover won the race;
- **the loop timers were constants and nothing else** — declared, cited, and never
  armed, so a cable-check loop had no bound at all.

And two in the EXI layer that fuzzing could not reach: a fractional value whose
reversed digit string came off the wire and overflowed when un-reversed, and the
non-strict second-level escape code being accepted below a particle's `minOccurs`.

## What a second reading found

A later pass over the same code, against the standards and against what EVerest
and Josev do, found eight more. None of them is a wire-format defect — the
differential scripts had already settled that — and none of them would fail a
happy-path session, which is exactly why they were still there.

- **ISO 15118-20 service ids were mapped to the wrong flows.** The standard
  assigns 1 `AC`, 2 `DC`, 3 `WPT`, 4 `DC_ACDP`, and 5–7 to their bidirectional
  twins — the numbers EVerest's `ServiceCategory` and Josev's `ServiceV20` both
  use; the mapping here paired them off differently. A wireless session would have been
  routed down the pantograph flow — asked to check a pantograph in that it does
  not have — and a pantograph session down the wireless one. Only plain `DC`
  happened to land on the right answer, which is why an ordinary DC test suite
  would never have noticed;
- **a service renegotiation inherited a schedule renegotiation's exemption from
  the DC isolation test.** The two are opposite cases: one keeps the contactors
  closed, the other opens them. A session that renegotiated its schedule and then
  its service could close a DC contactor on a cable nobody had re-checked;
- **the vehicle could pipeline.** Half-duplex was enforced on the side that
  *reads* and not on the side that *sends*, so an application driving a charge
  loop off a tick rather than off a response would have queued requests the
  ordering graph is unable to object to — it constrains which request, not when;
- **the vehicle adopted a session id from any response while its own was zero.**
  "Has one been assigned" was inferred from "is the id non-zero", so a station
  that answered `SessionSetupRes` with the all-zero id switched the check off for
  the rest of the session instead of failing;
- **the station could answer the wrong question**, or answer when none had been
  asked. The vehicle would have caught it; catching it locally costs one string
  comparison and turns a field report into a failed unit test;
- **a SLAC run in progress could be restarted by anything on the segment.**
  `CM_SLAC_PARM.REQ` is broadcast and unauthenticated, and only a *matched*
  station refused one. A bystander could abort every matching run within earshot,
  one frame at a time, and the vehicle would see nothing but a station that never
  finishes;
- **two ISO 15118-20 loop budgets cited a spec section nobody had read.** The
  values are reasonable and are still the defaults; what changed is that they now
  say they are this crate's judgement. A constant that cites a requirement it does
  not come from cannot be questioned, which is worse than one that admits it is a
  guess;
- **the grammar runtime assumed a repeated particle is never a choice.** True of
  every V2G schema, and the arithmetic silently depended on it. The generator now
  refuses to emit a shape that would break it, rather than emitting one that
  encodes at the wrong width.

The same pass added the check that was missing rather than wrong: a Plug & Charge
signature was verified but never tied to the session it arrived in. See
[the `GenChallenge` binding](@/docs/plug-and-charge.md).

## What a third reading found

Reading again, in the places the first two passes had not gone — the SLAC codec,
the generator's facet handling, and the API shapes themselves:

- **`xs:length` was being lowered to `xs:maxLength`, and `xs:minLength` was
  dropped.** Six V2G types have an exact length and they are precisely the
  security-relevant ones — both `GenChallenge`s, ISO 15118-20's `SessionID`, the
  ECDH public key, the three encrypted-contract-key envelopes — so a truncated
  one decoded, and would have been re-encoded into a message no conforming peer
  accepts. See [Bounded everything](@/docs/exi.md#bounded-everything-in-both-directions).
  Enforcing it immediately found **two more defects of its own**: the sample
  generator had been emitting three-byte stand-ins for every `base64Binary`, so
  the differential run had never once exercised a real 133-byte key; and this
  crate's own README had been showing a four-byte ISO 15118-20 `SessionID` since
  it was written — legal in ISO 15118-2, not in -20, and a compiled doctest, so
  it stopped building the moment the facet was enforced;
- **a SLAC engine reported malformed frames as errors.** It listens promiscuously
  on a shared, unauthenticated segment, so a bad frame is weather, not an
  exception — and a caller that acted on the error would let anything within
  earshot end somebody else's matching run with one packet. `handle_frame` no
  longer returns a `Result` at all. See [SLAC](@/docs/slac.md);
- **the SLAC message writer was bounded by the caller's buffer rather than by the
  message.** A field list that did not add up to the declared length would spill
  into whatever followed instead of failing — the exact shape of a defect this
  project has already had once, a `CM_ATTEN_CHAR.IND` one byte short. Each
  encoder now derives its length from what it wrote, and the two cannot disagree;
- **the design notes claimed all four engines share one five-method shape**, when
  two of them do not — `sdp::Discovery` and the SLAC engines have no `respond`,
  and their input method does not return a `Result`. Documentation, but a reader
  meets it before any code, and this page is where that counts as a defect.

And one check that was missing rather than wrong, the sibling of the last pass's:
a metering receipt was verified as a signature and never against the reading the
station actually metered. See
[the money](@/docs/plug-and-charge.md#and-the-same-again-for-the-money).

## What a fourth reading found

This pass went looking for the layers with the *weakest evidence* rather than the
most suspicious code — and found that the argument at the top of this page had a
hole in it.

- **SLAC had no external check at all.** Its thirteen message layouts are
  hand-transcribed from ISO 15118-3 and HomePlug GreenPHY, and what tested them
  was a round trip plus one four-byte endianness assertion. That is precisely the
  evidence this page opens by saying is not evidence: swap two fields of the same
  width in both the encoder and the decoder and every test still passes, while
  the frame is wrong on the wire and fails against every real modem.

  There is no reference implementation to run for SLAC, so `tests/slac_layout.rs`
  is the next strongest thing: every message encoded with a distinct byte per
  field and asserted verbatim — pinning field order, offsets, widths, the
  reserved gaps and both `MVFLength` constants. The layouts turned out to be
  **correct**, checked field for field against
  [EVerest's `libslac`](https://github.com/EVerest/libslac); what was missing was
  anything recording that. A mutation test demonstrates the gap it closes: a
  same-width field swap applied to encoder *and* decoder passes every
  pre-existing SLAC test and fails the new one.
- **ISO 15118-20 had no end-to-end test.** Half the crate, every layer tested
  alone — the sequencer had unit tests, the messages round-tripped, the drivers
  were exercised against ISO 15118-2. Nothing put the three together across the
  seam that is -20's alone: one session interleaving two V2GTP payload types and
  two schema sets. `tests/session_iso20.rs` is that session, and writing it
  failed on the first run.
- **A vehicle could not encode its own `SessionSetupReq` in ISO 15118-20.** The
  driver stamped the session id only *after* the station had assigned one, which
  left the first message of the session for the application to fill in — and
  -20's `SessionID` is exactly eight bytes, so an application that left it empty
  produced a message that would not encode at all. The fix is the better design
  regardless: every request is stamped, and rejoining a paused session moved to
  `EvccConfig::rejoin`, said once in configuration instead of hand-placed in the
  one message out of thirty where it belongs.

The generator's `--why` report came out clean on the same pass: the only types it
declines to express are the seven xmldsig ones ISO 15118 never uses, and every
field it declines is refused at decode rather than skipped — including the
`KeyInfo` a `ds:Signature` must never be allowed to smuggle in. See
[Plug & Charge](@/docs/plug-and-charge.md).

## Beyond the wire format

| Concern | Approach |
|---|---|
| **Fuzzing** | Nine `cargo-fuzz` targets: EXI primitives, every message decoder, fragment decoders, V2GTP, SDP, SLAC frames, SLAC matching, and the whole charging-station front door from raw TCP bytes with arbitrary read boundaries. Committed seed corpora get past the format gates random input never guesses. |
| **Session tests** | A whole DC charging session **per generation**, vehicle to station through byte vectors, with a mock clock — the ISO 15118-20 one crossing two V2GTP payload types and two schema sets in a single session. Sequence violations, failure responses, pauses, timer expiry and protocol mismatch each have a test. |
| **Hostile-peer tests** | A pipelined burst, a response to a question nobody asked, a forged SLAC key handover, a bystander's sounding packets, a bystander restarting somebody else's matching run, a Plug & Charge signature replayed from another session. Each is a peer inside the framing and outside the protocol, which is where a fuzzer's random bytes rarely land. |
| **Examples that run** | Two examples complete an AC session over a real socket, so the integration story cannot rot into prose. |
| **Signature tests** | Every refusal in the Plug & Charge profile has a test, including both directions of the coverage check, the suite-downgrade attempt, the truncation request, a signature replayed from another session, and a meter reading the vehicle made up. |
| **Timing** | Mock-clock tests for the spec timers, with each constant saying where it comes from — a requirement number where there is one, and "this crate's policy" where the value is derived — including the loop budgets, where the test is that the repeats do *not* extend them. |
| **Unsafe** | `#![forbid(unsafe_code)]` crate-wide, no exceptions. |
| **Feature matrix** | `cargo hack check --feature-powerset --depth 2`, 129 combinations. |
| **`no_std`** | CI builds for `thumbv7em-none-eabihf` with `std` off and everything else on. |
| **MSRV** | Declared and CI-enforced over the whole workspace — library, tests, doctests and examples — because an MSRV only the library meets is not one a reader can build against. |

## Running it yourself

```sh
cargo test --workspace --all-features
cargo hack check -p iso15118 --feature-powerset --depth 2 --no-dev-deps
cargo +nightly fuzz run session fuzz/corpus/session fuzz/seeds/session

scripts/generate.sh && git diff --exit-code src/generated   # codegen has not drifted
scripts/verify-grammars.sh              # every grammar vs. the reference
scripts/verify-messages.sh              # every message, as document and fragment
```

The last three need a JDK and the fetched schemas. `scripts/fetch-schemas.sh`
downloads the XSDs, which ISO publishes freely; the spec *texts* are paid
documents and nothing here depends on having them.
