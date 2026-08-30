+++
title = "Feature flags"
description = "Every iso15118 feature flag, what it gates, and how to compile only the message sets and roles your target actually needs."
weight = 80
+++

One crate, so downstream manages one version and cross-protocol types are shared
without a semver dance. Everything is additive: every combination compiles, and CI
proves it over 129 of them.

**Every flag gates real code.** A flag that gates nothing is a promise.

```toml
default = ["std", "iso2", "iso20", "sdp", "slac", "evcc", "secc", "pnc"]
```

## Environment

| Flag | Effect |
|---|---|
| `std` | Adds `std::error::Error` implementations and `Ipv6Addr` helpers. Off by default nowhere — but turning it off is what builds for a microcontroller. |

`alloc` is **not** a feature; it is a requirement. In bit-packed EXI a decoded
string is a run of bit-shifted code points, so it can never borrow from the input
and has to be owned.

## Roles

| Flag | Effect |
|---|---|
| `evcc` | The vehicle-side session driver. |
| `secc` | The charger-side session driver. |

A role driver needs a protocol to drive: `secc` on its own compiles and gates
nothing, because with no message set there is no flow.

## Protocols

| Flag | Effect |
|---|---|
| `iso2` | ISO 15118-2:2014 — all 34 body messages. |
| `iso20` | Shorthand for all four -20 schema sets. |
| `iso20-common` | ISO 15118-20 `CommonMessages`. Implied by each of the four below. |
| `iso20-ac` | AC charging. |
| `iso20-dc` | DC charging. |
| `iso20-wpt` | Wireless power transfer. |
| `iso20-acdp` | Automated connection device — the pantograph. |

There is no `iso20-bpt`. Bidirectional power transfer is not a schema set: the
`BPT_*` types live inside AC and DC and are generated with them.

## Link and discovery

| Flag | Effect |
|---|---|
| `sdp` | SECC discovery: the codec and the vehicle-side retry engine. |
| `slac` | ISO 15118-3 frames and the matching state machines for both roles. |

## Security

| Flag | Effect |
|---|---|
| `pnc` | The Plug & Charge signature profile. The hash and the curve are traits, so this pulls in no cryptography. |
| `pnc-rustcrypto` | A concrete backend for those traits: `sha2`, `p256`, `p521`. |

`pnc-rustcrypto` is the only flag that adds a dependency tree. It is off by
default because a controller with a secure element wants the traits and not an
implementation of them — but it is what a charging station on a general-purpose
CPU, and every test, would otherwise have to write itself.

## Integration

| Flag | Effect |
|---|---|
| `serde` | `Serialize`/`Deserialize` on the message types and the session state. What -20 pause and resume across a power cycle needs. |
| `tracing` | Structured spans and events from the protocol engines. |

## Compiling only what you need

A DC-only embedded vehicle controller:

```sh
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

gets exactly that. The message sets it does not enable **do not exist** in the
binary — grammar tables included. See [Embedded and `no_std`](@/docs/embedded.md)
for what that costs and what else to configure.

## The additivity contract

Additive means enabling a feature never removes or changes an item, so two
dependents of this crate in one build cannot break each other. CI enforces it with
`cargo hack check --feature-powerset --depth 2`, which is 129 combinations, on
every change.

The one place features affect *presence* rather than content is module gating:
`secc` and `evcc` only appear when at least one protocol generation is also
enabled, because a driver with no message set would be an empty shell. That still
only decides when a module appears, never what it contains.
