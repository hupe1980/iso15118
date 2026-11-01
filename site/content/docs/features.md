+++
title = "Feature flags"
description = "Every iso15118 feature flag, what it gates, and how to compile only the message sets and roles your target actually needs."
weight = 80
+++

Flags are additive and every one gates real code. There are eighteen flags besides `default`.

```toml
default = ["std", "iso2", "iso20", "sdp", "slac", "evcc", "secc", "pnc"]
```

## Environment

| Flag | Effect |
|---|---|
| `std` | `std::error::Error` implementations and `Ipv6Addr` helpers. Turn it off for a microcontroller. |

`alloc` is required, not a feature: decoded EXI strings cannot borrow from the
input.

## Roles

| Flag | Effect |
|---|---|
| `evcc` | The vehicle-side session driver. |
| `secc` | The charger-side session driver. |

A role driver appears only with at least one protocol generation enabled.

## Protocols

| Flag | Effect |
|---|---|
| `iso2` | ISO 15118-2:2014 — all 34 body messages, the ordering graph and the charging-profile rule. |
| `iso20` | Shorthand for all six -20 energy-transfer schema sets. |
| `iso20-common` | ISO 15118-20 `CommonMessages`. Implied by each of the six below. |
| `iso20-ac` | AC charging. |
| `iso20-dc` | DC charging. |
| `iso20-wpt` | Wireless power transfer. |
| `iso20-acdp` | Automated connection device — the pantograph. |
| `iso20-ac-der-iec` | ISO 15118-20 Amd 1 `AC_DER_IEC`: AC with distributed-energy-resource control, IEC grid codes (service id 10). Its own schema set — the AC messages as the DER schema extends them — so it does not need `iso20-ac`. |
| `iso20-ac-der-sae` | The same for SAE grid codes (service id 11). |

There is no `iso20-bpt` (the `BPT_*` types live inside AC and DC) and no
`iso20-mcs` (MCS runs the DC message set). A pantograph session needs
`iso20-acdp` and `iso20-dc`.

## Link and discovery

| Flag | Effect |
|---|---|
| `sdp` | SECC discovery: the codec and the vehicle-side retry engine. |
| `slac` | ISO 15118-3 frames and the matching state machines for both roles. |

## Security

| Flag | Effect |
|---|---|
| `pnc` | The Plug & Charge signature profile. The hash and the curve are traits, so this pulls in no cryptography. |
| `pnc-rustcrypto` | A concrete backend for those traits: `sha2`, `p256`, `p521`, and `aes` with `cbc` for the contract-key envelope. |

`pnc-rustcrypto` is the only flag that adds a dependency tree; it is off by
default so a secure element can implement the traits instead.

## Integration

| Flag | Effect |
|---|---|
| `serde` | `Serialize`/`Deserialize` on the message types and the session state — what -20 pause and resume across a power cycle needs. `Protocol` and `Protocols` serialise as their stable short names, so serde, `Display` and a hand-written `match` produce one spelling. |
| `tracing` | Structured events from the engines — message, phase, protocol, expired timer. No spans and no payload values (a `SessionID` or certificate identifies a person). Compiles to nothing when off. |

## Compiling only what you need

A DC-only embedded vehicle controller:

```sh
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

gets exactly that; other message sets and their grammar tables are not in the
binary. See [Embedded and `no_std`](@/docs/embedded.md).

## Additivity

Enabling a feature never removes or changes an item. CI checks every flag alone
and every pair with `cargo hack check --feature-powerset --depth 2` — 160
combinations — warnings denied.
