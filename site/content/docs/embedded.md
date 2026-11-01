+++
title = "Embedded and no_std"
description = "Running the ISO 15118 protocol stack on a microcontroller: why alloc is required, how to bound memory against a hostile peer, which features to leave out, and what you wire in."
weight = 90

[extra]
nav_title = "Embedded & no_std"
+++

CI builds the protocol core for `thumbv7em-none-eabihf` without `std`, with
`iso2`, `iso20`, `sdp`, `slac`, `evcc`, `secc` and `pnc` on. What changes on a
vehicle controller:

## `alloc` is required

In bit-packed EXI a string or `hexBinary` is a run of bit-shifted code points or
bytes, not contiguous in the input, so decoded values are owned. Every length is
bounded by its schema facet and by the bytes remaining before anything is
reserved. You need an allocator — `embedded-alloc` or a static arena works.

## Bound the buffers

The default maximum V2GTP payload is 1 MiB. Set it to what the target holds:

```rust,no_run
use iso15118::evcc::{Evcc, EvccConfig};

let mut evcc = Evcc::new(EvccConfig {
    max_payload_len: 16 * 1024,
    ..EvccConfig::default()
});
```

It bounds the reassembly buffer, every decode (rejected at the frame header), and
what an encode may produce. `max_pending_frames` bounds whole frames held
undrained.

## Leave out what you do not speak

Features gate real code, grammar tables included:

```sh
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

Everything else is not in the binary — see [Feature flags](@/docs/features.md).
`pnc` without `pnc-rustcrypto` gives the signature profile as traits, so a secure
element can hold the key.

## Randomness, clock, stack

- **No RNG.** Session ids, `GenChallenge`, SLAC run ids, sounding payloads and the
  NMK come from your entropy source; each call site takes the bytes. The
  `pnc-rustcrypto` backend signs deterministically (RFC 6979).
- **Clock.** `session::Instant` is a monotonic millisecond count — a `SysTick`
  counter works. Arithmetic saturates.
- **Stack.** Decoders recurse with message nesting; depth is capped before
  recursing.
- **Flash.** A content model is five integer slices, not a state table, so a
  `maxOccurs="2048"` particle costs one `u32`.
