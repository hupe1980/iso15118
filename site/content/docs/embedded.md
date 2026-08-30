+++
title = "Embedded and no_std"
description = "Running the ISO 15118 protocol stack on a microcontroller: what alloc buys you, how to bound memory against a hostile peer, and which features to leave out."
weight = 90

[extra]
nav_title = "Embedded & no_std"
+++

The protocol core builds for `thumbv7em-none-eabihf` with `std` off and everything
else on, and CI checks that on every change. This page is what to do differently
when the target is a vehicle controller rather than a server.

## `alloc` is required, and why

`alloc` is not a feature you can turn off. In bit-packed EXI a string is a run of
bit-shifted Unicode code points and a `hexBinary` is a run of bit-shifted bytes;
neither is contiguous in the input unless it happens to land byte-aligned. Zero-copy
borrowing from the input buffer is therefore not *chosen against* — it is not
expressible.

What the codec gives you instead is that **every length is bounded by its schema
facet, and by the bytes actually remaining, before anything is reserved.** A
forged length field cannot make the decoder allocate for a message the stream
could never contain.

If you are on a target with no allocator at all, this crate is not usable as-is.
If you have one — `embedded-alloc`, or a static arena — it is.

## Bound the buffers yourself

The crate default for one V2GTP payload is one mebibyte: far above the largest real
message and far below what would let a peer exhaust a server. On a controller with
64 KiB of RAM that default is meaningless, so set it to what you can actually hold:

```rust,no_run
use iso15118::evcc::{Evcc, EvccConfig};

let mut evcc = Evcc::new(EvccConfig {
    max_payload_len: 16 * 1024,
    ..EvccConfig::default()
});
```

That single number is what stops a peer from making the receiver buffer more than
it has. It bounds:

- the raw reassembly buffer, which by construction holds at most one frame;
- every decode, since a message longer than the limit is rejected at the frame
  header, before the EXI decoder sees a byte;
- what an encode may produce before it is refused.

Alongside it, the connection caps how many *whole undrained frames* it will hold —
V2G is half-duplex, so a peer that pipelines is already outside the protocol.

## Leave out what you do not speak

Feature flags gate real code, including the grammar tables. A controller that only
ever does ISO 15118-20 DC compiles that and nothing else:

```sh
cargo add iso15118 --no-default-features --features evcc,iso20-dc,pnc
```

The ISO 15118-2 message set, the AC/WPT/ACDP sets, the charger-side driver and the
SLAC engines are then not merely unused — they are not in the binary. See
[Feature flags](@/docs/features.md).

`pnc` without `pnc-rustcrypto` is the right default here: you get the signature
profile as three traits and pull in no cryptography, so a hardware key store or a
secure element implements them and the private key never reaches this crate.

## No RNG, and that is deliberate

Session ids, SLAC run ids, sounding payloads and the network membership key must
all be unpredictable, and there is no randomness in this crate. Every place one is
needed takes the bytes as configuration and says so in its documentation.

On a controller that means wiring your hardware entropy source to those call
sites — which is exactly the decision you want to be making explicitly, because a
predictable session id is a session anyone can resume and a guessable NMK is a
network anyone can join.

The one place randomness would normally be unavoidable is ECDSA, and the
`pnc-rustcrypto` backend signs with RFC 6979 determinism, so even that needs none.

## The clock

`session::Instant` is a monotonic millisecond count you supply, so a `SysTick`
counter works as well as `std::time::Instant`. The only requirement is
monotonicity: a wall clock that jumps backwards over an NTP step would make a
deadline appear to un-expire. Arithmetic on it saturates rather than wrapping, so
neither a backwards step nor the end of the timeline can produce a deadline in the
past by accident.

## Stack depth

Generated decoders recurse with the message structure, so nesting is capped and
the cap is enforced before the recursion happens rather than discovered by the
stack. The deepest ISO 15118 schema nests well under a dozen levels; a stream that
claims more is malformed or hostile.

## What the codegen did for you

Generated code carries no state tables. A content model's whole event-code
arithmetic is five short integer slices that a shared interpreter drives — the
equivalent unrolled state machine for one `maxOccurs="2048"` particle would be
2049 states, and ISO 15118-20 has several. Here each costs one extra `u32`.

That is not a micro-optimisation; it is the difference between the generated codec
fitting in flash and not.
