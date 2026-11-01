+++
title = "Certificates"
description = "Validating a V2G certificate chain in iso15118: RFC 5280 path validation under ISO 15118's Annex F profiles and the Amd 1 rules, the contract-key envelope, and what the caller still answers."
weight = 75

[extra]
nav_title = "Certificates"
+++

Plug & Charge asks two questions: is this signature about this session (the
`GenChallenge` binding — see [Plug & Charge](@/docs/plug-and-charge.md)), and is
this key one to trust? This page is the second. They are separate calls.

```rust,ignore
use iso15118::pnc::pki::{self, Policy, Profile, TrustAnchor, TrustAnchors};
use iso15118::pnc::rustcrypto::Backend;

// The trust anchors this side holds, each labelled with where it came from.
let anchors = [TrustAnchor::new(mo_root, "Hubject V2G Root")];

// Leaf first, as CertificateChainType carries it on the wire.
let path = pki::validate(
    &[contract_cert, mo_sub_ca_2, mo_sub_ca_1],
    &TrustAnchors::new(&anchors),
    Policy::iso20(Profile::ContractCertificate),   // or Policy::iso2(..)
    now_unix_seconds,
    &Backend,
)?;

let source = path.anchor_source;          // "Hubject V2G Root"

let emaid = path.subject_common_name();   // [V2G2-108]
let key = path.public_key();              // now worth checking a signature against
```

## What is checked

RFC 5280 §6.1 basic path validation — a signature at every step, validity
windows, `BasicConstraints`, `pathLenConstraint`, `keyCertSign`, the
critical-extension rule, issuer/subject chaining by DER equality — plus the Annex F
profile of the leaf. ISO 15118 pins the rest:

| | |
|---|---|
| Signature algorithm | `ecdsa-with-SHA256` \[V2G2-006\] (`-SHA512` in ISO 15118-20) |
| Curve | `secp256r1` \[V2G2-007\], `secp521r1` in -20 |
| Path length | at most three non-self-signed certificates \[V2G2-009\] |
| Size | at most 800 bytes DER in -2 \[V2G2-010\]; 1 600 under `Policy::iso20` |
| Extensions | Annex F's set; `KeyUsage` and `BasicConstraints` critical |

A trust anchor may sit anywhere in the path: a Private Operator Root anchors SECC
certificates \[V2G2-927\] and may sign leaves directly \[V2G2-868\].

`Policy::iso20` adds what ISO 15118-20 Amd 1's public text states: the size bound,
checked before parsing (`ChainError::TooLarge`), and a certificate valid only
within its issuer's validity \[V2G20-3000\] (`ChainError::OutlivesIssuer`).
`Policy::iso2` keeps ISO 15118-2's rules exactly.

## The profile is a parameter

```rust,ignore
Profile::SeccCertificate            // Table F.2
Profile::ContractCertificate        // Table F.4
Profile::OemProvisioningCertificate // Table F.5
Profile::Unchecked                  // path validation only
```

A certificate does not say what it was issued for, and \[V2G2-925\] makes the
right root and `Domain Component` a validity condition, so the caller names the
profile:

- SECC certificate: `digitalSignature` and `Domain Component` `"CPO"`.
- Contract certificate: `digitalSignature` and `nonRepudiation`.
- Every leaf is `CA = false` \[V2G2-867\].

## Trust anchors and chain selection

`TrustAnchor` pairs a root with its source; `Validated::anchor_source` reports
which one a chain reached. `select_chain` picks, among the chains a holder has,
the one reaching the authorities its peer lists (`TrustAnchors::authorities`) —
across cross-certificates, per RFC 5280 §7.1 \[V2G20-3373\]..\[V2G20-3385\]. A
cross-certificate counts toward the three-certificate path limit, so a
cross-certified path fits beneath a single Sub-CA.

## Parsing

- **DER is canonical or refused** — no indefinite lengths, no over-long lengths, no
  `BOOLEAN` outside `0x00`/`0xFF`, no non-minimal `INTEGER`.
- **ECDSA is converted inside the parser** from X.509's DER `SEQUENCE { r, s }` to
  XMLDSig's `r ‖ s`, so a backend implements one format.

## Crypto and time

`pki::VerifyWith` takes the SEC1 point out of each certificate;
`pnc::rustcrypto::Backend` implements it. `validate` takes Unix seconds, not
`session::Instant`: a validity period needs a wall clock, and a vehicle without
trustworthy time must say so \[V2G2-886\], \[V2G2-910\].

## The contract-key envelope

`CertificateInstallationRes` and `CertificateUpdateRes` deliver a contract
certificate and its private key:

```rust,ignore
use iso15118::pnc::envelope;

let contract_key = envelope::open(
    &res.contract_signature_encrypted_private_key.value,  // IV ‖ ciphertext
    &res.dh_public_key.value,                             // the sender's ephemeral point
    path.public_key(),                                    // the contract certificate's key
    &my_static_agreement_key,
    &Sha2,
    &Aes128,
)?;
```

```text
ContractSignatureEncryptedPrivateKey
  = IV ‖ AES-128-CBC( K, private key )        [V2G2-815], [V2G2-817]
K = leftmost 128 bits of                      [V2G2-818]
    SHA-256( 00 00 00 01 ‖ Z ‖ 01 55 56 )
```

- `open` always checks the delivered scalar against the contract certificate's
  public key \[V2G2-823\]; no call skips it.
- CBC has no integrity of its own: verify the surrounding signature first
  \[V2G2-818\].
- Key agreement is its own trait, `KeyAgreement`, beside `Sign` \[V2G2-822\].
  Sealing needs a fresh random IV \[V2G2-815\]; this crate has no RNG.

## Revocation is the caller's

There is no OCSP and no CRL: a revoked certificate validates like a live one.
Annex F makes OCSP a recommendation because a charging vehicle cannot be assumed
to reach a responder, and \[V2G2-868\] removes it from private environments. A
station's back end already asks a clearing house about the contract;
`Validated::subject_common_name` is the `EMAID` to ask about.

## Evidence

- Chains and the envelope are minted by OpenSSL (`scripts/make-test-pki.sh`,
  `scripts/make-test-envelope.sh`), positive and negative per rule.
- All ten OEM provisioning leaves of Hubject's public test PKI validate to its real
  V2G Root (`tests/pki_pool.rs`, reading `ISO15118_PKI_POOL`). The pool has no real
  leaf for the SECC and contract profiles.
- A fuzz target asserts every borrowed field lies inside the input.
