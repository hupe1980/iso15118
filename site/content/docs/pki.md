+++
title = "Certificates"
description = "Validating a V2G certificate chain: RFC 5280 path validation under ISO 15118's Annex F profiles, the contract-key envelope, and why revocation is not here."
weight = 75

[extra]
nav_title = "Certificates"
+++

Plug & Charge asks two independent questions. **Is this signature about the
session in front of me?** — the `GenChallenge` binding, which
[Plug & Charge](@/docs/plug-and-charge.md) covers. **Is this key one to trust?**
— a certificate chain, which is this page. They are two calls, so that answering
one cannot look like answering both.

```rust,ignore
use iso15118::pnc::pki::{self, Profile};
use iso15118::pnc::rustcrypto::Backend;

// Leaf first, as CertificateChainType carries it on the wire.
let path = pki::validate(
    &[contract_cert, mo_sub_ca_2, mo_sub_ca_1],
    &[mo_root],                 // the trust anchors this side holds
    Profile::ContractCertificate,
    now_unix_seconds,
    &Backend,
)?;

let emaid = path.subject_common_name();   // [V2G2-108]
let key = path.public_key();              // now worth checking a signature against
```

## What ISO 15118 fixes

X.509 is a large grammar and RFC 5280 §6.1 a large algorithm. ISO 15118 pins
almost every input to both, which is what lets a chain validator fit in a
`no_std` crate with no dependencies:

| | |
|---|---|
| Signature algorithm | `ecdsa-with-SHA256` \[V2G2-006\] (`-SHA512` for ISO 15118-20's higher level) |
| Curve | `secp256r1` \[V2G2-007\], `secp521r1` in -20 |
| Path length | at most three non-self-signed certificates \[V2G2-009\] |
| Certificate size | at most 800 bytes DER \[V2G2-010\], which the schema enforces |
| Extensions | Annex F's set; `KeyUsage` and `BasicConstraints` **critical** in every profile |
| Name constraints, policy mapping | not used |

What is implemented is basic path validation — a signature at every step,
validity windows, `BasicConstraints`, `pathLenConstraint`, `keyCertSign`, the
critical-extension rule, issuer/subject chaining by DER equality — plus the
Annex F profile of whichever leaf the caller names.

A trust anchor may sit anywhere in the path, not only above its top. That is
RFC 5280, and ISO 15118 needs it: \[V2G2-927\] makes a Private Operator Root an
anchor for SECC certificates and \[V2G2-868\] has it sign leaves directly.

## The profile is a parameter

```rust,ignore
Profile::SeccCertificate            // Table F.2
Profile::ContractCertificate        // Table F.4
Profile::OemProvisioningCertificate // Table F.5
Profile::Unchecked                  // path validation only
```

Nothing in a certificate says which use it was issued for, and \[V2G2-925\] makes
that a validity condition: a leaf "shall be treated as invalid, if the trust
anchor at the end of the chain does not match the specific root certificate
required for a certain use, or if the required Domain Component value is not
present". A chain that validates beautifully to the *wrong* root is the failure
that requirement names, and only the caller knows which root was meant.

So the same bytes get different answers:

- An SECC certificate needs `digitalSignature` and the `Domain Component`
  `"CPO"`. A contract certificate carries neither.
- A contract certificate needs `digitalSignature` **and** `nonRepudiation` —
  the second is what a metering receipt rests on.
- Every Annex F leaf row is `CA = false`; \[V2G2-867\] says a root shall not
  issue a leaf at all.

## Two places a PKI layer leaks

**DER is canonical or it is refused** — no indefinite lengths, no length written
wider than it needs, no `BOOLEAN` outside `0x00`/`0xFF`, no non-minimal
`INTEGER`. A signature covers a byte string, so a certificate with two legal
spellings is one where signer and verifier can be reading different bytes.

**An X.509 signature is DER and a V2G signature is not.** X.509 carries ECDSA as
`SEQUENCE { r INTEGER, s INTEGER }`; `XMLDSig` uses the fixed-width `r ‖ s` pair.
The conversion happens inside the parser, so a backend implements one signature
format for both a message and a certificate.

## Crypto and time are still yours

`pki::VerifyWith` is a sibling of [`Verify`](@/docs/plug-and-charge.md) rather
than a widening of it. `Verify` suits a key this side *holds*; a chain's keys are
not configuration — there is a new one at every step, inside the certificate
below it — so `VerifyWith` takes the SEC1 point out of the DER.
`pnc::rustcrypto::Backend` implements it.

`validate` takes seconds since the Unix epoch, deliberately not
`session::Instant`: that is a monotonic count for measuring timeouts, and a
validity period needs a wall clock. \[V2G2-886\] lets a vehicle choose its own
time accuracy and \[V2G2-910\] makes checking validity periods a *should*, so a
vehicle with no trustworthy time has to say so rather than pass a number it does
not have.

## The one secret that crosses the wire

`CertificateInstallationRes` and `CertificateUpdateRes` deliver a contract
certificate **and its private key**. `pnc::envelope` is that exchange:

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

Every choice is pinned by §7.9.2.4.3:

```text
ContractSignatureEncryptedPrivateKey
  = IV ‖ AES-128-CBC( K, private key )        [V2G2-815], [V2G2-817]
K = leftmost 128 bits of                      [V2G2-818]
    SHA-256( 00 00 00 01 ‖ Z ‖ 01 55 56 )
```

**The third argument is not optional.** \[V2G2-823\] has the vehicle verify that
the delivered scalar is "strictly smaller than the order of the base point, and
multiplication of the base point with this value must generate a key matching the
public key of the contract certificate". `open` does exactly that and offers no
call that skips it: a vehicle that installs an unchecked key has a contract it
can never use and cannot diagnose — every signature it makes is valid, over the
wrong key, and every station refuses it.

**CBC carries no integrity of its own.** \[V2G2-818\] NOTE 8: "The authenticity
of the transmission is ensured by the surrounding signature." Verify that first;
the key-match is the second line.

**Key agreement is a different capability from signing.** \[V2G2-822\] requires
the `keyAgreement` flag on exactly the certificates whose keys do this, so
`KeyAgreement` is a trait beside `Sign` and `rustcrypto` gives them separate
types. Sealing takes the ephemeral key and an IV that must be "randomly
generated ... and never reused" \[V2G2-815\] — this crate has no RNG.

## What is not here: revocation

<div class="note note-warn">
<span class="note-title">A validated chain says a certificate was issued, not that it was not withdrawn</span>

There is no OCSP and no CRL. A revoked contract certificate validates here
exactly as a live one does.

The standard says why that is hard rather than merely undone. Annex F's own note:
*"as access to OCSP services can not be guaranteed during charging, the usage of
OCSP can only be recommended but not be mandatory"* — and \[V2G2-868\] removes it
from private environments altogether. A vehicle in a basement has no path to a
responder.

The answer belongs where it already exists. A station's back end is asking a
clearing house whether to authorize this contract at all;
`Validated::subject_common_name` is the `EMAID` to ask about, and that answer
covers revocation with everything else the operator knows. An OCSP client inside
a sans-I/O crate would put a network round trip in a charge loop with a 25 ms
budget.
</div>

## Evidence

The chains in `tests/fixtures/pki` are minted by **OpenSSL**
(`scripts/make-test-pki.sh`), and the contract-key envelope is sealed by OpenSSL
too (`scripts/make-test-envelope.sh`) — the ECDH, the KDF and the cipher all done
by a third implementation from the requirement text. That matters for the same
reason `exificient` matters one layer down: a parser checked only against an
encoder from the same workspace is checked against its own opinions, and for a
key schedule the failure modes are symmetric — a counter left out of the KDF,
`OtherInfo` in the wrong order, the digest truncated from the wrong end, the IV
read off the tail. Seal-then-open passes for every one of them.

A fuzz target over the certificate parser asserts more than "does not panic":
that every borrowed field lies inside the input.

What this is **not** is a chain from a published V2G test pool — Hubject's and
OPNC's need registration — so the claim is "the Annex F profile is enforced
against certificates a third implementation encoded", which is weaker than
interoperability. See [Verification](@/docs/verification.md).
