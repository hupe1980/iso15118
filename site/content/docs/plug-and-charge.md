+++
title = "Plug & Charge"
description = "The ISO 15118 XML signature profile over EXI fragments: what gets digested, why SignedInfo uses a different schema, what verification refuses, and what a valid signature does not prove."
weight = 70

[extra]
nav_title = "Plug & Charge"
+++

A V2G signature is an XML signature in shape only. Everything that makes XMLDSig
hard — canonicalisation choices, arbitrary transforms, `KeyInfo`, enveloped
signatures, `Object` — is nailed shut by ISO 15118, and what is left fits on a
page:

```text
SignedInfo
  CanonicalizationMethod  Algorithm = http://www.w3.org/TR/canonical-exi/
  SignatureMethod         Algorithm = ...#ecdsa-sha256   (or ecdsa-sha512)
  Reference URI="#<Id>"                  one per signed element
    Transforms/Transform  Algorithm = http://www.w3.org/TR/canonical-exi/
    DigestMethod          Algorithm = ...#sha256         (or sha512)
    DigestValue           = H(EXI fragment of that element)
SignatureValue            = ECDSA(H(EXI fragment of SignedInfo))
```

## The two invisible details

Both decide whether anyone else can verify what you produce, and neither is
visible from the XML.

**1. The digested bytes are the element as an EXI _fragment_, not as an EXI
document.** The two differ from their very first event code, because a fragment is
indexed by every element qname the schema *declares* — 281 in ISO 15118-20
`CommonMessages` — and a document only by its global elements, of which there are
54.

**2. `SignedInfo` itself is encoded against the xmldsig schema _alone_** — ISO
15118-2 Annex J — not against the V2G schema set that imports it. OpenV2G
originally shipped the other reading and changed it for interoperability.

Both are pinned here against the EXI reference implementation, which is the only
way to know either of them is right.

## Signing

Every generated message type has a `to_fragment()`, which produces exactly the
bytes the signature covers.

```rust,no_run
use iso15118::pnc::{self, Signed};

let fragment = authorization_req.to_fragment()?;
let signature = pnc::iso2::sign(&[Signed::new("ID1", &fragment)], &sha256, &key)?;
```

`build_signed_info` is exposed separately, so a caller with an offline or remote
signer can obtain the exact bytes to sign without this crate ever holding the key.

For the authorization exchange itself, prefer `sign_authorization` and
`verify_authorization` below: they cover the same bytes and also carry the nonce
that ties the signature to the session.

## Verification is the security boundary

`pnc::{iso2,iso20}::verify` refuses a signature that:

- names a **canonicalisation, transform or digest algorithm outside the profile** —
  a signature is only as strong as the weakest algorithm it is allowed to name;
- carries a `Transforms` list that is anything but exactly one canonical-EXI
  transform. A transform is a program that runs over the signed bytes before they
  are digested; allowing an unexpected one is allowing the signer to decide what
  was signed;
- asks for **MAC truncation** via `HMACOutputLength`. That is the field behind
  CVE-2009-0217, where a verifier that honoured the truncation a signer chose
  would accept a signature over one byte of MAC. ISO 15118 has no HMAC suite at
  all, so a signature naming it is not one this profile describes;
- **covers an element the caller did not supply**, or **leaves one the caller did
  supply uncovered**. Both directions matter: the first is a signature over
  something you are not checking, the second is content nobody signed. XML
  signature wrapping is exactly that, which is why the check is on both sides
  rather than "every reference I recognise verifies".

Digests are compared without an early return, so a mismatch does not leak where it
first differed.

### ...and what it is not allowed to carry at all

`SignatureType` declares four children; ISO 15118 uses two. `KeyInfo` and
`Object` stay in the **grammar** — they have to, or every event code after them
shifts and nothing decodes — but they have no Rust form, and a peer that sends
one is **refused, not skipped**.

Skipping would be the dangerous answer. `KeyInfo` is where XMLDSig carries key
material, and a verifier that takes a key out of the signature it is checking is
checking that signature against itself. ISO 15118 takes the key from the contract
certificate chain in the message body and nowhere else.

The same applies to the `xs:any` wildcards inside `CanonicalizationMethod`,
`DigestMethod` and `SignatureMethod`, and to `Transform`'s second branch — which
is `XPath`, an expression language. All five are refused at the codec, before the
profile checks above ever see them.

ISO 15118-20 defines more than one suite, so the algorithm named in the signature
would otherwise decide which one is in force — a decision an attacker would like
to make. `pnc::iso20::verify` therefore takes the suites the *caller* is willing
to accept and refuses anything else.

## ...and a valid signature is not an authorization

Everything above establishes that the contract's key signed *these bytes*. It says
nothing about *when*, and a signature that could have been made last week is a
signature an eavesdropper can replay. What closes that is the `GenChallenge`: the
station picks sixteen random bytes, the vehicle echoes them inside the element it
signs, and the station checks that what came back is the nonce it issued.

```text
 ISO 15118-2                          ISO 15118-20
 SECC  PaymentDetailsRes              SECC  AuthorizationSetupRes
         GenChallenge = <16 random>            GenChallenge = <16 random>
 EVCC  AuthorizationReq               EVCC  AuthorizationReq
         GenChallenge = <the same>             PnC_AReqAuthorizationMode
         ds:Signature over this                  GenChallenge = <the same>
                                               ds:Signature over that
```

Both halves have to hold, and it is the second one implementations leave out: the
signature is verified, the echoed nonce is never looked at, and the check that was
supposed to bind the signature to this session binds it to nothing. So the two
checks are one call, and there is no way to ask for only the first.

```rust,no_run
use iso15118::pnc::{self, GenChallenge};

// The station's own randomness, sent in `PaymentDetailsRes`. This crate has no RNG.
let challenge = GenChallenge::new(rng.gen());

// ...and later, on the `AuthorizationReq` that came back:
pnc::iso2::verify_authorization(&request, &signature, &challenge, &sha256, &contract_key)?;
```

The vehicle's half is `pnc::iso2::sign_authorization`, which fills in the `Id` and
the echoed challenge and returns the `ds:Signature` for the message header.
ISO 15118-20 has the same pair over `PnC_AReqAuthorizationMode`, plus its suite
policy.

A signature made for another session is a *perfectly valid* signature; it simply
does not authorize this one. That is the whole of what the nonce buys, and it is
[a test](https://github.com/hupe1980/iso15118/blob/main/tests/pnc.rs).

## ...and the same again, for the money

Authorization is not the only exchange where one side signs something the *other*
side chose. The metering receipt is the other, and it is where the energy on the
invoice comes from:

| | ISO 15118-2 | ISO 15118-20 |
|---|---|---|
| Who signs | the **vehicle** | the **station** |
| What | `MeteringReceiptReq` | `SignedMeteringData` |
| Echoed by | — | the vehicle, in `MeteringConfirmationReq` |
| The check that is forgotten | is this the reading *we* metered? | is this the reading *we* issued? |

A vehicle that signs a `MeteringReceiptReq` signs whatever `MeterInfo` is in it.
A station that verifies the signature and files the receipt — without checking
that the reading inside is the one it actually metered — has a cryptographically
impeccable record of a number the vehicle made up. So the check is the same call:

```rust,no_run
use iso15118::pnc;

// `issued` is the `MeterInfo` this station sent in `ChargingStatusRes`.
pnc::iso2::verify_metering_receipt(
    &receipt, &signature, &issued, session_id, &sha256, &contract_key,
)?;
```

It checks the session, the echoed reading and the signature together, and offers
no way to ask for only the last. ISO 15118-20 splits the same exchange the other
way — `pnc::iso20::sign_metering_data` on the station, `verify_metering_data` on
the vehicle, and `verify_metering_confirmation` for the echo, which carries no
signature of its own and is therefore worth *only* the echo check.

## Bring your own cryptography

The hash and the curve are one-method traits, so `pnc` itself contains no
cryptography. The same code runs on RustCrypto, a TPM or a secure element — which
is what ISO 15118-20 anticipates for contract keys, and what a vehicle controller
with a hardware key store needs.

That is the right boundary, but it left the obvious case — a charging station on a
general-purpose CPU, or any test — writing the obvious binding itself. The
`pnc-rustcrypto` feature is that binding and nothing more:

```rust
use iso15118::pnc::rustcrypto::{Sha2, SigningKey};
use iso15118::pnc::{self, Signed};

let key = SigningKey::p256(&[0x42; 32])?;
let fragment = [0x80, 0x01, 0x02];

let signature = pnc::iso2::sign(&[Signed::new("ID1", &fragment)], &Sha2, &key)?;
pnc::iso2::verify(&signature, &[Signed::new("ID1", &fragment)], &Sha2, &key.verifying_key())?;
# Ok::<_, iso15118::pnc::PncError>(())
```

Two things it gets right that are easy to get wrong:

- **Signing is RFC 6979 deterministic**, so even the backend needs no RNG. That is
  not a convenience — a repeated ECDSA nonce leaks the private key.
- **It produces the raw `r ‖ s` pair** XMLDSig wants, not the ASN.1 DER wrapper
  most libraries return by default. That is the mistake that makes a signature
  nobody else can verify.

It also refuses a suite the key is not on, in both directions, because a suite
mismatch is how a peer talks a signature down to the weaker of two algorithms.

## What a valid signature does not prove

<div class="note note-warn">
<span class="note-title">Two limits worth stating plainly</span>

**A verifying key is not a trusted key.** Nothing in this crate parses X.509,
walks a V2G chain, or checks revocation. Verifying with a key you took out of an
unvalidated certificate proves only that whoever sent the certificate also made
the signature. Certificate path validation is the largest gap in this crate and is
named as one — see [What is not here](@/docs/roadmap.md).

**A valid signature does not mean the car is plugged in here.** What the vehicle
signs is the station's random challenge and nothing else: no timestamp, no station
identity. A relay between a victim's vehicle and a distant charger therefore
passes every check the protocol defines, and bills the victim
([arXiv 2512.15966](https://arxiv.org/abs/2512.15966)). That is a gap in the
standard, not in an implementation — the countermeasures are a protocol change
(bind the `EVSEID` into the signed data), mandatory OCSP, or distance bounding,
and none of them is something one implementation can add unilaterally.
</div>
