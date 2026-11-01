+++
title = "Plug & Charge"
description = "The ISO 15118 XML signature profile over EXI fragments in iso15118: what gets digested, how SignedInfo is encoded, what verification refuses, the challenge and metering bindings, and what a valid signature does not prove."
weight = 70

[extra]
nav_title = "Plug & Charge"
+++

ISO 15118 restricts XMLDSig to one shape:

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

## Three details that decide interoperability

1. **Digests cover the element as an EXI _fragment_**, not a document. Fragments
   are indexed over every declared element (281 in ISO 15118-20 `CommonMessages`),
   documents over global elements only (54) — they differ from the first event code.
2. **`SignedInfo` is encoded against the xmldsig schema alone** (ISO 15118-2
   Annex J), not the V2G schema set that imports it.
3. **The canonical-EXI URI is written out both times.** Canonical EXI requires a
   string-table reference for the second; `libcbv2g`, the codec EVerest ships, has
   no string table and cannot decode one. This crate signs the literal form and
   verifies either:

```rust,no_run
use iso15118::exi::ValueCoding;
# use iso15118::pnc;
# fn f(sig: &iso15118::iso2::Signature) -> Result<(), pnc::PncError> {
let field = pnc::iso2::signed_info_bytes(sig, ValueCoding::Literal)?;
let canonical = pnc::iso2::signed_info_bytes(sig, ValueCoding::Referenced)?;
# Ok(()) }
```

Algorithms, transforms and coverage are checked once on the decoded `SignedInfo`;
only the serialisation differs between the two attempts. All three details are
pinned — see [Verification](@/docs/verification.md).

## Signing

`to_fragment()` on every generated message type produces the bytes a signature
covers.

```rust,no_run
use iso15118::pnc::{self, Signed};

let fragment = authorization_req.to_fragment()?;
let signature = pnc::iso2::sign(&[Signed::new("ID1", &fragment)], &sha256, &key)?;
```

`build_signed_info` gives a remote or offline signer the exact bytes to sign. For
authorization, use `sign_authorization` / `verify_authorization` below.

## What verification refuses

`pnc::{iso2,iso20}::verify` refuses a signature that:

- names a canonicalisation, transform or digest algorithm outside the profile;
- has a `Transforms` list other than exactly one canonical-EXI transform;
- carries `HMACOutputLength` (MAC truncation, CVE-2009-0217);
- covers an element the caller did not supply, or leaves a supplied one uncovered
  (signature wrapping).

`KeyInfo`, `Object`, `xs:any` wildcards and `XPath` transforms are refused at the
codec: the key comes from the contract certificate chain, never from the signature.
Digests compare in constant time. `pnc::iso20::verify` takes the suites the caller
accepts and refuses others.

## The challenge binds the signature to the session

```text
 ISO 15118-2                          ISO 15118-20
 SECC  PaymentDetailsRes              SECC  AuthorizationSetupRes
         GenChallenge = <16 random>            GenChallenge = <16 random>
 EVCC  AuthorizationReq               EVCC  AuthorizationReq
         GenChallenge = <the same>             PnC_AReqAuthorizationMode
         ds:Signature over this                  GenChallenge = <the same>
                                               ds:Signature over that
```

Signature and echoed challenge are checked in one call; there is no way to check
only the signature.

```rust,no_run
use iso15118::pnc::{self, GenChallenge};

// The station's own randomness, sent in `PaymentDetailsRes`. This crate has no RNG.
let challenge = GenChallenge::new(rng.gen());

// ...and later, on the `AuthorizationReq` that came back:
pnc::iso2::verify_authorization(&request, &signature, &challenge, &sha256, &contract_key)?;
```

`sign_authorization` is the vehicle's half. ISO 15118-20 has the same pair over
`PnC_AReqAuthorizationMode`.

## The metering receipt

| | ISO 15118-2 | ISO 15118-20 |
|---|---|---|
| Who signs | the vehicle | the station |
| What | `MeteringReceiptReq` | `SignedMeteringData` |
| Echoed by | — | the vehicle, in `MeteringConfirmationReq` |
| Also checked | the reading is the one this station metered | the reading is the one this station issued |

```rust,no_run
use iso15118::pnc;

// `issued` is the `MeterInfo` this station sent in `ChargingStatusRes`.
pnc::iso2::verify_metering_receipt(
    &receipt, &signature, &issued, session_id, &sha256, &contract_key,
)?;
```

Session, echoed reading and signature are checked together. ISO 15118-20:
`sign_metering_data` (station), `verify_metering_data` and
`verify_metering_confirmation` (the echo, which carries no signature).

## Cryptography

Hash and curve are one-method traits; `pnc` contains no cryptography, so a TPM or
secure element plugs in. The `pnc-rustcrypto` feature is the binding for a
general-purpose CPU:

```rust
use iso15118::pnc::rustcrypto::{Sha2, SigningKey};
use iso15118::pnc::{self, Signed};

let key = SigningKey::p256(&[0x42; 32])?;
let fragment = [0x80, 0x01, 0x02];

let signature = pnc::iso2::sign(&[Signed::new("ID1", &fragment)], &Sha2, &key)?;
pnc::iso2::verify(&signature, &[Signed::new("ID1", &fragment)], &Sha2, &key.verifying_key())?;
# Ok::<_, iso15118::pnc::PncError>(())
```

It signs deterministically (RFC 6979, no RNG), produces the raw `r ‖ s` pair
XMLDSig wants rather than DER, and refuses a suite the key is not on.

## What a valid signature does not prove

- **That the key is trusted.** Chain validation is `pnc::pki`, a separate call —
  see [PKI](@/docs/pki.md). Revocation is not checked
  ([limitations](@/docs/faq.md#limitations)).
- **That the car is plugged in here.** The vehicle signs the station's challenge
  and nothing else, so a relay between a victim's vehicle and a distant station
  passes every check the protocol defines
  ([arXiv 2512.15966](https://arxiv.org/abs/2512.15966)). That is a gap in the
  standard.
