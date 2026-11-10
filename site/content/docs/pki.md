+++
title = "Certificates"
description = "Validating a V2G certificate chain in iso15118: RFC 5280 path validation under the Annex F and Annex B profiles and the Amd 1 rules, Ed448, OCSP and CRL revocation status, and the contract-key envelopes of both generations."
weight = 75

[extra]
nav_title = "Certificates"
+++

Plug & Charge asks two questions: is this signature about this session (the
`GenChallenge` binding — see [Plug & Charge](@/docs/plug-and-charge.md)), and is
this key one to trust? This page is the second. They are separate calls.

```rust,ignore
use iso15118::pnc::pki::{self, Evidence, Policy, Profile, TrustAnchor, TrustAnchors};
use iso15118::pnc::rustcrypto::Backend;

// Trust anchors: where each came from, and whether it roots a public or private PKI.
let anchors = [TrustAnchor::public(mo_root, "Hubject V2G Root")];

// Leaf first, as CertificateChainType carries it; OCSP responses and CRLs as DER.
let path = pki::validate(
    &[contract_cert, mo_sub_ca_2, mo_sub_ca_1],
    &TrustAnchors::new(&anchors),
    Policy::iso20(Profile::ContractCertificate),   // or Policy::iso2(..)
    &Evidence::new(&cached_ocsp, &crls),            // or Evidence::none()
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
| Algorithm | -2: `ecdsa-with-SHA256` over secp256r1 \[V2G2-006\]\[V2G2-007\]; -20: `ecdsa-with-SHA512` over secp521r1, or Ed448 \[V2G20-2674\]\[V2G20-2319\] |
| Path length | at most three non-self-signed certificates \[V2G2-009\] |
| Size | at most 800 bytes DER in -2 \[V2G2-010\]; 1 600 under `Policy::iso20` |
| Extensions | Annex F's set; `KeyUsage` and `BasicConstraints` critical; under -20 only Annex B's \[V2G20-2323\] |

A trust anchor may sit anywhere in the path: a Private Operator Root anchors SECC
certificates \[V2G2-927\] and may sign leaves directly \[V2G2-868\].

`Policy::iso20` accepts only -20's algorithms (`ChainError::AlgorithmNotAllowed`;
`with_algorithms` disables one \[V2G20-2320\]) and Annex B's extensions, plus
what Amd 1's public text states: the size bound, checked before parsing
(`ChainError::TooLarge`), and a certificate valid only within its issuer's
validity \[V2G20-3000\] (`ChainError::OutlivesIssuer`). `Policy::iso2` keeps
ISO 15118-2's rules exactly.

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

`CertificateInstallationRes` delivers a contract certificate and its private key.
ISO 15118-2 (`envelope::iso2`, also `CertificateUpdateRes`):

```rust,ignore
use iso15118::pnc::envelope;

let contract_key = envelope::iso2::open(
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

ISO 15118-20 (`envelope::iso20`), for an EVCC without TPM 2.0:

```rust,ignore
let aad = envelope::iso20::aad(pcid, contract.subject_key_id.unwrap())?;
let contract_key = envelope::iso20::open(
    envelope::iso20::Curve::Secp521r1,               // or X448
    &secp521_encrypted_private_key,                   // IV ‖ ciphertext ‖ tag
    &dh_public_key,                                   // 133 bytes (57 for X448)
    &aad,                                             // PCID ‖ hex(SKI)
    contract.public_key,
    &oem_agreement_key,
    &Sha2,
    &AesGcm,
)?;
```

```text
SECP521_EncryptedPrivateKey = IV (12) ‖ AES-GCM-256(K, IV, AAD, key) ‖ tag (16)   [V2G20-2497]
K = leftmost 256 bits of SHA-512( 00 00 00 01 ‖ Z ‖ 01 55 56 )                       [V2G20-2535]
```

- Both `open`s check the delivered key against the contract certificate's
  public key \[V2G2-823\]\[V2G20-2507\]\[V2G20-2510\]; no call skips it. The
  -20 one also refuses a failed tag \[V2G20-2504\] and non-zero padding bits
  \[V2G20-2678\]. For X448 the text compares a 448-bit key with an Ed448
  contract key; the check computes `key · B` on edwards448 \[V2G20-2510\].
- A -20 vehicle whose OEM certificate carries TPM information gets a TPM 2.0
  duplication blob instead (`envelope::tpm`, \[V2G20-2595\]): `seal` builds it
  on the SA side, `import_inputs` turns `TPM_EncryptedPrivateKey` and
  `DHPublicKey` into `TPM2_Import`'s three arguments. The seed uses the TPM's
  KDFe, which is what `TPM2_Import` accepts. Driving the TPM is yours.
- CBC has no integrity of its own: verify the surrounding signature first
  \[V2G2-818\].
- Key agreement is its own trait, `KeyAgreement`, beside `Sign` \[V2G2-822\].
  Sealing needs a fresh random IV; this crate has no RNG.

## Revocation

`validate` takes the revocation evidence you hold — OCSP responses (RFC 6960)
and CRLs (RFC 5280 §5), as DER, in any order — and verifies it. Nothing is
fetched.

| Chain | Generation | Must be shown good | Requirement |
|---|---|---|---|
| SECC, public V2G root | -2 | every Sub-CA | \[V2G2-070\], \[V2G2-873\] |
| SECC, public V2G root | -20 | every certificate below the anchor | \[V2G20-1240\], \[V2G20-2416\] |
| SECC, private root | -2 | nothing | \[V2G2-872\] |
| SECC, private root | -20 | all or none | \[V2G20-2410\], \[V2G20-2417\] |
| contract, OEM provisioning | both | nothing | \[V2G2-693\], \[V2G20-2214\] |

In every row, a certificate shown revoked or evidence that does not verify
refuses the chain \[V2G2-875\]\[V2G20-2413\]–\[V2G20-2415\].
`Validated::standing` reports each certificate as good, revoked, or unknown — no
evidence, or evidence rejected.

- **Vehicle:** pass the responses stapled in the TLS handshake (TLS 1.3
  `status_request`, TLS 1.2 `status_request_v2`); abort on `Err`.
- **Station:** pass what the back end holds; answer a refusal with
  `pnc::iso2::response_code` or `pnc::iso20::response_code`.
- **OCSP:** matched by `CertID` (SHA-1/256/384/512); signed by the issuer or a
  responder it certified with `id-kp-OCSPSigning`; `thisUpdate ≤ now ≤
  nextUpdate`; validity at most four weeks (-2, \[V2G2-876\]) or one week (-20,
  \[V2G20-1021\]).
- **CRL:** the issuer's own, `cRLSign`, current, v2, non-critical `CRLNumber`,
  not indirect or delta, no serial listed twice.
- **Yours:** fetching, caching (refresh weekly, \[V2G2-649\]), and the
  responder certificate's own status.

## Evidence

- Chains and the envelope are minted by OpenSSL (`scripts/make-test-pki.sh`,
  `scripts/make-test-envelope.sh`), positive and negative per rule.
- All ten OEM provisioning leaves of Hubject's public test PKI validate to its real
  V2G Root (`tests/pki_pool.rs`, reading `ISO15118_PKI_POOL`). The pool has no real
  leaf for the SECC and contract profiles.
- A fuzz target asserts every borrowed field lies inside the input.
- OCSP responses and CRLs are minted by OpenSSL as responder and CA
  (`scripts/make-test-pki.sh revocation`); each rule above is a test in
  `tests/revocation.rs`.
- x509-limbo's 22 CRL cases reach limbo's verdict.
- A fuzz target checks that no chain is accepted with a certificate revoked,
  evidence rejected, or a required status missing.
