//! ISO 15118-20 contract keys for an EVCC with TPM 2.0 (§7.9.2.5.3).
//!
//! The outer duplication wrapper is checked two ways: byte for byte against an
//! independent implementation (`scripts/lib/iso20_crypto.py`, OpenSSL-backed),
//! here; and by a TPM — `swtpm` imports what the crate seals and signs with it —
//! in `scripts/verify-tpm-import.sh`, which needs Docker and runs locally.

#![cfg(all(feature = "pnc-rustcrypto", feature = "std"))]

use iso15118::pnc::PncError;
use iso15118::pnc::envelope::tpm::{self, TpmInfo};
use iso15118::pnc::pki::Certificate;
use iso15118::pnc::rustcrypto::{AgreementKey, Backend, Sha2};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/pki/iso20-crypto/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("run scripts/make-test-pki.sh iso20-crypto: {path}: {e}"))
}

fn info() -> TpmInfo {
    TpmInfo {
        storage_key: fixture("tpm-storage-key.bin").try_into().unwrap(),
        policy_digest: Some(fixture("tpm-policy-digest.bin").try_into().unwrap()),
    }
}

fn sealed() -> tpm::Sealed {
    let ephemeral = AgreementKey::p521(&fixture("tpm-ephemeral-private.bin")).unwrap();
    tpm::seal(
        &fixture("tpm-contract-private.bin"),
        &fixture("tpm-contract-public.bin"),
        &info(),
        &ephemeral,
        &ephemeral.public_key(),
        &Sha2,
        &Backend,
        &Backend,
    )
    .unwrap()
}

/// \[V2G20-2518\], \[V2G20-2519\]: the wrapper — `KDFe` seed, Table 19 public
/// area and Name, `KDFa` keys, AES-256-CFB, HMAC-SHA-512 — matches the
/// independent implementation byte for byte, unpadded \[V2G20-2521\].
#[test]
fn the_wrapper_matches_the_other_implementation() {
    let sealed = sealed();
    assert_eq!(sealed.encrypted_private_key, fixture("tpm-encrypted-private-key.bin"));
    assert_eq!(sealed.encrypted_private_key.len(), 142);
}

/// \[V2G20-2523\]: the vehicle turns the message into `TPM2_Import`'s inputs;
/// the public area is Table 19's, with the OEM policy as `authPolicy`.
#[test]
fn the_vehicle_gets_tpm2_import_inputs() {
    let sealed = sealed();
    let policy: [u8; 64] = fixture("tpm-policy-digest.bin").try_into().unwrap();
    let inputs = tpm::import_inputs(
        &fixture("tpm-contract-public.bin"),
        Some(&policy),
        &sealed.encrypted_private_key,
        &sealed.dh_public_key,
    )
    .unwrap();
    assert_eq!(inputs.public, fixture("tpm-object-public.bin"));
    assert_eq!(inputs.duplicate.len(), 2 + 142);
    assert_eq!(inputs.in_sym_seed.len(), 2 + 2 * (2 + 66));
}

/// \[V2G20-2521\]: over 206 bytes, a digest that is not SHA-512, an encrypted
/// sensitive area of the wrong size, or a DH key that is not `04 ‖ X ‖ Y` is
/// refused before anything reaches the TPM.
#[test]
fn malformed_inputs_are_refused() {
    let sealed = sealed();
    let contract = fixture("tpm-contract-public.bin");
    let blob = &sealed.encrypted_private_key;
    let dh = &sealed.dh_public_key;
    let refused = |b: &[u8], d: &[u8]| {
        matches!(tpm::import_inputs(&contract, None, b, d), Err(PncError::BadEnvelope { .. }))
    };
    assert!(refused(&[0u8; 207], dh));
    let mut wrong_digest = blob.clone();
    wrong_digest[1] = 0x20;
    assert!(refused(&wrong_digest, dh));
    assert!(refused(&blob[..blob.len() - 1], dh));
    let mut compressed = dh.clone();
    compressed[0] = 0x02;
    assert!(refused(blob, &compressed));
    assert!(refused(blob, &dh[..132]));
}

/// \[V2G20-2594\]–\[V2G20-2596\], \[V2G20-2595\]: an OEM certificate with TPM
/// information selects the TPM method, and its values decode.
#[test]
fn the_certificate_selects_the_method() {
    let der = fixture("p521-tpm-oem.der");
    let cert = Certificate::parse(&der).unwrap();
    assert!(tpm::applies(&cert));
    assert_eq!(tpm::tpm_info(&cert).unwrap(), Some(info()));
    let plain = fixture("p521-plain.der");
    let plain = Certificate::parse(&plain).unwrap();
    assert!(!tpm::applies(&plain));
    assert_eq!(tpm::tpm_info(&plain).unwrap(), None);
}
