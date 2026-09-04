//! The contract private key, opened out of an envelope OpenSSL sealed.
//!
//! `CertificateInstallationRes` is the one place in ISO 15118 where a secret
//! crosses the wire, and this crate's own two halves agreeing about it proves
//! nothing: what §7.9.2.4.3 requires is that a *secondary actor's* envelope
//! opens. `scripts/make-test-envelope.sh` builds one with OpenSSL, from the
//! requirement text — the ECDH, the concatenation KDF and the AES-128-CBC each
//! done by a third implementation — so the fixture below is somebody else's
//! bytes.
//!
//! Which is the only way to catch the mistakes that matter here. Every one of
//! them is invisible to a self-round-trip: a counter left out of the KDF, the
//! `OtherInfo` in the wrong order, the digest truncated from the wrong end, the
//! IV read off the tail instead of the head, a padding scheme where the
//! standard says there is none.

#![cfg(all(feature = "pnc-rustcrypto", feature = "std"))]

use iso15118::pnc::PncError;
use iso15118::pnc::envelope::KeyAgreement as _;
use iso15118::pnc::envelope::{self, DH_PUBLIC_KEY_LEN, ENVELOPE_LEN, IV_LEN, PRIVATE_KEY_LEN};
use iso15118::pnc::rustcrypto::{Aes128, AgreementKey, Sha2};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/pki/{name}.bin", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("run scripts/make-test-envelope.sh: {name}.bin: {e}"))
}

/// The receiver's static key — in the field, the one inside the OEM
/// Provisioning Certificate \[V2G2-820\] or the existing Contract Certificate
/// \[V2G2-821\].
fn receiver() -> AgreementKey {
    AgreementKey::new(&fixture("receiver-key")).expect("a P-256 scalar")
}

/// The whole of it: an envelope a third implementation built, opened, checked
/// against the certificate's public key \[V2G2-823\], and equal to the key that
/// went in.
#[test]
fn an_envelope_openssl_sealed_opens_to_the_key_that_went_in() {
    let key = envelope::open(
        &fixture("envelope"),
        &fixture("dh-public-key"),
        &fixture("contract-public"),
        &receiver(),
        &Sha2,
        &Aes128,
    )
    .expect("the envelope is exactly what §7.9.2.4.3 describes");

    assert_eq!(key, fixture("contract-key"));
    assert_eq!(key.len(), PRIVATE_KEY_LEN);
}

/// The lengths ISO 15118 fixes, on the fixture rather than on a constant — so
/// the constants are checked against a file somebody else wrote.
#[test]
fn the_fixture_has_the_shape_the_standard_gives_it() {
    assert_eq!(fixture("envelope").len(), ENVELOPE_LEN);
    assert_eq!(fixture("envelope").len(), IV_LEN + PRIVATE_KEY_LEN);
    // \[V2G2-819\] NOTE 9: 65 bytes, first byte 0x04, uncompressed only.
    assert_eq!(fixture("dh-public-key").len(), DH_PUBLIC_KEY_LEN);
    assert_eq!(fixture("dh-public-key")[0], 0x04);
}

/// \[V2G2-823\] is the check that is easy to leave out, and the only thing
/// between a vehicle and a contract key that does not belong to the certificate
/// it arrived with. There is no call that skips it.
#[test]
fn a_key_that_does_not_match_its_certificate_is_refused() {
    // Any other valid public point stands in for "a certificate that is not
    // this key's".
    let other = AgreementKey::new(&[0x42; 32]).unwrap().public_key();
    assert_eq!(
        envelope::open(
            &fixture("envelope"),
            &fixture("dh-public-key"),
            &other,
            &receiver(),
            &Sha2,
            &Aes128,
        ),
        Err(PncError::KeyMismatch),
    );
}

/// A different static key derives a different secret, so the plaintext is
/// different bytes — and \[V2G2-823\] is what turns "different bytes" into a
/// named failure instead of a contract key that quietly does not work.
#[test]
fn the_wrong_receiver_key_does_not_open_it() {
    let stranger = AgreementKey::new(&[0x11; 32]).unwrap();
    assert_eq!(
        envelope::open(
            &fixture("envelope"),
            &fixture("dh-public-key"),
            &fixture("contract-public"),
            &stranger,
            &Sha2,
            &Aes128,
        ),
        Err(PncError::KeyMismatch),
    );
}

/// One flipped bit in the ciphertext changes the plaintext, and CBC has no
/// integrity of its own — \[V2G2-818\]'s NOTE 8 says the surrounding signature
/// is what provides it. So the check that catches this is the key-match, which
/// is exactly why it is not optional.
#[test]
fn a_tampered_envelope_does_not_yield_a_usable_key() {
    let mut tampered = fixture("envelope");
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        envelope::open(
            &tampered,
            &fixture("dh-public-key"),
            &fixture("contract-public"),
            &receiver(),
            &Sha2,
            &Aes128,
        )
        .is_err()
    );
}

/// Lengths are refused before any curve arithmetic, because a field that is not
/// the shape ISO 15118 gives it is not one to spend a scalar multiplication on.
#[test]
fn a_field_that_is_not_the_right_length_is_refused_outright() {
    let dh = fixture("dh-public-key");
    let cert = fixture("contract-public");
    for bad in [vec![0u8; ENVELOPE_LEN - 1], vec![0u8; ENVELOPE_LEN + 1], Vec::new()] {
        let len = bad.len();
        assert_eq!(
            envelope::open(&bad, &dh, &cert, &receiver(), &Sha2, &Aes128),
            Err(PncError::BadEnvelope { len }),
        );
    }
    // A compressed `DHpublickey`, which \[V2G2-819\] excludes outright.
    let mut compressed = dh.clone();
    compressed[0] = 0x02;
    compressed.truncate(33);
    assert_eq!(
        envelope::open(&fixture("envelope"), &compressed, &cert, &receiver(), &Sha2, &Aes128),
        Err(PncError::BadEnvelope { len: 33 }),
    );
}

/// The sender's half, which is the secondary actor's.
///
/// Note what this does **not** claim: the ephemeral private key is not in the
/// fixtures — only its public point is, because only that is on the wire — so
/// this cannot reproduce OpenSSL's exact ciphertext. What it checks is that
/// sealing and opening are the two directions of one exchange, with the key
/// pairing the protocol actually uses: the sender's ephemeral against the
/// receiver's static.
///
/// The claim that this crate agrees with a third implementation rests on the
/// test above, which opens bytes OpenSSL produced.
#[test]
fn sealing_and_opening_are_the_two_halves_of_one_exchange() {
    let ephemeral = AgreementKey::new(&[0x07; 32]).unwrap();
    let contract_key = fixture("contract-key");
    let receiver_public = receiver().public_key();
    let iv = [0xA5u8; IV_LEN];

    let sealed = envelope::seal(&contract_key, &receiver_public, &iv, &ephemeral, &Sha2, &Aes128)
        .expect("seal");
    assert_eq!(sealed.len(), ENVELOPE_LEN);
    assert_eq!(&sealed[..IV_LEN], &iv, "the IV is the 16 most significant bytes");

    let opened = envelope::open(
        &sealed,
        &ephemeral.public_key(),
        &fixture("contract-public"),
        &receiver(),
        &Sha2,
        &Aes128,
    )
    .expect("open what we sealed");
    assert_eq!(opened, contract_key);
}

/// The session key is the part with the most ways to be quietly wrong, so it
/// gets its own assertion against a value computed outside this crate.
///
/// `scripts/make-test-envelope.sh` derives it with `openssl dgst`; if the two
/// disagree the envelope test fails too, but this one says *where*.
#[test]
fn the_session_key_is_the_leftmost_half_of_one_sha256() {
    use iso15118::pnc::Hash as _;

    let shared = receiver().agree(&fixture("dh-public-key")).expect("ECDH");
    let derived = envelope::session_key(&shared, &Sha2);

    // The KDF, spelled out: counter ‖ Z ‖ AlgorithmID ‖ IDU ‖ IDV.
    let mut input = vec![0x00, 0x00, 0x00, 0x01];
    input.extend_from_slice(&shared);
    input.extend_from_slice(&[0x01, b'U', b'V']);
    let expected = Sha2.digest(iso15118::pnc::Suite::EcdsaSha256, &input);

    assert_eq!(derived.as_slice(), &expected[..16]);
    assert_eq!(derived.len(), 16, "exactly 128 bits [V2G2-818]");
}
