//! X.509 certificate parsing — the first hostile DER an ISO 15118 peer sends.
//!
//! A certificate arrives before anything about the peer is established, and it
//! is the one structure in this crate that is not EXI: a hand-written ASN.1
//! reader over attacker-supplied bytes, which is the classic place for a parser
//! to go wrong.
//!
//! Three properties, and the second is the interesting one:
//!
//! * parsing never panics, whatever the bytes;
//! * every borrowed field really is a subslice of the input — a parser that
//!   returns a length pointing past what it was given is one whose bounds
//!   checks are decorative;
//! * a certificate that parses is one whose profile invariants hold, so nothing
//!   downstream has to re-check what the parser already promised.
#![no_main]

use iso15118::pnc::pki::Certificate;
use libfuzzer_sys::fuzz_target;

/// True when `part` is a subslice of `whole`, by address.
fn within(whole: &[u8], part: &[u8]) -> bool {
    let base = whole.as_ptr() as usize;
    let start = part.as_ptr() as usize;
    start >= base && start + part.len() <= base + whole.len()
}

fuzz_target!(|data: &[u8]| {
    let Ok(cert) = Certificate::parse(data) else { return };

    // Everything the parser handed back points into what it was given.
    assert!(within(data, cert.tbs), "tbs escapes the input");
    assert!(within(data, cert.serial));
    assert!(within(data, cert.issuer.encoded));
    assert!(within(data, cert.subject.encoded));
    assert!(within(data, cert.public_key));

    // The invariants the ISO 15118 profile fixes, which the parser refuses
    // rather than reports: an uncompressed point of the curve's width, and a
    // signature that is the pair for that curve.
    assert_eq!(cert.public_key.len(), 1 + 2 * cert.curve.field_len());
    assert_eq!(cert.public_key[0], 0x04);
    assert_eq!(cert.signature.as_slice().len(), 2 * cert.curve.field_len());

    // A validity window that is a window. `notBefore > notAfter` is a
    // certificate that is valid at no instant, which is legal DER and is worth
    // knowing the parser does not turn into one that is valid at every instant.
    assert!(!cert.is_valid_at(i64::MIN));
    assert!(!cert.is_valid_at(i64::MAX));

    // Re-parsing the same bytes is the same certificate.
    assert_eq!(Certificate::parse(data), Ok(cert));
});
