//! The ISO 15118-20 contract-key envelope — bytes the SA sends, opened by the
//! vehicle with its OEM provisioning key.
//!
//! Properties: nothing panics; the PCID/SKI AAD is refused unless well formed;
//! an arbitrary field never opens, because opening requires a valid AES-GCM tag
//! and a key matching the contract certificate; and the TPM path's
//! `import_inputs` accepts only bounded, well-shaped input (\[V2G20-2521\]).
#![no_main]

use iso15118::pnc::envelope::iso20::{self, Curve};
use iso15118::pnc::envelope::tpm;
use iso15118::pnc::rustcrypto::{AesGcm, AgreementKey, Sha2};
use libfuzzer_sys::fuzz_target;

const OEM: &[u8] = include_bytes!("../../tests/fixtures/pki/iso20-crypto/secp521-oem-private.bin");
const CONTRACT: &[u8] =
    include_bytes!("../../tests/fixtures/pki/iso20-crypto/secp521-contract-public.bin");

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else { return };
    let at = usize::from(split).min(rest.len());
    let (blob, dh) = rest.split_at(at);
    if let Ok(inputs) = tpm::import_inputs(CONTRACT, None, blob, dh) {
        assert!(blob.len() <= tpm::MAX_ENCRYPTED_PRIVATE_KEY_LEN && dh.len() == 133);
        assert_eq!(inputs.duplicate.len(), 2 + blob.len());
    }
    let (pcid, rest) = rest.split_at(usize::from(split % 24).min(rest.len()));
    if let Ok(text) = core::str::from_utf8(pcid)
        && let Ok(aad) = iso20::aad(text, rest.get(..8).unwrap_or(&[]))
    {
        assert!(text.len() == 18);
        let oem = AgreementKey::p521(OEM).expect("fixture key");
        let at = rest.len().min(Curve::Secp521r1.field_len());
        let (field, dh) = rest.split_at(at);
        let opened = iso20::open(Curve::Secp521r1, field, dh, &aad, CONTRACT, &oem, &Sha2, &AesGcm);
        assert!(opened.is_err(), "an arbitrary field opened");
    }
});
