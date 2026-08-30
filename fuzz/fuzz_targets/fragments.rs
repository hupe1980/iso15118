//! The EXI *fragment* decoders — the bytes a Plug & Charge signature is
//! computed over.
//!
//! A fragment is indexed by a different, much larger root table than a
//! document, so this reaches grammar states the `messages` target cannot. It
//! matters more than its size suggests: these bytes are what a signature
//! commits to, so a decoder that accepts something it cannot re-encode
//! identically is a signature that cannot be re-checked.
#![no_main]

use libfuzzer_sys::fuzz_target;

macro_rules! check {
    ($ty:ty, $data:expr) => {
        if let Ok(message) = <$ty>::from_fragment($data) {
            let bytes = message.to_fragment().expect("a decoded fragment must re-encode");
            let again = <$ty>::from_fragment(&bytes).expect("our own output must decode");
            assert_eq!(message, again, "fragment decode/encode is not a round trip");
        }
    };
}

fuzz_target!(|data: &[u8]| {
    check!(iso15118::iso2::Document, data);
    check!(iso15118::iso20::messages::Document, data);
    check!(iso15118::iso20::ac::Document, data);
    check!(iso15118::iso20::dc::Document, data);
    check!(iso15118::iso20::wpt::Document, data);
    check!(iso15118::iso20::acdp::Document, data);

    // `SignedInfo` is the one element encoded against the xmldsig schema alone,
    // and the one whose bytes a signature is directly over.
    if let Ok(info) = iso15118::iso2::SignedInfo::from_xmldsig_fragment(data) {
        let bytes = info.to_xmldsig_fragment().expect("must re-encode");
        assert_eq!(iso15118::iso2::SignedInfo::from_xmldsig_fragment(&bytes).unwrap(), info);
    }
});
