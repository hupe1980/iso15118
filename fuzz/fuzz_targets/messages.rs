//! The generated message decoders, which run on bytes from the charging cable
//! once the V2GTP and EXI layers have unwrapped them.
//!
//! Two properties, both of which the state machines depend on:
//!   * no input panics;
//!   * anything that decodes re-encodes to something that decodes identically.
//!
//! The second is what catches an asymmetry between the generated encoder and
//! decoder — a field bound enforced on one side only, or an event code written
//! differently from how it is read.
#![no_main]

use iso15118::exi::ExiDocument;
use libfuzzer_sys::fuzz_target;

macro_rules! check {
    ($ty:ty, $data:expr) => {
        if let Ok(message) = <$ty>::from_bytes($data) {
            let bytes = message.to_vec().expect("a decoded message must re-encode");
            let again = <$ty>::from_bytes(&bytes).expect("our own output must decode");
            assert_eq!(message, again, "decode/encode is not a round trip");
        }
    };
}

fuzz_target!(|data: &[u8]| {
    // Every schema set shares the document event-code space only by accident,
    // so each is tried independently — exactly as a receiver would, having
    // learned the schema from the V2GTP payload type.
    check!(iso15118::iso2::Document, data);
    check!(iso15118::iso20::messages::Document, data);
    check!(iso15118::iso20::ac::Document, data);
    check!(iso15118::iso20::dc::Document, data);
    check!(iso15118::iso20::wpt::Document, data);
    check!(iso15118::iso20::acdp::Document, data);
});
