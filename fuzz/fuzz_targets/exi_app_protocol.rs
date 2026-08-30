//! The decoder that runs on unauthenticated bytes from the charging cable.
//!
//! Any panic here is a denial-of-service on a charging station. A successful
//! decode must additionally re-encode to something that decodes to the same
//! message, because the state machines compare messages for equality.
#![no_main]

use iso15118::app_protocol::{SupportedAppProtocolReq, SupportedAppProtocolRes};
use iso15118::exi::ExiDocument;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = SupportedAppProtocolReq::from_bytes(data) {
        let reencoded = req.to_vec().expect("a decoded message must re-encode");
        let again = SupportedAppProtocolReq::from_bytes(&reencoded)
            .expect("our own output must decode");
        assert_eq!(req, again, "decode/encode is not a round trip");
    }
    if let Ok(res) = SupportedAppProtocolRes::from_bytes(data) {
        let reencoded = res.to_vec().expect("a decoded message must re-encode");
        assert_eq!(
            SupportedAppProtocolRes::from_bytes(&reencoded).as_ref(),
            Ok(&res),
            "decode/encode is not a round trip"
        );
    }
});
