//! V2GTP framing, including the 32-bit attacker-controlled length field.
#![no_main]

use iso15118::v2gtp::{self, Header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = Header::decode(data) {
        // A parsed header must survive a re-encode unchanged.
        assert_eq!(Header::decode(&header.to_bytes()), Ok(header));
    }
    if let Ok((header, payload, rest)) = v2gtp::split_frame(data, 1 << 20) {
        assert_eq!(payload.len() as u64, u64::from(header.payload_len));
        assert_eq!(v2gtp::HEADER_LEN + payload.len() + rest.len(), data.len());
    }
});
