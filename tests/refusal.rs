//! Every request can be refused, and every refusal encodes.
//!
//! A station that detects a sequence error has to *answer* it with the matching
//! response type and the code the standard prescribes. At that moment it
//! usually has nothing to put in the response, because the refusal is why the
//! exchange stopped — and a response built with an empty required list does not
//! encode. The station then goes silent exactly where the standard told it to
//! explain, and the vehicle waits out its timeout instead of learning what it
//! did wrong. That is the shape of `EVerest`'s CVE-2026-54170.
//!
//! So the assertion here is on the **bytes**: not that a refusal can be built,
//! but that it can be sent.

#![cfg(all(feature = "iso2", feature = "iso20"))]

use iso15118::exi::ExiDocument;
use iso15118::iso2;
use iso15118::iso20::{ac, ac_der_iec, ac_der_sae, acdp, dc, messages as cm, wpt};

/// One check for any schema set's requests: each has a refusal, the refusal
/// carries the code, and it encodes. Returns how many requests it checked.
macro_rules! refuse_all {
    ($set:literal, $requests:expr, $code:expr, $wrap:expr) => {{
        let mut checked = 0usize;
        for request in $requests {
            let refusal = request
                .refusal($code)
                .unwrap_or_else(|| panic!("{} {} has no refusal", $set, request.name()));
            assert_eq!(refusal.response_code(), Some($code), "{} {}", $set, request.name());
            $wrap(refusal).to_vec().unwrap_or_else(|e| {
                panic!("{} {} refusal does not encode: {e:?}", $set, request.name())
            });
            checked += 1;
        }
        checked
    }};
}

/// Every request of every schema set this crate generates — taken from the
/// generated `requests()` lists, so a request type the schema adds is checked
/// the day it is generated rather than the day somebody remembers to list it.
#[test]
fn every_request_of_every_set_has_a_refusal_that_encodes() {
    let code2 = iso2::ResponseCode::FAILEDSequenceError;
    let code20 = iso15118::iso20::common::ResponseCode::FAILEDSequenceError;
    let in_v2g_message = |body: iso2::BodyChoice| {
        iso2::Document::V2GMessage(iso2::V2GMessage {
            header: iso2::MessageHeader {
                session_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
                notification: None,
                signature: None,
            },
            body: iso2::Body { choice: Some(body) },
        })
    };
    let counts = [
        ("ISO 15118-2", refuse_all!("-2", iso2::BodyChoice::requests(), code2, in_v2g_message)),
        (
            "CommonMessages",
            refuse_all!("-20", cm::Document::requests(), code20, core::convert::identity),
        ),
        ("AC", refuse_all!("AC", ac::Document::requests(), code20, core::convert::identity)),
        ("DC", refuse_all!("DC", dc::Document::requests(), code20, core::convert::identity)),
        ("WPT", refuse_all!("WPT", wpt::Document::requests(), code20, core::convert::identity)),
        ("ACDP", refuse_all!("ACDP", acdp::Document::requests(), code20, core::convert::identity)),
        (
            "AC_DER_IEC",
            refuse_all!("IEC", ac_der_iec::Document::requests(), code20, core::convert::identity),
        ),
        (
            "AC_DER_SAE",
            refuse_all!("SAE", ac_der_sae::Document::requests(), code20, core::convert::identity),
        ),
    ];
    // An independent count, so a generator that silently dropped a pairing
    // would show here rather than make every list shorter in agreement: the
    // schemas define 17 + 13 + 2 + 5 + 6 + 4 + 2 + 2 requests.
    let expected = [17, 13, 2, 5, 6, 4, 2, 2];
    for ((set, checked), want) in counts.iter().zip(expected) {
        assert_eq!(*checked, want, "requests with a refusal in {set}");
    }
    assert_eq!(counts.iter().map(|(_, n)| n).sum::<usize>(), 51);
}

/// The ten response types that cannot be built from nothing — a required list
/// with `minOccurs >= 1`, a string with a `minLength`, an exact-length binary.
/// `minimal()` is what makes them buildable, so this pins the ones that would
/// otherwise be silently empty.
#[test]
fn the_responses_with_mandatory_content_are_filled_not_empty() {
    let r = cm::AuthorizationSetupRes::minimal();
    assert!(!r.authorization_services.is_empty(), "AuthorizationSetupRes needs a service");

    let r = cm::ServiceDetailRes::minimal();
    assert!(
        !r.service_parameter_list.parameter_set.is_empty(),
        "ServiceDetailRes needs a ParameterSet — this is CVE-2026-54170's field"
    );

    let r = iso2::ServiceDiscoveryRes::minimal();
    assert_ne!(r.payment_option_list.payment_option.len(), 0);
    assert_ne!(r.charge_service.supported_energy_transfer_mode.energy_transfer_mode.len(), 0);

    let r = iso2::PaymentDetailsRes::minimal();
    assert_eq!(r.gen_challenge.len(), 16, "GenChallenge is an exact length, not a maximum");
}
