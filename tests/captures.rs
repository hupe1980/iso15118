//! Replays V2G sessions real hardware recorded, byte for byte.
//!
//! The corpus is dSPACE's `dsV2Gshark` example captures — a DS5366 bench driving
//! Josev and `RiseV2G` — and it is GPL-2.0, so it never enters this repository.
//! `scripts/verify-captures.sh` fetches it at a pinned commit, has `tshark`
//! reassemble each TCP stream and remove TLS with the key log the capture
//! carries, and points this test at the result through `ISO15118_CAPTURES`.
//! Without that variable the test **skips by name**: a replay that quietly
//! passes when its input is missing reads exactly like one that ran.
//!
//! Every other check in the repository asks whether this crate agrees with a
//! specification or with a reference encoder. This one asks whether it agrees
//! with the equipment that exists, and it has already been the only check that
//! could tell those apart: a string-table reference `exificient` writes and the
//! field cannot read.
//!
//! Per message: decode, and re-encode to the identical bytes. Per -2 Plug &
//! Charge `AuthorizationReq`: the signature verifies against the contract key
//! the same stream's `PaymentDetailsReq` carried and the challenge its
//! `PaymentDetailsRes` issued. A DIN SPEC 70121 session is counted as an
//! expected decline — this crate recognises it in the handshake and has no
//! message set for it.

#![cfg(all(feature = "std", feature = "iso2", feature = "iso20", feature = "pnc-rustcrypto"))]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use iso15118::Protocol;
use iso15118::exi::{ExiDocument, ValueCoding};
use iso15118::iso2::BodyChoice;
use iso15118::message::{Message, MessageError};
use iso15118::pnc::GenChallenge;
use iso15118::pnc::pki::Certificate;
use iso15118::pnc::rustcrypto::{Sha2, VerifyingKey};
use iso15118::v2gtp::{PayloadType, split_frame};

/// Large enough for any message in the corpus; the crate's own default.
const MAX_PAYLOAD: usize = 1 << 20;

/// One direction of a stream: each frame's payload type and payload.
type Frames = Vec<(PayloadType, Vec<u8>)>;

#[derive(Default)]
struct Tally {
    foreign_streams: usize,
    messages: usize,
    reencoded: usize,
    /// Messages whose bytes differ when re-encoded with string-table
    /// references — the coding a deployed peer cannot read.
    referenced_differs: usize,
    declined: usize,
    authorizations: usize,
    verified: usize,
}

fn frames(path: &Path, all: &[u8]) -> Result<Frames, String> {
    let mut out = Vec::new();
    let mut bytes = all;
    while !bytes.is_empty() {
        let offset = all.len() - bytes.len();
        let (header, payload, rest) = split_frame(bytes, MAX_PAYLOAD).map_err(|e| {
            format!(
                "{}: V2GTP framing at byte {offset} (frame {}): {e:?}",
                path.display(),
                out.len()
            )
        })?;
        out.push((header.payload_type, payload.to_vec()));
        bytes = rest;
    }
    Ok(out)
}

/// The two directions of one TCP stream, vehicle first.
fn directions(stream_a: &Path) -> Result<Option<[Frames; 2]>, String> {
    let stream_b = stream_a.with_extension("").with_extension("b.bin");
    // A capture may hold TCP streams that are not V2G at all — a battery-data
    // side channel, say. V2GTP's first two bytes are its version and the
    // inverted version; a stream that does not start with them is not one.
    let is_v2gtp = |p: &Path| fs::read(p).is_ok_and(|b| b.starts_with(&[0x01, 0xFE]));
    if !is_v2gtp(stream_a) && !is_v2gtp(&stream_b) {
        return Ok(None);
    }
    let a = frames(stream_a, &fs::read(stream_a).map_err(|e| e.to_string())?)?;
    let b = frames(&stream_b, &fs::read(&stream_b).map_err(|e| e.to_string())?)?;
    let opens = |side: &[(PayloadType, Vec<u8>)]| {
        side.first().is_some_and(|(t, p)| {
            matches!(Message::decode(None, *t, p), Ok(Message::AppProtocolReq(_)))
        })
    };
    Ok(if opens(&a) {
        Some([a, b])
    } else if opens(&b) {
        Some([b, a])
    } else {
        None
    })
}

/// What a -2 Plug & Charge session has said so far: the contract key from
/// `PaymentDetailsReq` and the challenge from `PaymentDetailsRes`, which is
/// what the next signed `AuthorizationReq` must verify against.
#[derive(Default)]
struct PlugAndCharge {
    contract_key: Option<VerifyingKey>,
    challenge: Option<GenChallenge>,
}

impl PlugAndCharge {
    fn observe(
        &mut self,
        doc: &iso15118::iso2::Document,
        at: &str,
        tally: &mut Tally,
        failures: &mut String,
    ) -> Result<(), String> {
        let iso15118::iso2::Document::V2GMessage(v) = doc else { return Ok(()) };
        match v.body.choice.as_ref() {
            Some(BodyChoice::PaymentDetailsReq(req)) => {
                let cert = Certificate::parse(&req.contract_signature_cert_chain.certificate)
                    .map_err(|e| format!("{at}: contract certificate: {e:?}"))?;
                self.contract_key = Some(
                    VerifyingKey::p256_sec1(cert.public_key)
                        .map_err(|e| format!("{at}: contract key: {e:?}"))?,
                );
            }
            Some(BodyChoice::PaymentDetailsRes(res)) => {
                self.challenge = GenChallenge::from_slice(&res.gen_challenge).ok();
            }
            Some(BodyChoice::AuthorizationReq(req)) => {
                let Some(signature) = &v.header.signature else { return Ok(()) };
                tally.authorizations += 1;
                let (Some(key), Some(issued)) = (&self.contract_key, &self.challenge) else {
                    let _ = writeln!(
                        failures,
                        "{at}: a signed AuthorizationReq with no contract key or challenge before it"
                    );
                    return Ok(());
                };
                match iso15118::pnc::iso2::verify_authorization(req, signature, issued, &Sha2, key)
                {
                    Ok(()) => tally.verified += 1,
                    Err(e) => {
                        let _ = writeln!(failures, "{at}: AuthorizationReq signature: {e:?}");
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn replay(stream: &Path, tally: &mut Tally, failures: &mut String) -> Result<(), String> {
    let Some([ev, se]) = directions(stream)? else {
        // Not a V2G session: nothing on either side opens with the handshake.
        tally.foreign_streams += 1;
        return Ok(());
    };
    let mut protocol: Option<Protocol> = None;
    let mut offered = None;
    let mut pnc = PlugAndCharge::default();

    // Half-duplex: request, response, request, ... — so interleaving the two
    // directions by index restores the order the session ran in.
    let mut order = Vec::new();
    for i in 0..ev.len().max(se.len()) {
        if let Some(f) = ev.get(i) {
            order.push(("EVCC", i, f));
        }
        if let Some(f) = se.get(i) {
            order.push(("SECC", i, f));
        }
    }

    for (side, index, (payload_type, payload)) in order {
        let at = format!("{} {side} frame {index}", stream.display());
        let message = match Message::decode(protocol, *payload_type, payload) {
            Ok(m) => m,
            Err(MessageError::NoCodec { .. }) if protocol == Some(Protocol::Din70121) => {
                tally.declined += 1;
                continue;
            }
            Err(e) => {
                let _ = writeln!(failures, "{at}: decode: {e:?}");
                continue;
            }
        };
        tally.messages += 1;

        // The coding the field cannot read: if this ever matched the captured
        // bytes everywhere, the replay could not tell the regression apart.
        let referenced = match &message {
            Message::Iso2(m) => m.to_vec_with(ValueCoding::Referenced).ok(),
            Message::Iso20(m) => m.to_vec_with(ValueCoding::Referenced).ok(),
            _ => None,
        };
        if referenced.is_some_and(|bytes| bytes != *payload) {
            tally.referenced_differs += 1;
        }

        match message.encode() {
            Ok((t, bytes)) if t == *payload_type && bytes == *payload => tally.reencoded += 1,
            Ok((t, bytes)) => {
                let _ = writeln!(
                    failures,
                    "{at}: {} re-encodes differently ({t:?}, {} vs {} bytes)",
                    message.name(),
                    bytes.len(),
                    payload.len()
                );
            }
            Err(e) => {
                let _ = writeln!(failures, "{at}: {} does not re-encode: {e:?}", message.name());
            }
        }

        match &message {
            Message::AppProtocolReq(req) => offered = Some(req.clone()),
            Message::AppProtocolRes(res) => {
                protocol =
                    res.schema_id.and_then(|id| offered.as_ref()?.protocol_for_schema_id(id));
                if protocol.is_none() {
                    let names: Vec<_> = offered
                        .iter()
                        .flat_map(|r| r.app_protocols.iter())
                        .map(|e| (e.protocol_namespace.as_str(), e.schema_id))
                        .collect();
                    let _ = writeln!(
                        failures,
                        "{at}: the handshake chose schema id {:?} from {names:?}, which names no protocol",
                        res.schema_id
                    );
                    return Ok(());
                }
            }
            Message::Iso2(doc) => pnc.observe(doc, &at, tally, failures)?,
            _ => {}
        }
    }
    Ok(())
}

#[test]
fn every_captured_message_decodes_re_encodes_and_verifies() {
    let Some(root) = std::env::var_os("ISO15118_CAPTURES").map(PathBuf::from) else {
        eprintln!("skipping: ISO15118_CAPTURES is not set — run scripts/verify-captures.sh");
        return;
    };
    let mut captures: Vec<_> = fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("ISO15118_CAPTURES={}: {e}", root.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    captures.sort();
    assert!(!captures.is_empty(), "ISO15118_CAPTURES was set but holds no captures");

    let mut total = Tally::default();
    let mut failures = String::new();
    for capture in &captures {
        let mut tally = Tally::default();
        let mut streams: Vec<_> = fs::read_dir(capture)
            .expect("read capture")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(".a.bin"))
            .collect();
        streams.sort();
        for stream in &streams {
            if let Err(e) = replay(stream, &mut tally, &mut failures) {
                let _ = writeln!(failures, "{e}");
            }
        }
        eprintln!(
            "{:<62} {:>5} messages {:>5} identical {:>4} declined {:>2}/{:<2} signatures",
            capture.file_name().unwrap_or_default().to_string_lossy(),
            tally.messages,
            tally.reencoded,
            tally.declined,
            tally.verified,
            tally.authorizations,
        );
        total.foreign_streams += tally.foreign_streams;
        total.messages += tally.messages;
        total.reencoded += tally.reencoded;
        total.referenced_differs += tally.referenced_differs;
        total.declined += tally.declined;
        total.authorizations += tally.authorizations;
        total.verified += tally.verified;
    }
    eprintln!(
        "total: {} messages decoded, {} re-encoded byte-identical, {} DIN frames declined by name, {}/{} Plug & Charge authorizations verify, {} non-V2G stream(s) skipped",
        total.messages,
        total.reencoded,
        total.declined,
        total.verified,
        total.authorizations,
        total.foreign_streams
    );
    assert!(failures.is_empty(), "replay failures:\n{failures}");
    assert!(total.messages > 0, "no V2G message in the corpus");
    // The replay must be able to see that regression: an encoder writing
    // string-table references would re-encode these messages differently, and
    // every one of them would be a failure above.
    println!(
        "string-table coding would differ on {} of {} messages",
        total.referenced_differs, total.messages
    );
    assert!(
        total.referenced_differs > 0,
        "re-encoding with string-table references changed nothing, so this replay \
         could not catch that regression"
    );
}
