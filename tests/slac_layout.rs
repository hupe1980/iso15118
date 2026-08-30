//! Every SLAC message's byte layout, pinned field by field.
//!
//! # Why this file exists
//!
//! This crate argues, at length, that round-tripping your own encoder through
//! your own decoder proves the two agree with each other and nothing more. The
//! EXI layer is held to that standard by `scripts/verify-*.sh`, which check
//! every grammar and every message against the EXI reference implementation.
//!
//! SLAC had no such check. Its message layouts are hand-transcribed from
//! ISO 15118-3 and `HomePlug` `GreenPHY`, and what tested them was a round trip
//! plus one four-byte endianness assertion on a single field of a single
//! message — exactly the evidence this project says is not evidence. Swap two
//! fields of the same width in both the encoder and the decoder and every
//! round-trip test still passes; the frame is simply wrong on the wire, and it
//! fails against every real modem.
//!
//! There is no reference implementation to run here, so this is the next
//! strongest thing: each message is encoded with a distinct byte value per
//! field and the whole frame is asserted verbatim. That pins the field *order*,
//! each field's *offset*, each field's *width*, the reserved gaps, and the two
//! `MVFLength` constants — everything a layout can get wrong.
//!
//! The expected bytes were derived from the layouts in
//! [EVerest's `libslac`](https://github.com/EVerest/libslac) — an independent
//! C++ implementation whose packed structs are the same messages — and checked
//! against them field for field. Where this file and that header disagree, one
//! of them is wrong and it matters.

#![cfg(feature = "slac")]

use iso15118::slac::{
    AttenCharInd, AttenCharRsp, AttenProfile, AttenProfileInd, MnbcSoundInd, SetKeyCnf, SetKeyReq,
    SlacMatchCnf, SlacMatchReq, SlacParmCnf, SlacParmReq, StartAttenCharInd, ValidateCnf,
    ValidateReq,
};

/// A distinct filler per field, so a swap between two fields cannot pass.
const RUN_ID: [u8; 8] = [0x11; 8];
const PEV_MAC: [u8; 6] = [0x22; 6];
const EVSE_MAC: [u8; 6] = [0x33; 6];
const PEV_ID: [u8; 17] = [0x44; 17];
const EVSE_ID: [u8; 17] = [0x55; 17];
const NMK: [u8; 16] = [0x66; 16];
const NID: [u8; 7] = [0x77; 7];
const RANDOM: [u8; 16] = [0x88; 16];

/// `application_type = 0x00`, `security_type = 0x00` — the only pair
/// ISO 15118-3 defines, and two bytes wide wherever it appears.
const PROFILE: [u8; 2] = [0x00, 0x00];

fn encoded(f: impl Fn(&mut [u8]) -> Result<usize, iso15118::slac::SlacError>) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = f(&mut buf).expect("encode");
    buf[..n].to_vec()
}

/// Builds the expected byte string from a field list, and checks the pieces add
/// up to the length the message declares.
fn expect(fields: &[&[u8]], declared: usize) -> Vec<u8> {
    let out: Vec<u8> = fields.concat();
    assert_eq!(out.len(), declared, "the field list does not add up to LEN");
    out
}

#[test]
fn slac_parm_req_layout() {
    let msg = SlacParmReq { run_id: RUN_ID };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(&[&PROFILE, &RUN_ID], SlacParmReq::LEN),
        "application_type, security_type, RunID"
    );
}

#[test]
fn slac_parm_cnf_layout() {
    // The profile pair sits *after* `forwarding_sta` here and before `run_id` —
    // unlike every other message, where it opens. Getting that wrong shifts the
    // run id by two bytes and every station on the segment ignores the frame.
    let msg = SlacParmCnf {
        m_sound_target: [0xFF; 6],
        num_sounds: 10,
        timeout: 6,
        resp_type: 0x01,
        forwarding_sta: PEV_MAC,
        run_id: RUN_ID,
    };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(&[&[0xFF; 6], &[10], &[6], &[0x01], &PEV_MAC, &PROFILE, &RUN_ID], SlacParmCnf::LEN),
        "M-SOUND_TARGET, NUM_SOUNDS, Time_Out, RESP_TYPE, FORWARDING_STA, profile, RunID"
    );
}

#[test]
fn start_atten_char_ind_layout() {
    let msg = StartAttenCharInd {
        num_sounds: 10,
        timeout: 6,
        resp_type: 0x01,
        forwarding_sta: PEV_MAC,
        run_id: RUN_ID,
    };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(&[&PROFILE, &[10], &[6], &[0x01], &PEV_MAC, &RUN_ID], StartAttenCharInd::LEN),
        "profile, NUM_SOUNDS, Time_Out, RESP_TYPE, FORWARDING_STA, RunID"
    );
}

#[test]
fn mnbc_sound_ind_layout() {
    let msg = MnbcSoundInd {
        sender_id: PEV_ID,
        remaining_sound_count: 9,
        run_id: RUN_ID,
        random: RANDOM,
    };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(&[&PROFILE, &PEV_ID, &[9], &RUN_ID, &[0u8; 8], &RANDOM], MnbcSoundInd::LEN),
        "profile, SenderID, Cnt, RunID, 8 reserved, Rnd"
    );
}

#[test]
fn atten_char_ind_layout() {
    let mut aag = [0u8; 58];
    aag[0] = 0xA0;
    aag[57] = 0xA1;
    let msg = AttenCharInd {
        source_address: PEV_MAC,
        run_id: RUN_ID,
        source_id: PEV_ID,
        resp_id: EVSE_ID,
        num_sounds: 10,
        profile: AttenProfile { num_groups: 58, aag },
    };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(
            &[&PROFILE, &PEV_MAC, &RUN_ID, &PEV_ID, &EVSE_ID, &[10], &[58], &aag],
            AttenCharInd::LEN
        ),
        "profile, SOURCE_ADDRESS, RunID, SOURCE_ID, RESP_ID, NumSounds, NumGroups, AAG"
    );
}

#[test]
fn atten_char_rsp_layout() {
    let msg = AttenCharRsp {
        source_address: PEV_MAC,
        run_id: RUN_ID,
        source_id: PEV_ID,
        resp_id: EVSE_ID,
        result: 0,
    };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(&[&PROFILE, &PEV_MAC, &RUN_ID, &PEV_ID, &EVSE_ID, &[0]], AttenCharRsp::LEN),
        "profile, SOURCE_ADDRESS, RunID, SOURCE_ID, RESP_ID, Result"
    );
}

/// The one message with no profile pair at all: it never leaves the host, it
/// comes *from* the modem.
#[test]
fn atten_profile_ind_layout() {
    let mut aag = [0u8; 58];
    aag[0] = 0xA0;
    aag[57] = 0xA1;
    let msg = AttenProfileInd { pev_mac: PEV_MAC, profile: AttenProfile { num_groups: 58, aag } };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(&[&PEV_MAC, &[58], &[0], &aag], AttenProfileInd::LEN),
        "PEV MAC, NumGroups, 1 reserved, AAG"
    );
}

#[test]
fn slac_match_req_layout() {
    let msg = SlacMatchReq {
        pev_id: PEV_ID,
        pev_mac: PEV_MAC,
        evse_id: EVSE_ID,
        evse_mac: EVSE_MAC,
        run_id: RUN_ID,
    };
    let bytes = encoded(|b| msg.encode(b));
    assert_eq!(
        bytes,
        expect(
            &[
                &PROFILE,
                &0x3Eu16.to_le_bytes(),
                &PEV_ID,
                &PEV_MAC,
                &EVSE_ID,
                &EVSE_MAC,
                &RUN_ID,
                &[0u8; 8],
            ],
            SlacMatchReq::LEN
        ),
        "profile, MVFLength, PEV ID, PEV MAC, EVSE ID, EVSE MAC, RunID, 8 reserved"
    );
    // MVFLength counts the bytes *after itself*, little-endian. It is the one
    // field here that is derived rather than copied, so it is the one that can
    // silently disagree with the layout around it.
    let mvf = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    assert_eq!(mvf, SlacMatchReq::LEN - 4, "MVFLength must cover everything after itself");
    assert_eq!(mvf, 0x3E, "libslac: 0x3e");
}

#[test]
fn slac_match_cnf_layout() {
    let msg = SlacMatchCnf {
        pev_id: PEV_ID,
        pev_mac: PEV_MAC,
        evse_id: EVSE_ID,
        evse_mac: EVSE_MAC,
        run_id: RUN_ID,
        nid: NID,
        nmk: NMK,
    };
    let bytes = encoded(|b| msg.encode(b));
    assert_eq!(
        bytes,
        expect(
            &[
                &PROFILE,
                &0x56u16.to_le_bytes(),
                &PEV_ID,
                &PEV_MAC,
                &EVSE_ID,
                &EVSE_MAC,
                &RUN_ID,
                &[0u8; 8],
                &NID,
                &[0],
                &NMK,
            ],
            SlacMatchCnf::LEN
        ),
        "profile, MVFLength, PEV ID, PEV MAC, EVSE ID, EVSE MAC, RunID, 8 reserved, \
         NID, 1 reserved, NMK"
    );
    let mvf = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    assert_eq!(mvf, SlacMatchCnf::LEN - 4, "MVFLength must cover everything after itself");
    assert_eq!(mvf, 0x56, "libslac: 0x56");

    // The key is the last sixteen bytes and the NID the seven before the pad.
    // This is the frame that hands over the network key in the clear; if the
    // two ever swapped places the vehicle would join with a key made of the
    // wrong bytes and the fault would look like a radio problem.
    assert_eq!(&bytes[SlacMatchCnf::LEN - 16..], &NMK);
    assert_eq!(&bytes[SlacMatchCnf::LEN - 24..SlacMatchCnf::LEN - 17], &NID);
}

#[test]
fn validate_layouts() {
    let req = ValidateReq { signal_type: 0, timer: 1, result: 2 };
    assert_eq!(encoded(|b| req.encode(b)), expect(&[&[0], &[1], &[2]], ValidateReq::LEN));

    // `CNF` puts `toggle_num` where `REQ` puts `timer` — same width, different
    // meaning, so only the order distinguishes them.
    let cnf = ValidateCnf { signal_type: 0, toggle_num: 3, result: 4 };
    assert_eq!(encoded(|b| cnf.encode(b)), expect(&[&[0], &[3], &[4]], ValidateCnf::LEN));
}

#[test]
fn set_key_req_layout() {
    let msg = SetKeyReq {
        key_type: 0x01,
        my_nonce: 0xAABB_CCDD,
        your_nonce: 0x1122_3344,
        pid: 0x04,
        prn: 0x0102,
        pmn: 0x00,
        cco_capability: 0x00,
        nid: NID,
        new_eks: 0x01,
        new_key: NMK,
    };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(
            &[
                &[0x01],
                // HomePlug is little-endian for multi-byte fields, unlike the
                // EtherType above it and unlike V2GTP.
                &0xAABB_CCDDu32.to_le_bytes(),
                &0x1122_3344u32.to_le_bytes(),
                &[0x04],
                &0x0102u16.to_le_bytes(),
                &[0x00],
                &[0x00],
                &NID,
                &[0x01],
                &NMK,
            ],
            SetKeyReq::LEN
        ),
        "KeyType, MyNonce, YourNonce, PID, PRN, PMN, CCoCapability, NID, NewEKS, NewKey"
    );
}

#[test]
fn set_key_cnf_layout() {
    let msg = SetKeyCnf {
        result: 0x01,
        my_nonce: 0xAABB_CCDD,
        your_nonce: 0x1122_3344,
        pid: 0x04,
        prn: 0x0102,
        pmn: 0x00,
        cco_capability: 0x00,
    };
    assert_eq!(
        encoded(|b| msg.encode(b)),
        expect(
            &[
                &[0x01],
                &0xAABB_CCDDu32.to_le_bytes(),
                &0x1122_3344u32.to_le_bytes(),
                &[0x04],
                &0x0102u16.to_le_bytes(),
                &[0x00],
                &[0x00],
            ],
            SetKeyCnf::LEN
        ),
        "Result, MyNonce, YourNonce, PID, PRN, PMN, CCoCapability"
    );
}

/// The Ethernet framing around all of the above, which has its own trap: the
/// `EtherType` is big-endian and the management-message type immediately after
/// it is little-endian.
#[test]
fn ethernet_framing_layout() {
    use iso15118::slac::{ETHERNET_HEADER_LEN, MIN_FRAME_LEN, Mmtype, Mmv, write_frame};

    let mut payload = [0u8; 64];
    let n = SlacParmReq { run_id: RUN_ID }.encode(&mut payload).unwrap();
    let mut wire = [0u8; 128];
    let len =
        write_frame(&mut wire, EVSE_MAC, PEV_MAC, Mmv::Av1_1, Mmtype::SlacParmReq, &payload[..n])
            .unwrap();

    assert_eq!(len, MIN_FRAME_LEN, "a short MME is padded to the Ethernet minimum");
    assert_eq!(&wire[..6], &EVSE_MAC, "destination");
    assert_eq!(&wire[6..12], &PEV_MAC, "source");
    assert_eq!(&wire[12..14], &0x88E1u16.to_be_bytes(), "EtherType is big-endian");
    assert_eq!(wire[14], 0x01, "MMV = AV 1.1");
    assert_eq!(&wire[15..17], &0x6064u16.to_le_bytes(), "MMTYPE is little-endian");
    assert_eq!(&wire[17..19], &[0, 0], "the two-byte fragmentation field AV 1.1 adds");
    assert_eq!(&wire[ETHERNET_HEADER_LEN + 3 + 2..][..n], &payload[..n], "then the body");
    assert!(wire[ETHERNET_HEADER_LEN + 3 + 2 + n..len].iter().all(|&b| b == 0), "zero padded");
}

/// AV 1.0 has no fragmentation field, so the body starts two bytes earlier.
/// Reading that wrong shifts every field of every message.
#[test]
fn the_fragmentation_field_only_exists_from_av_1_1() {
    use iso15118::slac::{Mmtype, Mmv, parse_frame, write_frame};

    for (mmv, offset) in [(Mmv::Av1_0, 17), (Mmv::Av1_1, 19), (Mmv::Av2_0, 19)] {
        let mut wire = [0u8; 128];
        let len = write_frame(&mut wire, EVSE_MAC, PEV_MAC, mmv, Mmtype::SlacParmReq, &[0xAB; 10])
            .unwrap();
        assert_eq!(wire[offset], 0xAB, "{mmv:?}: body starts at {offset}");
        let f = parse_frame(&wire[..len]).unwrap();
        assert_eq!(f.mmv, mmv);
        assert_eq!(f.payload[0], 0xAB);
    }
}
