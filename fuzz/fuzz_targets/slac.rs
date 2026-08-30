//! SLAC runs on raw Ethernet frames before any authentication exists at all.
#![no_main]

use iso15118::slac::{self, Mmtype};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = slac::parse_frame(data) else { return };
    let p = frame.payload;
    match frame.mmtype {
        Mmtype::SlacParmReq => drop(slac::SlacParmReq::decode(p)),
        Mmtype::SlacParmCnf => drop(slac::SlacParmCnf::decode(p)),
        Mmtype::StartAttenCharInd => drop(slac::StartAttenCharInd::decode(p)),
        Mmtype::MnbcSoundInd => drop(slac::MnbcSoundInd::decode(p)),
        Mmtype::AttenCharInd => drop(slac::AttenCharInd::decode(p)),
        Mmtype::AttenCharRsp => drop(slac::AttenCharRsp::decode(p)),
        Mmtype::AttenProfileInd => drop(slac::AttenProfileInd::decode(p)),
        Mmtype::SlacMatchReq => drop(slac::SlacMatchReq::decode(p)),
        Mmtype::SlacMatchCnf => drop(slac::SlacMatchCnf::decode(p)),
        Mmtype::ValidateReq => drop(slac::ValidateReq::decode(p)),
        Mmtype::ValidateCnf => drop(slac::ValidateCnf::decode(p)),
        Mmtype::SetKeyReq => drop(slac::SetKeyReq::decode(p)),
        Mmtype::SetKeyCnf => drop(slac::SetKeyCnf::decode(p)),
        Mmtype::Other(_) => {}
        _ => {}
    }
});
