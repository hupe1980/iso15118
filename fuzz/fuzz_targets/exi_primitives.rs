//! Every EXI primitive decoder, driven by arbitrary bits.
#![no_main]

use iso15118::exi::{Decoder, Lengths, ValueCtx};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Drive a different primitive per input, using the first byte as a selector
    // so a single corpus exercises all of them.
    let Some((&selector, body)) = data.split_first() else { return };
    let mut d = Decoder::new(body);
    match selector % 8 {
        0 => drop(d.uint()),
        1 => drop(d.int()),
        2 => drop(d.decimal()),
        3 => drop(d.float()),
        4 => drop(d.datetime()),
        5 => drop(d.binary(Lengths::max(4096))),
        6 => drop(d.string(ValueCtx(0), Lengths::max(4096))),
        _ => {
            // A sequence of values sharing one string table: the interesting
            // case, because table indices depend on decode history.
            for _ in 0..8 {
                if d.string(ValueCtx(u32::from(selector) % 3), Lengths::max(512)).is_err() {
                    break;
                }
            }
        }
    }
});
