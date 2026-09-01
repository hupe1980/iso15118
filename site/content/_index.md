+++
title = "iso15118"
description = "ISO 15118 vehicle-to-grid communication in pure Rust. Sans-I/O, no_std-capable EXI codec, message sets, session engines and Plug & Charge signatures for both EVCC and SECC."
template = "index.html"
+++

<!-- pinned-to: src/secc.rs -->
```rust
let mut secc = Secc::new(SeccConfig {
    protocols: Protocols::ISO,
    session_id: SessionId::new(*b"\x11\x22\x33\x44\x55\x66\x77\x88"),
    ..SeccConfig::default()
});

let mut buf = [0u8; 4096];
loop {
    let n = read(&mut buf);
    secc.handle_input(now(), &buf[..n])?;
    while let Some(event) = secc.poll_event() {
        match event {
            Event::ProtocolAgreed(p) => println!("speaking {p}"),
            Event::Request(req) => secc.respond(now(), answer(&req))?,
            Event::Refused { .. } => break,
            Event::Closed(why) => return Ok(println!("session over: {why}")),
            _ => {}
        }
    }
    write(&secc.take_transmit());
}
```
