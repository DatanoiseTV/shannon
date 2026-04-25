#![no_main]
use libfuzzer_sys::fuzz_target;
use shannon::events::Direction;
use shannon::parsers::http2::Http2Parser;

fuzz_target!(|data: &[u8]| {
    let mut p = Http2Parser::default();
    let _ = p.parse(data, Direction::Tx);
});
