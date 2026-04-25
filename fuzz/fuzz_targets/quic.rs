#![no_main]
use libfuzzer_sys::fuzz_target;
use shannon::events::Direction;
use shannon::parsers::quic::QuicParser;

fuzz_target!(|data: &[u8]| {
    let mut p = QuicParser::default();
    let _ = p.parse(data, Direction::Tx);
});
