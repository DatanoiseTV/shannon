#![no_main]
use libfuzzer_sys::fuzz_target;
use shannon::events::Direction;
use shannon::parsers::tls::TlsParser;

fuzz_target!(|data: &[u8]| {
    let mut p = TlsParser::default();
    let _ = p.parse(data, Direction::Tx);
});
