#![no_main]
use libfuzzer_sys::fuzz_target;
use shannon::events::Direction;
use shannon::parsers::snmp::SnmpParser;

fuzz_target!(|data: &[u8]| {
    let mut p = SnmpParser::default();
    let _ = p.parse(data, Direction::Tx);
});
