#![no_main]
use libfuzzer_sys::fuzz_target;
use shannon::events::Direction;
use shannon::parsers::kerberos::KerberosParser;

fuzz_target!(|data: &[u8]| {
    let mut p = KerberosParser::default();
    let _ = p.parse(data, Direction::Tx);
});
