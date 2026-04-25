#![no_main]
//! Fuzz the DNS parser. DNS is a primary attack surface — every shannon
//! deployment sees DNS, the parser handles label compression and
//! variably-typed RR data, and bugs here are likely OOB reads.

use libfuzzer_sys::fuzz_target;
use shannon::events::Direction;
use shannon::parsers::dns::DnsParser;

fuzz_target!(|data: &[u8]| {
    let mut p = DnsParser::default();
    let _ = p.parse(data, Direction::Tx);
});
