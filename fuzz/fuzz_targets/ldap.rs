#![no_main]
use libfuzzer_sys::fuzz_target;
use shannon::events::Direction;
use shannon::parsers::ldap::LdapParser;

fuzz_target!(|data: &[u8]| {
    let mut p = LdapParser::default();
    let _ = p.parse(data, Direction::Tx);
});
