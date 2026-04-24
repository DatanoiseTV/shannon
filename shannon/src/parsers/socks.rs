//! SOCKS4 / SOCKS5 proxy protocol — tcp/1080 (default), + common
//! malware C2 ports.
//!
//! Proxy protocols show up in two places on a real network: as
//! legitimate outbound egress through corp proxies, and as a common
//! tunneling carrier for C2 / reverse shells / redirectors. Both
//! are worth surfacing; shannon decodes the handshake so operators
//! can see which internal process is reaching out through a proxy
//! and to what target.
//!
//! We parse:
//!   - SOCKS4  / SOCKS4a CONNECT and BIND requests (RFC draft)
//!   - SOCKS5  client greeting + method selection, CONNECT /
//!     BIND / UDP-ASSOCIATE request with IPv4 / IPv6 / DOMAIN
//!     address (RFC 1928), plus the server's reply.
//!
//! The client greeting is detected by its leading version byte:
//!   0x04 → SOCKS4 request (vn=4, cd=1|2)
//!   0x05 → SOCKS5 greeting (ver=5, nmethods, methods[])

use crate::events::Direction;

pub struct SocksParser {
    bypass: bool,
    state: State,
}

impl Default for SocksParser {
    fn default() -> Self {
        Self {
            bypass: false,
            state: State::Greeting,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum State {
    Greeting,       // first client bytes (deduce v4 vs v5)
    MethodResponse, // v5 server's method choice
    V5Request,      // v5 client's CONNECT/BIND/UDP
    V5Reply,        // v5 server's reply
    Done,
}

pub enum SocksParserOutput {
    Need,
    Record {
        record: SocksRecord,
        consumed: usize,
    },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SocksRecord {
    pub direction: Direction,
    pub kind: SocksKind,
}

#[derive(Debug, Clone)]
pub enum SocksKind {
    V4Connect {
        command: u8,
        port: u16,
        ip: [u8; 4],
        userid: String,
        domain: Option<String>,
    },
    V5Greeting {
        methods: Vec<u8>,
    },
    V5MethodResponse {
        method: u8,
    },
    V5Request {
        command: u8,
        target: Target,
        port: u16,
    },
    V5Reply {
        reply: u8,
        target: Target,
        port: u16,
    },
}

#[derive(Debug, Clone)]
pub enum Target {
    V4([u8; 4]),
    Domain(String),
    V6([u8; 16]),
}

impl Target {
    pub fn display(&self) -> String {
        match self {
            Target::V4(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Target::Domain(d) => d.clone(),
            Target::V6(b) => b
                .chunks_exact(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }
}

impl SocksRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            SocksKind::V4Connect {
                command,
                port,
                ip,
                userid,
                domain,
            } => {
                let tgt = match domain {
                    Some(d) => d.clone(),
                    None => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                };
                let cmd = match command {
                    1 => "CONNECT",
                    2 => "BIND",
                    _ => "?",
                };
                let uid = if userid.is_empty() {
                    String::new()
                } else {
                    format!(" userid={userid}")
                };
                format!("socks4 {cmd} {tgt}:{port}{uid}")
            }
            SocksKind::V5Greeting { methods } => {
                let names: Vec<&str> = methods.iter().map(|m| method_name(*m)).collect();
                format!("socks5 greeting methods=[{}]", names.join(","))
            }
            SocksKind::V5MethodResponse { method } => {
                format!("socks5 method={}", method_name(*method))
            }
            SocksKind::V5Request {
                command,
                target,
                port,
            } => {
                let cmd = match command {
                    1 => "CONNECT",
                    2 => "BIND",
                    3 => "UDP-ASSOCIATE",
                    _ => "?",
                };
                format!("socks5 {cmd} {}:{port}", target.display())
            }
            SocksKind::V5Reply {
                reply,
                target,
                port,
            } => {
                format!(
                    "socks5 reply={} ({}) bnd={}:{port}",
                    reply,
                    reply_name(*reply),
                    target.display(),
                )
            }
        }
    }
}

const fn method_name(m: u8) -> &'static str {
    match m {
        0x00 => "none",
        0x01 => "gssapi",
        0x02 => "userpass",
        0x03 => "chap",
        0xff => "no-acceptable",
        _ => "?",
    }
}

const fn reply_name(r: u8) -> &'static str {
    match r {
        0x00 => "succeeded",
        0x01 => "general-failure",
        0x02 => "not-allowed",
        0x03 => "network-unreachable",
        0x04 => "host-unreachable",
        0x05 => "connection-refused",
        0x06 => "ttl-expired",
        0x07 => "command-not-supported",
        0x08 => "address-type-not-supported",
        _ => "?",
    }
}

impl SocksParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SocksParserOutput {
        if self.bypass {
            return SocksParserOutput::Skip(buf.len());
        }
        match self.state {
            State::Greeting => match dir {
                Direction::Tx => self.parse_greeting(buf, dir),
                Direction::Rx => {
                    // Server speaking before client greeting = wrong.
                    self.bypass = true;
                    SocksParserOutput::Skip(buf.len())
                }
            },
            State::MethodResponse => self.parse_method_response(buf, dir),
            State::V5Request => self.parse_v5_request(buf, dir),
            State::V5Reply => self.parse_v5_reply(buf, dir),
            State::Done => SocksParserOutput::Skip(buf.len()),
        }
    }

    fn parse_greeting(&mut self, buf: &[u8], dir: Direction) -> SocksParserOutput {
        if buf.is_empty() {
            return SocksParserOutput::Need;
        }
        match buf[0] {
            4 => self.parse_v4_request(buf, dir),
            5 => self.parse_v5_greeting(buf, dir),
            _ => {
                self.bypass = true;
                SocksParserOutput::Skip(buf.len())
            }
        }
    }

    fn parse_v4_request(&mut self, buf: &[u8], dir: Direction) -> SocksParserOutput {
        // 4 vn, 1 cd, 2 dstport, 4 dstip, userid\0, [domain\0 if socks4a]
        if buf.len() < 9 {
            return SocksParserOutput::Need;
        }
        let command = buf[1];
        if command != 1 && command != 2 {
            self.bypass = true;
            return SocksParserOutput::Skip(buf.len());
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = [buf[4], buf[5], buf[6], buf[7]];
        // Find end of userid
        let userid_end = match buf[8..].iter().position(|&b| b == 0) {
            Some(i) => 8 + i,
            None => return SocksParserOutput::Need,
        };
        let userid = std::str::from_utf8(&buf[8..userid_end])
            .unwrap_or("")
            .to_string();
        let mut consumed = userid_end + 1;
        // SOCKS4a: ip == 0.0.0.x with x != 0 → domain follows
        let mut domain = None;
        if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
            let dom_end = match buf[consumed..].iter().position(|&b| b == 0) {
                Some(i) => consumed + i,
                None => return SocksParserOutput::Need,
            };
            domain = Some(
                std::str::from_utf8(&buf[consumed..dom_end])
                    .unwrap_or("")
                    .to_string(),
            );
            consumed = dom_end + 1;
        }
        self.state = State::Done;
        SocksParserOutput::Record {
            record: SocksRecord {
                direction: dir,
                kind: SocksKind::V4Connect {
                    command,
                    port,
                    ip,
                    userid,
                    domain,
                },
            },
            consumed,
        }
    }

    fn parse_v5_greeting(&mut self, buf: &[u8], dir: Direction) -> SocksParserOutput {
        // 5 ver, nmethods, methods[]
        if buf.len() < 2 {
            return SocksParserOutput::Need;
        }
        let n = buf[1] as usize;
        if n == 0 || n > 255 {
            self.bypass = true;
            return SocksParserOutput::Skip(buf.len());
        }
        if buf.len() < 2 + n {
            return SocksParserOutput::Need;
        }
        let methods = buf[2..2 + n].to_vec();
        self.state = State::MethodResponse;
        SocksParserOutput::Record {
            record: SocksRecord {
                direction: dir,
                kind: SocksKind::V5Greeting { methods },
            },
            consumed: 2 + n,
        }
    }

    fn parse_method_response(&mut self, buf: &[u8], dir: Direction) -> SocksParserOutput {
        // 5 ver, method
        if buf.len() < 2 {
            return SocksParserOutput::Need;
        }
        if buf[0] != 5 {
            self.bypass = true;
            return SocksParserOutput::Skip(buf.len());
        }
        let method = buf[1];
        self.state = State::V5Request;
        SocksParserOutput::Record {
            record: SocksRecord {
                direction: dir,
                kind: SocksKind::V5MethodResponse { method },
            },
            consumed: 2,
        }
    }

    fn parse_v5_request(&mut self, buf: &[u8], dir: Direction) -> SocksParserOutput {
        // 5 ver, cmd, 0 rsv, atyp, addr, 2 port
        if buf.len() < 4 {
            return SocksParserOutput::Need;
        }
        if buf[0] != 5 {
            self.bypass = true;
            return SocksParserOutput::Skip(buf.len());
        }
        let command = buf[1];
        let atyp = buf[3];
        let (target, addr_end) = match parse_address(&buf[4..], atyp) {
            Some(v) => v,
            None => return SocksParserOutput::Need,
        };
        let port_off = 4 + addr_end;
        if buf.len() < port_off + 2 {
            return SocksParserOutput::Need;
        }
        let port = u16::from_be_bytes([buf[port_off], buf[port_off + 1]]);
        self.state = State::V5Reply;
        SocksParserOutput::Record {
            record: SocksRecord {
                direction: dir,
                kind: SocksKind::V5Request {
                    command,
                    target,
                    port,
                },
            },
            consumed: port_off + 2,
        }
    }

    fn parse_v5_reply(&mut self, buf: &[u8], dir: Direction) -> SocksParserOutput {
        if buf.len() < 4 {
            return SocksParserOutput::Need;
        }
        if buf[0] != 5 {
            self.bypass = true;
            return SocksParserOutput::Skip(buf.len());
        }
        let reply = buf[1];
        let atyp = buf[3];
        let (target, addr_end) = match parse_address(&buf[4..], atyp) {
            Some(v) => v,
            None => return SocksParserOutput::Need,
        };
        let port_off = 4 + addr_end;
        if buf.len() < port_off + 2 {
            return SocksParserOutput::Need;
        }
        let port = u16::from_be_bytes([buf[port_off], buf[port_off + 1]]);
        self.state = State::Done;
        SocksParserOutput::Record {
            record: SocksRecord {
                direction: dir,
                kind: SocksKind::V5Reply {
                    reply,
                    target,
                    port,
                },
            },
            consumed: port_off + 2,
        }
    }
}

fn parse_address(buf: &[u8], atyp: u8) -> Option<(Target, usize)> {
    match atyp {
        0x01 => {
            if buf.len() < 4 {
                None
            } else {
                Some((Target::V4([buf[0], buf[1], buf[2], buf[3]]), 4))
            }
        }
        0x03 => {
            if buf.is_empty() {
                return None;
            }
            let n = buf[0] as usize;
            if buf.len() < 1 + n {
                return None;
            }
            let s = std::str::from_utf8(&buf[1..1 + n]).ok()?.to_string();
            Some((Target::Domain(s), 1 + n))
        }
        0x04 => {
            if buf.len() < 16 {
                None
            } else {
                let mut a = [0u8; 16];
                a.copy_from_slice(&buf[..16]);
                Some((Target::V6(a), 16))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks4_connect_with_userid() {
        let mut buf = vec![0x04, 0x01]; // vn, cd=connect
        buf.extend_from_slice(&80u16.to_be_bytes()); // dstport
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(b"alice\0");
        let mut p = SocksParser::default();
        match p.parse(&buf, Direction::Tx) {
            SocksParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                match record.kind {
                    SocksKind::V4Connect {
                        command,
                        port,
                        ip,
                        userid,
                        domain,
                    } => {
                        assert_eq!(command, 1);
                        assert_eq!(port, 80);
                        assert_eq!(ip, [10, 0, 0, 1]);
                        assert_eq!(userid, "alice");
                        assert!(domain.is_none());
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn socks5_full_handshake() {
        let mut p = SocksParser::default();
        // Greeting: ver=5, nmethods=1, methods=[0]
        let g = [0x05, 0x01, 0x00];
        match p.parse(&g, Direction::Tx) {
            SocksParserOutput::Record { record, .. } => match record.kind {
                SocksKind::V5Greeting { methods } => assert_eq!(methods, vec![0]),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Method response: ver=5, method=0
        let m = [0x05, 0x00];
        match p.parse(&m, Direction::Rx) {
            SocksParserOutput::Record { record, .. } => match record.kind {
                SocksKind::V5MethodResponse { method } => assert_eq!(method, 0),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Request: 05 01 00 03 len "example.com" 01bb
        let host = b"example.com";
        let mut r = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        r.extend_from_slice(host);
        r.extend_from_slice(&443u16.to_be_bytes());
        match p.parse(&r, Direction::Tx) {
            SocksParserOutput::Record { record, .. } => match record.kind {
                SocksKind::V5Request {
                    command,
                    target,
                    port,
                } => {
                    assert_eq!(command, 1);
                    assert_eq!(port, 443);
                    assert_eq!(target.display(), "example.com");
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn non_socks_bypasses() {
        let mut p = SocksParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            SocksParserOutput::Skip(_)
        ));
    }
}
