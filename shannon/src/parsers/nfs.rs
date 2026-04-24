//! NFS over ONC-RPC (RFC 5531 + RFC 1813 + RFC 7530) — tcp/2049.
//!
//! NFS traffic rides Sun RPC / ONC RPC. Over TCP each PDU carries a
//! 4-byte record marker whose top bit flags "last fragment" and low
//! 31 bits give the length of this fragment:
//!
//! ```text
//!   u32 fragment          (BE)  top bit = last_fragment, low 31 bits = length
//!   u32 xid               (BE)  request/response correlation
//!   u32 msg_type          (BE)  0 = CALL, 1 = REPLY
//!   CALL:
//!     u32 rpc_version (=2)
//!     u32 program            (100003 NFS, 100005 MOUNT, 100021 NLM,
//!                              100024 STATUS, 100000 PORTMAP, 400000 NFS ACL)
//!     u32 program_version
//!     u32 procedure
//!     opaque_auth credentials
//!     opaque_auth verifier
//!     procedure-specific args
//!   REPLY:
//!     u32 reply_state (0 = MSG_ACCEPTED, 1 = MSG_DENIED)
//!     if accepted: opaque_auth verifier + u32 accept_state + results
//! ```
//!
//! shannon surfaces program + procedure names, xid, and reply
//! accept/deny state. Full NFS argument decoding (file handles, path
//! components, range counts) is a deeper follow-up; the record
//! envelope already tells operators which clients are hammering
//! which servers with what mix of READ / WRITE / GETATTR / LOOKUP —
//! enough for the kind of I/O-pattern debugging shannon exists for.

use crate::events::Direction;

pub struct NfsParser {
    bypass: bool,
}

impl Default for NfsParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum NfsParserOutput {
    Need,
    Record { record: NfsRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct NfsRecord {
    pub direction: Direction,
    pub xid: u32,
    pub kind: NfsKind,
}

#[derive(Debug, Clone)]
pub enum NfsKind {
    Call {
        rpc_version: u32,
        program: u32,
        program_name: &'static str,
        program_version: u32,
        procedure: u32,
        procedure_name: &'static str,
    },
    Reply {
        accepted: bool,
        accept_state: Option<u32>,
        accept_state_name: &'static str,
    },
}

impl NfsRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            NfsKind::Call {
                program_name,
                program_version,
                procedure,
                procedure_name,
                ..
            } => format!(
                "nfs CALL xid={:08x} {}(v{}) {}({})",
                self.xid, program_name, program_version, procedure_name, procedure,
            ),
            NfsKind::Reply { accepted: true, accept_state_name, .. } => format!(
                "nfs REPLY xid={:08x} accepted {}",
                self.xid, accept_state_name,
            ),
            NfsKind::Reply { accepted: false, .. } => {
                format!("nfs REPLY xid={:08x} denied", self.xid)
            }
        }
    }
}

impl NfsParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> NfsParserOutput {
        if self.bypass {
            return NfsParserOutput::Skip(buf.len());
        }
        if buf.len() < 4 {
            return NfsParserOutput::Need;
        }
        let frag = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let len = (frag & 0x7fff_ffff) as usize;
        if len < 8 || len > 16 * 1024 * 1024 {
            self.bypass = true;
            return NfsParserOutput::Skip(buf.len());
        }
        let total = 4 + len;
        if buf.len() < total {
            return NfsParserOutput::Need;
        }
        let body = &buf[4..total];
        if body.len() < 8 {
            self.bypass = true;
            return NfsParserOutput::Skip(total);
        }
        let xid = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let msg_type = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let rec = match msg_type {
            0 => decode_call(xid, &body[8..]),
            1 => decode_reply(xid, &body[8..]),
            _ => {
                self.bypass = true;
                return NfsParserOutput::Skip(total);
            }
        };
        match rec {
            Some(rec) => NfsParserOutput::Record {
                record: NfsRecord { direction: dir, xid, kind: rec },
                consumed: total,
            },
            None => {
                self.bypass = true;
                NfsParserOutput::Skip(total)
            }
        }
    }
}

fn decode_call(_xid: u32, body: &[u8]) -> Option<NfsKind> {
    if body.len() < 16 {
        return None;
    }
    let rpc_version = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if rpc_version != 2 {
        return None;
    }
    let program = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let program_version = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let procedure = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
    Some(NfsKind::Call {
        rpc_version,
        program,
        program_name: program_name(program),
        program_version,
        procedure,
        procedure_name: procedure_name(program, procedure),
    })
}

fn decode_reply(_xid: u32, body: &[u8]) -> Option<NfsKind> {
    if body.len() < 4 {
        return None;
    }
    let reply_state = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let accepted = reply_state == 0;
    if !accepted {
        return Some(NfsKind::Reply {
            accepted: false,
            accept_state: None,
            accept_state_name: "denied",
        });
    }
    // After opaque_auth verifier ({u32 flavor, u32 len, bytes}) comes
    // u32 accept_state.
    if body.len() < 12 {
        return Some(NfsKind::Reply {
            accepted: true,
            accept_state: None,
            accept_state_name: "?",
        });
    }
    let verifier_len = u32::from_be_bytes([body[8], body[9], body[10], body[11]]) as usize;
    let verifier_pad = (verifier_len + 3) & !3;
    let accept_off = 12 + verifier_pad;
    if body.len() < accept_off + 4 {
        return Some(NfsKind::Reply {
            accepted: true,
            accept_state: None,
            accept_state_name: "?",
        });
    }
    let accept_state = u32::from_be_bytes([
        body[accept_off], body[accept_off + 1], body[accept_off + 2], body[accept_off + 3],
    ]);
    Some(NfsKind::Reply {
        accepted: true,
        accept_state: Some(accept_state),
        accept_state_name: accept_state_name(accept_state),
    })
}

const fn program_name(p: u32) -> &'static str {
    match p {
        100000 => "PORTMAP",
        100003 => "NFS",
        100005 => "MOUNT",
        100021 => "NLM",
        100024 => "STATUS",
        100227 => "NFS_ACL",
        _ => "?",
    }
}

const fn procedure_name(program: u32, proc_num: u32) -> &'static str {
    match (program, proc_num) {
        // NFSv3 (100003 v3)
        (100003, 0) => "NULL",
        (100003, 1) => "GETATTR",
        (100003, 2) => "SETATTR",
        (100003, 3) => "LOOKUP",
        (100003, 4) => "ACCESS",
        (100003, 5) => "READLINK",
        (100003, 6) => "READ",
        (100003, 7) => "WRITE",
        (100003, 8) => "CREATE",
        (100003, 9) => "MKDIR",
        (100003, 10) => "SYMLINK",
        (100003, 11) => "MKNOD",
        (100003, 12) => "REMOVE",
        (100003, 13) => "RMDIR",
        (100003, 14) => "RENAME",
        (100003, 15) => "LINK",
        (100003, 16) => "READDIR",
        (100003, 17) => "READDIRPLUS",
        (100003, 18) => "FSSTAT",
        (100003, 19) => "FSINFO",
        (100003, 20) => "PATHCONF",
        (100003, 21) => "COMMIT",
        // MOUNT v3
        (100005, 0) => "NULL",
        (100005, 1) => "MNT",
        (100005, 2) => "DUMP",
        (100005, 3) => "UMNT",
        (100005, 4) => "UMNTALL",
        (100005, 5) => "EXPORT",
        // PORTMAP
        (100000, 0) => "NULL",
        (100000, 1) => "SET",
        (100000, 2) => "UNSET",
        (100000, 3) => "GETPORT",
        (100000, 4) => "DUMP",
        (100000, 5) => "CALLIT",
        _ => "?",
    }
}

const fn accept_state_name(s: u32) -> &'static str {
    match s {
        0 => "SUCCESS",
        1 => "PROG_UNAVAIL",
        2 => "PROG_MISMATCH",
        3 => "PROC_UNAVAIL",
        4 => "GARBAGE_ARGS",
        5 => "SYSTEM_ERR",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_call(program: u32, version: u32, proc_num: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0xabcd_0123u32.to_be_bytes()); // xid
        body.extend_from_slice(&0u32.to_be_bytes()); // msg_type = CALL
        body.extend_from_slice(&2u32.to_be_bytes()); // rpc_version
        body.extend_from_slice(&program.to_be_bytes());
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&proc_num.to_be_bytes());
        // opaque_auth credentials: flavor=0 (AUTH_NULL), len=0
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        // opaque_auth verifier: flavor=0, len=0
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());

        let mut frame = Vec::new();
        let frag = (body.len() as u32) | 0x8000_0000; // last fragment
        frame.extend_from_slice(&frag.to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn nfs_v3_read_call() {
        let frame = build_call(100003, 3, 6); // NFS v3 READ
        let mut p = NfsParser::default();
        match p.parse(&frame, Direction::Tx) {
            NfsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                match record.kind {
                    NfsKind::Call {
                        program_name, program_version, procedure_name, ..
                    } => {
                        assert_eq!(program_name, "NFS");
                        assert_eq!(program_version, 3);
                        assert_eq!(procedure_name, "READ");
                    }
                    _ => panic!(),
                }
                assert_eq!(record.xid, 0xabcd_0123);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn mount_v3_mnt_call() {
        let frame = build_call(100005, 3, 1);
        let mut p = NfsParser::default();
        match p.parse(&frame, Direction::Tx) {
            NfsParserOutput::Record { record, .. } => match record.kind {
                NfsKind::Call { program_name, procedure_name, .. } => {
                    assert_eq!(program_name, "MOUNT");
                    assert_eq!(procedure_name, "MNT");
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn non_rpc_bypasses() {
        let mut p = NfsParser::default();
        // Length 0 is out of range and should bypass.
        let buf = [0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(p.parse(&buf, Direction::Tx), NfsParserOutput::Skip(_)));
    }

    #[test]
    fn short_needs_more() {
        let mut p = NfsParser::default();
        assert!(matches!(p.parse(&[0u8; 2], Direction::Tx), NfsParserOutput::Need));
    }
}
