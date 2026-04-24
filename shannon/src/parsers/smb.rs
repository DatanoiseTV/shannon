//! SMB2 / SMB3 (MS-SMB2) — tcp/445, tcp/139 (NetBIOS-over-TCP).
//!
//! Windows file sharing. Over tcp/445 the wire format is a 4-byte
//! NetBIOS length prefix followed by the SMB2 packet:
//!
//! ```text
//!   u32 length            (BE, top byte usually 0; only low 24 bits used)
//!   SMB2 header (64 bytes):
//!     u8[4] magic         (0xfe "SMB")
//!     u16 structure_size  (0x0040)
//!     u16 credit_charge
//!     u32 status
//!     u16 command
//!     u16 credits
//!     u32 flags
//!     u32 next_command
//!     u64 message_id
//!     u32 process_id       (reserved in SMB3)
//!     u32 tree_id
//!     u64 session_id
//!     u8[16] signature
//!   payload...
//! ```
//!
//! shannon surfaces command name, status code (with a handful of
//! common NT_STATUS values named), session id, tree id, and message
//! id. Commands: Negotiate (0x0), SessionSetup (0x1), TreeConnect
//! (0x3), Create (0x5), Close (0x6), Read (0x8), Write (0x9),
//! Query Info / Set Info, Ioctl, Change Notify, …
//!
//! For TreeConnect we decode the UTF-16LE share path so operators
//! see "\\\\server\\C$" access on the wire. Create requests carry
//! the filename in UCS-2 as well; that's extracted too.

use crate::events::Direction;

const NBT_HEADER: usize = 4;
const SMB2_HEADER: usize = 64;

pub struct SmbParser {
    bypass: bool,
}

impl Default for SmbParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum SmbParserOutput {
    Need,
    Record { record: SmbRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SmbRecord {
    pub direction: Direction,
    pub command: u16,
    pub command_name: &'static str,
    pub status: u32,
    pub status_name: &'static str,
    pub flags: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub share_path: Option<String>,
    pub file_name: Option<String>,
}

impl SmbRecord {
    pub fn display_line(&self) -> String {
        let share = self
            .share_path
            .as_deref()
            .map(|s| format!(" share={s}"))
            .unwrap_or_default();
        let file = self
            .file_name
            .as_deref()
            .map(|s| format!(" file={s}"))
            .unwrap_or_default();
        let status = if self.status == 0 {
            "ok".to_string()
        } else {
            format!("0x{:08x} ({})", self.status, self.status_name)
        };
        format!(
            "smb2 {} msg={} tid={} sess=0x{:016x} status={status}{share}{file}",
            self.command_name, self.message_id, self.tree_id, self.session_id,
        )
    }
}

impl SmbParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SmbParserOutput {
        if self.bypass {
            return SmbParserOutput::Skip(buf.len());
        }
        if buf.len() < NBT_HEADER {
            return SmbParserOutput::Need;
        }
        // NetBIOS session header: u8 type, u24 length. Type 0 = message.
        let nbt_type = buf[0];
        if nbt_type != 0 {
            self.bypass = true;
            return SmbParserOutput::Skip(buf.len());
        }
        let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
        if len < SMB2_HEADER || len > 16 * 1024 * 1024 {
            self.bypass = true;
            return SmbParserOutput::Skip(buf.len());
        }
        let total = NBT_HEADER + len;
        if buf.len() < total {
            return SmbParserOutput::Need;
        }
        let smb = &buf[NBT_HEADER..total];
        if smb.len() < SMB2_HEADER || &smb[..4] != b"\xfeSMB" {
            self.bypass = true;
            return SmbParserOutput::Skip(total);
        }
        let status = u32::from_le_bytes([smb[8], smb[9], smb[10], smb[11]]);
        let command = u16::from_le_bytes([smb[12], smb[13]]);
        let flags = u32::from_le_bytes([smb[16], smb[17], smb[18], smb[19]]);
        let message_id = u64::from_le_bytes([
            smb[24], smb[25], smb[26], smb[27], smb[28], smb[29], smb[30], smb[31],
        ]);
        let tree_id = u32::from_le_bytes([smb[36], smb[37], smb[38], smb[39]]);
        let session_id = u64::from_le_bytes([
            smb[40], smb[41], smb[42], smb[43], smb[44], smb[45], smb[46], smb[47],
        ]);
        let body = &smb[SMB2_HEADER..];
        let (share_path, file_name) = match command {
            0x0003 => (decode_tree_connect_path(body, flags), None),
            0x0005 => (None, decode_create_filename(body)),
            _ => (None, None),
        };
        let rec = SmbRecord {
            direction: dir,
            command,
            command_name: command_name(command),
            status,
            status_name: status_name(status),
            flags,
            message_id,
            tree_id,
            session_id,
            share_path,
            file_name,
        };
        SmbParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }
}

/// TreeConnect Request (§2.2.9): structure_size=9, u8[2] flags
/// (SMB3.1.1), u16 path_offset, u16 path_length, u8[] path (UTF-16LE).
fn decode_tree_connect_path(body: &[u8], req_flags: u32) -> Option<String> {
    // Response has a different shape; only client requests carry path.
    // Flags SMB2_FLAGS_SERVER_TO_REDIR (bit 0) tells us which is which.
    if req_flags & 0x01 != 0 {
        return None;
    }
    if body.len() < 8 {
        return None;
    }
    let path_off = u16::from_le_bytes([body[4], body[5]]) as usize;
    let path_len = u16::from_le_bytes([body[6], body[7]]) as usize;
    // Offset is from start of SMB2 header; body starts at +64.
    let off_in_body = path_off.checked_sub(SMB2_HEADER)?;
    let bytes = body.get(off_in_body..off_in_body + path_len)?;
    utf16le(bytes)
}

/// Create Request (§2.2.13) — filename is at offset 56 from the body
/// start via NameOffset/NameLength u16 pair at body[44..48].
fn decode_create_filename(body: &[u8]) -> Option<String> {
    if body.len() < 48 {
        return None;
    }
    let name_off = u16::from_le_bytes([body[44], body[45]]) as usize;
    let name_len = u16::from_le_bytes([body[46], body[47]]) as usize;
    let off_in_body = name_off.checked_sub(SMB2_HEADER)?;
    let bytes = body.get(off_in_body..off_in_body + name_len)?;
    utf16le(bytes)
}

fn utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut s = String::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if let Some(c) = char::from_u32(u as u32) {
            s.push(c);
        }
    }
    Some(s)
}

const fn command_name(c: u16) -> &'static str {
    match c {
        0x0000 => "Negotiate",
        0x0001 => "SessionSetup",
        0x0002 => "Logoff",
        0x0003 => "TreeConnect",
        0x0004 => "TreeDisconnect",
        0x0005 => "Create",
        0x0006 => "Close",
        0x0007 => "Flush",
        0x0008 => "Read",
        0x0009 => "Write",
        0x000a => "Lock",
        0x000b => "Ioctl",
        0x000c => "Cancel",
        0x000d => "Echo",
        0x000e => "QueryDirectory",
        0x000f => "ChangeNotify",
        0x0010 => "QueryInfo",
        0x0011 => "SetInfo",
        0x0012 => "OplockBreak",
        _ => "?",
    }
}

const fn status_name(s: u32) -> &'static str {
    match s {
        0x00000000 => "STATUS_SUCCESS",
        0x00000103 => "STATUS_PENDING",
        0x80000005 => "STATUS_BUFFER_OVERFLOW",
        0x80000006 => "STATUS_NO_MORE_FILES",
        0xc000000d => "STATUS_INVALID_PARAMETER",
        0xc0000022 => "STATUS_ACCESS_DENIED",
        0xc0000034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xc0000043 => "STATUS_SHARING_VIOLATION",
        0xc000006d => "STATUS_LOGON_FAILURE",
        0xc000006e => "STATUS_ACCOUNT_RESTRICTION",
        0xc0000072 => "STATUS_ACCOUNT_DISABLED",
        0xc0000071 => "STATUS_PASSWORD_EXPIRED",
        0xc000009a => "STATUS_INSUFFICIENT_RESOURCES",
        0xc00000ba => "STATUS_FILE_IS_A_DIRECTORY",
        0xc00000bb => "STATUS_NOT_SUPPORTED",
        0xc000015b => "STATUS_LOGON_TYPE_NOT_GRANTED",
        0xc0000225 => "STATUS_NOT_FOUND",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_request_minimal() {
        // NBT header (type=0, len=64 + 36-byte minimal Negotiate body) +
        // SMB2 header with command=0 + empty-ish Negotiate body.
        let total_smb = SMB2_HEADER + 36;
        let mut buf = Vec::new();
        buf.push(0);
        buf.push(((total_smb >> 16) & 0xff) as u8);
        buf.push(((total_smb >> 8) & 0xff) as u8);
        buf.push((total_smb & 0xff) as u8);
        // SMB2 header
        buf.extend_from_slice(b"\xfeSMB");
        buf.extend_from_slice(&64u16.to_le_bytes()); // structure_size
        buf.extend_from_slice(&0u16.to_le_bytes()); // credit_charge
        buf.extend_from_slice(&0u32.to_le_bytes()); // status
        buf.extend_from_slice(&0u16.to_le_bytes()); // command = Negotiate
        buf.extend_from_slice(&0u16.to_le_bytes()); // credits
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // next_command
        buf.extend_from_slice(&1u64.to_le_bytes()); // message_id
        buf.extend_from_slice(&0u32.to_le_bytes()); // process_id
        buf.extend_from_slice(&0u32.to_le_bytes()); // tree_id
        buf.extend_from_slice(&0u64.to_le_bytes()); // session_id
        buf.extend_from_slice(&[0u8; 16]); // signature
        buf.extend_from_slice(&[0u8; 36]); // negotiate body
        let mut p = SmbParser::default();
        match p.parse(&buf, Direction::Tx) {
            SmbParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.command_name, "Negotiate");
                assert_eq!(record.message_id, 1);
                assert_eq!(record.status, 0);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_smb_bypasses() {
        let mut p = SmbParser::default();
        let buf = [0x01, 0, 0, 0, 0]; // nbt_type=1 (session msg), not 0
        assert!(matches!(
            p.parse(&buf, Direction::Tx),
            SmbParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_needs_more() {
        let mut p = SmbParser::default();
        assert!(matches!(
            p.parse(&[0u8; 3], Direction::Tx),
            SmbParserOutput::Need
        ));
    }
}
