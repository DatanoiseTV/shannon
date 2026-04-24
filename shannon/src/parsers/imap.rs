//! IMAP4rev1 (RFC 3501) / IMAP4rev2 (RFC 9051).
//!
//! Far more complex than POP3/SMTP. Client commands are prefixed with a
//! tag (alphanumeric, 1–16 chars) followed by the verb and args; server
//! responses are either untagged (`*` prefix) continuation lines or a
//! final tagged completion (`<tag> OK|NO|BAD [resp]`). Strings can
//! include literals `{N}\r\n<N bytes>` so a naïve line-at-a-time parse
//! desyncs on realistic traffic.
//!
//! We handle the literal framing, bypass anything we can't classify, and
//! keep the credential-bearing verbs (`LOGIN`, `AUTHENTICATE`) redacted.

use crate::events::Direction;

const MAX_LINE: usize = 16 * 1024;
const MAX_TAG: usize = 16;
const MAX_ARG: usize = 1024;

#[derive(Default)]
pub struct ImapParser {
    bypass: bool,
    /// When >0, the next N bytes are literal payload continuing a
    /// previous command line. We skip them (don't emit a record per
    /// chunk) and resume line-parsing when the literal is exhausted.
    literal_remaining: usize,
    /// After seeing a tagged `AUTHENTICATE` command, following client
    /// lines are the base64 continuation — redact them.
    auth_continuations: u8,
}

pub enum ImapParserOutput {
    Need,
    Record { record: ImapRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct ImapRecord {
    pub direction: Direction,
    pub tag: String, // empty for server untagged responses
    pub kind: ImapKind,
    pub args: String, // verbatim trailing args (post-redaction)
    pub text: String, // free-form response text
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapKind {
    // Client commands.
    Capability,
    Noop,
    Logout,
    Login,            // args redacted (password)
    Authenticate,     // args redacted
    AuthContinuation, // base64 line after AUTHENTICATE
    Select,
    Examine,
    Create,
    Delete,
    Rename,
    Subscribe,
    Unsubscribe,
    List,
    Lsub,
    Status,
    Append,
    Check,
    Close,
    Expunge,
    Search,
    Fetch,
    Store,
    Copy,
    Move,
    Uid,
    Idle,
    Starttls,
    Enable,
    OtherCommand(String),

    // Server untagged responses.
    UntaggedOk,
    UntaggedNo,
    UntaggedBad,
    UntaggedBye,
    UntaggedPreauth,
    UntaggedCapability,
    UntaggedFlags,
    UntaggedList,
    UntaggedLsub,
    UntaggedSearch,
    UntaggedStatus,
    UntaggedFetch,
    UntaggedExists,
    UntaggedRecent,
    UntaggedOther(String),

    // Server continuation (`+ ...`).
    ServerContinuation,

    // Server tagged completion.
    TaggedOk,
    TaggedNo,
    TaggedBad,
}

impl ImapRecord {
    pub fn display_line(&self) -> String {
        use ImapKind::*;
        match &self.kind {
            Login => format!("{} LOGIN <redacted>", self.tag),
            Authenticate => format!("{} AUTHENTICATE <redacted>", self.tag),
            AuthContinuation => "<auth continuation redacted>".to_string(),
            ServerContinuation => format!("+ {}", self.text),
            UntaggedOk => format!("* OK {}", self.text),
            UntaggedNo => format!("* NO {}", self.text),
            UntaggedBad => format!("* BAD {}", self.text),
            UntaggedBye => format!("* BYE {}", self.text),
            UntaggedPreauth => format!("* PREAUTH {}", self.text),
            UntaggedCapability => format!("* CAPABILITY {}", self.text),
            UntaggedFlags => format!("* FLAGS {}", self.text),
            UntaggedList => format!("* LIST {}", self.text),
            UntaggedLsub => format!("* LSUB {}", self.text),
            UntaggedSearch => format!("* SEARCH {}", self.text),
            UntaggedStatus => format!("* STATUS {}", self.text),
            UntaggedFetch => format!("* FETCH {}", self.text),
            UntaggedExists => format!("* {} EXISTS", self.text),
            UntaggedRecent => format!("* {} RECENT", self.text),
            UntaggedOther(label) => format!("* {} {}", label, self.text),
            TaggedOk => format!("{} OK {}", self.tag, self.text),
            TaggedNo => format!("{} NO {}", self.tag, self.text),
            TaggedBad => format!("{} BAD {}", self.tag, self.text),
            OtherCommand(v) => format!("{} {} {}", self.tag, v, self.args),
            _ => {
                let verb = verb_label(&self.kind);
                if self.args.is_empty() {
                    format!("{} {verb}", self.tag)
                } else {
                    format!("{} {verb} {}", self.tag, self.args)
                }
            }
        }
    }
}

fn verb_label(k: &ImapKind) -> &'static str {
    use ImapKind::*;
    match k {
        Capability => "CAPABILITY",
        Noop => "NOOP",
        Logout => "LOGOUT",
        Select => "SELECT",
        Examine => "EXAMINE",
        Create => "CREATE",
        Delete => "DELETE",
        Rename => "RENAME",
        Subscribe => "SUBSCRIBE",
        Unsubscribe => "UNSUBSCRIBE",
        List => "LIST",
        Lsub => "LSUB",
        Status => "STATUS",
        Append => "APPEND",
        Check => "CHECK",
        Close => "CLOSE",
        Expunge => "EXPUNGE",
        Search => "SEARCH",
        Fetch => "FETCH",
        Store => "STORE",
        Copy => "COPY",
        Move => "MOVE",
        Uid => "UID",
        Idle => "IDLE",
        Starttls => "STARTTLS",
        Enable => "ENABLE",
        _ => "?",
    }
}

impl ImapParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> ImapParserOutput {
        if self.bypass {
            return ImapParserOutput::Skip(buf.len());
        }
        // Drain any pending literal before classifying lines.
        if self.literal_remaining > 0 {
            let take = buf.len().min(self.literal_remaining);
            if take == 0 {
                return ImapParserOutput::Need;
            }
            self.literal_remaining -= take;
            return ImapParserOutput::Skip(take);
        }

        let Some(line_end) = find_crlf(buf) else {
            if buf.len() > MAX_LINE {
                self.bypass = true;
                return ImapParserOutput::Skip(buf.len());
            }
            return ImapParserOutput::Need;
        };
        let line = &buf[..line_end];
        let consumed = line_end + 2;

        // Detect trailing literal marker `{N}` at the very end of the line.
        // If present, after this line's CRLF we must consume N bytes.
        if let Some(n) = trailing_literal_count(line) {
            self.literal_remaining = n;
        }

        if !line.is_ascii() {
            self.bypass = true;
            return ImapParserOutput::Skip(buf.len());
        }
        let text = std::str::from_utf8(line).unwrap_or("").trim_end();

        match dir {
            Direction::Tx => self.parse_command(text, consumed),
            Direction::Rx => Self::parse_response(text, consumed),
        }
    }

    fn parse_command(&mut self, line: &str, consumed: usize) -> ImapParserOutput {
        if self.auth_continuations > 0 {
            self.auth_continuations -= 1;
            return ImapParserOutput::Record {
                record: ImapRecord {
                    direction: Direction::Tx,
                    tag: String::new(),
                    kind: ImapKind::AuthContinuation,
                    args: String::new(),
                    text: String::new(),
                },
                consumed,
            };
        }
        if line.is_empty() {
            return ImapParserOutput::Skip(consumed);
        }

        let mut iter = line.splitn(3, ' ');
        let tag_raw = iter.next().unwrap_or("");
        let verb_raw = iter.next().unwrap_or("");
        let rest = iter.next().unwrap_or("").trim();
        if tag_raw.is_empty() || verb_raw.is_empty() {
            return ImapParserOutput::Skip(consumed);
        }
        if !tag_raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            || tag_raw.len() > MAX_TAG
        {
            // Not an IMAP tag — bypass.
            self.bypass = true;
            return ImapParserOutput::Skip(consumed);
        }
        let verb = verb_raw.to_ascii_uppercase();
        let kind = match verb.as_str() {
            "CAPABILITY" => ImapKind::Capability,
            "NOOP" => ImapKind::Noop,
            "LOGOUT" => ImapKind::Logout,
            "LOGIN" => ImapKind::Login,
            "AUTHENTICATE" => {
                // Expect one follow-up base64 line from the client.
                self.auth_continuations = 1;
                ImapKind::Authenticate
            }
            "SELECT" => ImapKind::Select,
            "EXAMINE" => ImapKind::Examine,
            "CREATE" => ImapKind::Create,
            "DELETE" => ImapKind::Delete,
            "RENAME" => ImapKind::Rename,
            "SUBSCRIBE" => ImapKind::Subscribe,
            "UNSUBSCRIBE" => ImapKind::Unsubscribe,
            "LIST" => ImapKind::List,
            "LSUB" => ImapKind::Lsub,
            "STATUS" => ImapKind::Status,
            "APPEND" => ImapKind::Append,
            "CHECK" => ImapKind::Check,
            "CLOSE" => ImapKind::Close,
            "EXPUNGE" => ImapKind::Expunge,
            "SEARCH" => ImapKind::Search,
            "FETCH" => ImapKind::Fetch,
            "STORE" => ImapKind::Store,
            "COPY" => ImapKind::Copy,
            "MOVE" => ImapKind::Move,
            "UID" => ImapKind::Uid,
            "IDLE" => ImapKind::Idle,
            "STARTTLS" => ImapKind::Starttls,
            "ENABLE" => ImapKind::Enable,
            v if v.chars().all(|c| c.is_ascii_alphanumeric()) => {
                ImapKind::OtherCommand(v.to_string())
            }
            _ => {
                self.bypass = true;
                return ImapParserOutput::Skip(consumed);
            }
        };
        let args = match kind {
            ImapKind::Login | ImapKind::Authenticate => String::new(),
            _ => truncate_to(rest.to_string(), MAX_ARG),
        };
        ImapParserOutput::Record {
            record: ImapRecord {
                direction: Direction::Tx,
                tag: tag_raw.to_string(),
                kind,
                args,
                text: String::new(),
            },
            consumed,
        }
    }

    fn parse_response(line: &str, consumed: usize) -> ImapParserOutput {
        if line.is_empty() {
            return ImapParserOutput::Skip(consumed);
        }
        // Continuation.
        if let Some(rest) = line.strip_prefix("+ ").or(line.strip_prefix('+')) {
            return ImapParserOutput::Record {
                record: ImapRecord {
                    direction: Direction::Rx,
                    tag: String::new(),
                    kind: ImapKind::ServerContinuation,
                    args: String::new(),
                    text: rest.trim_start().to_string(),
                },
                consumed,
            };
        }
        // Untagged.
        if let Some(rest) = line.strip_prefix("* ") {
            let (first, after) = rest.split_once(' ').unwrap_or((rest, ""));
            let kind = match first.to_ascii_uppercase().as_str() {
                "OK" => ImapKind::UntaggedOk,
                "NO" => ImapKind::UntaggedNo,
                "BAD" => ImapKind::UntaggedBad,
                "BYE" => ImapKind::UntaggedBye,
                "PREAUTH" => ImapKind::UntaggedPreauth,
                "CAPABILITY" => ImapKind::UntaggedCapability,
                "FLAGS" => ImapKind::UntaggedFlags,
                "LIST" => ImapKind::UntaggedList,
                "LSUB" => ImapKind::UntaggedLsub,
                "SEARCH" => ImapKind::UntaggedSearch,
                "STATUS" => ImapKind::UntaggedStatus,
                v => {
                    // Numeric responses: `* 23 EXISTS`, `* 2 RECENT`, `* 5 FETCH ...`.
                    if v.chars().all(|c| c.is_ascii_digit()) {
                        let kind2 = match after.split(' ').next().map(str::to_ascii_uppercase) {
                            Some(ref s) if s == "EXISTS" => ImapKind::UntaggedExists,
                            Some(ref s) if s == "RECENT" => ImapKind::UntaggedRecent,
                            Some(ref s) if s == "FETCH" => ImapKind::UntaggedFetch,
                            _ => ImapKind::UntaggedOther(v.to_string()),
                        };
                        return ImapParserOutput::Record {
                            record: ImapRecord {
                                direction: Direction::Rx,
                                tag: String::new(),
                                kind: kind2,
                                args: String::new(),
                                text: truncate_to(format!("{} {}", v, after.trim_end()), MAX_ARG),
                            },
                            consumed,
                        };
                    }
                    ImapKind::UntaggedOther(v.to_string())
                }
            };
            return ImapParserOutput::Record {
                record: ImapRecord {
                    direction: Direction::Rx,
                    tag: String::new(),
                    kind,
                    args: String::new(),
                    text: truncate_to(after.trim_end().to_string(), MAX_ARG),
                },
                consumed,
            };
        }
        // Tagged completion: `<tag> OK|NO|BAD <text>`.
        let mut parts = line.splitn(3, ' ');
        let tag = parts.next().unwrap_or("");
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").trim_end();
        if tag.is_empty() || verb.is_empty() {
            return ImapParserOutput::Skip(consumed);
        }
        let kind = match verb.as_str() {
            "OK" => ImapKind::TaggedOk,
            "NO" => ImapKind::TaggedNo,
            "BAD" => ImapKind::TaggedBad,
            _ => return ImapParserOutput::Skip(consumed),
        };
        ImapParserOutput::Record {
            record: ImapRecord {
                direction: Direction::Rx,
                tag: tag.to_string(),
                kind,
                args: String::new(),
                text: truncate_to(rest.to_string(), MAX_ARG),
            },
            consumed,
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn trailing_literal_count(line: &[u8]) -> Option<usize> {
    // A literal marker `{N}` at end-of-line (possibly with `+` suffix for
    // non-synchronising literals per RFC 7888).
    let s = std::str::from_utf8(line).ok()?.trim_end();
    if !s.ends_with('}') {
        return None;
    }
    let inside_start = s.rfind('{')?;
    let inside = &s[inside_start + 1..s.len() - 1];
    let digits = inside.trim_end_matches('+');
    digits.parse::<usize>().ok()
}

fn truncate_to(mut s: String, n: usize) -> String {
    if s.len() > n {
        s.truncate(n);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_redacts_password() {
        let mut p = ImapParser::default();
        let out = p.parse(b"A001 LOGIN alice s3cr3t\r\n", Direction::Tx);
        match out {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::Login);
                assert!(record.args.is_empty(), "no password bytes in record args");
                assert!(record.display_line().contains("<redacted>"));
                assert!(!record.display_line().contains("s3cr3t"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn authenticate_plus_continuation_redacted() {
        let mut p = ImapParser::default();
        match p.parse(b"A002 AUTHENTICATE PLAIN\r\n", Direction::Tx) {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::Authenticate);
            }
            _ => panic!(),
        }
        match p.parse(b"AHVzZXIAcGFzcw==\r\n", Direction::Tx) {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::AuthContinuation);
                assert!(record.display_line().contains("<"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn untagged_responses() {
        let mut p = ImapParser::default();
        match p.parse(b"* 23 EXISTS\r\n", Direction::Rx) {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::UntaggedExists);
            }
            _ => panic!(),
        }
        match p.parse(b"* OK IMAP4rev1 service ready\r\n", Direction::Rx) {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::UntaggedOk);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn tagged_ok() {
        let mut p = ImapParser::default();
        match p.parse(b"A001 OK LOGIN completed\r\n", Direction::Rx) {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::TaggedOk);
                assert_eq!(record.tag, "A001");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn literal_skips_exact_bytes() {
        let mut p = ImapParser::default();
        // APPEND command with a literal — 10 bytes to follow.
        let out = p.parse(b"A003 APPEND INBOX {10}\r\n", Direction::Tx);
        match out {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::Append);
            }
            _ => panic!(),
        }
        // Now 10 bytes + CRLF follow — should be skipped.
        assert!(matches!(
            p.parse(b"0123456789\r\n", Direction::Tx),
            ImapParserOutput::Skip(10)
        ));
        // Then the trailing CRLF becomes a normal line.
        assert!(matches!(
            p.parse(b"\r\n", Direction::Tx),
            ImapParserOutput::Skip(_)
        ));
    }

    #[test]
    fn list_response() {
        let mut p = ImapParser::default();
        match p.parse(
            b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n",
            Direction::Rx,
        ) {
            ImapParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, ImapKind::UntaggedList);
                assert!(record.text.contains("INBOX"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_ascii_bypasses() {
        let mut p = ImapParser::default();
        assert!(matches!(
            p.parse(b"\xff\xfejunk\r\n", Direction::Tx),
            ImapParserOutput::Skip(_)
        ));
    }
}
