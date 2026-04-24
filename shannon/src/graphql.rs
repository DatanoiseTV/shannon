//! Lightweight GraphQL classifier for HTTP bodies.
//!
//! Most GraphQL traffic rides HTTP POST with one of:
//!
//!   - `Content-Type: application/graphql` + raw query body
//!   - `Content-Type: application/json` + `{"query":"...", "operationName":"...", "variables":{...}}`
//!
//! We extract the operation name (explicit `operationName` wins; otherwise
//! the first `query Foo`, `mutation Foo`, or `subscription Foo` in the
//! query body) and the first selected top-level field — the canonical
//! summary for an API catalog or a trace display ("graphql query
//! GetUser.user"). Everything else is deferred; this isn't a GraphQL
//! parser, just a body-sniffer with enough smarts to produce useful
//! labels for observability.

/// What the classifier found in the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphqlOp {
    pub kind: OpKind,
    pub operation_name: Option<String>,
    pub root_field: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Query,
    Mutation,
    Subscription,
}

impl OpKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
            Self::Subscription => "subscription",
        }
    }
}

impl GraphqlOp {
    pub fn display_line(&self) -> String {
        let name = self.operation_name.as_deref().unwrap_or("-");
        let field = self.root_field.as_deref().unwrap_or("?");
        format!("graphql {} {}.{}", self.kind.label(), name, field)
    }
}

/// Try to classify an HTTP request body. `content_type` is matched
/// case-insensitively; `None` falls back to JSON-sniffing.
pub fn classify(content_type: Option<&str>, body: &[u8]) -> Option<GraphqlOp> {
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    if ct.starts_with("application/graphql") {
        let body_str = std::str::from_utf8(body).ok()?;
        return classify_query_body(body_str, None);
    }
    if ct.starts_with("application/json") || ct.is_empty() {
        let body_str = std::str::from_utf8(body).ok()?;
        // Quick reject for non-GraphQL JSON payloads.
        if !body_str.contains("\"query\"") {
            return None;
        }
        let operation_name = extract_json_string(body_str, "\"operationName\"");
        let query = extract_json_string(body_str, "\"query\"")?;
        return classify_query_body(&query, operation_name);
    }
    None
}

fn classify_query_body(query: &str, forced_op: Option<String>) -> Option<GraphqlOp> {
    // First strip line comments but keep whitespace — we need word
    // boundaries for keyword detection (`query GetUser` vs a field
    // literally named `queryGetUser`).
    let s = strip_comments(query);
    let bytes = s.as_bytes();
    let start = skip_ws(bytes, 0);

    let (kind, after_keyword) = if bytes.get(start).copied() == Some(b'{') {
        (OpKind::Query, start) // shorthand anonymous query
    } else {
        let (k, next) = match_keyword(bytes, start)?;
        (k, next)
    };

    // Operation name, if any, immediately after the keyword + whitespace.
    let after_ws = skip_ws(bytes, after_keyword);
    let op_name = if after_ws < bytes.len() && is_ident_start(bytes[after_ws]) {
        read_ident(bytes, after_ws)
    } else {
        None
    };

    // First `{` after the keyword = top-level selection set.
    let selection_start = bytes[after_keyword..]
        .iter()
        .position(|&b| b == b'{')
        .map(|i| after_keyword + i)?;
    let root_field = {
        let after_brace = skip_ws(bytes, selection_start + 1);
        if after_brace < bytes.len() && is_ident_start(bytes[after_brace]) {
            read_ident(bytes, after_brace)
        } else {
            None
        }
    };

    Some(GraphqlOp {
        kind,
        operation_name: forced_op.or(op_name),
        root_field,
    })
}

fn match_keyword(bytes: &[u8], pos: usize) -> Option<(OpKind, usize)> {
    for (kw, kind) in [
        (&b"query"[..], OpKind::Query),
        (&b"mutation"[..], OpKind::Mutation),
        (&b"subscription"[..], OpKind::Subscription),
    ] {
        if bytes.len() < pos + kw.len() {
            continue;
        }
        if &bytes[pos..pos + kw.len()] == kw {
            let after = pos + kw.len();
            // Next char must be a word boundary (whitespace, `{`, `(`,
            // EOF, …) — otherwise we've matched a prefix of a longer
            // identifier.
            let ok = bytes.get(after).map_or(true, |&b| !is_ident_cont(b));
            if ok {
                return Some((kind, after));
            }
        }
    }
    None
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' || b == b',' {
            i += 1;
        } else {
            break;
        }
    }
    i
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Read an identifier at `bytes[start..]`. `bytes[start]` must already
/// satisfy [`is_ident_start`] — callers ensure this before calling.
fn read_ident(bytes: &[u8], start: usize) -> Option<String> {
    let mut i = start;
    while i < bytes.len() && is_ident_cont(bytes[i]) {
        i += 1;
    }
    if i > start {
        std::str::from_utf8(&bytes[start..i]).ok().map(str::to_string)
    } else {
        None
    }
}

/// Strip `# …` line comments, preserving whitespace + commas so word
/// boundaries are intact for the keyword matcher.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '#' {
            for n in it.by_ref() {
                if n == '\n' {
                    out.push('\n');
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn extract_json_string(s: &str, key: &str) -> Option<String> {
    // Very small `"key": "value"` extractor — same pattern used
    // elsewhere in shannon for header sniffing. Not a full JSON parser;
    // enough for GraphQL's common body shape.
    let pos = s.find(key)?;
    let rest = &s[pos + key.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut it = rest.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'u' => {
                    let hex: String = (0..4).filter_map(|_| it.next()).collect();
                    if hex.len() == 4 {
                        if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                            }
                        }
                    }
                }
                other => out.push(other),
            }
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_wrapped_query_with_operation_name() {
        let body = br#"{"operationName":"GetUser","query":"query GetUser($id: ID!) { user(id: $id) { id name } }","variables":{"id":"42"}}"#;
        let op = classify(Some("application/json"), body).expect("op");
        assert_eq!(op.kind, OpKind::Query);
        assert_eq!(op.operation_name.as_deref(), Some("GetUser"));
    }

    #[test]
    fn raw_graphql_mutation() {
        let body = b"mutation CreateTodo { createTodo(input: { title: \"x\" }) { id } }";
        let op = classify(Some("application/graphql"), body).expect("op");
        assert_eq!(op.kind, OpKind::Mutation);
        assert_eq!(op.operation_name.as_deref(), Some("CreateTodo"));
    }

    #[test]
    fn anonymous_shorthand_query() {
        let body = br#"{"query":"{ me { id } }"}"#;
        let op = classify(Some("application/json"), body).expect("op");
        assert_eq!(op.kind, OpKind::Query);
        assert_eq!(op.operation_name, None);
    }

    #[test]
    fn non_graphql_json_rejected() {
        let body = br#"{"hello":"world"}"#;
        assert!(classify(Some("application/json"), body).is_none());
    }

    #[test]
    fn non_json_plain_rejected() {
        assert!(classify(Some("text/plain"), b"hello").is_none());
    }
}
