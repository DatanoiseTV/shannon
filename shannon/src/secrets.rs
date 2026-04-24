//! Credential and API-key leak scanner.
//!
//! A userspace byte-stream scanner that looks for common credential and
//! API-key shapes in captured plaintext (HTTP bodies, database queries,
//! log lines) and surfaces them as structured [`SecretFinding`]s.
//!
//! Everything in this module is intentionally defensive: the whole point
//! is to *help* shannon avoid leaking secrets, so the finding itself
//! **never** carries the full matched bytes — only a `first4***last4`
//! preview via [`SecretFinding::sample`]. A companion [`redact`] helper
//! rewrites the input buffer with `[kind_label]` placeholders for
//! shipping downstream.
//!
//! ## Scope
//!
//! - Pattern catalogue covers the credential shapes most commonly seen
//!   in captured HTTP / DB traffic: cloud provider keys (AWS, GCP),
//!   VCS / package manager tokens (GitHub, GitLab, npm), PSP keys
//!   (Stripe), messaging webhooks (Slack, Discord), generic Bearer /
//!   Basic auth headers, PEM private keys and high-entropy base64.
//! - Regex-only. We don't validate checksums or prefix parity; the goal
//!   is high recall with a redacted preview, not proof of validity.
//! - Bounded: scans at most 4 MiB per call, emits at most 1000 findings.
//!
//! ## Thread-safety
//!
//! All compiled regexes live in `OnceLock` cells and are shared across
//! threads; the scanner is fully re-entrant.

use std::sync::OnceLock;

use regex::bytes::{Regex, RegexSet};

/// Maximum input length we will scan in a single call.
///
/// Longer inputs are truncated from the *start* (callers often
/// front-load fresh bytes onto rolling buffers, so keeping the tail
/// preserves the most recent data).
pub const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// Maximum findings returned from a single [`scan`] call.
pub const MAX_FINDINGS: usize = 1000;

/// Shannon-entropy threshold (bits/char) above which a base64-ish run
/// is surfaced as a low-confidence finding.
const ENTROPY_THRESHOLD_BITS: f32 = 4.5;

/// A single credential-shaped match.
#[derive(Clone, Debug)]
pub struct SecretFinding {
    /// Enum tag identifying the pattern family.
    pub kind: SecretKind,
    /// Stable human-readable label — also what [`redact`] substitutes in.
    pub kind_label: &'static str,
    /// Severity assigned to this kind of match.
    pub severity: Severity,
    /// Redacted preview of the match, e.g. `"AKIA***XYZA"`.
    pub sample: String,
    /// Byte offset in the *scanned slice* where the match starts.
    pub byte_offset: usize,
    /// Length in bytes of the matched region.
    pub byte_len: usize,
    /// Shannon entropy (bits/char) — populated only for generic /
    /// high-entropy matches where it meaningfully feeds triage.
    pub entropy_bits: Option<f32>,
}

/// Kind of credential shape that matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    AwsAccessKeyId,
    AwsSecretAccessKey,
    AwsSessionToken,
    /// `"-----BEGIN PRIVATE KEY-----"` embedded in a Google-shaped JSON.
    GcpServiceAccountKey,
    GitHubPersonalToken,
    GitHubOAuthToken,
    GitHubUserToken,
    GitHubServerToken,
    GitHubAppToken,
    GitLabPersonalToken,
    SlackToken,
    SlackWebhook,
    DiscordWebhook,
    StripeLiveSecret,
    StripeTestSecret,
    StripePublishableLive,
    TwilioApiKey,
    TwilioAccountSid,
    SendGridApiKey,
    MailgunApiKey,
    OpenAiApiKey,
    AnthropicApiKey,
    /// Anthropic OAuth access token issued by the
    /// `sk-ant-oat01-…` flow. Used by Claude Code subscription
    /// sign-in and any other OAuth-driven consumer of the
    /// Anthropic API.
    AnthropicOauthToken,
    /// Anthropic Admin key (`sk-ant-admin01-…`) — workspace /
    /// org-management privileges; high-sev if leaked.
    AnthropicAdminKey,
    HuggingFaceToken,
    GoogleAiApiKey,
    GroqApiKey,
    PerplexityApiKey,
    XaiApiKey,
    ReplicateApiToken,
    NpmToken,
    JwtBearer,
    PrivateKeyPem,
    SshPrivateKey,
    BasicAuthHeader,
    BearerToken,
    GenericApiKeyAssignment,
    HighEntropyBase64,
    Other,
}

/// Finding severity. Callers can use this to gate alerting or choose
/// between "fail the build" and "file a JIRA".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl SecretKind {
    /// Stable `snake_case` label used in [`SecretFinding::kind_label`]
    /// and as the placeholder wrapped in square brackets by [`redact`].
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::AwsSecretAccessKey => "aws_secret_access_key",
            Self::AwsSessionToken => "aws_session_token",
            Self::GcpServiceAccountKey => "gcp_service_account_key",
            Self::GitHubPersonalToken => "github_personal_token",
            Self::GitHubOAuthToken => "github_oauth_token",
            Self::GitHubUserToken => "github_user_token",
            Self::GitHubServerToken => "github_server_token",
            Self::GitHubAppToken => "github_app_token",
            Self::GitLabPersonalToken => "gitlab_personal_token",
            Self::SlackToken => "slack_token",
            Self::SlackWebhook => "slack_webhook",
            Self::DiscordWebhook => "discord_webhook",
            Self::StripeLiveSecret => "stripe_live_secret",
            Self::StripeTestSecret => "stripe_test_secret",
            Self::StripePublishableLive => "stripe_publishable_live",
            Self::TwilioApiKey => "twilio_api_key",
            Self::TwilioAccountSid => "twilio_account_sid",
            Self::SendGridApiKey => "sendgrid_api_key",
            Self::MailgunApiKey => "mailgun_api_key",
            Self::OpenAiApiKey => "openai_api_key",
            Self::AnthropicApiKey => "anthropic_api_key",
            Self::AnthropicOauthToken => "anthropic_oauth_token",
            Self::AnthropicAdminKey => "anthropic_admin_key",
            Self::HuggingFaceToken => "huggingface_token",
            Self::GoogleAiApiKey => "google_ai_api_key",
            Self::GroqApiKey => "groq_api_key",
            Self::PerplexityApiKey => "perplexity_api_key",
            Self::XaiApiKey => "xai_api_key",
            Self::ReplicateApiToken => "replicate_api_token",
            Self::NpmToken => "npm_token",
            Self::JwtBearer => "jwt_bearer",
            Self::PrivateKeyPem => "private_key_pem",
            Self::SshPrivateKey => "ssh_private_key",
            Self::BasicAuthHeader => "basic_auth_header",
            Self::BearerToken => "bearer_token",
            Self::GenericApiKeyAssignment => "generic_api_key_assignment",
            Self::HighEntropyBase64 => "high_entropy_base64",
            Self::Other => "other",
        }
    }

    /// Default severity for this kind.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::AwsAccessKeyId
            | Self::AwsSessionToken
            | Self::GcpServiceAccountKey
            | Self::GitHubPersonalToken
            | Self::GitHubOAuthToken
            | Self::GitHubUserToken
            | Self::GitHubServerToken
            | Self::GitHubAppToken
            | Self::GitLabPersonalToken
            | Self::SlackToken
            | Self::StripeLiveSecret
            | Self::AnthropicApiKey
            | Self::AnthropicOauthToken
            | Self::AnthropicAdminKey
            | Self::OpenAiApiKey
            | Self::GoogleAiApiKey
            | Self::GroqApiKey
            | Self::PerplexityApiKey
            | Self::XaiApiKey
            | Self::ReplicateApiToken
            | Self::PrivateKeyPem
            | Self::SshPrivateKey
            | Self::NpmToken => Severity::High,
            Self::AwsSecretAccessKey
            | Self::SlackWebhook
            | Self::DiscordWebhook
            | Self::StripeTestSecret
            | Self::StripePublishableLive
            | Self::TwilioApiKey
            | Self::TwilioAccountSid
            | Self::SendGridApiKey
            | Self::MailgunApiKey
            | Self::HuggingFaceToken
            | Self::JwtBearer
            | Self::BasicAuthHeader
            | Self::BearerToken
            | Self::GenericApiKeyAssignment => Severity::Medium,
            Self::HighEntropyBase64 | Self::Other => Severity::Low,
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern catalogue
// ---------------------------------------------------------------------------

/// Simple "anchored regex → kind" rule. `capture_group` is the group whose
/// bounds should be reported as the finding (0 = whole match).
struct Rule {
    kind: SecretKind,
    pattern: &'static str,
    capture_group: usize,
}

/// The static catalogue. Order matters: earlier entries win over later
/// ones for overlapping matches.
const RULES: &[Rule] = &[
    // -- private keys first so they shadow the more generic patterns ----
    Rule {
        kind: SecretKind::SshPrivateKey,
        pattern: r"-----BEGIN OPENSSH PRIVATE KEY-----",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::PrivateKeyPem,
        pattern: r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |)PRIVATE KEY-----",
        capture_group: 0,
    },
    // -- cloud ------------------------------------------------------------
    Rule {
        kind: SecretKind::AwsAccessKeyId,
        pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        capture_group: 0,
    },
    // -- VCS / package managers ------------------------------------------
    Rule {
        kind: SecretKind::GitHubPersonalToken,
        pattern: r"\bghp_[A-Za-z0-9]{36,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::GitHubOAuthToken,
        pattern: r"\bgho_[A-Za-z0-9]{36,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::GitHubUserToken,
        pattern: r"\bghu_[A-Za-z0-9]{36,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::GitHubServerToken,
        pattern: r"\bghs_[A-Za-z0-9]{36,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::GitHubAppToken,
        pattern: r"\bghr_[A-Za-z0-9]{36,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::GitLabPersonalToken,
        pattern: r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::NpmToken,
        pattern: r"\bnpm_[A-Za-z0-9]{36}\b",
        capture_group: 0,
    },
    // -- messaging webhooks ----------------------------------------------
    Rule {
        kind: SecretKind::SlackWebhook,
        pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::DiscordWebhook,
        pattern: r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::SlackToken,
        pattern: r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b",
        capture_group: 0,
    },
    // -- PSP --------------------------------------------------------------
    Rule {
        kind: SecretKind::StripeLiveSecret,
        pattern: r"\bsk_live_[A-Za-z0-9]{24,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::StripeTestSecret,
        pattern: r"\bsk_test_[A-Za-z0-9]{24,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::StripePublishableLive,
        pattern: r"\bpk_live_[A-Za-z0-9]{24,}\b",
        capture_group: 0,
    },
    // -- Twilio / SendGrid / Mailgun -------------------------------------
    Rule {
        kind: SecretKind::TwilioApiKey,
        pattern: r"\bSK[0-9a-fA-F]{32}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::TwilioAccountSid,
        pattern: r"\bAC[0-9a-fA-F]{32}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::SendGridApiKey,
        pattern: r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::MailgunApiKey,
        pattern: r"\bkey-[0-9a-f]{32}\b",
        capture_group: 0,
    },
    // -- LLM providers ----------------------------------------------------
    // Order: more-specific Anthropic prefixes before the generic API
    // pattern so they win the match.
    Rule {
        kind: SecretKind::AnthropicAdminKey,
        pattern: r"\bsk-ant-admin01-[A-Za-z0-9_-]{60,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::AnthropicOauthToken,
        // Claude Code's subscription sign-in produces this format;
        // also any other OAuth-driven Anthropic API consumer.
        pattern: r"\bsk-ant-oat01-[A-Za-z0-9_-]{60,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::AnthropicApiKey,
        pattern: r"\bsk-ant-api03-[A-Za-z0-9_-]{90,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::OpenAiApiKey,
        // Specifically *not* sk-ant-...; we match sk- or sk-proj-.
        pattern: r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b",
        capture_group: 0,
    },
    Rule {
        kind: SecretKind::HuggingFaceToken,
        pattern: r"\bhf_[A-Za-z0-9]{30,}\b",
        capture_group: 0,
    },
    // Google AI Studio (Gemini API keys) — fixed prefix `AIza` + 35 chars
    // of base64-url alphabet. Same shape as legacy Google API keys; the
    // distinction is contextual (use of generativelanguage.googleapis.com),
    // which we don't try to enforce here. Either way a leak is high-sev.
    Rule {
        kind: SecretKind::GoogleAiApiKey,
        pattern: r"\bAIza[A-Za-z0-9_-]{35}\b",
        capture_group: 0,
    },
    // Groq Cloud — `gsk_` + 52 alphanumeric.
    Rule {
        kind: SecretKind::GroqApiKey,
        pattern: r"\bgsk_[A-Za-z0-9]{52}\b",
        capture_group: 0,
    },
    // Perplexity AI — `pplx-` + 48 alphanumeric/underscore.
    Rule {
        kind: SecretKind::PerplexityApiKey,
        pattern: r"\bpplx-[A-Za-z0-9_]{40,}\b",
        capture_group: 0,
    },
    // xAI (Grok) — `xai-` + 80 alphanumeric.
    Rule {
        kind: SecretKind::XaiApiKey,
        pattern: r"\bxai-[A-Za-z0-9]{80}\b",
        capture_group: 0,
    },
    // Replicate — `r8_` + 37 alphanumeric.
    Rule {
        kind: SecretKind::ReplicateApiToken,
        pattern: r"\br8_[A-Za-z0-9]{37}\b",
        capture_group: 0,
    },
    // -- AWS secret access key (contextual) ------------------------------
    //
    // The raw 40-char base64 alphabet is far too common to flag on its own;
    // we only fire when preceded by an `aws_secret_access_key` / `aws-secret`
    // -ish label on the same line.
    Rule {
        kind: SecretKind::AwsSecretAccessKey,
        pattern: r"(?i)aws[_-]?secret[_-]?access[_-]?key[^A-Za-z0-9]{1,20}([A-Za-z0-9/+=]{40})\b",
        capture_group: 1,
    },
    // -- JWT --------------------------------------------------------------
    //
    // Structure match only; the scanner additionally decodes the header
    // (first base64url segment) to confirm it parses as JSON containing
    // `"alg":` before emitting the finding.
    Rule {
        kind: SecretKind::JwtBearer,
        pattern: r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        capture_group: 0,
    },
    // -- HTTP auth --------------------------------------------------------
    Rule {
        kind: SecretKind::BasicAuthHeader,
        pattern: r"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]{4,})",
        capture_group: 1,
    },
    Rule {
        kind: SecretKind::BearerToken,
        pattern: r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9_.\-]{20,})",
        capture_group: 1,
    },
    // -- env-style assignment (very noisy; keep last so more specific
    //    kinds win) ------------------------------------------------------
    Rule {
        kind: SecretKind::GenericApiKeyAssignment,
        pattern: concat!(
            r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASS|PWD)[A-Z0-9_]*)",
            r#"\s*=\s*['"]?([A-Za-z0-9+/=_\-]{8,})['"]?"#,
        ),
        capture_group: 2,
    },
];

/// Separate pattern for the generic high-entropy base64 run detector.
const BASE64_RUN_PATTERN: &str = r"[A-Za-z0-9+/=_\-]{40,}";

// ---------------------------------------------------------------------------
// Compiled regexes, lazily initialised.
// ---------------------------------------------------------------------------

struct Compiled {
    /// Fast `contains-any-pattern` prefilter. Used purely as an early
    /// bail-out on big buffers with no credentials in them.
    set: RegexSet,
    /// One compiled `Regex` per `RULES` entry, same order.
    regexes: Vec<Regex>,
    /// Generic high-entropy base64 run matcher.
    base64_run: Regex,
}

fn compiled() -> &'static Compiled {
    static CELL: OnceLock<Compiled> = OnceLock::new();
    CELL.get_or_init(|| {
        let patterns: Vec<&str> = RULES.iter().map(|r| r.pattern).collect();
        // `regex::bytes::RegexSet::new` only fails on invalid patterns;
        // the catalogue is static so this can't fail at runtime.
        let set = RegexSet::new(&patterns).expect("shannon secrets: RegexSet compiles");
        let regexes = RULES
            .iter()
            .map(|r| Regex::new(r.pattern).expect("shannon secrets: pattern compiles"))
            .collect();
        let base64_run = Regex::new(BASE64_RUN_PATTERN).expect("base64 run pattern compiles");
        Compiled {
            set,
            regexes,
            base64_run,
        }
    })
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Scan `input` and return all credential-shaped findings.
///
/// Bounded: at most [`MAX_SCAN_BYTES`] of input are scanned (longer
/// inputs are truncated *from the start*), and at most [`MAX_FINDINGS`]
/// findings are returned.
///
/// Offsets in the returned findings are relative to the *scanned slice*
/// (the tail of the input once it's been truncated), not the original
/// buffer.
#[must_use]
pub fn scan(input: &[u8]) -> Vec<SecretFinding> {
    let slice = truncate_tail(input);
    let c = compiled();

    // Prefilter: if no rule matches at all, skip the expensive scan.
    // We still run the generic high-entropy pass unconditionally because
    // `RegexSet` doesn't include it.
    let set_matches = c.set.matches(slice);

    let mut findings: Vec<SecretFinding> = Vec::new();
    // Occupied byte ranges, sorted by start, used to suppress overlapping
    // lower-priority matches (esp. the generic catch-alls).
    let mut occupied: Vec<(usize, usize)> = Vec::new();

    if set_matches.matched_any() {
        for (rule_idx, rule) in RULES.iter().enumerate() {
            if !set_matches.matched(rule_idx) {
                continue;
            }
            let re = &c.regexes[rule_idx];
            for caps in re.captures_iter(slice) {
                let Some(whole) = caps.get(0) else { continue };
                let target = caps.get(rule.capture_group).unwrap_or(whole);

                let start = target.start();
                let end = target.end();
                let bytes = &slice[start..end];

                // Rule-specific post-filters.
                if !post_filter(rule.kind, bytes) {
                    continue;
                }

                if overlaps(&occupied, start, end) {
                    continue;
                }

                let finding = SecretFinding {
                    kind: rule.kind,
                    kind_label: rule.kind.label(),
                    severity: rule.kind.severity(),
                    sample: redact_sample(bytes),
                    byte_offset: start,
                    byte_len: end - start,
                    entropy_bits: None,
                };
                push_sorted(&mut occupied, start, end);
                findings.push(finding);

                if findings.len() >= MAX_FINDINGS {
                    return findings;
                }
            }
        }
    }

    // -- generic high-entropy base64 pass --------------------------------
    //
    // This is intentionally last; anything that a named rule already
    // claimed is skipped by the overlap check.
    for m in c.base64_run.find_iter(slice) {
        let start = m.start();
        let end = m.end();
        if overlaps(&occupied, start, end) {
            continue;
        }
        let bytes = &slice[start..end];
        let bits = shannon_entropy_bits_per_char(bytes);
        if bits <= ENTROPY_THRESHOLD_BITS {
            continue;
        }
        let finding = SecretFinding {
            kind: SecretKind::HighEntropyBase64,
            kind_label: SecretKind::HighEntropyBase64.label(),
            severity: Severity::Low,
            sample: redact_sample(bytes),
            byte_offset: start,
            byte_len: end - start,
            entropy_bits: Some(bits),
        };
        push_sorted(&mut occupied, start, end);
        findings.push(finding);
        if findings.len() >= MAX_FINDINGS {
            return findings;
        }
    }

    findings.sort_by_key(|f| f.byte_offset);
    findings
}

/// Produce a redacted copy of `input` with every matched region replaced
/// by `[kind_label]`.
///
/// Input is truncated using the same rule as [`scan`]; untruncated
/// prefix bytes are preserved verbatim at the start of the output.
#[must_use]
pub fn redact(input: &[u8]) -> Vec<u8> {
    let slice = truncate_tail(input);
    let findings = scan(input);

    // Preserve whatever was truncated off the front so the caller's
    // offsets into `input` still line up if they concatenate.
    let prefix_len = input.len().saturating_sub(slice.len());
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..prefix_len]);

    let mut cursor = 0usize;
    for f in &findings {
        if f.byte_offset < cursor {
            // Overlap (shouldn't happen — scan already de-dupes) — skip.
            continue;
        }
        out.extend_from_slice(&slice[cursor..f.byte_offset]);
        out.push(b'[');
        out.extend_from_slice(f.kind_label.as_bytes());
        out.push(b']');
        cursor = f.byte_offset + f.byte_len;
    }
    out.extend_from_slice(&slice[cursor..]);
    out
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Truncate `input` to at most [`MAX_SCAN_BYTES`], keeping the tail.
fn truncate_tail(input: &[u8]) -> &[u8] {
    if input.len() <= MAX_SCAN_BYTES {
        input
    } else {
        &input[input.len() - MAX_SCAN_BYTES..]
    }
}

/// Build the `first4***last4` preview, falling back to `***` for short
/// matches.
fn redact_sample(bytes: &[u8]) -> String {
    // Treat any non-UTF8 gunk as `?` — samples are purely for humans.
    let s: String = bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '?'
            }
        })
        .collect();
    let n = s.chars().count();
    if n < 8 {
        return "***".to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{head}***{tail}")
}

/// Returns true if `[start, end)` overlaps any range in `occupied`.
/// `occupied` is kept sorted by start; we use a linear scan — 1000
/// elements worst case, fine for this hot path.
fn overlaps(occupied: &[(usize, usize)], start: usize, end: usize) -> bool {
    for &(s, e) in occupied {
        if start < e && s < end {
            return true;
        }
        if s >= end {
            break;
        }
    }
    false
}

fn push_sorted(occupied: &mut Vec<(usize, usize)>, start: usize, end: usize) {
    let idx = occupied.partition_point(|&(s, _)| s < start);
    occupied.insert(idx, (start, end));
}

/// Per-rule post-match validation for patterns whose regex alone is
/// too loose.
fn post_filter(kind: SecretKind, bytes: &[u8]) -> bool {
    match kind {
        SecretKind::OpenAiApiKey => {
            // Disambiguate from the Anthropic prefix.
            !bytes.starts_with(b"sk-ant-")
        }
        SecretKind::JwtBearer => is_plausible_jwt(bytes),
        _ => true,
    }
}

/// Base64-url-decode the first segment of a JWT and check it parses as
/// JSON containing an `"alg"` field. Any failure → reject.
fn is_plausible_jwt(bytes: &[u8]) -> bool {
    let Some(first_dot) = bytes.iter().position(|&b| b == b'.') else {
        return false;
    };
    let header = &bytes[..first_dot];
    let Some(decoded) = base64url_decode(header) else {
        return false;
    };
    // Strip leading ASCII whitespace then require `{` and a `"alg"` key.
    let trimmed = trim_ascii_start(&decoded);
    if !trimmed.starts_with(b"{") {
        return false;
    }
    // Cheap substring — we don't need a full JSON parser here; we just
    // want to suppress "three random dotted base64-ish words".
    twoway_find(trimmed, b"\"alg\"").is_some() || twoway_find(trimmed, b"'alg'").is_some()
}

fn trim_ascii_start(input: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < input.len() && input[i].is_ascii_whitespace() {
        i += 1;
    }
    &input[i..]
}

fn twoway_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode a base64url-no-pad segment. Returns `None` on any decode error.
///
/// Hand-rolled rather than pulling in the `base64` crate — the JWT
/// header is the only caller, and we want to keep the dep footprint at
/// zero additions.
fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    // Table from the base64url alphabet; 0xff = invalid.
    static TABLE: OnceLock<[u8; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0xff_u8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (i, &c) in alphabet.iter().enumerate() {
            t[c as usize] = i as u8;
        }
        // Accept standard base64 too, which is handy for sloppy producers.
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    });

    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        if c == b'=' {
            break;
        }
        let v = table[c as usize];
        if v == 0xff {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Shannon entropy of `bytes` in **bits per character**. Empty input
/// returns 0.0.
fn shannon_entropy_bits_per_char(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut h = 0.0_f32;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = (c as f32) / len;
        h -= p * p.log2();
    }
    h
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(findings: &[SecretFinding]) -> Vec<SecretKind> {
        findings.iter().map(|f| f.kind).collect()
    }

    /// Build a test fixture from multiple byte slices. Used so the raw
    /// source code never contains a complete vendor-specific secret
    /// signature that GitHub's push-protection scanner would flag.
    fn fx(parts: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in parts {
            v.extend_from_slice(p);
        }
        v
    }

    #[test]
    fn github_personal_token() {
        let input = fx(&[b"token=", b"gh", b"p_1234567890abcdefghij1234567890abcdef trailing"]);
        let input = input.as_slice();
        let f = scan(input);
        assert_eq!(f.len(), 1, "expected single finding, got {f:?}");
        assert_eq!(f[0].kind, SecretKind::GitHubPersonalToken);
        assert_eq!(f[0].sample, "ghp_***cdef");
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn aws_access_key() {
        let input = b"id=AKIAIOSFODNN7EXAMPLE and then some";
        let f = scan(input);
        assert!(f.iter().any(|x| x.kind == SecretKind::AwsAccessKeyId));
    }

    #[test]
    fn aws_secret_access_key_contextual() {
        let input = b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY next";
        let f = scan(input);
        assert!(f.iter().any(|x| x.kind == SecretKind::AwsSecretAccessKey));
    }

    #[test]
    fn gitlab_pat() {
        let input = b"glpat-abc123ABC456def789XYZ";
        let f = scan(input);
        assert!(f.iter().any(|x| x.kind == SecretKind::GitLabPersonalToken));
    }

    #[test]
    fn slack_token_and_webhook() {
        let input = b"xoxb-1234567890-0987654321-abcdefghij foo https://hooks.slack.com/services/T01ABCDEF/B0123456/AbCdEfGhIjKlMnOpQrStUv";
        let f = scan(input);
        let ks = kinds(&f);
        assert!(ks.contains(&SecretKind::SlackToken));
        assert!(ks.contains(&SecretKind::SlackWebhook));
    }

    #[test]
    fn discord_webhook() {
        let input =
            b"https://discord.com/api/webhooks/123456789012345678/AbCdEfGh_iJkLmNoPqRs-TuVwXyZ";
        let f = scan(input);
        assert!(f.iter().any(|x| x.kind == SecretKind::DiscordWebhook));
    }

    #[test]
    fn stripe_keys() {
        // Test fixtures — split prefix from body so the source bytes
        // never form a complete signature for GitHub's secret scanner.
        const SL: &[u8] = b"sk_li";
        const PL: &[u8] = b"pk_li";
        const ST: &[u8] = b"sk_te";
        let mut input = Vec::new();
        input.extend_from_slice(SL); input.extend_from_slice(b"ve_ZZfAkeFixtureFixtureFixture  ");
        input.extend_from_slice(PL); input.extend_from_slice(b"ve_ZZfAkeFixtureFixtureFixture  ");
        input.extend_from_slice(ST); input.extend_from_slice(b"st_ZZfAkeFixtureFixtureFixture");
        let input = input.as_slice();
        let f = scan(input);
        let ks = kinds(&f);
        assert!(ks.contains(&SecretKind::StripeLiveSecret));
        assert!(ks.contains(&SecretKind::StripeTestSecret));
        assert!(ks.contains(&SecretKind::StripePublishableLive));
    }

    #[test]
    fn twilio_keys() {
        // Test fixtures — prefix split from body.
        let mut input = Vec::new();
        input.extend_from_slice(b"S"); input.extend_from_slice(b"K");
        input.extend_from_slice(b"ffffffffffffffffffffffffffffffff ");
        input.extend_from_slice(b"A"); input.extend_from_slice(b"C");
        input.extend_from_slice(b"ffffffffffffffffffffffffffffffff");
        let input = input.as_slice();
        let f = scan(input);
        let ks = kinds(&f);
        assert!(ks.contains(&SecretKind::TwilioApiKey));
        assert!(ks.contains(&SecretKind::TwilioAccountSid));
    }

    #[test]
    fn sendgrid_and_mailgun() {
        // Test fixtures — prefix split from body.
        let mut sg_buf = Vec::new();
        sg_buf.extend_from_slice(b"S"); sg_buf.extend_from_slice(b"G");
        sg_buf.extend_from_slice(b".ZZzzZZzzZZzzZZzzZZzzZZ.ZZzzZZzzZZzzZZzzZZzzZZzzZZzzZZzzZZzzZZzzZZz");
        let sg = sg_buf.as_slice();
        let mut mg_buf = Vec::new();
        mg_buf.extend_from_slice(b"ke"); mg_buf.extend_from_slice(b"y-");
        mg_buf.extend_from_slice(b"ffffffffffffffffffffffffffffffff");
        let mg = mg_buf.as_slice();
        assert!(scan(sg)
            .iter()
            .any(|x| x.kind == SecretKind::SendGridApiKey));
        assert!(scan(mg).iter().any(|x| x.kind == SecretKind::MailgunApiKey));
    }

    #[test]
    fn openai_vs_anthropic() {
        let oa = b"sk-proj-ABCDEFGHIJKLMNOPQRSTUV0123456789";
        let an = b"sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghijklmnopqrstuvwxyzXX";
        let fo = scan(oa);
        let fa = scan(an);
        assert!(fo.iter().any(|x| x.kind == SecretKind::OpenAiApiKey));
        assert!(fa.iter().any(|x| x.kind == SecretKind::AnthropicApiKey));
        // The Anthropic input must not additionally be flagged as OpenAI.
        assert!(!fa.iter().any(|x| x.kind == SecretKind::OpenAiApiKey));
    }

    #[test]
    fn huggingface_and_npm() {
        let hf = b"hf_abcdefghijklmnopqrstuvwxyzABCDEF";
        let npm = b"npm_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
        assert!(scan(hf)
            .iter()
            .any(|x| x.kind == SecretKind::HuggingFaceToken));
        assert!(scan(npm).iter().any(|x| x.kind == SecretKind::NpmToken));
    }

    #[test]
    fn ai_provider_keys() {
        // Built via fx() so the source never holds a complete vendor
        // signature that GitHub's push-protection scanner would flag.
        // 35-char suffix exactly so the `\b` after `{35}` matches
        // (Google's AIza-prefixed keys are always 39 chars total).
        let google = fx(&[b"AI", b"za", b"abcdefghijklmnopqrstuvwxyz012345678"]);
        let groq = fx(&[b"gs", b"k_", &[b'a'; 52]]);
        let pplx = fx(&[b"pp", b"lx-", &[b'a'; 48]]);
        let xai = fx(&[b"xa", b"i-", &[b'a'; 80]]);
        let r8 = fx(&[b"r8", b"_", &[b'a'; 37]]);

        let kinds_of = |b: &[u8]| -> Vec<SecretKind> {
            scan(b).into_iter().map(|f| f.kind).collect()
        };
        assert!(kinds_of(&google).contains(&SecretKind::GoogleAiApiKey));
        assert!(kinds_of(&groq).contains(&SecretKind::GroqApiKey));
        assert!(kinds_of(&pplx).contains(&SecretKind::PerplexityApiKey));
        assert!(kinds_of(&xai).contains(&SecretKind::XaiApiKey));
        assert!(kinds_of(&r8).contains(&SecretKind::ReplicateApiToken));
    }

    #[test]
    fn anthropic_oauth_and_admin() {
        // Same fx() pattern. The `sk-ant-oat01-` prefix is what Claude
        // Code's subscription sign-in produces; admin01 is for
        // workspace / org-management keys.
        let oat = fx(&[b"sk-", b"ant-oat01-", &[b'a'; 70]]);
        let admin = fx(&[b"sk-", b"ant-admin01-", &[b'a'; 70]]);
        let api = fx(&[b"sk-", b"ant-api03-", &[b'a'; 95]]);
        let kinds = |b: &[u8]| -> Vec<SecretKind> {
            scan(b).into_iter().map(|f| f.kind).collect()
        };
        assert!(kinds(&oat).contains(&SecretKind::AnthropicOauthToken));
        // OAuth must not also be matched as the API03 catalogue.
        assert!(!kinds(&oat).contains(&SecretKind::AnthropicApiKey));
        assert!(kinds(&admin).contains(&SecretKind::AnthropicAdminKey));
        assert!(!kinds(&admin).contains(&SecretKind::AnthropicApiKey));
        assert!(kinds(&api).contains(&SecretKind::AnthropicApiKey));
    }

    #[test]
    fn jwt_real_token() {
        // Header `{"alg":"HS256","typ":"JWT"}`, payload `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
        // sig unchanged. Canonical example from jwt.io.
        let jwt = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let f = scan(jwt);
        assert!(
            f.iter().any(|x| x.kind == SecretKind::JwtBearer),
            "expected JWT finding, got: {f:?}"
        );
    }

    #[test]
    fn jwt_garbage_dotted_segments_rejected() {
        // Three base64-ish segments starting with eyJ but header decodes
        // to nonsense — should NOT emit a JWT finding.
        let not_jwt = b"eyJnb29kbW9ybmluZw.eyJhYmMiOjF9.c2lnbmF0dXJlaGVyZQ";
        let f = scan(not_jwt);
        assert!(!f.iter().any(|x| x.kind == SecretKind::JwtBearer));
    }

    #[test]
    fn pem_private_key() {
        let pem =
            b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let f = scan(pem);
        assert!(f.iter().any(|x| x.kind == SecretKind::PrivateKeyPem));
    }

    #[test]
    fn openssh_private_key() {
        let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...\n-----END OPENSSH PRIVATE KEY-----";
        let f = scan(key);
        assert!(f.iter().any(|x| x.kind == SecretKind::SshPrivateKey));
    }

    #[test]
    fn basic_and_bearer_auth_headers() {
        let req = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n";
        let bearer =
            b"GET / HTTP/1.1\r\nAuthorization: Bearer abcdefghijABCDEFGHIJ0123456789\r\n\r\n";
        assert!(scan(req)
            .iter()
            .any(|x| x.kind == SecretKind::BasicAuthHeader));
        assert!(scan(bearer)
            .iter()
            .any(|x| x.kind == SecretKind::BearerToken));
    }

    #[test]
    fn generic_env_assignment() {
        let env = b"DATABASE_PASSWORD='hunter22hunter22hunter22'";
        let f = scan(env);
        assert!(f
            .iter()
            .any(|x| x.kind == SecretKind::GenericApiKeyAssignment));
    }

    #[test]
    fn high_entropy_base64_flagged() {
        // Pseudorandom 64-char base64url string. Not derived from any
        // secret — just high-entropy ASCII.
        let rand = b"xK9pQ2mL7vR3nB8sT5fH4jD6wY1cE0aZ-gU_iO2xK9pQ2mL7vR3nB8sT5fH4jD";
        let f = scan(rand);
        assert!(
            f.iter().any(|x| x.kind == SecretKind::HighEntropyBase64),
            "expected high-entropy finding, got {f:?}",
        );
    }

    #[test]
    fn low_entropy_same_length_not_flagged() {
        let low = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let f = scan(low);
        assert!(!f.iter().any(|x| x.kind == SecretKind::HighEntropyBase64));
    }

    #[test]
    fn redact_replaces_with_kind_label() {
        let input = fx(&[b"before ", b"gh", b"p_1234567890abcdefghij1234567890abcdef after"]);
        let out = redact(&input);
        let s = String::from_utf8(out).expect("ascii");
        assert_eq!(s, "before [github_personal_token] after");
    }

    #[test]
    fn redact_multiple_findings_in_order() {
        let input = fx(&[
            b"A", b"K",
            b"IAIOSFODNN7EXAMPLE and ",
            b"gh", b"p_1234567890abcdefghij1234567890abcdef",
        ]);
        let out = redact(&input);
        let s = String::from_utf8(out).expect("ascii");
        assert_eq!(s, "[aws_access_key_id] and [github_personal_token]");
    }

    #[test]
    fn scan_truncates_large_input() {
        // 10 MiB input with a key sitting at the very end — must still
        // be found because we truncate from the start.
        let mut input = vec![b'x'; 10 * 1024 * 1024];
        let tail = fx(&[b" ", b"gh", b"p_1234567890abcdefghij1234567890abcdef"]);
        let start = input.len() - tail.len();
        input[start..].copy_from_slice(&tail);
        let f = scan(&input);
        assert!(f.iter().any(|x| x.kind == SecretKind::GitHubPersonalToken));
    }

    #[test]
    fn scan_caps_finding_count() {
        let row = fx(&[b"gh", b"p_1234567890abcdefghij1234567890abcdef\n"]);
        let mut input = Vec::new();
        for _ in 0..(MAX_FINDINGS + 50) {
            input.extend_from_slice(&row);
        }
        let f = scan(&input);
        assert!(f.len() <= MAX_FINDINGS);
    }

    #[test]
    fn sample_for_short_match_is_asterisks() {
        assert_eq!(redact_sample(b"short"), "***");
        assert_eq!(redact_sample(b"1234abcd"), "1234***abcd");
    }

    #[test]
    fn overlapping_matches_deduped() {
        // A Stripe test key is also *shape-compatible* with the generic
        // base64 run detector. Confirm we don't double-emit. Prefix
        // assembled from parts so the source literal isn't a signature.
        let input = fx(&[b"sk_te", b"st_abcdefghijABCDEFGHIJ01234567890000000000"]);
        let input = input.as_slice();
        let f = scan(input);
        let st = f
            .iter()
            .filter(|x| x.kind == SecretKind::StripeTestSecret)
            .count();
        let hi = f
            .iter()
            .filter(|x| x.kind == SecretKind::HighEntropyBase64)
            .count();
        assert_eq!(st, 1);
        assert_eq!(hi, 0);
    }

    #[test]
    fn entropy_monotonic() {
        let low = shannon_entropy_bits_per_char(b"aaaaaaaaaa");
        let hi = shannon_entropy_bits_per_char(b"abcdefghij");
        assert!(hi > low);
    }
}
