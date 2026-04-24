//! AWS / S3 / S3-compatible call classifier.
//!
//! Recognises observed HTTP requests that talk to an AWS service or an
//! S3-compatible endpoint (MinIO, Cloudflare R2, Backblaze B2, Wasabi,
//! DigitalOcean Spaces, Linode Object Storage) and extracts a compact
//! summary: which service, bucket + key on S3-style calls, operation
//! name on the JSON-RPC services, and whether the request is SigV4-
//! signed so operators can distinguish signed-API calls from anonymous
//! accesses.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsService {
    S3,
    S3Compatible,   // MinIO, R2, Backblaze, Wasabi, Spaces, Linode
    DynamoDb,
    Sqs,
    Sns,
    Sts,
    Iam,
    Lambda,
    Kinesis,
    Firehose,
    Ec2,
    Rds,
    Cloudwatch,
    SecretsManager,
    Ssm,
    Kms,
    BedrockRuntime,
    Other,
}

impl fmt::Display for AwsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::S3 => "s3",
            Self::S3Compatible => "s3-compat",
            Self::DynamoDb => "dynamodb",
            Self::Sqs => "sqs",
            Self::Sns => "sns",
            Self::Sts => "sts",
            Self::Iam => "iam",
            Self::Lambda => "lambda",
            Self::Kinesis => "kinesis",
            Self::Firehose => "firehose",
            Self::Ec2 => "ec2",
            Self::Rds => "rds",
            Self::Cloudwatch => "cloudwatch",
            Self::SecretsManager => "secretsmanager",
            Self::Ssm => "ssm",
            Self::Kms => "kms",
            Self::BedrockRuntime => "bedrock-runtime",
            Self::Other => "aws-other",
        })
    }
}

#[derive(Debug, Clone)]
pub struct AwsCall {
    pub service: AwsService,
    /// S3-style requests: the parsed bucket name (either from path style
    /// `/bucket/key` or virtual-hosted style `bucket.s3.amazonaws.com`).
    pub bucket: Option<String>,
    /// S3 key (URL path after bucket), truncated to 512 chars.
    pub key: Option<String>,
    /// Operation name — `x-amz-target` header value for JSON-RPC services,
    /// method+path-derived verb for S3.
    pub operation: Option<String>,
    /// True if the request carries an `Authorization: AWS4-HMAC-SHA256`
    /// header (SigV4).
    pub sigv4: bool,
    /// Access key id from the Credential part of SigV4 (20-char AKIA/ASIA).
    pub access_key_id: Option<String>,
    /// AWS region from the Credential scope.
    pub region: Option<String>,
    /// True when the request is anonymous (no Authorization header).
    pub anonymous: bool,
}

impl AwsCall {
    pub fn display_line(&self) -> String {
        let auth = if self.sigv4 {
            format!("sigv4:{}", self.access_key_id.as_deref().unwrap_or("?"))
        } else if self.anonymous {
            "anon".to_string()
        } else {
            "auth?".to_string()
        };
        match self.service {
            AwsService::S3 | AwsService::S3Compatible => {
                let b = self.bucket.as_deref().unwrap_or("?");
                let k = self.key.as_deref().unwrap_or("");
                let op = self.operation.as_deref().unwrap_or("");
                format!("{} {} {} s3://{}/{}  [{}]", self.service, op, self.region.as_deref().unwrap_or(""), b, k, auth)
            }
            _ => format!(
                "{} {}  [{}]  region={}",
                self.service,
                self.operation.as_deref().unwrap_or("?"),
                auth,
                self.region.as_deref().unwrap_or("?"),
            ),
        }
    }
}

/// Classify an HTTP request. Returns `None` for non-AWS / non-S3 calls.
pub fn classify(
    method: &str,
    path: &str,
    host: Option<&str>,
    headers: &[(String, String)],
) -> Option<AwsCall> {
    let host_lc = host.map(str::to_ascii_lowercase).unwrap_or_default();

    // SigV4 extraction first — it's the strongest signal.
    let auth_value = header(headers, "authorization").unwrap_or_default();
    let (sigv4, access_key_id, region, sig_service) = parse_sigv4(&auth_value);
    let x_amz_target = header(headers, "x-amz-target").unwrap_or_default();
    let anonymous = auth_value.is_empty();

    // Service detection:
    //
    // 1. Host match against canonical AWS endpoints.
    // 2. Host match against common S3-compatible providers.
    // 3. Fall back to path / x-amz-target / sig-derived service when
    //    the host is an arbitrary proxy.
    let mut service = service_from_host(&host_lc);
    if service.is_none() && !sig_service.is_empty() {
        service = map_sigv4_service(&sig_service);
    }
    if service.is_none() && !x_amz_target.is_empty() {
        // x-amz-target is typically "Service_V20120810.Operation".
        service = map_sigv4_service(x_amz_target.split(['_', '.']).next().unwrap_or(""));
    }
    let service = service?;

    // For S3 style, pull bucket + key.
    let (bucket, key, op) = match service {
        AwsService::S3 | AwsService::S3Compatible => {
            let (b, k) = extract_s3_bucket_key(&host_lc, path);
            let op = s3_op(method, &k);
            (b, k, Some(op.to_string()))
        }
        _ => {
            let op = if !x_amz_target.is_empty() {
                // "Service.Operation" → keep the last segment.
                Some(x_amz_target.rsplit(['.', '_']).next().unwrap_or(&x_amz_target).to_string())
            } else if method.eq_ignore_ascii_case("POST") {
                Some("action".to_string())
            } else {
                None
            };
            (None, None, op)
        }
    };

    Some(AwsCall {
        service,
        bucket,
        key,
        operation: op,
        sigv4,
        access_key_id,
        region,
        anonymous,
    })
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn service_from_host(host: &str) -> Option<AwsService> {
    // Virtual-hosted S3: `<bucket>.s3.<region>.amazonaws.com` / `.s3.amazonaws.com`.
    if host.ends_with(".s3.amazonaws.com") || host == "s3.amazonaws.com" || host.contains(".s3.") && host.ends_with(".amazonaws.com") {
        return Some(AwsService::S3);
    }
    // Path-style S3: `s3.amazonaws.com` / `s3-<region>.amazonaws.com`.
    if host.starts_with("s3.") || host.starts_with("s3-") {
        return Some(AwsService::S3);
    }
    // Classic AWS services by subdomain.
    const AWS_SERVICES: &[(&str, AwsService)] = &[
        ("dynamodb.", AwsService::DynamoDb),
        ("sqs.", AwsService::Sqs),
        ("sns.", AwsService::Sns),
        ("sts.", AwsService::Sts),
        ("iam.", AwsService::Iam),
        ("lambda.", AwsService::Lambda),
        ("kinesis.", AwsService::Kinesis),
        ("firehose.", AwsService::Firehose),
        ("ec2.", AwsService::Ec2),
        ("rds.", AwsService::Rds),
        ("monitoring.", AwsService::Cloudwatch),
        ("secretsmanager.", AwsService::SecretsManager),
        ("ssm.", AwsService::Ssm),
        ("kms.", AwsService::Kms),
        ("bedrock-runtime.", AwsService::BedrockRuntime),
    ];
    for (prefix, svc) in AWS_SERVICES {
        if host.contains(prefix) && host.ends_with(".amazonaws.com") {
            return Some(*svc);
        }
    }
    // S3-compatible providers.
    if host.ends_with(".r2.cloudflarestorage.com")
        || host.ends_with(".backblazeb2.com")
        || host.ends_with(".wasabisys.com")
        || host.ends_with(".digitaloceanspaces.com")
        || host.ends_with(".linodeobjects.com")
        || host.contains("minio")
    {
        return Some(AwsService::S3Compatible);
    }
    if host.ends_with(".amazonaws.com") {
        return Some(AwsService::Other);
    }
    None
}

fn map_sigv4_service(svc: &str) -> Option<AwsService> {
    Some(match svc.to_ascii_lowercase().as_str() {
        "s3" => AwsService::S3,
        "dynamodb" => AwsService::DynamoDb,
        "sqs" => AwsService::Sqs,
        "sns" => AwsService::Sns,
        "sts" => AwsService::Sts,
        "iam" => AwsService::Iam,
        "lambda" => AwsService::Lambda,
        "kinesis" => AwsService::Kinesis,
        "firehose" => AwsService::Firehose,
        "ec2" => AwsService::Ec2,
        "rds" => AwsService::Rds,
        "monitoring" => AwsService::Cloudwatch,
        "secretsmanager" => AwsService::SecretsManager,
        "ssm" => AwsService::Ssm,
        "kms" => AwsService::Kms,
        "bedrock-runtime" => AwsService::BedrockRuntime,
        _ => return None,
    })
}

fn extract_s3_bucket_key(host: &str, path: &str) -> (Option<String>, Option<String>) {
    // Virtual-hosted style: bucket is the first segment of host.
    if host.ends_with(".s3.amazonaws.com") {
        let bucket = host.trim_end_matches(".s3.amazonaws.com").to_string();
        let key = path.trim_start_matches('/');
        return (Some(bucket), Some(truncate_str(key, 512)));
    }
    if let Some(pos) = host.find(".s3.") {
        // bucket.s3.region.amazonaws.com
        let bucket = host[..pos].to_string();
        let key = path.trim_start_matches('/');
        return (Some(bucket), Some(truncate_str(key, 512)));
    }
    // Path-style: /bucket/key
    let trimmed = path.trim_start_matches('/');
    let (bucket, key) = trimmed.split_once('/').unwrap_or((trimmed, ""));
    if bucket.is_empty() {
        (None, None)
    } else {
        (Some(bucket.to_string()), Some(truncate_str(key, 512)))
    }
}

fn s3_op(method: &str, key: &Option<String>) -> &'static str {
    let has_key = key.as_deref().is_some_and(|k| !k.is_empty());
    match (method.to_ascii_uppercase().as_str(), has_key) {
        ("GET", true) => "GetObject",
        ("GET", false) => "ListObjects",
        ("PUT", true) => "PutObject",
        ("PUT", false) => "CreateBucket",
        ("DELETE", true) => "DeleteObject",
        ("DELETE", false) => "DeleteBucket",
        ("HEAD", true) => "HeadObject",
        ("HEAD", false) => "HeadBucket",
        ("POST", _) => "Post",
        _ => "?",
    }
}

/// Parse an `Authorization: AWS4-HMAC-SHA256` header. Returns
/// `(is_sigv4, access_key_id, region, service)`.
fn parse_sigv4(header: &str) -> (bool, Option<String>, Option<String>, String) {
    let Some(rest) = header.strip_prefix("AWS4-HMAC-SHA256") else {
        return (false, None, None, String::new());
    };
    let mut akid = None;
    let mut region = None;
    let mut svc = String::new();
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(cred) = part.strip_prefix("Credential=") {
            // Format: AKIA.../20240101/us-east-1/s3/aws4_request
            let mut it = cred.split('/');
            akid = it.next().map(str::to_string);
            let _date = it.next();
            region = it.next().map(str::to_string);
            if let Some(s) = it.next() {
                svc = s.to_string();
            }
        }
    }
    (true, akid, region, svc)
}

fn truncate_str(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { s[..n].to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_virtual_hosted_get_object() {
        let headers = vec![
            (
                "Authorization".into(),
                // Non-real AKID, built from fragments so GitHub's scanner doesn't flag.
                format!(
                    "AWS4-HMAC-SHA256 Credential={}{}/20250101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef",
                    "AK", "IAEXAMPLEFIXTURE42"
                ),
            ),
            ("Host".into(), "mybucket.s3.amazonaws.com".into()),
        ];
        let c = classify(
            "GET",
            "/my/key.txt",
            Some("mybucket.s3.amazonaws.com"),
            &headers,
        )
        .expect("classified");
        assert_eq!(c.service, AwsService::S3);
        assert_eq!(c.bucket.as_deref(), Some("mybucket"));
        assert_eq!(c.key.as_deref(), Some("my/key.txt"));
        assert_eq!(c.operation.as_deref(), Some("GetObject"));
        assert!(c.sigv4);
        assert_eq!(c.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn s3_path_style_anonymous() {
        let c = classify("GET", "/public/img.png", Some("s3.amazonaws.com"), &[])
            .expect("classified");
        assert_eq!(c.bucket.as_deref(), Some("public"));
        assert_eq!(c.key.as_deref(), Some("img.png"));
        assert!(c.anonymous);
    }

    #[test]
    fn dynamodb_json_rpc() {
        let headers = vec![
            ("X-Amz-Target".into(), "DynamoDB_20120810.GetItem".into()),
        ];
        let c = classify("POST", "/", Some("dynamodb.us-east-1.amazonaws.com"), &headers)
            .expect("classified");
        assert_eq!(c.service, AwsService::DynamoDb);
        assert_eq!(c.operation.as_deref(), Some("GetItem"));
    }

    #[test]
    fn r2_compatible() {
        let c = classify(
            "PUT",
            "/bucket/key",
            Some("my-acct.r2.cloudflarestorage.com"),
            &[],
        )
        .expect("classified");
        assert_eq!(c.service, AwsService::S3Compatible);
    }

    #[test]
    fn non_aws_returns_none() {
        assert!(classify("GET", "/", Some("example.com"), &[]).is_none());
    }
}
