//! The APNs push client: HTTP/2 to `api.push.apple.com` with
//! the MDM push certificate, sending the wake-up payload
//! `{"aps": {}, "mdm": "<push magic>"}` that tells an enrolled
//! device to check in.
//!
//! Transport choice, recorded: the estate's backend pattern is
//! already "bounded argv-only subprocess" (adb, ssh, winget), and
//! the fleet machine's curl is built with nghttp2. The push
//! transport is therefore a bounded `curl --http2` invocation
//! carrying the client certificate — no new async HTTP stack, no
//! TLS implementation of our own, and the certificate handling is
//! OpenSSL's, the same stack that will verify the cert at install
//! time. The transport sits behind a trait so tests inject a
//! mock; the simulated-device gate uses the file-logging mock
//! selected by `BOSUN_MDM_PUSH_TRANSPORT=mock`. No code path in
//! this stage places a real APNs call: without a push
//! certificate configured, the server refuses before any
//! transport runs.
//!
//! The topic (`com.apple.mgmt.External.<UUID>`) is read from the
//! certificate's subject UID via openssl, unless config pins
//! `BOSUN_MDM_TOPIC`.

use std::future::Future;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::backend::run_bounded;
use crate::config::MdmConfig;
use crate::plist::hex_encode;

/// The APNs production host. There is no sandbox host for MDM
/// push; the same endpoint serves every environment.
pub const APNS_HOST: &str = "api.push.apple.com";

/// Hex device tokens are 32 bytes today; the bound leaves room
/// and refuses anything absurd before it reaches an argv.
const MAX_TOKEN_HEX_CHARS: usize = 512;

#[derive(Debug)]
pub struct PushError {
    pub code: &'static str,
    pub message: String,
}

impl PushError {
    fn new(code: &'static str, message: impl Into<String>) -> PushError {
        PushError {
            code,
            message: message.into(),
        }
    }
}

/// Push configuration resolved from the MDM config: certificate
/// and key paths plus an optional pinned topic.
#[derive(Clone, Debug)]
pub struct ApnsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub topic_override: Option<String>,
}

impl ApnsConfig {
    /// `None` when either path is unconfigured — push is simply
    /// not available in that deployment, and callers say so.
    pub fn from_config(config: &MdmConfig) -> Option<ApnsConfig> {
        Some(ApnsConfig {
            cert_path: config.push_cert.clone()?,
            key_path: config.push_key.clone()?,
            topic_override: config.topic.clone(),
        })
    }
}

/// One wake-up: the device's APNs token (hex, as TokenUpdate
/// reported it) and the push magic from the same check-in.
#[derive(Clone, Debug)]
pub struct PushRequest {
    pub device_token_hex: String,
    pub push_magic: String,
}

/// What APNs (or the mock) answered. A non-200 status is an
/// outcome, not a transport error: APNs explains itself in
/// `reason`, and the caller surfaces it verbatim.
#[derive(Clone, Debug)]
pub struct PushOutcome {
    pub status: u16,
    pub apns_id: Option<String>,
    pub reason: Option<String>,
}

/// The transport seam. Production is curl; tests and the
/// simulated-device gate use mocks.
pub trait PushTransport: Send + Sync {
    fn push(
        &self,
        config: &ApnsConfig,
        topic: &str,
        request: &PushRequest,
    ) -> impl Future<Output = Result<PushOutcome, PushError>> + Send;
}

/// The wake-up payload for a push magic.
pub fn wake_payload(push_magic: &str) -> Value {
    json!({ "aps": {}, "mdm": push_magic })
}

fn validate_token(token_hex: &str) -> Result<(), PushError> {
    if token_hex.is_empty()
        || token_hex.len() > MAX_TOKEN_HEX_CHARS
        || !token_hex.len().is_multiple_of(2)
        || !token_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(PushError::new(
            "push_token_invalid",
            "the stored APNs device token is not bounded hex; refusing to push",
        ));
    }
    Ok(())
}

/// Extract the topic from an openssl subject string (RFC2253
/// form: `CN=...,UID=com.apple.mgmt.External.<UUID>,...`). The
/// UID RDN carries the topic on Apple MDM push certificates.
pub fn topic_from_subject(subject: &str) -> Option<String> {
    for part in subject.split(',') {
        let part = part.trim();
        if let Some(uid) = part.strip_prefix("UID=") {
            let uid = uid.trim();
            if uid.starts_with("com.apple.mgmt.") {
                return Some(uid.to_string());
            }
        }
    }
    None
}

/// Read the topic from the configured certificate via openssl.
pub async fn read_topic(config: &ApnsConfig) -> Result<String, PushError> {
    if let Some(topic) = &config.topic_override {
        return Ok(topic.clone());
    }
    let output = run_bounded(
        "openssl",
        &[
            "x509".to_string(),
            "-noout".to_string(),
            "-subject".to_string(),
            "-nameopt".to_string(),
            "RFC2253".to_string(),
            "-in".to_string(),
            config.cert_path.display().to_string(),
        ],
    )
    .await
    .map_err(|e| PushError::new(e.code, e.message))?;
    let text = output["stdout"].as_str().unwrap_or_default();
    let subject = text.trim().strip_prefix("subject=").unwrap_or(text.trim());
    topic_from_subject(subject).ok_or_else(|| {
        PushError::new(
            "push_topic_not_found",
            format!(
                "no com.apple.mgmt.* UID in the push certificate subject ({subject}); set BOSUN_MDM_TOPIC to pin it"
            ),
        )
    })
}

/// Validate, resolve the topic, and push one wake-up.
pub async fn push_wake<T: PushTransport>(
    transport: &T,
    config: &ApnsConfig,
    request: &PushRequest,
) -> Result<PushOutcome, PushError> {
    validate_token(&request.device_token_hex)?;
    if request.push_magic.is_empty() || request.push_magic.len() > 256 {
        return Err(PushError::new(
            "push_magic_invalid",
            "the stored push magic is empty or oversized; refusing to push",
        ));
    }
    let topic = read_topic(config).await?;
    transport.push(config, &topic, request).await
}

// ---------------------------------------------------------------------------
// curl transport
// ---------------------------------------------------------------------------

/// Build the curl argv for one push. Pure, so the wire shape is
/// unit-tested without a network or a certificate.
pub fn curl_args(
    config: &ApnsConfig,
    topic: &str,
    request: &PushRequest,
) -> Result<Vec<String>, PushError> {
    validate_token(&request.device_token_hex)?;
    let payload = wake_payload(&request.push_magic).to_string();
    Ok(vec![
        "--http2".to_string(),
        "-sS".to_string(),
        "-i".to_string(),
        "--cert".to_string(),
        config.cert_path.display().to_string(),
        "--key".to_string(),
        config.key_path.display().to_string(),
        "-H".to_string(),
        format!("apns-topic: {topic}"),
        "-H".to_string(),
        "apns-push-type: mdm".to_string(),
        "-H".to_string(),
        "content-type: application/json".to_string(),
        "--data".to_string(),
        payload,
        format!("https://{APNS_HOST}/3/device/{}", request.device_token_hex),
    ])
}

/// Parse `curl -i` output: a status line, headers, then the JSON
/// body APNs returns on failure (`{"reason": "..."}`).
pub fn parse_curl_output(output: &[u8]) -> Result<PushOutcome, PushError> {
    let text = String::from_utf8_lossy(output);
    let mut lines = text.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            PushError::new(
                "apns_response_unparsable",
                format!("no HTTP status in the APNs response (first line: {status_line:?})"),
            )
        })?;
    let mut apns_id = None;
    let mut body: Vec<&str> = Vec::new();
    let mut in_body = false;
    for line in lines {
        if in_body {
            body.push(line);
            continue;
        }
        if line.is_empty() || line == "\r" {
            in_body = true;
            continue;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("apns-id")
        {
            apns_id = Some(value.trim().to_string());
        }
    }
    let reason = serde_json::from_str::<Value>(&body.join("\n"))
        .ok()
        .and_then(|v| v.get("reason").and_then(Value::as_str).map(str::to_string));
    Ok(PushOutcome {
        status,
        apns_id,
        reason,
    })
}

pub struct CurlTransport;

impl PushTransport for CurlTransport {
    async fn push(
        &self,
        config: &ApnsConfig,
        topic: &str,
        request: &PushRequest,
    ) -> Result<PushOutcome, PushError> {
        let args = curl_args(config, topic, request)?;
        let output = run_bounded("curl", &args)
            .await
            .map_err(|e| PushError::new(e.code, e.message))?;
        let stdout = output["stdout"].as_str().unwrap_or_default();
        parse_curl_output(stdout.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Mock transport (tests and the simulated-device gate)
// ---------------------------------------------------------------------------

/// A mock that records each push as a JSON line in a log file and
/// answers 200. Selected by `BOSUN_MDM_PUSH_TRANSPORT=mock`; the
/// log lands at `$BOSUN_HOME/mock_push_log.jsonl`.
pub struct MockTransport {
    pub log_path: Option<PathBuf>,
}

impl PushTransport for MockTransport {
    async fn push(
        &self,
        _config: &ApnsConfig,
        topic: &str,
        request: &PushRequest,
    ) -> Result<PushOutcome, PushError> {
        if let Some(path) = &self.log_path {
            let line = json!({
                "device_token": request.device_token_hex,
                "push_magic": request.push_magic,
                "topic": topic,
                "payload": wake_payload(&request.push_magic),
            })
            .to_string();
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    PushError::new(
                        "mock_push_log_unwritable",
                        format!("cannot open {}: {e}", path.display()),
                    )
                })?;
            writeln!(file, "{line}").map_err(|e| {
                PushError::new(
                    "mock_push_log_unwritable",
                    format!("cannot write {}: {e}", path.display()),
                )
            })?;
        }
        Ok(PushOutcome {
            status: 200,
            apns_id: Some("mock-apns-id".to_string()),
            reason: None,
        })
    }
}

/// The deployment's transport as a concrete type (the trait's
/// `impl Future` methods are not dyn-compatible, and with two
/// fixed transports an enum is the honest shape — the same call
/// the backends make).
pub enum PushTransportKind {
    Curl(CurlTransport),
    Mock(MockTransport),
}

impl PushTransport for PushTransportKind {
    async fn push(
        &self,
        config: &ApnsConfig,
        topic: &str,
        request: &PushRequest,
    ) -> Result<PushOutcome, PushError> {
        match self {
            PushTransportKind::Curl(t) => t.push(config, topic, request).await,
            PushTransportKind::Mock(t) => t.push(config, topic, request).await,
        }
    }
}

/// Choose the transport for a deployment: the mock only when the
/// operator explicitly asks for it in the environment.
pub fn transport_from_env(home: &std::path::Path) -> PushTransportKind {
    if std::env::var("BOSUN_MDM_PUSH_TRANSPORT").as_deref() == Ok("mock") {
        PushTransportKind::Mock(MockTransport {
            log_path: Some(home.join("mock_push_log.jsonl")),
        })
    } else {
        PushTransportKind::Curl(CurlTransport)
    }
}

/// Hex-encode a raw APNs token for the wire form. TokenUpdate
/// reports the token as plist data; the state store keeps this
/// form.
pub fn token_hex(data: &[u8]) -> String {
    hex_encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ApnsConfig {
        ApnsConfig {
            cert_path: PathBuf::from("/nonexistent/push.pem"),
            key_path: PathBuf::from("/nonexistent/push.key"),
            topic_override: Some("com.apple.mgmt.External.test".to_string()),
        }
    }

    fn request() -> PushRequest {
        PushRequest {
            device_token_hex: "0123456789abcdef".repeat(4),
            push_magic: "magic-1".to_string(),
        }
    }

    #[test]
    fn topic_parses_from_the_cert_subject() {
        let subject = "UID=com.apple.mgmt.External.11111111-2222-3333-4444-555555555555,CN=Apple MDM Push,OU=Example,O=Example";
        assert_eq!(
            topic_from_subject(subject).as_deref(),
            Some("com.apple.mgmt.External.11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(topic_from_subject("CN=Something Else,O=Example"), None);
    }

    #[test]
    fn curl_args_carry_cert_topic_and_payload() {
        let args =
            curl_args(&config(), "com.apple.mgmt.External.test", &request()).expect("args build");
        let joined = args.join(" ");
        assert!(joined.contains("--http2"));
        assert!(joined.contains("/nonexistent/push.pem"));
        assert!(joined.contains("apns-topic: com.apple.mgmt.External.test"));
        assert!(joined.contains("apns-push-type: mdm"));
        assert!(joined.contains("https://api.push.apple.com/3/device/0123456789abcdef"));
        assert!(joined.contains("\"mdm\":\"magic-1\""));
    }

    #[test]
    fn curl_output_parses_success_and_failure() {
        let ok = parse_curl_output(b"HTTP/2 200\r\napns-id: ABC-123\r\ncontent-length: 0\r\n\r\n")
            .expect("parses");
        assert_eq!(ok.status, 200);
        assert_eq!(ok.apns_id.as_deref(), Some("ABC-123"));
        assert_eq!(ok.reason, None);
        let bad = parse_curl_output(
            b"HTTP/2 400\r\napns-id: DEF-456\r\n\r\n{\"reason\":\"BadDeviceToken\"}",
        )
        .expect("parses");
        assert_eq!(bad.status, 400);
        assert_eq!(bad.reason.as_deref(), Some("BadDeviceToken"));
        assert!(parse_curl_output(b"garbage").is_err());
    }

    #[tokio::test]
    async fn invalid_tokens_and_magics_refuse_before_transport() {
        // Adversarial: malformed stored credentials must never
        // reach argv.
        struct Exploding;
        impl PushTransport for Exploding {
            async fn push(
                &self,
                _: &ApnsConfig,
                _: &str,
                _: &PushRequest,
            ) -> Result<PushOutcome, PushError> {
                panic!("transport must not run for invalid input");
            }
        }
        let huge = "ab".repeat(300);
        for bad in ["", "xyz", "abc", huge.as_str()] {
            let req = PushRequest {
                device_token_hex: bad.to_string(),
                push_magic: "m".to_string(),
            };
            assert_eq!(
                push_wake(&Exploding, &config(), &req)
                    .await
                    .expect_err("must refuse")
                    .code,
                "push_token_invalid"
            );
        }
        let req = PushRequest {
            device_token_hex: "abcd".to_string(),
            push_magic: String::new(),
        };
        assert_eq!(
            push_wake(&Exploding, &config(), &req)
                .await
                .expect_err("must refuse")
                .code,
            "push_magic_invalid"
        );
    }

    #[tokio::test]
    async fn mock_transport_records_and_answers() {
        let dir = std::env::temp_dir().join(format!("bosun-apns-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let log = dir.join("push.jsonl");
        let mock = MockTransport {
            log_path: Some(log.clone()),
        };
        let outcome = push_wake(&mock, &config(), &request())
            .await
            .expect("mock push works");
        assert_eq!(outcome.status, 200);
        let text = std::fs::read_to_string(&log).expect("log written");
        assert!(text.contains("\"push_magic\":\"magic-1\""));
        assert!(text.contains("com.apple.mgmt.External.test"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
