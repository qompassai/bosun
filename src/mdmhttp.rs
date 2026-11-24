//! The MDM HTTPS server: check-in, command channel, SCEP, and
//! the enrollment-profile download. Runs as the `bosun
//! mdm-serve` subcommand, a separate process from the MCP stdio
//! server; the two coordinate only through the home directory's
//! files (inventory + MDM state), each loading fresh per
//! operation, so either can restart without the other noticing.
//!
//! Shape: a std-thread socket server (one thread per
//! connection, a hard connection cap, socket timeouts) with
//! rustls TLS. TLS posture, in order: the configured
//! certificate/key when present; otherwise, on a loopback bind,
//! a self-signed development certificate generated under the
//! home (key 0600); otherwise plaintext only when the operator
//! explicitly set `BOSUN_MDM_ALLOW_PLAIN_LOOPBACK=1` AND the
//! bind is loopback. A non-loopback bind without TLS refuses to
//! start. Development material is for the LAN/simulated gate —
//! the real-device gate installs the real certificate.
//!
//! `handle` is the whole protocol as a pure-ish function over
//! (context, request) so it is unit-tested without sockets; the
//! socket layer is a thin shell around it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::capability::Enrollment;
use crate::config::MdmConfig;
use crate::mdmstate::MdmState;
use crate::plist;
use crate::profile;
use crate::scep::LocalCa;
use crate::store::Store;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub struct HttpError {
    pub code: &'static str,
    pub message: String,
}

impl HttpError {
    fn new(code: &'static str, message: impl Into<String>) -> HttpError {
        HttpError {
            code,
            message: message.into(),
        }
    }
}

/// Everything a request needs: the server home and its config.
pub struct Context {
    pub home: PathBuf,
    pub config: MdmConfig,
}

impl Context {
    pub fn new(home: PathBuf, config: MdmConfig) -> Context {
        Context { home, config }
    }

    fn inventory_path(&self) -> PathBuf {
        self.home.join("inventory.json")
    }
}

/// One HTTP response, before the socket layer frames it.
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

fn json_error(status: u16, code: &str, message: &str) -> Response {
    Response {
        status,
        content_type: "application/json",
        body: json!({"error": {"code": code, "message": message}})
            .to_string()
            .into_bytes(),
    }
}

fn empty_ok() -> Response {
    Response {
        status: 200,
        content_type: "text/plain",
        body: Vec::new(),
    }
}

fn plist_response(value: &Value) -> Response {
    match plist::to_string(value) {
        Ok(text) => Response {
            status: 200,
            content_type: "application/xml",
            body: text.into_bytes(),
        },
        Err(e) => json_error(500, e.code, &e.message),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == name { Some(v) } else { None }
    })
}

fn str_field<'a>(dict: &'a Value, name: &str) -> Option<&'a str> {
    dict.get(name).and_then(Value::as_str)
}

/// The protocol core. `path` carries no query string; `query`
/// is the raw query (session tokens ride there).
pub fn handle(ctx: &Context, method: &str, path: &str, query: &str, body: &[u8]) -> Response {
    match (method, path) {
        ("GET", "/scep") => scep_get(ctx, query),
        ("POST", "/scep") => scep_post(ctx, query, body),
        ("GET", "/enroll") => enroll_download(ctx, query),
        ("PUT", "/mdm/checkin") => checkin(ctx, query, body),
        ("PUT", "/mdm/server") => command_channel(ctx, body),
        ("GET", "/health") => Response {
            status: 200,
            content_type: "application/json",
            body: json!({"status": "ok", "service": "bosun-mdm"})
                .to_string()
                .into_bytes(),
        },
        _ => json_error(404, "not_found", &format!("no route for {method} {path}")),
    }
}

// ---------------------------------------------------------------------------
// SCEP (fenced local CA — see scep.rs for the choice and why)
// ---------------------------------------------------------------------------

fn scep_get(ctx: &Context, query: &str) -> Response {
    let ca = LocalCa::new(&ctx.home);
    match query_param(query, "operation") {
        Some("GetCACert") => match ca.ca_cert_der() {
            Ok(der) => Response {
                status: 200,
                content_type: "application/x-x509-ca-cert",
                body: der,
            },
            Err(e) => json_error(404, e.code, &e.message),
        },
        Some("GetCACaps") => Response {
            status: 200,
            content_type: "text/plain",
            body: LocalCa::caps().as_bytes().to_vec(),
        },
        _ => json_error(
            400,
            "scep_operation_unknown",
            "GET /scep takes operation=GetCACert or operation=GetCACaps",
        ),
    }
}

fn scep_post(ctx: &Context, query: &str, body: &[u8]) -> Response {
    if query_param(query, "operation") != Some("PKIOperation") {
        return json_error(
            400,
            "scep_operation_unknown",
            "POST /scep takes operation=PKIOperation with a bare CSR body (the fenced form; see STAGE1.md)",
        );
    }
    let ca = LocalCa::new(&ctx.home);
    match ca.issue(body) {
        Ok(p7) => Response {
            status: 200,
            content_type: "application/x-pki-message",
            body: p7,
        },
        Err(e) => {
            let status = if e.code == "ca_not_initialized" {
                404
            } else {
                400
            };
            json_error(status, e.code, &e.message)
        }
    }
}

// ---------------------------------------------------------------------------
// Enrollment profile download
// ---------------------------------------------------------------------------

fn enroll_download(ctx: &Context, query: &str) -> Response {
    let Some(token) = query_param(query, "session") else {
        return json_error(400, "invalid_argument", "missing session query parameter");
    };
    // Peek, do not consume: the session is spent by the
    // Authenticate it authorizes, not by the download.
    let state = match MdmState::load(&ctx.home) {
        Ok(s) => s,
        Err(e) => return json_error(500, e.code, &e.message),
    };
    let Some(session) = state.session(token) else {
        return json_error(
            404,
            "enrollment_session_not_found",
            "no live enrollment session for that token (sessions are one-shot and are spent by Authenticate)",
        );
    };
    let ca = LocalCa::new(&ctx.home);
    let fingerprint = if ca.is_initialized() {
        ca.ca_fingerprint_sha1().ok()
    } else {
        None
    };
    let enrollment: Enrollment = session.enrollment;
    match profile::render_profile(&ctx.config, token, enrollment, fingerprint.as_deref()) {
        Ok(text) => Response {
            status: 200,
            content_type: "application/x-apple-aspen-config",
            body: text.into_bytes(),
        },
        Err(e) => json_error(500, e.code, &e.message),
    }
}

// ---------------------------------------------------------------------------
// Check-in: Authenticate / TokenUpdate / CheckOut
// ---------------------------------------------------------------------------

fn checkin(ctx: &Context, query: &str, body: &[u8]) -> Response {
    let message = match plist::parse(body) {
        Ok(v) => v,
        Err(e) => return json_error(400, e.code, &e.message),
    };
    let Some(message_type) = str_field(&message, "MessageType") else {
        return json_error(400, "invalid_checkin", "check-in body lacks MessageType");
    };
    let Some(udid) = str_field(&message, "UDID") else {
        return json_error(400, "invalid_checkin", "check-in body lacks UDID");
    };
    if udid.is_empty() || udid.len() > crate::mdmstate::MAX_UDID_CHARS {
        return json_error(400, "invalid_checkin", "UDID is empty or oversized");
    }
    let mut state = match MdmState::load(&ctx.home) {
        Ok(s) => s,
        Err(e) => return json_error(500, e.code, &e.message),
    };
    let now = now_unix();
    match message_type {
        "Authenticate" => {
            let (device_id, enrollment) = match query_param(query, "session") {
                Some(token) => match state.take_session(token) {
                    Some(session) => (session.device_id, session.enrollment),
                    None => {
                        return json_error(
                            403,
                            "enrollment_session_invalid",
                            "the enrollment session token is unknown or already spent",
                        );
                    }
                },
                None => match state.device(udid) {
                    // A known device re-authenticating (it does
                    // so after every reboot) needs no session.
                    Some(d) => (d.inventory_id.clone().unwrap_or_default(), d.enrollment),
                    None => {
                        return json_error(
                            403,
                            "enrollment_session_required",
                            "first Authenticate for a device must carry the enrollment session token",
                        );
                    }
                },
            };
            // The session names an inventory record; it must
            // exist and its transport must be this UDID.
            let store = match Store::load(ctx.inventory_path()) {
                Ok(s) => s,
                Err(e) => return json_error(500, e.code, &e.message),
            };
            match store.get(&device_id) {
                Some(record) if record.transport == udid => {}
                Some(_) => {
                    return json_error(
                        403,
                        "udid_mismatch",
                        "the enrolling device's UDID does not match the inventory record's transport",
                    );
                }
                None => {
                    return json_error(
                        403,
                        "device_not_registered",
                        "the enrollment session names a device that is not in the inventory",
                    );
                }
            }
            if let Err(e) = state.authenticate(udid, &device_id, enrollment, now) {
                return json_error(500, e.code, &e.message);
            }
            match state.save() {
                Ok(()) => empty_ok(),
                Err(e) => json_error(500, e.code, &e.message),
            }
        }
        "TokenUpdate" => {
            if state.device(udid).is_none() {
                return json_error(
                    403,
                    "not_authenticated",
                    "TokenUpdate from a device that has not authenticated",
                );
            }
            let token_hex = message
                .get("Token")
                .and_then(plist::data_bytes)
                .map(|b| crate::plist::hex_encode(&b));
            let push_magic = str_field(&message, "PushMagic").map(str::to_string);
            let topic = str_field(&message, "Topic").map(str::to_string);
            state.token_update(udid, token_hex, push_magic, topic, now);
            match state.save() {
                Ok(()) => empty_ok(),
                Err(e) => json_error(500, e.code, &e.message),
            }
        }
        "CheckOut" => {
            state.check_out(udid, now);
            match state.save() {
                Ok(()) => empty_ok(),
                Err(e) => json_error(500, e.code, &e.message),
            }
        }
        other => json_error(
            400,
            "unsupported_message_type",
            &format!("check-in MessageType {other:?} is not supported"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Command channel: poll for commands, record responses
// ---------------------------------------------------------------------------

fn command_channel(ctx: &Context, body: &[u8]) -> Response {
    let message = match plist::parse(body) {
        Ok(v) => v,
        Err(e) => return json_error(400, e.code, &e.message),
    };
    let Some(udid) = str_field(&message, "UDID") else {
        return json_error(400, "invalid_command_poll", "command poll lacks UDID");
    };
    let Some(status) = str_field(&message, "Status") else {
        return json_error(400, "invalid_command_poll", "command poll lacks Status");
    };
    let mut state = match MdmState::load(&ctx.home) {
        Ok(s) => s,
        Err(e) => return json_error(500, e.code, &e.message),
    };
    if state.device(udid).is_none() {
        return json_error(
            403,
            "not_authenticated",
            "command poll from a device that has not authenticated",
        );
    }
    let now = now_unix();
    if status != "Idle" {
        // A response to an earlier command. It must name the
        // command it answers; the state refuses mismatches and
        // leaves the record untouched. `NotNow` records nothing:
        // the device is deferring, the command stays delivered
        // and outstanding.
        let Some(uuid) = str_field(&message, "CommandUUID") else {
            return json_error(
                400,
                "invalid_command_response",
                "a command response must carry CommandUUID",
            );
        };
        let acknowledged = match status {
            "Acknowledged" => Some(true),
            "Error" => Some(false),
            "NotNow" => None,
            other => {
                return json_error(
                    400,
                    "invalid_command_response",
                    &format!("unknown command-poll Status {other:?}"),
                );
            }
        };
        if let Some(acknowledged) = acknowledged
            && let Err(e) = state.record_response(udid, uuid, acknowledged, message.clone(), now)
        {
            return json_error(400, e.code, &e.message);
        }
    }
    // Deliver the next queued command, if any — including in
    // the same response that acknowledged the previous one,
    // which is how the protocol chains.
    let next = state.next_deliverable(udid, now);
    if let Err(e) = state.save() {
        return json_error(500, e.code, &e.message);
    }
    match next {
        Some(record) => {
            let rendered = record
                .kind()
                .and_then(|kind| kind.to_command_value(&record.command_uuid).ok());
            match rendered {
                Some(command) => plist_response(&command),
                None => json_error(
                    500,
                    "command_unrenderable",
                    "a queued command could not be rendered for delivery",
                ),
            }
        }
        None => empty_ok(),
    }
}

// ---------------------------------------------------------------------------
// Socket layer
// ---------------------------------------------------------------------------

enum TlsMode {
    Tls(Arc<rustls::ServerConfig>),
    Plain,
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig, HttpError> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let cert_bytes = std::fs::read(cert_path).map_err(|e| {
        HttpError::new(
            "tls_config_unreadable",
            format!("cannot read {}: {e}", cert_path.display()),
        )
    })?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<_, _>>()
        .map_err(|e| {
            HttpError::new(
                "tls_config_invalid",
                format!("cannot parse certificates in {}: {e}", cert_path.display()),
            )
        })?;
    if certs.is_empty() {
        return Err(HttpError::new(
            "tls_config_invalid",
            format!("no certificates in {}", cert_path.display()),
        ));
    }
    let key_bytes = std::fs::read(key_path).map_err(|e| {
        HttpError::new(
            "tls_config_unreadable",
            format!("cannot read {}: {e}", key_path.display()),
        )
    })?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
        HttpError::new(
            "tls_config_invalid",
            format!("cannot parse the key in {}: {e}", key_path.display()),
        )
    })?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpError::new("tls_config_invalid", format!("TLS versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| HttpError::new("tls_config_invalid", format!("TLS config: {e}")))
}

/// Generate the loopback development certificate under the home
/// (openssl; key 0600). Returns (cert, key) paths.
fn dev_cert_paths(home: &Path) -> Result<(PathBuf, PathBuf), HttpError> {
    let dir = home.join("dev-tls");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    if cert.exists() && key.exists() {
        return Ok((cert, key));
    }
    std::fs::create_dir_all(&dir).map_err(|e| {
        HttpError::new(
            "tls_dev_cert_failed",
            format!("cannot create {}: {e}", dir.display()),
        )
    })?;
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key.to_str().unwrap_or_default(),
            "-out",
            cert.to_str().unwrap_or_default(),
            "-days",
            "825",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| HttpError::new("tls_dev_cert_failed", format!("cannot run openssl: {e}")))?;
    if !status.success() {
        return Err(HttpError::new(
            "tls_dev_cert_failed",
            "openssl could not generate the development certificate",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
    }
    Ok((cert, key))
}

fn resolve_tls(ctx: &Context) -> Result<TlsMode, HttpError> {
    let config = &ctx.config;
    if let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) {
        return Ok(TlsMode::Tls(Arc::new(load_tls_config(cert, key)?)));
    }
    let loopback = config.bind.ip().is_loopback();
    if !loopback {
        return Err(HttpError::new(
            "tls_required",
            format!(
                "refusing to serve MDM on non-loopback {} without a TLS certificate (set BOSUN_MDM_TLS_CERT/BOSUN_MDM_TLS_KEY)",
                config.bind
            ),
        ));
    }
    if config.allow_plain_loopback {
        return Ok(TlsMode::Plain);
    }
    let (cert, key) = dev_cert_paths(&ctx.home)?;
    Ok(TlsMode::Tls(Arc::new(load_tls_config(&cert, &key)?)))
}

/// Serve until the process is stopped. The caller (the
/// `mdm-serve` subcommand) owns the lifetime.
pub fn serve(ctx: Context) -> Result<(), HttpError> {
    let tls = resolve_tls(&ctx)?;
    let listener = TcpListener::bind(ctx.config.bind).map_err(|e| {
        HttpError::new(
            "bind_failed",
            format!("cannot bind {}: {e}", ctx.config.bind),
        )
    })?;
    let mode = match &tls {
        TlsMode::Tls(_) => "https",
        TlsMode::Plain => "http (loopback, explicitly allowed)",
    };
    eprintln!(
        "bosun mdm-serve: listening on {} ({mode}); check-in {}, server {}, scep {}",
        ctx.config.bind,
        ctx.config.checkin_url("<session>"),
        ctx.config.server_endpoint_url(),
        ctx.config.scep_url()
    );
    let ctx = Arc::new(ctx);
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            drop(stream);
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let ctx = Arc::clone(&ctx);
        let active = Arc::clone(&active);
        let tls = match &tls {
            TlsMode::Tls(cfg) => TlsMode::Tls(Arc::clone(cfg)),
            TlsMode::Plain => TlsMode::Plain,
        };
        std::thread::spawn(move || {
            let _ = handle_stream(stream, &ctx, &tls);
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

fn handle_stream(stream: TcpStream, ctx: &Context, tls: &TlsMode) -> std::io::Result<()> {
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).ok();
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).ok();
    let mut stream = stream;
    match tls {
        TlsMode::Plain => serve_on(&mut stream, ctx),
        TlsMode::Tls(config) => {
            let conn =
                rustls::ServerConnection::new(Arc::clone(config)).map_err(std::io::Error::other)?;
            let mut tls_stream = rustls::StreamOwned::new(conn, stream);
            // Drive the handshake by attempting the first read
            // inside serve_on; a failed handshake just ends the
            // connection, like a dropped client.
            serve_on(&mut tls_stream, ctx)
        }
    }
}

fn serve_on<S: Read + Write>(stream: &mut S, ctx: &Context) -> std::io::Result<()> {
    let (method, path, query, body) = match read_request(stream)? {
        Some(r) => r,
        None => return Ok(()),
    };
    let response = handle(ctx, &method, &path, &query, &body);
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Response",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

/// One parsed request: (method, path, query, body).
type Request = (String, String, String, Vec<u8>);

/// Read one HTTP request: request line, headers, and exactly
/// `content-length` body bytes, all bounded. `None` is a clean
/// empty connection.
fn read_request<S: Read>(stream: &mut S) -> std::io::Result<Option<Request>> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(None);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head_text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head_text.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
            if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                return Ok(None);
            }
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Ok(None);
    }
    let mut body = buf.split_off(header_end);
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    Ok(Some((method, path, query, body)))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdm::MdmCommandKind;

    struct Fixture {
        dir: PathBuf,
        ctx: Context,
    }

    fn fixture() -> Fixture {
        let dir = std::env::temp_dir().join(format!(
            "bosun-mdmhttp-test-{}-{}",
            std::process::id(),
            crate::mdmstate::random_token().expect("rng")
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // Inventory: one iOS device whose transport is its UDID.
        let mut store = Store::load(dir.join("inventory.json")).expect("store");
        store
            .register(crate::capability::DeviceRecord {
                id: "iphone-sim".to_string(),
                label: "Sim iPhone".to_string(),
                platform: crate::capability::Platform::Ios,
                transport: "UDID-SIM-1".to_string(),
                enrollment: Enrollment::Unenrolled,
            })
            .expect("register");
        let config = MdmConfig::for_test(&dir, "127.0.0.1:8443".parse().expect("addr"));
        Fixture {
            ctx: Context::new(dir.clone(), config),
            dir,
        }
    }

    fn plist_body(value: &Value) -> Vec<u8> {
        plist::to_string(value).expect("render").into_bytes()
    }

    fn open_session(dir: &Path, enrollment: Enrollment) -> String {
        let token = crate::mdmstate::random_token().expect("rng");
        let mut state = MdmState::load(dir).expect("state");
        state
            .create_session(token.clone(), "iphone-sim", enrollment, 1000)
            .expect("session");
        state.save().expect("save");
        token
    }

    #[test]
    fn full_checkin_and_command_flow() {
        let fx = fixture();
        // Open a supervised enrollment session.
        let token = open_session(&fx.dir, Enrollment::EnrolledSupervised);
        // Authenticate without the session refuses.
        let body = plist_body(&json!({"MessageType": "Authenticate", "UDID": "UDID-SIM-1"}));
        let r = handle(&fx.ctx, "PUT", "/mdm/checkin", "", &body);
        assert_eq!(r.status, 403);
        // With the session it lands, and enrollment is recorded.
        let r = handle(
            &fx.ctx,
            "PUT",
            "/mdm/checkin",
            &format!("session={token}"),
            &body,
        );
        assert_eq!(r.status, 200);
        // TokenUpdate stores push credentials.
        let body = plist_body(&json!({
            "MessageType": "TokenUpdate", "UDID": "UDID-SIM-1",
            "Token": { "$plist_data": crate::plist::base64_encode(&[0xAA; 32]) },
            "PushMagic": "magic-sim",
        }));
        let r = handle(&fx.ctx, "PUT", "/mdm/checkin", "", &body);
        assert_eq!(r.status, 200);
        let state = MdmState::load(&fx.dir).expect("state");
        let device = state.device("UDID-SIM-1").expect("device enrolled");
        assert_eq!(device.enrollment, Enrollment::EnrolledSupervised);
        assert!(device.push_ready());
        // Queue a command; an Idle poll delivers it.
        let mut state = MdmState::load(&fx.dir).expect("state");
        let uuid = state
            .enqueue("UDID-SIM-1", MdmCommandKind::DeviceInformation, 1001)
            .expect("enqueue");
        state.save().expect("save");
        let body = plist_body(&json!({"UDID": "UDID-SIM-1", "Status": "Idle"}));
        let r = handle(&fx.ctx, "PUT", "/mdm/server", "", &body);
        assert_eq!(r.status, 200);
        let delivered = plist::parse(&r.body).expect("plist");
        assert_eq!(delivered["CommandUUID"], uuid);
        assert_eq!(delivered["Command"]["RequestType"], "DeviceInformation");
        // A response with a wrong UUID is refused and the record
        // stays delivered (adversarial).
        let body = plist_body(&json!({
            "UDID": "UDID-SIM-1", "Status": "Acknowledged", "CommandUUID": "bogus",
        }));
        let r = handle(&fx.ctx, "PUT", "/mdm/server", "", &body);
        assert_eq!(r.status, 400);
        let state = MdmState::load(&fx.dir).expect("state");
        assert_eq!(
            state.commands_for("UDID-SIM-1")[0].state,
            crate::mdmstate::CommandState::Delivered
        );
        // The correct acknowledgment lands.
        let body = plist_body(&json!({
            "UDID": "UDID-SIM-1", "Status": "Acknowledged", "CommandUUID": uuid,
            "QueryResponses": {"OSVersion": "26.0"},
        }));
        let r = handle(&fx.ctx, "PUT", "/mdm/server", "", &body);
        assert_eq!(r.status, 200);
        let state = MdmState::load(&fx.dir).expect("state");
        let record = &state.commands_for("UDID-SIM-1")[0];
        assert_eq!(record.state, crate::mdmstate::CommandState::Acknowledged);
        assert_eq!(
            record.response.as_ref().expect("response")["QueryResponses"]["OSVersion"],
            "26.0"
        );
        std::fs::remove_dir_all(&fx.dir).ok();
    }

    #[test]
    fn unenrolled_and_mismatched_devices_refuse() {
        // Adversarial: TokenUpdate before Authenticate, a poll
        // from an unknown UDID, and a session spent twice.
        let fx = fixture();
        let body = plist_body(&json!({"MessageType": "TokenUpdate", "UDID": "UDID-SIM-1"}));
        let r = handle(&fx.ctx, "PUT", "/mdm/checkin", "", &body);
        assert_eq!(r.status, 403);
        let body = plist_body(&json!({"UDID": "UDID-UNKNOWN", "Status": "Idle"}));
        let r = handle(&fx.ctx, "PUT", "/mdm/server", "", &body);
        assert_eq!(r.status, 403);
        let token = open_session(&fx.dir, Enrollment::EnrolledSupervised);
        let body = plist_body(&json!({"MessageType": "Authenticate", "UDID": "UDID-SIM-1"}));
        let q = format!("session={token}");
        assert_eq!(
            handle(&fx.ctx, "PUT", "/mdm/checkin", &q, &body).status,
            200
        );
        // Second spend of the same session (a different UDID
        // trying to ride it) refuses.
        let body2 = plist_body(&json!({"MessageType": "Authenticate", "UDID": "UDID-OTHER"}));
        assert_eq!(
            handle(&fx.ctx, "PUT", "/mdm/checkin", &q, &body2).status,
            403
        );
        std::fs::remove_dir_all(&fx.dir).ok();
    }

    #[test]
    fn enroll_download_uses_but_does_not_spend_the_session() {
        let fx = fixture();
        let token = open_session(&fx.dir, Enrollment::EnrolledSupervised);
        let r = handle(&fx.ctx, "GET", "/enroll", &format!("session={token}"), &[]);
        assert_eq!(r.status, 200);
        let text = std::str::from_utf8(&r.body).expect("utf8");
        assert!(text.contains("com.apple.mdm"));
        assert!(text.contains(&token));
        // Still spendable by Authenticate afterwards.
        let body = plist_body(&json!({"MessageType": "Authenticate", "UDID": "UDID-SIM-1"}));
        let r = handle(
            &fx.ctx,
            "PUT",
            "/mdm/checkin",
            &format!("session={token}"),
            &body,
        );
        assert_eq!(r.status, 200);
        // Unknown sessions 404.
        let r = handle(&fx.ctx, "GET", "/enroll", "session=nope", &[]);
        assert_eq!(r.status, 404);
        std::fs::remove_dir_all(&fx.dir).ok();
    }
}
