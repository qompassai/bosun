//! The simulated-device gate: Stage 1's exit evidence.
//!
//! A test harness plays the iPhone's side of the MDM protocol
//! end-to-end against bosun's real processes on localhost:
//!
//!   enroll (Authenticate / TokenUpdate) → push wake (mock APNs)
//!   → check in → DeviceInformation → respond →
//!   InstallApplication → acknowledge
//!
//! The MCP server and `bosun mdm-serve` run as separate
//! processes over one shared BOSUN_HOME, exactly as deployed;
//! the device side is raw HTTP + the crate's plist codec. The
//! adversarial half: a wrong-UUID response must not clear the
//! queue record, and an install for an unsupervised device must
//! refuse at the capability layer with nothing queued.
//!
//! The real-device round-trip remains the Stage 1 completion
//! gate and stays open until the Owner's certificate steps land
//! (STAGE1.md); this simulation is what this stage can prove.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use bosun::plist;
use serde_json::{Value, json};

const UDID: &str = "00008030-SIMULATED0001";
const UDID2: &str = "00008030-SIMULATED0002";
const META: &str = "\"io.modelcontextprotocol/protocolVersion\": \"2026-07-28\", \"io.modelcontextprotocol/clientCapabilities\": {}";

// ---------------------------------------------------------------------------
// Process plumbing
// ---------------------------------------------------------------------------

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn shared_env(home: &Path, port: u16) -> Vec<(String, String)> {
    let home = home.display().to_string();
    vec![
        ("BOSUN_HOME".to_string(), home.clone()),
        ("BOSUN_MDM_BIND".to_string(), format!("127.0.0.1:{port}")),
        (
            "BOSUN_MDM_SERVER_URL".to_string(),
            format!("https://127.0.0.1:{port}"),
        ),
        (
            "BOSUN_MDM_ALLOW_PLAIN_LOOPBACK".to_string(),
            "1".to_string(),
        ),
        ("BOSUN_MDM_PUSH_TRANSPORT".to_string(), "mock".to_string()),
        (
            "BOSUN_MDM_PUSH_CERT".to_string(),
            format!("{home}/push.pem"),
        ),
        ("BOSUN_MDM_PUSH_KEY".to_string(), format!("{home}/push.key")),
        (
            "BOSUN_MDM_TOPIC".to_string(),
            "com.apple.mgmt.External.simulated".to_string(),
        ),
    ]
}

fn spawn(bin: &Path, args: &[&str], home: &Path, port: u16, stdio: bool) -> Child {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .envs(shared_env(home, port))
        .env("PATH", "/usr/bin:/bin");
    if stdio {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    cmd.spawn().expect("spawn bosun")
}

// ---------------------------------------------------------------------------
// A minimal MCP client over the child's stdio
// ---------------------------------------------------------------------------

struct Mcp {
    _guard: Guard,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn spawn(bin: &Path, home: &Path, port: u16) -> Mcp {
        let mut child = spawn(bin, &[], home, port, true);
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let mut mcp = Mcp {
            _guard: Guard(child),
            stdin,
            reader: BufReader::new(stdout),
            next_id: 0,
        };
        let discovered = mcp.request("server/discover", json!({}));
        assert!(
            discovered["result"]["supportedVersions"]
                .as_array()
                .is_some_and(|v| v.iter().any(|x| x == "2026-07-28")),
            "discover must offer the modern era: {discovered}"
        );
        mcp
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let mut params = params;
        params["_meta"] = serde_json::from_str(&format!("{{{META}}}")).expect("meta json");
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{line}").expect("write request");
        self.stdin.flush().expect("flush");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(Instant::now() < deadline, "timed out waiting for {method}");
            let mut buf = String::new();
            let n = self.reader.read_line(&mut buf).expect("read response");
            assert!(n > 0, "server closed stdout waiting for {method}");
            let Ok(msg) = serde_json::from_str::<Value>(&buf) else {
                continue;
            };
            if msg["id"] == id {
                return msg;
            }
        }
    }

    /// Call a tool; returns (body, is_error).
    fn call(&mut self, name: &str, args: Value) -> (Value, bool) {
        let msg = self.request("tools/call", json!({"name": name, "arguments": args}));
        let result = &msg["result"];
        let is_error = result["isError"].as_bool().unwrap_or(false);
        let text = result["content"][0]["text"].as_str().unwrap_or("");
        let body: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        (body, is_error)
    }
}

// ---------------------------------------------------------------------------
// The device side: raw HTTP against mdm-serve
// ---------------------------------------------------------------------------

fn http(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect mdm-serve");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status line");
    let split = text.find("\r\n\r\n").expect("header end");
    (status, raw[split + 4..].to_vec())
}

fn plist_body(value: &Value) -> Vec<u8> {
    plist::to_string(value).expect("render plist").into_bytes()
}

fn wait_for_server(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok((200, _)) = std::panic::catch_unwind(|| http(port, "GET", "/health", &[])) {
            return;
        }
        assert!(Instant::now() < deadline, "mdm-serve never came up");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn temp_home() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bosun-sim-test-{}-{}",
        std::process::id(),
        bosun::mdmstate::random_token().expect("rng")
    ));
    std::fs::create_dir_all(&dir).expect("mkdir home");
    dir
}

fn approved() -> Value {
    json!({"approved_by": "sim-operator"})
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn simulated_device_round_trip() {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_bosun"));
    let home = temp_home();
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
        listener.local_addr().expect("addr").port()
    };
    let _mdm = Guard(spawn(&bin, &["mdm-serve"], &home, port, false));
    wait_for_server(port);
    let mut mcp = Mcp::spawn(&bin, &home, port);

    // -- Register two iPhones: one will enroll supervised, one
    //    unsupervised. Both start unenrolled in the inventory.
    for (id, udid) in [("iphone-sim", UDID), ("iphone-sim2", UDID2)] {
        let (body, is_error) = mcp.call(
            "bosun_device_register",
            json!({"id": id, "label": id, "platform": "ios", "transport": udid,
                   "operator_approval": approved()}),
        );
        assert!(!is_error, "register {id}: {body}");
        assert_eq!(body["enrollment"], "unenrolled");
    }

    // -- Enrollment profile for the supervised device.
    let (body, is_error) = mcp.call(
        "bosun_mdm_enrollment_profile",
        json!({"device_id": "iphone-sim", "enrollment": "enrolled_supervised",
               "operator_approval": approved()}),
    );
    assert!(!is_error, "enrollment profile: {body}");
    let session = body["session_token"].as_str().expect("token").to_string();
    assert!(
        body["profile"]
            .as_str()
            .expect("profile")
            .contains(&session),
        "profile carries the session token"
    );

    // -- The device enrolls: Authenticate spends the session,
    //    TokenUpdate stores its push credentials.
    let (status, _) = http(
        port,
        "PUT",
        &format!("/mdm/checkin?session={session}"),
        &plist_body(&json!({"MessageType": "Authenticate", "UDID": UDID})),
    );
    assert_eq!(status, 200, "Authenticate");
    let token_data = plist::data_value(&[0xAB; 32]);
    let (status, _) = http(
        port,
        "PUT",
        "/mdm/checkin",
        &plist_body(&json!({"MessageType": "TokenUpdate", "UDID": UDID,
                            "Token": token_data, "PushMagic": "magic-sim-1"})),
    );
    assert_eq!(status, 200, "TokenUpdate");

    // The inventory record now reads supervised: the MDM state
    // overlay reflects the enacted enrollment.
    let (body, _) = mcp.call("bosun_device_get", json!({"device_id": "iphone-sim"}));
    assert_eq!(body["enrollment"], "enrolled_supervised", "overlay: {body}");

    // -- Diagnostics queues DeviceInformation.
    let (body, is_error) = mcp.call(
        "bosun_device_diagnostics",
        json!({"device_id": "iphone-sim"}),
    );
    assert!(!is_error, "diagnostics: {body}");
    assert_eq!(body["delivery"], "queued");
    let uuid1 = body["command_uuid"].as_str().expect("uuid").to_string();

    // -- The push wake reaches the mock APNs with the device's
    //    token and magic.
    let (body, is_error) = mcp.call(
        "bosun_mdm_send_push",
        json!({"device_id": "iphone-sim", "operator_approval": approved()}),
    );
    assert!(!is_error, "send_push: {body}");
    assert_eq!(body["pushed"], true);
    let log = std::fs::read_to_string(home.join("mock_push_log.jsonl")).expect("mock push log");
    assert!(
        log.contains("magic-sim-1"),
        "push log carries the magic: {log}"
    );
    assert!(
        log.contains(&"ab".repeat(32)),
        "push log carries the token hex: {log}"
    );

    // -- Woken, the device polls and receives DeviceInformation.
    let (status, resp) = http(
        port,
        "PUT",
        "/mdm/server",
        &plist_body(&json!({"UDID": UDID, "Status": "Idle"})),
    );
    assert_eq!(status, 200, "Idle poll");
    let command = plist::parse(&resp).expect("command plist");
    assert_eq!(command["CommandUUID"], uuid1);
    assert_eq!(command["Command"]["RequestType"], "DeviceInformation");

    // -- It answers; the response lands against the queue record.
    let (status, _) = http(
        port,
        "PUT",
        "/mdm/server",
        &plist_body(
            &json!({"UDID": UDID, "Status": "Acknowledged", "CommandUUID": uuid1,
                            "QueryResponses": {"OSVersion": "26.0", "IsSupervised": true}}),
        ),
    );
    assert_eq!(status, 200, "DeviceInformation response");
    let (body, _) = mcp.call("bosun_mdm_queue", json!({"device_id": "iphone-sim"}));
    let record = &body["commands"][0];
    assert_eq!(record["state"], "acknowledged", "queue record: {record}");
    assert_eq!(record["response"]["QueryResponses"]["OSVersion"], "26.0");

    // -- InstallApplication by the same path.
    let (body, is_error) = mcp.call(
        "bosun_package_install",
        json!({"device_id": "iphone-sim", "package": "123456789",
               "operator_approval": approved()}),
    );
    assert!(!is_error, "install: {body}");
    let uuid2 = body["command_uuid"].as_str().expect("uuid").to_string();
    let (status, resp) = http(
        port,
        "PUT",
        "/mdm/server",
        &plist_body(&json!({"UDID": UDID, "Status": "Idle"})),
    );
    assert_eq!(status, 200);
    let command = plist::parse(&resp).expect("command plist");
    assert_eq!(command["CommandUUID"], uuid2);
    assert_eq!(command["Command"]["RequestType"], "InstallApplication");
    assert_eq!(command["Command"]["iTunesStoreID"], 123456789);

    // Adversarial: an answer naming a wrong UUID is refused and
    // the record stays delivered, still awaiting its answer.
    let (status, _) = http(
        port,
        "PUT",
        "/mdm/server",
        &plist_body(&json!({"UDID": UDID, "Status": "Acknowledged",
                            "CommandUUID": "bosun-cmd-999999"})),
    );
    assert_eq!(status, 400, "wrong-UUID response must refuse");
    let (body, _) = mcp.call("bosun_mdm_queue", json!({"device_id": "iphone-sim"}));
    let record = body["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|c| c["command_uuid"] == uuid2)
        .expect("install record");
    assert_eq!(record["state"], "delivered", "record untouched: {record}");

    // The true acknowledgment lands.
    let (status, _) = http(
        port,
        "PUT",
        "/mdm/server",
        &plist_body(&json!({"UDID": UDID, "Status": "Acknowledged", "CommandUUID": uuid2})),
    );
    assert_eq!(status, 200);
    let (body, _) = mcp.call("bosun_mdm_queue", json!({"device_id": "iphone-sim"}));
    let record = body["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|c| c["command_uuid"] == uuid2)
        .expect("install record");
    assert_eq!(record["state"], "acknowledged");

    // -- Adversarial capability case: the second device enrolls
    //    unsupervised; an approved install refuses at the
    //    capability layer and queues nothing.
    let (body, is_error) = mcp.call(
        "bosun_mdm_enrollment_profile",
        json!({"device_id": "iphone-sim2", "enrollment": "enrolled_unsupervised",
               "operator_approval": approved()}),
    );
    assert!(!is_error, "profile 2: {body}");
    let session2 = body["session_token"].as_str().expect("token").to_string();
    let (status, _) = http(
        port,
        "PUT",
        &format!("/mdm/checkin?session={session2}"),
        &plist_body(&json!({"MessageType": "Authenticate", "UDID": UDID2})),
    );
    assert_eq!(status, 200);
    let (body, is_error) = mcp.call(
        "bosun_package_install",
        json!({"device_id": "iphone-sim2", "package": "123456789",
               "operator_approval": approved()}),
    );
    assert!(is_error, "unsupervised install must fail: {body}");
    assert_eq!(body["error"]["code"], "capability_not_declared");
    let (body, _) = mcp.call("bosun_mdm_queue", json!({"device_id": "iphone-sim2"}));
    assert_eq!(
        body["commands"].as_array().map(Vec::len),
        Some(0),
        "nothing queued for the unsupervised device: {body}"
    );

    std::fs::remove_dir_all(&home).ok();
}
