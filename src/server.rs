//! The rmcp server: tool dispatch over the declared catalog.
//!
//! Dispatch contract:
//!
//! 1. `bosun_gate_check` answers the gate's verdict directly —
//!    it IS the gate, exposed so the gate is demonstrable without
//!    attempting a mutation (the meister pattern).
//! 2. Read tools resolve the device, check the declared
//!    capability, and call the platform backend. They never pass
//!    through the gate: diagnostics are read-only by construction.
//! 3. Mutation tools pass through `gate::decide` FIRST. A denial
//!    returns before the store or any backend is touched; an
//!    allow proceeds to the backend (or, for registration, the
//!    store).
//! 4. An unknown name returns `unknown tool` as an `isError`
//!    result — an execution failure, never a protocol error
//!    (Tiger Style MCP Rule 6).
//!
//! Modern era only: the era guard (see `guard`) owns the stdio
//! front door, and `supported_protocol_versions` pins this
//! handler to 2026-07-28.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    InitializeResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::apns::{self, ApnsConfig, PushRequest, PushTransportKind};
use crate::approval::{self, ApprovalKey};
use crate::backend::Backends;
use crate::capability::{Capability, DeviceRecord, Enrollment, Platform};
use crate::catalog::{self, Kind};
use crate::config::MdmConfig;
use crate::gate::{self, Action, Approval, ApprovalPolicy, Decision};
use crate::mdmstate::MdmState;
use crate::profile;
use crate::scep::LocalCa;
use crate::store::Store;

fn text_result(value: &Value, is_error: bool) -> CallToolResult {
    let content = vec![ContentBlock::text(value.to_string())];
    if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    }
}

fn typed_error(code: &str, message: &str) -> CallToolResult {
    text_result(&json!({"error": {"code": code, "message": message}}), true)
}

fn str_arg<'a>(args: &'a Value, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The Stage 1 MDM runtime the MCP process shares with the
/// `mdm-serve` process through the home directory: config, the
/// approval channel's key (when one exists), and the push
/// transport. Config and key problems are recorded, not hidden:
/// the MDM tools surface them as typed errors and the approval
/// policy fails closed.
struct MdmRuntime {
    home: std::path::PathBuf,
    config: MdmConfig,
    config_error: Option<String>,
    approval_key: Option<ApprovalKey>,
    approval_error: Option<String>,
    push: PushTransportKind,
}

impl MdmRuntime {
    fn new(home: std::path::PathBuf) -> MdmRuntime {
        let (config, config_error) = match MdmConfig::from_env(&home) {
            Ok(c) => (c, None),
            Err(e) => (
                MdmConfig::for_test(&home, "127.0.0.1:8443".parse().expect("static addr")),
                Some(format!("{}: {}", e.code, e.message)),
            ),
        };
        let (approval_key, approval_error) = match ApprovalKey::load(&config.approval_key_file) {
            Ok(k) => (k, None),
            Err(e) => (None, Some(format!("{}: {}", e.code, e.message))),
        };
        let push = apns::transport_from_env(&home);
        MdmRuntime {
            home,
            config,
            config_error,
            approval_key,
            approval_error,
            push,
        }
    }

    /// The gate policy for this deployment: verified approvals
    /// are required whenever a key exists — and also when a key
    /// file exists but failed to load, so a broken key file
    /// fails closed instead of silently reopening the presented
    /// channel.
    fn policy(&self) -> ApprovalPolicy {
        if self.approval_key.is_some() || self.approval_error.is_some() {
            ApprovalPolicy::RequireVerified
        } else {
            ApprovalPolicy::PresentedAccepted
        }
    }

    /// Run the approval channel's check: if this deployment
    /// holds a key and the approval carries a token, verify the
    /// token against (action, device, approver, now) and mark
    /// the approval. Anything else leaves it unverified.
    fn verify(&self, action: Action, device_id: Option<&str>, approval: &mut Approval) {
        approval.verified = false;
        let (Some(key), Some(proof)) = (&self.approval_key, &approval.proof) else {
            return;
        };
        if approval::verify(
            key,
            proof,
            action.as_str(),
            device_id,
            &approval.approved_by,
            now_unix(),
        ) {
            approval.verified = true;
        }
    }
}

/// The server state: the inventory plus one backend per platform.
pub struct BosunServer {
    store: Arc<Mutex<Store>>,
    backends: Arc<Backends>,
    mdm: MdmRuntime,
}

impl BosunServer {
    pub fn new(store: Store) -> BosunServer {
        let home = store.home_dir();
        BosunServer {
            store: Arc::new(Mutex::new(store)),
            backends: Arc::new(Backends::new(home.clone())),
            mdm: MdmRuntime::new(home),
        }
    }

    async fn call_tool(&self, name: &str, args: &Value) -> CallToolResult {
        let Some(spec) = catalog::spec_named(name) else {
            return text_result(&json!({"error": "unknown tool"}), true);
        };
        match spec.kind {
            Kind::GateCheck => self.gate_check(args).await,
            Kind::Read => self.read_tool(name, args).await,
            Kind::Mutation(action) => self.mutation(action, args).await,
        }
    }

    async fn gate_check(&self, args: &Value) -> CallToolResult {
        let Some(action_name) = str_arg(args, "action") else {
            return typed_error("invalid_argument", "gate_check requires an `action` string");
        };
        let Some(action) = Action::parse(action_name) else {
            return typed_error("invalid_action", &format!("unknown action {action_name:?}"));
        };
        let mut approval = Approval::from_args(args);
        let store = self.store.lock().await;
        let device = match str_arg(args, "device_id") {
            Some(id) => match store.get(id) {
                Some(d) => {
                    let mut d = d.clone();
                    self.overlay_enrollment(&mut d);
                    Some(d)
                }
                None => {
                    return text_result(
                        &json!({
                            "action": action.as_str(),
                            "decision": "deny",
                            "code": "device_not_found",
                            "reason": format!("no device registered with id {id}"),
                        }),
                        false,
                    );
                }
            },
            None => None,
        };
        drop(store);
        if let Some(a) = &mut approval {
            self.mdm
                .verify(action, device.as_ref().map(|d| d.id.as_str()), a);
        }
        let verdict = gate::decide_with_policy(
            action,
            device.as_ref(),
            approval.as_ref(),
            self.mdm.policy(),
        );
        text_result(&verdict.to_json(action, approval.as_ref()), false)
    }

    async fn read_tool(&self, name: &str, args: &Value) -> CallToolResult {
        match name {
            "bosun_device_list" => {
                let limit =
                    args.get("limit")
                        .and_then(Value::as_u64)
                        .unwrap_or(50)
                        .clamp(1, crate::store::MAX_DEVICES as u64) as usize;
                let store = self.store.lock().await;
                let all = store.list();
                let page: Vec<Value> = all.iter().take(limit).map(DeviceRecord::to_json).collect();
                text_result(
                    &json!({"total": all.len(), "returned": page.len(), "devices": page}),
                    false,
                )
            }
            "bosun_device_get" => {
                let Some(id) = str_arg(args, "device_id") else {
                    return typed_error("invalid_argument", "device_get requires `device_id`");
                };
                match self.resolve(args).await {
                    Some(d) => text_result(&d.to_json(), false),
                    None => typed_error(
                        "device_not_found",
                        &format!("no device registered with id {id}"),
                    ),
                }
            }
            "bosun_mdm_queue" => {
                let state = match MdmState::load(&self.mdm.home) {
                    Ok(s) => s,
                    Err(e) => return typed_error(e.code, &e.message),
                };
                // An optional device filter resolves to the
                // device's UDID through the inventory.
                let udid_filter = match str_arg(args, "device_id") {
                    Some(id) => {
                        let store = self.store.lock().await;
                        match store.get(id) {
                            Some(d) => Some(d.transport.clone()),
                            None => {
                                return typed_error(
                                    "device_not_found",
                                    &format!("no device registered with id {id}"),
                                );
                            }
                        }
                    }
                    None => None,
                };
                let devices: Vec<Value> = state
                    .devices()
                    .iter()
                    .filter(|d| udid_filter.as_deref().is_none_or(|u| u == d.udid))
                    .map(|d| d.to_json())
                    .collect();
                let commands: Vec<Value> = state
                    .all_commands()
                    .iter()
                    .filter(|c| udid_filter.as_deref().is_none_or(|u| u == c.device_udid))
                    .map(|c| c.to_json())
                    .collect();
                text_result(&json!({"devices": devices, "commands": commands}), false)
            }
            "bosun_device_diagnostics" | "bosun_package_list" => {
                let capability = if name == "bosun_device_diagnostics" {
                    Capability::Diagnostics
                } else {
                    Capability::PackageList
                };
                let Some(device) = self.resolve(args).await else {
                    return typed_error(
                        "device_not_found",
                        "no device registered with the given device_id",
                    );
                };
                if !device.has(capability) {
                    return typed_error(
                        "capability_not_declared",
                        &format!(
                            "device {} ({}) does not declare capability {}",
                            device.id,
                            device.platform.as_str(),
                            capability.as_str()
                        ),
                    );
                }
                let outcome = if name == "bosun_device_diagnostics" {
                    self.backends.diagnostics(&device).await
                } else {
                    self.backends.package_list(&device).await
                };
                match outcome {
                    Ok(v) => text_result(&v, false),
                    Err(e) => text_result(&e.to_json(), true),
                }
            }
            _ => text_result(&json!({"error": "unknown tool"}), true),
        }
    }

    async fn mutation(&self, action: Action, args: &Value) -> CallToolResult {
        let mut approval = Approval::from_args(args);
        if action == Action::RegisterDevice {
            if let Some(a) = &mut approval {
                self.mdm.verify(action, str_arg(args, "id"), a);
            }
            let verdict =
                gate::decide_with_policy(action, None, approval.as_ref(), self.mdm.policy());
            if let Decision::Deny { code, reason } = verdict {
                return text_result(&json!({"error": {"code": code, "message": reason}}), true);
            }
            return self.register(args).await;
        }
        let Some(device) = self.resolve(args).await else {
            return typed_error(
                "device_not_found",
                "no device registered with the given device_id",
            );
        };
        if let Some(a) = &mut approval {
            self.mdm.verify(action, Some(&device.id), a);
        }
        let verdict =
            gate::decide_with_policy(action, Some(&device), approval.as_ref(), self.mdm.policy());
        if let Decision::Deny { code, reason } = verdict {
            return text_result(&json!({"error": {"code": code, "message": reason}}), true);
        }
        if action == Action::EnrollDevice {
            return self.enroll_device(&device, args).await;
        }
        if action == Action::PushWake {
            return self.send_push(&device).await;
        }
        let outcome = match action {
            Action::PackageInstall => {
                let Some(package) = str_arg(args, "package").filter(|p| !p.trim().is_empty())
                else {
                    return typed_error(
                        "invalid_argument",
                        "package_install requires a non-empty `package`",
                    );
                };
                self.backends.package_install(&device, package).await
            }
            Action::PackageUpdate => {
                let package = str_arg(args, "package").filter(|p| !p.trim().is_empty());
                self.backends.package_update(&device, package).await
            }
            Action::Reboot => self.backends.reboot(&device).await,
            Action::RegisterDevice | Action::EnrollDevice | Action::PushWake => {
                unreachable!("handled above")
            }
        };
        match outcome {
            Ok(v) => text_result(&v, false),
            Err(e) => text_result(&e.to_json(), true),
        }
    }

    /// Generate an enrollment profile for an inventoried iOS
    /// device and open its one-shot session. The gate has
    /// already allowed the call.
    async fn enroll_device(&self, device: &DeviceRecord, args: &Value) -> CallToolResult {
        if device.platform != Platform::Ios {
            return typed_error(
                "invalid_argument",
                "enrollment profiles are an iOS MDM artifact",
            );
        }
        let enrollment = match str_arg(args, "enrollment") {
            Some("enrolled_unsupervised") => Enrollment::EnrolledUnsupervised,
            Some("enrolled_supervised") => Enrollment::EnrolledSupervised,
            _ => {
                return typed_error(
                    "invalid_argument",
                    "enrollment must be enrolled_unsupervised or enrolled_supervised",
                );
            }
        };
        if let Some(err) = &self.mdm.config_error {
            return typed_error("mdm_config_invalid", err);
        }
        let token = match crate::mdmstate::random_token() {
            Ok(t) => t,
            Err(e) => {
                return typed_error(
                    "rng_unavailable",
                    &format!("cannot mint an enrollment session token: {e}"),
                );
            }
        };
        let mut state = match MdmState::load(&self.mdm.home) {
            Ok(s) => s,
            Err(e) => return typed_error(e.code, &e.message),
        };
        if let Err(e) = state.create_session(token.clone(), &device.id, enrollment, now_unix()) {
            return typed_error(e.code, &e.message);
        }
        if let Err(e) = state.save() {
            return typed_error(e.code, &e.message);
        }
        let ca = LocalCa::new(&self.mdm.home);
        let fingerprint = if ca.is_initialized() {
            ca.ca_fingerprint_sha1().ok()
        } else {
            None
        };
        let text = match profile::render_profile(
            &self.mdm.config,
            &token,
            enrollment,
            fingerprint.as_deref(),
        ) {
            Ok(t) => t,
            Err(e) => return typed_error(e.code, &e.message),
        };
        let dir = self.mdm.home.join("profiles");
        let path = dir.join(format!("{token}.mobileconfig"));
        let written = std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(&path, &text))
            .map(|()| path.display().to_string());
        text_result(
            &json!({
                "device_id": device.id,
                "enrollment": enrollment.as_str(),
                "session_token": token,
                "profile_path": written.ok(),
                "download_url": self.mdm.config.enroll_url(&token),
                "checkin_url": self.mdm.config.checkin_url(&token),
                "topic": self.mdm.config.profile_topic(),
                "profile": text,
                "note": "install the profile on the device (or serve the download URL); its first Authenticate spends the session and binds the device at the declared enrollment",
            }),
            false,
        )
    }

    /// Send one APNs wake-up to an enrolled iOS device. The gate
    /// has already allowed the call.
    async fn send_push(&self, device: &DeviceRecord) -> CallToolResult {
        if device.platform != Platform::Ios {
            return typed_error("invalid_argument", "APNs push applies to iOS devices only");
        }
        let state = match MdmState::load(&self.mdm.home) {
            Ok(s) => s,
            Err(e) => return typed_error(e.code, &e.message),
        };
        let Some(mdm_device) = state.device(&device.transport) else {
            return typed_error(
                "push_not_ready",
                "the device has not checked in, so no push credentials are stored for it",
            );
        };
        if !mdm_device.push_ready() {
            return typed_error(
                "push_not_ready",
                "the device has not stored a push token and magic (TokenUpdate), or it has checked out",
            );
        }
        let Some(apns_config) = ApnsConfig::from_config(&self.mdm.config) else {
            return typed_error(
                "push_not_configured",
                "BOSUN_MDM_PUSH_CERT and BOSUN_MDM_PUSH_KEY are not configured on this server",
            );
        };
        let request = PushRequest {
            device_token_hex: mdm_device.push_token_hex.clone().unwrap_or_default(),
            push_magic: mdm_device.push_magic.clone().unwrap_or_default(),
        };
        match apns::push_wake(&self.mdm.push, &apns_config, &request).await {
            Ok(outcome) if outcome.status == 200 => text_result(
                &json!({
                    "device_id": device.id,
                    "pushed": true,
                    "apns_id": outcome.apns_id,
                    "note": "APNs accepted the wake-up; the device checks in on its own schedule and picks up queued commands",
                }),
                false,
            ),
            Ok(outcome) => typed_error(
                "apns_rejected",
                &format!(
                    "APNs answered status {} ({})",
                    outcome.status,
                    outcome.reason.as_deref().unwrap_or("no reason given")
                ),
            ),
            Err(e) => typed_error(e.code, &e.message),
        }
    }

    async fn resolve(&self, args: &Value) -> Option<DeviceRecord> {
        let id = str_arg(args, "device_id")?;
        let store = self.store.lock().await;
        let mut record = store.get(id).cloned()?;
        self.overlay_enrollment(&mut record);
        Some(record)
    }

    /// The MDM state is authoritative for an iOS device's
    /// enrollment once it has checked in: the inventory keeps
    /// the enrollment the operator *registered*, the state holds
    /// the one the device *enacted*. The overlay applies only
    /// when the state's binding names this record and the device
    /// has not checked out.
    fn overlay_enrollment(&self, record: &mut DeviceRecord) {
        if record.platform != Platform::Ios {
            return;
        }
        if let Ok(state) = MdmState::load(&self.mdm.home)
            && let Some(d) = state.device(&record.transport)
            && d.inventory_id.as_deref() == Some(record.id.as_str())
            && !d.checked_out
        {
            record.enrollment = d.enrollment;
        }
    }

    async fn register(&self, args: &Value) -> CallToolResult {
        let (Some(id), Some(label), Some(platform_raw), Some(transport)) = (
            str_arg(args, "id"),
            str_arg(args, "label"),
            str_arg(args, "platform"),
            str_arg(args, "transport"),
        ) else {
            return typed_error(
                "invalid_argument",
                "register requires id, label, platform, and transport",
            );
        };
        if id.is_empty()
            || id.len() > 64
            || !id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return typed_error(
                "invalid_argument",
                "device id must be 1-64 chars of [a-z0-9-]",
            );
        }
        if label.is_empty() || label.len() > 128 {
            return typed_error("invalid_argument", "label must be 1-128 chars");
        }
        if transport.is_empty() || transport.len() > 256 {
            return typed_error("invalid_argument", "transport must be 1-256 chars");
        }
        let Some(platform) = Platform::parse(platform_raw) else {
            return typed_error(
                "invalid_argument",
                &format!("unknown platform {platform_raw:?}"),
            );
        };
        let enrollment_raw = str_arg(args, "enrollment");
        let enrollment = match (platform, enrollment_raw) {
            (Platform::Ios, Some(raw)) => match Enrollment::parse(raw) {
                Some(e) if e != Enrollment::NotApplicable => e,
                _ => {
                    return typed_error(
                        "invalid_argument",
                        "iOS enrollment must be unenrolled, enrolled_unsupervised, or enrolled_supervised",
                    );
                }
            },
            (Platform::Ios, None) => Enrollment::Unenrolled,
            (_, Some(raw)) if raw != "not_applicable" => {
                return typed_error(
                    "invalid_argument",
                    "enrollment applies to iOS only; omit it for android/windows",
                );
            }
            _ => Enrollment::NotApplicable,
        };
        let record = DeviceRecord {
            id: id.to_string(),
            label: label.to_string(),
            platform,
            transport: transport.to_string(),
            enrollment,
        };
        let mut store = self.store.lock().await;
        match store.register(record.clone()) {
            Ok(()) => text_result(&record.to_json(), false),
            Err(e) => typed_error(e.code, &e.message),
        }
    }
}

impl ServerHandler for BosunServer {
    fn get_info(&self) -> InitializeResult {
        let mut server_info = Implementation::default();
        server_info.name = "bosun".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        let mut info = InitializeResult::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = server_info;
        info
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: catalog::tool_definitions(),
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        Ok(self.call_tool(&name, &arguments).await.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_dir(devices: &[DeviceRecord]) -> (std::path::PathBuf, Store) {
        // Unique directory per call: tests in one process run in
        // parallel threads and must not share a store path.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("bosun-server-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::load(dir.join("inventory.json")).expect("fresh store");
        for d in devices {
            store.register(d.clone()).expect("register fixture");
        }
        (dir, store)
    }

    fn server_with(devices: &[DeviceRecord]) -> BosunServer {
        BosunServer::new(server_dir(devices).1)
    }

    fn server_with_home(devices: &[DeviceRecord]) -> (BosunServer, std::path::PathBuf) {
        let (dir, store) = server_dir(devices);
        (BosunServer::new(store), dir)
    }

    fn result_json(result: &CallToolResult) -> Value {
        let ContentBlock::Text(text) = &result.content[0] else {
            panic!("expected text content");
        };
        serde_json::from_str(&text.text).expect("result text is JSON")
    }

    fn android() -> DeviceRecord {
        DeviceRecord {
            id: "pixel-test".into(),
            label: "Test Android".into(),
            platform: Platform::Android,
            transport: "192.0.2.1:5555".into(),
            enrollment: Enrollment::NotApplicable,
        }
    }

    fn ios_unsupervised() -> DeviceRecord {
        DeviceRecord {
            id: "iphone-test".into(),
            label: "Test iPhone".into(),
            platform: Platform::Ios,
            transport: "00008030-TESTUDID".into(),
            enrollment: Enrollment::EnrolledUnsupervised,
        }
    }

    #[tokio::test]
    async fn unknown_tool_is_an_error_result() {
        let server = server_with(&[]);
        let result = server.call_tool("bosun_nope", &json!({})).await;
        assert!(result.is_error.unwrap_or(false));
        assert_eq!(result_json(&result)["error"], "unknown tool");
    }

    #[tokio::test]
    async fn gate_check_reports_the_verdict_without_acting() {
        let server = server_with(&[android()]);
        let denied = server
            .call_tool(
                "bosun_gate_check",
                &json!({"action": "package_install", "device_id": "pixel-test"}),
            )
            .await;
        assert!(!denied.is_error.unwrap_or(false));
        assert_eq!(result_json(&denied)["code"], "operator_approval_required");
        let allowed = server
            .call_tool(
                "bosun_gate_check",
                &json!({"action": "package_install", "device_id": "pixel-test",
                        "operator_approval": {"approved_by": "op"}}),
            )
            .await;
        assert_eq!(result_json(&allowed)["decision"], "allow");
    }

    #[tokio::test]
    async fn mutation_without_approval_never_reaches_a_backend() {
        // If the gate leaked, this call would attempt an adb
        // connection to a TEST-NET address and take seconds or
        // fail with a transport code; the gate denial is instant
        // and typed.
        let server = server_with(&[android()]);
        let result = server
            .call_tool(
                "bosun_package_install",
                &json!({"device_id": "pixel-test", "package": "x.apk"}),
            )
            .await;
        assert!(result.is_error.unwrap_or(false));
        assert_eq!(
            result_json(&result)["error"]["code"],
            "operator_approval_required"
        );
    }

    #[tokio::test]
    async fn approved_install_on_unsupervised_ios_is_capability_denied() {
        let server = server_with(&[ios_unsupervised()]);
        let result = server
            .call_tool(
                "bosun_package_install",
                &json!({"device_id": "iphone-test", "package": "12345",
                        "operator_approval": {"approved_by": "op"}}),
            )
            .await;
        assert_eq!(
            result_json(&result)["error"]["code"],
            "capability_not_declared"
        );
    }

    #[tokio::test]
    async fn ios_diagnostics_queues_device_information() {
        // Stage 1: an iOS diagnostics call queues DeviceInformation
        // against the UDID and says so; the answer arrives at the
        // device's next check-in.
        let server = server_with(&[ios_unsupervised()]);
        let result = server
            .call_tool(
                "bosun_device_diagnostics",
                &json!({"device_id": "iphone-test"}),
            )
            .await;
        assert!(!result.is_error.unwrap_or(false));
        let body = result_json(&result);
        assert_eq!(body["delivery"], "queued");
        assert!(
            body["command_uuid"]
                .as_str()
                .is_some_and(|u| u.starts_with("bosun-cmd-"))
        );
        // And the record is readable through the queue tool.
        let queue = server
            .call_tool("bosun_mdm_queue", &json!({"device_id": "iphone-test"}))
            .await;
        let queue = result_json(&queue);
        assert_eq!(queue["commands"].as_array().map(Vec::len), Some(1));
        assert_eq!(queue["commands"][0]["request_type"], "DeviceInformation");
        assert_eq!(queue["commands"][0]["state"], "queued");
    }

    #[tokio::test]
    async fn enrollment_profile_opens_a_one_shot_session() {
        let (server, home) = server_with_home(&[ios_unsupervised()]);
        // Without approval the gate refuses before any session.
        let denied = server
            .call_tool(
                "bosun_mdm_enrollment_profile",
                &json!({"device_id": "iphone-test", "enrollment": "enrolled_supervised"}),
            )
            .await;
        assert_eq!(
            result_json(&denied)["error"]["code"],
            "operator_approval_required"
        );
        let ok = server
            .call_tool(
                "bosun_mdm_enrollment_profile",
                &json!({"device_id": "iphone-test", "enrollment": "enrolled_supervised",
                        "operator_approval": {"approved_by": "op"}}),
            )
            .await;
        assert!(!ok.is_error.unwrap_or(false));
        let body = result_json(&ok);
        let token = body["session_token"]
            .as_str()
            .expect("session token")
            .to_string();
        assert!(
            body["profile"]
                .as_str()
                .expect("profile text")
                .contains("com.apple.mdm")
        );
        // The session is live in the MDM state, bound to the device.
        let state = MdmState::load(&home).expect("state");
        let session = state.session(&token).expect("session stored");
        assert_eq!(session.device_id, "iphone-test");
        assert_eq!(session.enrollment, Enrollment::EnrolledSupervised);
    }

    #[tokio::test]
    async fn verified_channel_denies_presented_and_allows_token() {
        // A home with an approval key: the Stage 0 presented
        // approval no longer suffices; a channel token does. The
        // key must exist before the server is constructed (the
        // runtime loads it at startup).
        let (home, store) = server_dir(&[android()]);
        ApprovalKey::create(&home.join("approval.key")).expect("create key");
        let server = BosunServer::new(store);
        let key = ApprovalKey::load(&home.join("approval.key"))
            .expect("load")
            .expect("key exists");
        let now = now_unix();
        let token =
            crate::approval::mint(&key, "package_install", Some("pixel-test"), "op", now + 300);
        let presented = server
            .call_tool(
                "bosun_gate_check",
                &json!({"action": "package_install", "device_id": "pixel-test",
                        "operator_approval": {"approved_by": "op"}}),
            )
            .await;
        assert_eq!(result_json(&presented)["code"], "approval_not_verified");
        let verified = server
            .call_tool(
                "bosun_gate_check",
                &json!({"action": "package_install", "device_id": "pixel-test",
                        "operator_approval": {"approved_by": "op", "token": token}}),
            )
            .await;
        let body = result_json(&verified);
        assert_eq!(body["decision"], "allow");
        assert_eq!(body["approval_verified"], true);
        // Adversarial: the same token presented by another name
        // does not verify.
        let replayed = server
            .call_tool(
                "bosun_gate_check",
                &json!({"action": "package_install", "device_id": "pixel-test",
                        "operator_approval": {"approved_by": "eve", "token": token}}),
            )
            .await;
        assert_eq!(result_json(&replayed)["code"], "approval_not_verified");
    }

    #[tokio::test]
    async fn device_list_counts_from_the_store() {
        let server = server_with(&[android(), ios_unsupervised()]);
        let result = server.call_tool("bosun_device_list", &json!({})).await;
        let body = result_json(&result);
        assert_eq!(body["total"], 2);
        assert_eq!(body["returned"], 2);
        let capped = server
            .call_tool("bosun_device_list", &json!({"limit": 1}))
            .await;
        assert_eq!(result_json(&capped)["returned"], 1);
    }

    #[tokio::test]
    async fn registration_validates_the_enrollment_model() {
        let server = server_with(&[]);
        // Android with an iOS enrollment state: refused.
        let bad = server
            .call_tool(
                "bosun_device_register",
                &json!({"id": "d1", "label": "D1", "platform": "android", "transport": "x",
                        "enrollment": "enrolled_supervised",
                        "operator_approval": {"approved_by": "op"}}),
            )
            .await;
        assert_eq!(result_json(&bad)["error"]["code"], "invalid_argument");
        // iOS without approval: the gate refuses before validation.
        let gated = server
            .call_tool(
                "bosun_device_register",
                &json!({"id": "d2", "label": "D2", "platform": "ios", "transport": "udid"}),
            )
            .await;
        assert_eq!(
            result_json(&gated)["error"]["code"],
            "operator_approval_required"
        );
        // iOS with approval: registers as unenrolled by default.
        let ok = server
            .call_tool(
                "bosun_device_register",
                &json!({"id": "d2", "label": "D2", "platform": "ios", "transport": "udid",
                        "operator_approval": {"approved_by": "op"}}),
            )
            .await;
        assert!(!ok.is_error.unwrap_or(false));
        assert_eq!(result_json(&ok)["enrollment"], "unenrolled");
    }
}
