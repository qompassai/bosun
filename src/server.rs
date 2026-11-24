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

use crate::backend::Backends;
use crate::capability::{Capability, DeviceRecord, Enrollment, Platform};
use crate::catalog::{self, Kind};
use crate::gate::{self, Action, Approval, Decision};
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

/// The server state: the inventory plus one backend per platform.
pub struct BosunServer {
    store: Arc<Mutex<Store>>,
    backends: Arc<Backends>,
}

impl BosunServer {
    pub fn new(store: Store) -> BosunServer {
        BosunServer {
            store: Arc::new(Mutex::new(store)),
            backends: Arc::new(Backends::new()),
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
        let approval = Approval::from_args(args);
        let store = self.store.lock().await;
        let device = match str_arg(args, "device_id") {
            Some(id) => match store.get(id) {
                Some(d) => Some(d.clone()),
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
        let verdict = gate::decide(action, device.as_ref(), approval.as_ref());
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
                let store = self.store.lock().await;
                match store.get(id) {
                    Some(d) => text_result(&d.to_json(), false),
                    None => typed_error(
                        "device_not_found",
                        &format!("no device registered with id {id}"),
                    ),
                }
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
        let approval = Approval::from_args(args);
        if action == Action::RegisterDevice {
            let verdict = gate::decide(action, None, approval.as_ref());
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
        let verdict = gate::decide(action, Some(&device), approval.as_ref());
        if let Decision::Deny { code, reason } = verdict {
            return text_result(&json!({"error": {"code": code, "message": reason}}), true);
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
            Action::RegisterDevice => unreachable!("registration handled above"),
        };
        match outcome {
            Ok(v) => text_result(&v, false),
            Err(e) => text_result(&e.to_json(), true),
        }
    }

    async fn resolve(&self, args: &Value) -> Option<DeviceRecord> {
        let id = str_arg(args, "device_id")?;
        let store = self.store.lock().await;
        store.get(id).cloned()
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

    fn server_with(devices: &[DeviceRecord]) -> BosunServer {
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
        BosunServer::new(store)
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
    async fn ios_diagnostics_is_an_honest_stage1_refusal() {
        let server = server_with(&[ios_unsupervised()]);
        let result = server
            .call_tool(
                "bosun_device_diagnostics",
                &json!({"device_id": "iphone-test"}),
            )
            .await;
        assert!(result.is_error.unwrap_or(false));
        assert_eq!(result_json(&result)["error"]["code"], "stage1_not_live");
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
