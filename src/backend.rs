//! Platform backends behind one trait. The trait is the contract;
//! the Stage 0 truth of each implementation is stated in its doc
//! comment and in STAGE0.md:
//!
//! - Android: REAL command paths over `adb` (present on the host).
//!   Implemented and unit-shaped, but not yet exercised against a
//!   live device — no device is registered at Stage 0 and this
//!   stage performs no device contact.
//! - Windows: REAL command paths over `ssh` + `winget`. Same
//!   exercise status as Android.
//! - iOS: the MDM queue seam. Commands enqueue and are reported
//!   as queued; delivery (check-in endpoint + APNs) is Stage 1,
//!   so every iOS operation that would touch a device answers
//!   with the typed `stage1_not_live` error rather than a
//!   fabricated success.
//!
//! Every external command runs under a hard timeout and a hard
//! output bound. A backend failure is an execution error value,
//! never a panic and never a protocol error.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::timeout;

use crate::capability::{DeviceRecord, Platform};
use crate::mdm::{CommandQueue, MdmCommandKind};

/// Bound on one backend command's wall clock.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// Bound on captured command output (bytes per stream).
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct BackendError {
    pub code: &'static str,
    pub message: String,
}

impl BackendError {
    fn new(code: &'static str, message: String) -> BackendError {
        BackendError { code, message }
    }

    pub fn to_json(&self) -> Value {
        json!({"error": {"code": self.code, "message": self.message}})
    }
}

pub type BackendResult = Result<Value, BackendError>;

/// Run one external command under the stage bounds and shape its
/// output as JSON. `program` is a fixed binary name chosen by the
/// backend (never caller input); `args` may carry device data
/// (transports, package ids) and are passed as argv, never through
/// a shell.
async fn run_bounded(program: &str, args: &[String]) -> BackendResult {
    let fut = tokio::process::Command::new(program).args(args).output();
    let output = match timeout(COMMAND_TIMEOUT, fut).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            return Err(BackendError::new(
                "transport_unavailable",
                format!("cannot run {program}: {e}"),
            ));
        }
        Err(_) => {
            return Err(BackendError::new(
                "transport_timeout",
                format!(
                    "{program} exceeded the {}s bound",
                    COMMAND_TIMEOUT.as_secs()
                ),
            ));
        }
    };
    let stdout = truncate(&output.stdout);
    let stderr = truncate(&output.stderr);
    if output.status.success() {
        Ok(json!({"program": program, "stdout": stdout, "stderr": stderr}))
    } else {
        Err(BackendError::new(
            "backend_command_failed",
            format!("{program} exited with {}: {stderr}", output.status),
        ))
    }
}

fn truncate(bytes: &[u8]) -> String {
    let slice = &bytes[..bytes.len().min(MAX_OUTPUT_BYTES)];
    String::from_utf8_lossy(slice).into_owned()
}

/// The backend contract. Methods take the full device record so a
/// backend never re-derives platform facts from a bare id.
pub trait Backend: Send + Sync {
    fn diagnostics(&self, device: &DeviceRecord) -> impl Future<Output = BackendResult> + Send;
    fn package_list(&self, device: &DeviceRecord) -> impl Future<Output = BackendResult> + Send;
    fn package_install(
        &self,
        device: &DeviceRecord,
        package: &str,
    ) -> impl Future<Output = BackendResult> + Send;
    fn package_update(
        &self,
        device: &DeviceRecord,
        package: Option<&str>,
    ) -> impl Future<Output = BackendResult> + Send;
    fn reboot(&self, device: &DeviceRecord) -> impl Future<Output = BackendResult> + Send;
}

/// Android over ADB. The transport is an ADB target: a serial for
/// USB or `host:port` for ADB-over-network (the tailnet path).
pub struct AndroidBackend;

impl Backend for AndroidBackend {
    async fn diagnostics(&self, device: &DeviceRecord) -> BackendResult {
        // A bounded bundle: battery, storage, and build facts —
        // the three questions provisioning asks first.
        let mut bundle = serde_json::Map::new();
        for (key, args) in [
            ("battery", vec!["shell", "dumpsys", "battery"]),
            ("storage", vec!["shell", "df", "/data"]),
            ("build", vec!["shell", "getprop", "ro.build.fingerprint"]),
        ] {
            let mut argv: Vec<String> = vec!["-s".into(), device.transport.clone()];
            argv.extend(args.iter().map(|s| s.to_string()));
            match run_bounded("adb", &argv).await {
                Ok(v) => {
                    bundle.insert(key.to_string(), v);
                }
                Err(e) => {
                    bundle.insert(key.to_string(), e.to_json());
                }
            }
        }
        Ok(json!({"device": device.id, "platform": "android", "diagnostics": bundle}))
    }

    async fn package_list(&self, device: &DeviceRecord) -> BackendResult {
        let argv = vec![
            "-s".into(),
            device.transport.clone(),
            "shell".into(),
            "pm".into(),
            "list".into(),
            "packages".into(),
        ];
        let out = run_bounded("adb", &argv).await?;
        let stdout = out["stdout"].as_str().unwrap_or_default();
        let packages: Vec<&str> = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("package:"))
            .collect();
        Ok(json!({"device": device.id, "count": packages.len(), "packages": packages}))
    }

    async fn package_install(&self, device: &DeviceRecord, package: &str) -> BackendResult {
        // `package` is an APK path on the server host at Stage 0;
        // store-id installs arrive with the Stage 1 package
        // catalogue. `-r` makes a repeat install an update.
        let argv = vec![
            "-s".into(),
            device.transport.clone(),
            "install".into(),
            "-r".into(),
            package.to_string(),
        ];
        run_bounded("adb", &argv).await
    }

    async fn package_update(&self, device: &DeviceRecord, package: Option<&str>) -> BackendResult {
        let Some(package) = package else {
            return Err(BackendError::new(
                "package_required",
                "android updates name one package (an APK path) at Stage 0; fleet-wide update is a Stage 1 catalogue operation".to_string(),
            ));
        };
        self.package_install(device, package).await
    }

    async fn reboot(&self, device: &DeviceRecord) -> BackendResult {
        let argv = vec!["-s".into(), device.transport.clone(), "reboot".into()];
        run_bounded("adb", &argv).await
    }
}

/// Windows over SSH + winget. The transport is an SSH target
/// (`user@host`); the remote shell is PowerShell-free by design —
/// winget is invoked directly so output stays parseable.
pub struct WindowsBackend;

impl WindowsBackend {
    fn ssh_argv(device: &DeviceRecord, remote: &[&str]) -> Vec<String> {
        let mut argv = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            format!("ConnectTimeout={}", COMMAND_TIMEOUT.as_secs()),
            device.transport.clone(),
        ];
        argv.extend(remote.iter().map(|s| s.to_string()));
        argv
    }
}

impl Backend for WindowsBackend {
    async fn diagnostics(&self, device: &DeviceRecord) -> BackendResult {
        // CIM via a fixed PowerShell one-liner: computer name, OS
        // caption/build, and free space on the system drive.
        let script = "Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Caption,Version,FreePhysicalMemory | ConvertTo-Json -Compress";
        let argv = Self::ssh_argv(device, &["powershell", "-NoProfile", "-Command", script]);
        run_bounded("ssh", &argv).await
    }

    async fn package_list(&self, device: &DeviceRecord) -> BackendResult {
        let argv = Self::ssh_argv(device, &["winget", "list", "--accept-source-agreements"]);
        run_bounded("ssh", &argv).await
    }

    async fn package_install(&self, device: &DeviceRecord, package: &str) -> BackendResult {
        let argv = Self::ssh_argv(
            device,
            &[
                "winget",
                "install",
                "--id",
                package,
                "--exact",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ],
        );
        run_bounded("ssh", &argv).await
    }

    async fn package_update(&self, device: &DeviceRecord, package: Option<&str>) -> BackendResult {
        let argv = match package {
            Some(id) => Self::ssh_argv(
                device,
                &[
                    "winget",
                    "upgrade",
                    "--id",
                    id,
                    "--exact",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ],
            ),
            None => Self::ssh_argv(
                device,
                &[
                    "winget",
                    "upgrade",
                    "--all",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ],
            ),
        };
        run_bounded("ssh", &argv).await
    }

    async fn reboot(&self, device: &DeviceRecord) -> BackendResult {
        let argv = Self::ssh_argv(device, &["shutdown", "/r", "/t", "0"]);
        run_bounded("ssh", &argv).await
    }
}

/// iOS over the MDM queue. Stage 0: commands enqueue against the
/// device UDID and the result says exactly that — `queued`, with
/// the command UUID — for operations the queue can carry, and the
/// typed Stage 1 error where even queueing would be a lie
/// (nothing delivers yet, so a "queued" diagnostics request would
/// never answer; reads therefore refuse honestly instead).
pub struct IosMdmBackend {
    pub queue: std::sync::Mutex<CommandQueue>,
}

impl IosMdmBackend {
    pub fn new() -> IosMdmBackend {
        IosMdmBackend {
            queue: std::sync::Mutex::new(CommandQueue::new()),
        }
    }

    fn stage1_error(what: &str) -> BackendError {
        BackendError::new(
            "stage1_not_live",
            format!(
                "{what} requires the MDM check-in endpoint and APNs push, which land in Stage 1 (see STAGE0.md)"
            ),
        )
    }

    fn enqueue(&self, device: &DeviceRecord, kind: MdmCommandKind) -> BackendResult {
        let mut queue = self.queue.lock().map_err(|_| {
            BackendError::new(
                "queue_unavailable",
                "MDM command queue lock is poisoned".to_string(),
            )
        })?;
        match queue.enqueue(&device.transport, kind) {
            Some(uuid) => Ok(json!({
                "device": device.id,
                "delivery": "queued",
                "command_uuid": uuid,
                "note": "queued only: no check-in endpoint exists until Stage 1, so the device has not received this command",
            })),
            None => Err(BackendError::new(
                "queue_full",
                format!(
                    "MDM command queue is at its bound of {}",
                    crate::mdm::MAX_QUEUED_COMMANDS
                ),
            )),
        }
    }
}

impl Default for IosMdmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for IosMdmBackend {
    async fn diagnostics(&self, _device: &DeviceRecord) -> BackendResult {
        Err(Self::stage1_error("iOS diagnostics (DeviceInformation)"))
    }

    async fn package_list(&self, _device: &DeviceRecord) -> BackendResult {
        Err(Self::stage1_error("iOS installed-application query"))
    }

    async fn package_install(&self, device: &DeviceRecord, package: &str) -> BackendResult {
        self.enqueue(
            device,
            MdmCommandKind::InstallApplication {
                identifier: package.to_string(),
            },
        )
    }

    async fn package_update(&self, device: &DeviceRecord, package: Option<&str>) -> BackendResult {
        // MDM has no "update this app" verb distinct from install:
        // InstallApplication on a managed app updates it in place.
        let Some(package) = package else {
            return Err(BackendError::new(
                "package_required",
                "iOS updates name one managed application identifier; there is no MDM upgrade-all verb".to_string(),
            ));
        };
        self.enqueue(
            device,
            MdmCommandKind::InstallApplication {
                identifier: package.to_string(),
            },
        )
    }

    async fn reboot(&self, _device: &DeviceRecord) -> BackendResult {
        // The capability model does not declare Reboot for iOS at
        // Stage 0, so the gate refuses before this is reached; the
        // arm exists to keep the trait total.
        Err(Self::stage1_error("iOS restart (RestartDevice)"))
    }
}

/// Select the backend for a platform. One instance per platform,
/// held by the server for its lifetime.
pub struct Backends {
    pub android: AndroidBackend,
    pub windows: WindowsBackend,
    pub ios: IosMdmBackend,
}

impl Backends {
    pub fn new() -> Backends {
        Backends {
            android: AndroidBackend,
            windows: WindowsBackend,
            ios: IosMdmBackend::new(),
        }
    }

    // Dispatch by platform to the concrete backend. (The trait's
    // `impl Future` methods are not dyn-compatible, and with three
    // fixed backends a match is the honest shape anyway.)
    pub async fn diagnostics(&self, device: &DeviceRecord) -> BackendResult {
        match device.platform {
            Platform::Android => self.android.diagnostics(device).await,
            Platform::Windows => self.windows.diagnostics(device).await,
            Platform::Ios => self.ios.diagnostics(device).await,
        }
    }

    pub async fn package_list(&self, device: &DeviceRecord) -> BackendResult {
        match device.platform {
            Platform::Android => self.android.package_list(device).await,
            Platform::Windows => self.windows.package_list(device).await,
            Platform::Ios => self.ios.package_list(device).await,
        }
    }

    pub async fn package_install(&self, device: &DeviceRecord, package: &str) -> BackendResult {
        match device.platform {
            Platform::Android => self.android.package_install(device, package).await,
            Platform::Windows => self.windows.package_install(device, package).await,
            Platform::Ios => self.ios.package_install(device, package).await,
        }
    }

    pub async fn package_update(
        &self,
        device: &DeviceRecord,
        package: Option<&str>,
    ) -> BackendResult {
        match device.platform {
            Platform::Android => self.android.package_update(device, package).await,
            Platform::Windows => self.windows.package_update(device, package).await,
            Platform::Ios => self.ios.package_update(device, package).await,
        }
    }

    pub async fn reboot(&self, device: &DeviceRecord) -> BackendResult {
        match device.platform {
            Platform::Android => self.android.reboot(device).await,
            Platform::Windows => self.windows.reboot(device).await,
            Platform::Ios => self.ios.reboot(device).await,
        }
    }
}

impl Default for Backends {
    fn default() -> Self {
        Self::new()
    }
}
