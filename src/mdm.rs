//! The iOS MDM model: check-in kinds, the command vocabulary, and
//! the per-device command queue. Stage 0 defined the types and
//! the queue; Stage 1 lands the consumers — the check-in endpoint
//! (`mdmhttp`), the persisted command records (`mdmstate`), and
//! APNs push (`apns`). Nothing in this module pretends a command
//! has reached a device: a command is `Queued` until a check-in
//! delivers it, and the record of that lives in `mdmstate`.
//!
//! `CommandQueue` below is the Stage 0 in-memory queue, retained
//! as the vocabulary model and for its tests; the live path uses
//! the persisted records, whose FIFO-per-device semantics mirror
//! it. Dead-code allowances cover the parts of the vocabulary
//! Stage 1 defines but only the real-device gate will exercise.
#![allow(dead_code)]

use std::collections::VecDeque;

use serde_json::{Value, json};

/// MDM check-in message kinds (the `MessageType` values a device
/// posts to the check-in endpoint), plus the idle poll a device
/// makes against the server endpoint when pushed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckinKind {
    Authenticate,
    TokenUpdate,
    Checkout,
    Idle,
}

impl CheckinKind {
    pub fn parse(raw: &str) -> Option<CheckinKind> {
        match raw {
            "Authenticate" => Some(CheckinKind::Authenticate),
            "TokenUpdate" => Some(CheckinKind::TokenUpdate),
            "Checkout" => Some(CheckinKind::Checkout),
            "Idle" => Some(CheckinKind::Idle),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CheckinKind::Authenticate => "Authenticate",
            CheckinKind::TokenUpdate => "TokenUpdate",
            CheckinKind::Checkout => "Checkout",
            CheckinKind::Idle => "Idle",
        }
    }
}

/// The MDM command vocabulary this server will speak. Each entry
/// names the platform `RequestType`; the supervision requirement
/// is stated in code, mirroring the capability model, so a command
/// cannot be queued for a device whose enrollment forbids it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MdmCommandKind {
    /// Query device facts (name, OS, serial, battery, storage).
    DeviceInformation,
    /// Query the installed application list.
    InstalledApplicationList,
    /// Install a configuration profile (enrollment plumbing).
    InstallProfile,
    /// Install a managed application by store id / manifest URL.
    InstallApplication { identifier: String },
    /// Remove a managed application.
    RemoveApplication { identifier: String },
    /// Schedule an OS update (supervised only).
    ScheduleOsUpdate,
    /// Restart the device (supervised only).
    RestartDevice,
    /// Query restriction state (supervised only for the full set).
    RestrictionsQuery,
}

impl MdmCommandKind {
    pub fn request_type(&self) -> &'static str {
        match self {
            MdmCommandKind::DeviceInformation => "DeviceInformation",
            MdmCommandKind::InstalledApplicationList => "InstalledApplicationList",
            MdmCommandKind::InstallProfile => "InstallProfile",
            MdmCommandKind::InstallApplication { .. } => "InstallApplication",
            MdmCommandKind::RemoveApplication { .. } => "RemoveApplication",
            MdmCommandKind::ScheduleOsUpdate => "ScheduleOSUpdate",
            MdmCommandKind::RestartDevice => "RestartDevice",
            MdmCommandKind::RestrictionsQuery => "Restrictions",
        }
    }

    pub fn requires_supervision(&self) -> bool {
        matches!(
            self,
            MdmCommandKind::InstallApplication { .. }
                | MdmCommandKind::RemoveApplication { .. }
                | MdmCommandKind::ScheduleOsUpdate
                | MdmCommandKind::RestartDevice
        )
    }

    /// Render the command as the plist value the server endpoint
    /// hands a checking-in device: `{CommandUUID, Command}`. This
    /// is the one place command bodies are shaped, so the enqueue
    /// path can validate renderability up front (a malformed
    /// install identifier refuses at enqueue, not at delivery).
    pub fn to_command_value(&self, command_uuid: &str) -> Result<Value, CommandError> {
        let command = match self {
            MdmCommandKind::DeviceInformation => json!({
                "RequestType": "DeviceInformation",
                "Queries": [
                    "AvailableDeviceCapacity", "BatteryLevel", "BuildVersion",
                    "DeviceCapacity", "DeviceName", "IsSupervised", "ModelName",
                    "OSVersion", "ProductName", "SerialNumber", "UDID",
                ],
            }),
            MdmCommandKind::InstalledApplicationList => json!({
                "RequestType": "InstalledApplicationList",
                "IdentifiersOnly": false,
            }),
            MdmCommandKind::InstallProfile => {
                return Err(CommandError::new(
                    "command_unrenderable",
                    "InstallProfile needs a profile payload; Stage 1 queues no profile installs",
                ));
            }
            MdmCommandKind::InstallApplication { identifier } => {
                if let Ok(store_id) = identifier.parse::<u64>() {
                    json!({
                        "RequestType": "InstallApplication",
                        "iTunesStoreID": store_id,
                    })
                } else if identifier.starts_with("https://") {
                    json!({
                        "RequestType": "InstallApplication",
                        "ManifestURL": identifier,
                    })
                } else {
                    return Err(CommandError::new(
                        "command_unrenderable",
                        format!(
                            "InstallApplication identifier {identifier:?} is neither a store id nor an https manifest URL"
                        ),
                    ));
                }
            }
            MdmCommandKind::RemoveApplication { identifier } => json!({
                "RequestType": "RemoveApplication",
                "Identifier": identifier,
            }),
            MdmCommandKind::ScheduleOsUpdate => json!({
                "RequestType": "ScheduleOSUpdate",
                "InstallAction": "Default",
            }),
            MdmCommandKind::RestartDevice => json!({ "RequestType": "RestartDevice" }),
            MdmCommandKind::RestrictionsQuery => json!({ "RequestType": "Restrictions" }),
        };
        Ok(json!({
            "CommandUUID": command_uuid,
            "Command": command,
        }))
    }
}

/// A command that cannot be rendered for delivery. Typed, like
/// every other refusal in the crate.
#[derive(Debug)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
}

impl CommandError {
    fn new(code: &'static str, message: impl Into<String>) -> CommandError {
        CommandError {
            code,
            message: message.into(),
        }
    }
}

/// One queued command. Ids are server-minted and monotonic per
/// queue instance at Stage 0; Stage 1 persists the queue.
#[derive(Clone, Debug)]
pub struct QueuedCommand {
    pub command_uuid: String,
    pub kind: MdmCommandKind,
}

/// The per-server command queue: bounded, FIFO per device.
/// The bound matters — an MDM server that queues without limit
/// can bury a device under stale commands after an outage.
pub struct CommandQueue {
    entries: Vec<(String, QueuedCommand)>,
    next_seq: u64,
}

/// Hard bound on queued commands across all devices.
pub const MAX_QUEUED_COMMANDS: usize = 512;

impl CommandQueue {
    pub fn new() -> CommandQueue {
        CommandQueue {
            entries: Vec::new(),
            next_seq: 1,
        }
    }

    /// Enqueue a command for a device. Returns the command UUID,
    /// or `None` when the queue is at its bound.
    pub fn enqueue(&mut self, device_udid: &str, kind: MdmCommandKind) -> Option<String> {
        if self.entries.len() >= MAX_QUEUED_COMMANDS {
            return None;
        }
        let uuid = format!("bosun-cmd-{:06}", self.next_seq);
        self.next_seq += 1;
        self.entries.push((
            device_udid.to_string(),
            QueuedCommand {
                command_uuid: uuid.clone(),
                kind,
            },
        ));
        Some(uuid)
    }

    /// Take the oldest queued command for one device (what a
    /// check-in would deliver). Other devices' commands wait.
    pub fn next_for(&mut self, device_udid: &str) -> Option<QueuedCommand> {
        let pos = self
            .entries
            .iter()
            .position(|(udid, _)| udid == device_udid)?;
        Some(self.entries.remove(pos).1)
    }

    pub fn pending_for(&self, device_udid: &str) -> usize {
        self.entries
            .iter()
            .filter(|(udid, _)| udid == device_udid)
            .count()
    }

    pub fn total_pending(&self) -> usize {
        self.entries.len()
    }
}

impl Default for CommandQueue {
    fn default() -> Self {
        Self::new()
    }
}

// The queue is FIFO per device; the VecDeque import documents the
// intended Stage 1 shape (per-device deques) without changing the
// bounded Stage 0 semantics.
#[allow(dead_code)]
type Stage1Shape = VecDeque<QueuedCommand>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkin_kinds_parse() {
        assert_eq!(
            CheckinKind::parse("TokenUpdate"),
            Some(CheckinKind::TokenUpdate)
        );
        assert_eq!(CheckinKind::parse("DeclarativeManagement"), None);
    }

    #[test]
    fn supervision_requirements_match_the_platform() {
        assert!(!MdmCommandKind::DeviceInformation.requires_supervision());
        assert!(!MdmCommandKind::InstalledApplicationList.requires_supervision());
        assert!(
            MdmCommandKind::InstallApplication {
                identifier: "x".into()
            }
            .requires_supervision()
        );
        assert!(MdmCommandKind::ScheduleOsUpdate.requires_supervision());
        assert!(MdmCommandKind::RestartDevice.requires_supervision());
    }

    #[test]
    fn commands_render_their_wire_shape() {
        let info = MdmCommandKind::DeviceInformation
            .to_command_value("bosun-cmd-000001")
            .expect("renders");
        assert_eq!(info["CommandUUID"], "bosun-cmd-000001");
        assert_eq!(info["Command"]["RequestType"], "DeviceInformation");
        assert!(
            info["Command"]["Queries"]
                .as_array()
                .expect("queries")
                .iter()
                .any(|q| q == "IsSupervised")
        );
        let store_app = MdmCommandKind::InstallApplication {
            identifier: "123456789".into(),
        }
        .to_command_value("u2")
        .expect("store id renders");
        assert_eq!(store_app["Command"]["iTunesStoreID"], 123456789);
        let manifest = MdmCommandKind::InstallApplication {
            identifier: "https://example.invalid/app.plist".into(),
        }
        .to_command_value("u3")
        .expect("manifest renders");
        assert_eq!(
            manifest["Command"]["ManifestURL"],
            "https://example.invalid/app.plist"
        );
    }

    #[test]
    fn unrenderable_commands_refuse_at_render() {
        // Adversarial: a free-form identifier is neither a store
        // id nor a manifest URL; it must fail here, at enqueue
        // time, not on the device.
        let bad = MdmCommandKind::InstallApplication {
            identifier: "not an app".into(),
        };
        assert_eq!(
            bad.to_command_value("u").expect_err("must refuse").code,
            "command_unrenderable"
        );
        assert!(
            MdmCommandKind::InstallProfile
                .to_command_value("u")
                .is_err()
        );
    }

    #[test]
    fn queue_is_fifo_per_device_and_bounded() {
        let mut q = CommandQueue::new();
        let a1 = q
            .enqueue("udid-a", MdmCommandKind::DeviceInformation)
            .expect("a1");
        let b1 = q
            .enqueue("udid-b", MdmCommandKind::DeviceInformation)
            .expect("b1");
        let a2 = q
            .enqueue("udid-a", MdmCommandKind::InstalledApplicationList)
            .expect("a2");
        assert_ne!(a1, b1);
        assert_eq!(q.pending_for("udid-a"), 2);
        assert_eq!(q.next_for("udid-a").map(|c| c.command_uuid), Some(a1));
        assert_eq!(q.next_for("udid-a").map(|c| c.command_uuid), Some(a2));
        assert!(q.next_for("udid-a").is_none());
        assert_eq!(q.total_pending(), 1);

        let mut full = CommandQueue::new();
        for _ in 0..MAX_QUEUED_COMMANDS {
            assert!(
                full.enqueue("u", MdmCommandKind::DeviceInformation)
                    .is_some()
            );
        }
        assert!(
            full.enqueue("u", MdmCommandKind::DeviceInformation)
                .is_none()
        );
    }
}
