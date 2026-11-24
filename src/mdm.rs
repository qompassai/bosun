//! The iOS MDM model: check-in kinds, the command vocabulary, and
//! the per-device command queue. Stage 0 defines the types and the
//! queue; the HTTPS check-in endpoint, SCEP, and APNs push that
//! move commands to devices are Stage 1 (see STAGE0.md). Nothing
//! in this module pretends a command has reached a device: queue
//! entries are `Queued` until a check-in delivers them, and no
//! delivery path exists yet.

// The MDM vocabulary is Stage-1-facing API: it is fully unit-
// tested here, and the check-in endpoint that consumes it lands
// in Stage 1. Dead-code warnings against it are expected until
// then; everything else in the crate stays warning-clean.
#![allow(dead_code)]

use std::collections::VecDeque;

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
