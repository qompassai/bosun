//! The persisted MDM state: one bounded JSON file beside the
//! inventory (`$BOSUN_HOME/mdm_state.json`) holding what the
//! protocol learns at runtime — per-device enrollment and push
//! credentials, one-shot enrollment sessions, and the command
//! records (queued → delivered → acknowledged/error) that the
//! Stage 0 in-memory queue grew into.
//!
//! The MCP server and `bosun mdm-serve` are separate processes;
//! this file is their meeting point. Both sides load it fresh
//! for each operation and rewrite it whole on change, atomically,
//! exactly like the inventory store. At household scale that is
//! the honest coordination mechanism; the bounds below keep a
//! corrupt or hostile state file from becoming a memory or disk
//! problem, and a parse failure is an error, never a reset —
//! silently forgetting which devices are enrolled would be worse
//! than refusing to start.
//!
//! No clock is read inside this module: callers pass `now_unix`,
//! so every transition is testable without sleeping.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capability::Enrollment;
use crate::mdm::{MAX_QUEUED_COMMANDS, MdmCommandKind};

/// Hard bound on the state file.
pub const MAX_STATE_BYTES: u64 = 512 * 1024;

/// Hard bound on MDM-known devices.
pub const MAX_MDM_DEVICES: usize = 256;

/// Hard bound on retained command records (queued + completed).
pub const MAX_COMMAND_RECORDS: usize = 1024;

/// Hard bound on one recorded response payload, serialized.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024;

/// Hard bound on live enrollment sessions.
pub const MAX_SESSIONS: usize = 256;

/// Hard bound on a device UDID string.
pub const MAX_UDID_CHARS: usize = 128;

#[derive(Debug)]
pub struct StateError {
    pub code: &'static str,
    pub message: String,
}

impl StateError {
    fn new(code: &'static str, message: impl Into<String>) -> StateError {
        StateError {
            code,
            message: message.into(),
        }
    }
}

/// A command's lifecycle. A response is only ever recorded
/// against `Delivered` — a device cannot acknowledge a command
/// it was never handed (asserted by the adversarial tests).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandState {
    Queued,
    Delivered,
    Acknowledged,
    Error,
}

impl CommandState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommandState::Queued => "queued",
            CommandState::Delivered => "delivered",
            CommandState::Acknowledged => "acknowledged",
            CommandState::Error => "error",
        }
    }

    fn is_completed(&self) -> bool {
        matches!(self, CommandState::Acknowledged | CommandState::Error)
    }
}

/// One command, from enqueue to its recorded answer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommandRecord {
    pub command_uuid: String,
    pub device_udid: String,
    pub request_type: String,
    /// The command's distinguishing argument (an app identifier),
    /// when the kind carries one.
    pub detail: Option<String>,
    pub state: CommandState,
    /// The device's answer, bounded at record time.
    pub response: Option<Value>,
    pub created_unix: u64,
    pub updated_unix: u64,
}

impl CommandRecord {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "command_uuid": self.command_uuid,
            "device_udid": self.device_udid,
            "request_type": self.request_type,
            "detail": self.detail,
            "state": self.state.as_str(),
            "response": self.response,
            "created_unix": self.created_unix,
            "updated_unix": self.updated_unix,
        })
    }

    /// Rebuild the command kind from the record, for delivery.
    pub fn kind(&self) -> Option<MdmCommandKind> {
        match self.request_type.as_str() {
            "DeviceInformation" => Some(MdmCommandKind::DeviceInformation),
            "InstalledApplicationList" => Some(MdmCommandKind::InstalledApplicationList),
            "InstallProfile" => Some(MdmCommandKind::InstallProfile),
            "InstallApplication" => self
                .detail
                .clone()
                .map(|identifier| MdmCommandKind::InstallApplication { identifier }),
            "RemoveApplication" => self
                .detail
                .clone()
                .map(|identifier| MdmCommandKind::RemoveApplication { identifier }),
            "ScheduleOSUpdate" => Some(MdmCommandKind::ScheduleOsUpdate),
            "RestartDevice" => Some(MdmCommandKind::RestartDevice),
            "Restrictions" => Some(MdmCommandKind::RestrictionsQuery),
            _ => None,
        }
    }
}

/// What the server knows about one device's MDM relationship.
/// Push credentials live here and only here; the MCP surface
/// reports their presence, never their values.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MdmDeviceState {
    pub udid: String,
    /// The inventory id this UDID was bound to by an enrollment
    /// session, when known.
    pub inventory_id: Option<String>,
    pub enrollment: Enrollment,
    pub push_token_hex: Option<String>,
    pub push_magic: Option<String>,
    pub topic: Option<String>,
    pub checked_out: bool,
    pub last_checkin_unix: u64,
}

impl MdmDeviceState {
    fn new(udid: &str) -> MdmDeviceState {
        MdmDeviceState {
            udid: udid.to_string(),
            inventory_id: None,
            enrollment: Enrollment::Unenrolled,
            push_token_hex: None,
            push_magic: None,
            topic: None,
            checked_out: false,
            last_checkin_unix: 0,
        }
    }

    pub fn push_ready(&self) -> bool {
        self.push_token_hex.is_some() && self.push_magic.is_some() && !self.checked_out
    }

    /// The state as served: presence booleans for credentials,
    /// never the credential values.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "udid": self.udid,
            "inventory_id": self.inventory_id,
            "enrollment": self.enrollment.as_str(),
            "push_token_stored": self.push_token_hex.is_some(),
            "push_magic_stored": self.push_magic.is_some(),
            "push_ready": self.push_ready(),
            "checked_out": self.checked_out,
            "last_checkin_unix": self.last_checkin_unix,
        })
    }
}

/// A one-shot enrollment session, minted when an enrollment
/// profile is generated. The profile's check-in URL carries the
/// token; the first Authenticate that presents it binds the
/// device to the declared enrollment kind and consumes it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnrollmentSession {
    pub token: String,
    pub device_id: String,
    pub enrollment: Enrollment,
    pub created_unix: u64,
}

#[derive(Default, Deserialize, Serialize)]
struct StateFile {
    devices: Vec<MdmDeviceState>,
    commands: Vec<CommandRecord>,
    sessions: Vec<EnrollmentSession>,
    next_seq: u64,
}

pub struct MdmState {
    path: PathBuf,
    inner: StateFile,
}

/// A random hex token (128 bits) for enrollment sessions, read
/// from the OS random source. Session tokens are bearer
/// credentials for exactly one enrollment, so they do not come
/// from a PRNG.
pub fn random_token() -> std::io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(crate::plist::hex_encode(&bytes))
}

pub fn state_path(home: &Path) -> PathBuf {
    home.join("mdm_state.json")
}

impl MdmState {
    pub fn load(home: &Path) -> Result<MdmState, StateError> {
        let path = state_path(home);
        let inner = match std::fs::metadata(&path) {
            Ok(meta) => {
                if meta.len() > MAX_STATE_BYTES {
                    return Err(StateError::new(
                        "state_too_large",
                        format!(
                            "mdm state file is {} bytes; bound is {MAX_STATE_BYTES}",
                            meta.len()
                        ),
                    ));
                }
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    StateError::new(
                        "state_read_failed",
                        format!("cannot read {}: {e}", path.display()),
                    )
                })?;
                serde_json::from_str::<StateFile>(&text).map_err(|e| {
                    StateError::new(
                        "state_parse_failed",
                        format!("cannot parse {}: {e}", path.display()),
                    )
                })?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StateFile {
                next_seq: 1,
                ..StateFile::default()
            },
            Err(e) => {
                return Err(StateError::new(
                    "state_read_failed",
                    format!("cannot stat {}: {e}", path.display()),
                ));
            }
        };
        if inner.devices.len() > MAX_MDM_DEVICES || inner.commands.len() > MAX_COMMAND_RECORDS {
            return Err(StateError::new(
                "state_too_large",
                "mdm state exceeds its device or command bounds",
            ));
        }
        Ok(MdmState { path, inner })
    }

    pub fn save(&self) -> Result<(), StateError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                StateError::new(
                    "state_write_failed",
                    format!("cannot create {}: {e}", parent.display()),
                )
            })?;
        }
        let text = serde_json::to_string_pretty(&self.inner).map_err(|e| {
            StateError::new(
                "state_write_failed",
                format!("cannot serialize mdm state: {e}"),
            )
        })?;
        if text.len() as u64 > MAX_STATE_BYTES {
            return Err(StateError::new(
                "state_too_large",
                format!("serialized mdm state exceeds {MAX_STATE_BYTES} bytes"),
            ));
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| {
            StateError::new(
                "state_write_failed",
                format!("cannot write {}: {e}", tmp.display()),
            )
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            StateError::new(
                "state_write_failed",
                format!("cannot replace {}: {e}", self.path.display()),
            )
        })
    }

    // -- devices ------------------------------------------------------------

    pub fn device(&self, udid: &str) -> Option<&MdmDeviceState> {
        self.inner.devices.iter().find(|d| d.udid == udid)
    }

    pub fn devices(&self) -> &[MdmDeviceState] {
        &self.inner.devices
    }

    /// Fetch-or-create the device entry. Creation is refused at
    /// the device bound.
    pub fn device_mut(&mut self, udid: &str) -> Result<&mut MdmDeviceState, StateError> {
        if let Some(pos) = self.inner.devices.iter().position(|d| d.udid == udid) {
            return Ok(&mut self.inner.devices[pos]);
        }
        if self.inner.devices.len() >= MAX_MDM_DEVICES {
            return Err(StateError::new(
                "state_full",
                format!("mdm device bound of {MAX_MDM_DEVICES} reached"),
            ));
        }
        self.inner.devices.push(MdmDeviceState::new(udid));
        let pos = self.inner.devices.len() - 1;
        Ok(&mut self.inner.devices[pos])
    }

    // -- sessions -----------------------------------------------------------

    pub fn create_session(
        &mut self,
        token: String,
        device_id: &str,
        enrollment: Enrollment,
        now: u64,
    ) -> Result<(), StateError> {
        if self.inner.sessions.len() >= MAX_SESSIONS {
            return Err(StateError::new(
                "state_full",
                format!("enrollment session bound of {MAX_SESSIONS} reached"),
            ));
        }
        self.inner.sessions.push(EnrollmentSession {
            token,
            device_id: device_id.to_string(),
            enrollment,
            created_unix: now,
        });
        Ok(())
    }

    pub fn session(&self, token: &str) -> Option<&EnrollmentSession> {
        self.inner.sessions.iter().find(|s| s.token == token)
    }

    /// Consume a session (one-shot): returns it and removes it.
    pub fn take_session(&mut self, token: &str) -> Option<EnrollmentSession> {
        let pos = self.inner.sessions.iter().position(|s| s.token == token)?;
        Some(self.inner.sessions.remove(pos))
    }

    // -- check-in mutations --------------------------------------

    /// Record an Authenticate: bind the UDID to its inventory id
    /// and the enrollment kind its session declared, and mark it
    /// present. Re-authentication refreshes the binding.
    pub fn authenticate(
        &mut self,
        udid: &str,
        inventory_id: &str,
        enrollment: Enrollment,
        now: u64,
    ) -> Result<(), StateError> {
        let device = self.device_mut(udid)?;
        device.inventory_id = Some(inventory_id.to_string());
        device.enrollment = enrollment;
        device.checked_out = false;
        device.last_checkin_unix = now;
        Ok(())
    }

    /// Record a TokenUpdate: store the push credentials the
    /// device reported. Only fields the message actually carries
    /// change — a TokenUpdate without a token (it happens, for
    /// AwaitingConfiguration) must not erase stored credentials.
    /// Unknown devices are ignored; the endpoint refuses them
    /// before this is called.
    pub fn token_update(
        &mut self,
        udid: &str,
        token_hex: Option<String>,
        push_magic: Option<String>,
        topic: Option<String>,
        now: u64,
    ) {
        if let Some(device) = self.inner.devices.iter_mut().find(|d| d.udid == udid) {
            if token_hex.is_some() {
                device.push_token_hex = token_hex;
            }
            if push_magic.is_some() {
                device.push_magic = push_magic;
            }
            if topic.is_some() {
                device.topic = topic;
            }
            device.checked_out = false;
            device.last_checkin_unix = now;
        }
    }

    /// Record a CheckOut: the device has left management. Its
    /// push credentials are dropped — a checked-out device must
    /// never be woken — and the record remains for the operator
    /// to see that it left.
    pub fn check_out(&mut self, udid: &str, now: u64) {
        if let Some(device) = self.inner.devices.iter_mut().find(|d| d.udid == udid) {
            device.checked_out = true;
            device.push_token_hex = None;
            device.push_magic = None;
            device.last_checkin_unix = now;
        }
    }

    // -- commands -----------------------------------------------------------

    /// Enqueue a command. The kind is rendered once here so an
    /// unrenderable command (an install with a malformed
    /// identifier) refuses at enqueue time, not at delivery.
    pub fn enqueue(
        &mut self,
        udid: &str,
        kind: MdmCommandKind,
        now: u64,
    ) -> Result<String, StateError> {
        let pending = self
            .inner
            .commands
            .iter()
            .filter(|c| !c.state.is_completed())
            .count();
        if pending >= MAX_QUEUED_COMMANDS {
            return Err(StateError::new(
                "queue_full",
                format!("MDM command queue is at its bound of {MAX_QUEUED_COMMANDS}"),
            ));
        }
        let uuid = format!("bosun-cmd-{:06}", self.inner.next_seq);
        // Validation render: the UUID in the render is a probe;
        // the stored record renders again at delivery.
        kind.to_command_value(&uuid)
            .map_err(|e| StateError::new(e.code, e.message))?;
        self.inner.next_seq += 1;
        let detail = match &kind {
            MdmCommandKind::InstallApplication { identifier }
            | MdmCommandKind::RemoveApplication { identifier } => Some(identifier.clone()),
            _ => None,
        };
        self.inner.commands.push(CommandRecord {
            command_uuid: uuid.clone(),
            device_udid: udid.to_string(),
            request_type: kind.request_type().to_string(),
            detail,
            state: CommandState::Queued,
            response: None,
            created_unix: now,
            updated_unix: now,
        });
        self.prune_completed();
        Ok(uuid)
    }

    /// Drop oldest completed records while the file is over its
    /// record bound. Queued and delivered records are never
    /// pruned — losing a live command silently is the one outcome
    /// this state file exists to prevent.
    fn prune_completed(&mut self) {
        while self.inner.commands.len() > MAX_COMMAND_RECORDS {
            let Some(pos) = self
                .inner
                .commands
                .iter()
                .position(|c| c.state.is_completed())
            else {
                break;
            };
            self.inner.commands.remove(pos);
        }
    }

    /// The oldest queued command for a device, marked delivered.
    /// This is the check-in poll's take.
    pub fn next_deliverable(&mut self, udid: &str, now: u64) -> Option<CommandRecord> {
        let record = self
            .inner
            .commands
            .iter_mut()
            .find(|c| c.device_udid == udid && c.state == CommandState::Queued)?;
        record.state = CommandState::Delivered;
        record.updated_unix = now;
        Some(record.clone())
    }

    pub fn command(&self, uuid: &str) -> Option<&CommandRecord> {
        self.inner.commands.iter().find(|c| c.command_uuid == uuid)
    }

    pub fn commands_for(&self, udid: &str) -> Vec<&CommandRecord> {
        self.inner
            .commands
            .iter()
            .filter(|c| c.device_udid == udid)
            .collect()
    }

    pub fn all_commands(&self) -> &[CommandRecord] {
        &self.inner.commands
    }

    /// Record a device's answer to a delivered command. The
    /// adversarial core of the protocol: an unknown UUID, a UUID
    /// belonging to another device, an answer to a command that
    /// was never delivered, and a second answer to a completed
    /// command are all refusals that leave the record untouched.
    pub fn record_response(
        &mut self,
        udid: &str,
        command_uuid: &str,
        acknowledged: bool,
        response: Value,
        now: u64,
    ) -> Result<CommandRecord, StateError> {
        let Some(record) = self
            .inner
            .commands
            .iter_mut()
            .find(|c| c.command_uuid == command_uuid)
        else {
            return Err(StateError::new(
                "command_not_found",
                format!("no command record with uuid {command_uuid}"),
            ));
        };
        if record.device_udid != udid {
            return Err(StateError::new(
                "command_device_mismatch",
                format!("command {command_uuid} belongs to a different device"),
            ));
        }
        match record.state {
            CommandState::Queued => {
                return Err(StateError::new(
                    "command_not_delivered",
                    format!("command {command_uuid} has not been delivered yet"),
                ));
            }
            CommandState::Acknowledged | CommandState::Error => {
                return Err(StateError::new(
                    "command_already_completed",
                    format!("command {command_uuid} already has a recorded answer"),
                ));
            }
            CommandState::Delivered => {}
        }
        record.response = Some(bound_response(response));
        record.state = if acknowledged {
            CommandState::Acknowledged
        } else {
            CommandState::Error
        };
        record.updated_unix = now;
        Ok(record.clone())
    }
}

/// Bound one response payload: oversized answers are replaced by
/// a marker carrying the original size, so a device cannot grow
/// the state file by talking.
fn bound_response(response: Value) -> Value {
    let serialized = response.to_string();
    if serialized.len() <= MAX_RESPONSE_BYTES {
        response
    } else {
        serde_json::json!({
            "truncated": true,
            "original_bytes": serialized.len(),
            "note": "device response exceeded the recording bound and was not retained",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bosun-mdmstate-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn enqueue_deliver_acknowledge_round_trip_persists() {
        let home = temp_home("roundtrip");
        let mut state = MdmState::load(&home).expect("load");
        let uuid = state
            .enqueue("udid-1", MdmCommandKind::DeviceInformation, 100)
            .expect("enqueue");
        state.save().expect("save");

        let mut reloaded = MdmState::load(&home).expect("reload");
        let delivered = reloaded
            .next_deliverable("udid-1", 110)
            .expect("deliverable");
        assert_eq!(delivered.command_uuid, uuid);
        assert_eq!(delivered.state, CommandState::Delivered);
        // A second poll finds nothing new to deliver.
        assert!(reloaded.next_deliverable("udid-1", 111).is_none());

        let record = reloaded
            .record_response(
                "udid-1",
                &uuid,
                true,
                serde_json::json!({"DeviceName": "Sim"}),
                120,
            )
            .expect("record");
        assert_eq!(record.state, CommandState::Acknowledged);
        assert_eq!(record.response.expect("response")["DeviceName"], "Sim");
    }

    #[test]
    fn wrong_uuid_and_wrong_device_responses_never_touch_the_record() {
        // Adversarial (the brief's named case): a response with a
        // wrong command UUID must not clear the queue record.
        let home = temp_home("wronguuid");
        let mut state = MdmState::load(&home).expect("load");
        let uuid = state
            .enqueue("udid-1", MdmCommandKind::DeviceInformation, 100)
            .expect("enqueue");
        state.next_deliverable("udid-1", 110).expect("deliver");

        let err = state
            .record_response("udid-1", "bosun-cmd-999999", true, Value::Null, 120)
            .expect_err("unknown uuid must refuse");
        assert_eq!(err.code, "command_not_found");
        let err = state
            .record_response("udid-2", &uuid, true, Value::Null, 120)
            .expect_err("wrong device must refuse");
        assert_eq!(err.code, "command_device_mismatch");
        let record = state.command(&uuid).expect("record still there");
        assert_eq!(record.state, CommandState::Delivered);
        assert!(record.response.is_none());
    }

    #[test]
    fn undelivered_and_double_answers_refuse() {
        // Adversarial: answering before delivery, and answering
        // twice, both refuse and leave state unchanged.
        let home = temp_home("doubleanswer");
        let mut state = MdmState::load(&home).expect("load");
        let uuid = state
            .enqueue("udid-1", MdmCommandKind::DeviceInformation, 100)
            .expect("enqueue");
        let err = state
            .record_response("udid-1", &uuid, true, Value::Null, 105)
            .expect_err("queued command cannot be answered");
        assert_eq!(err.code, "command_not_delivered");

        state.next_deliverable("udid-1", 110).expect("deliver");
        state
            .record_response("udid-1", &uuid, true, Value::Null, 120)
            .expect("first answer");
        let err = state
            .record_response("udid-1", &uuid, false, Value::Null, 130)
            .expect_err("second answer must refuse");
        assert_eq!(err.code, "command_already_completed");
        assert_eq!(
            state.command(&uuid).expect("record").state,
            CommandState::Acknowledged
        );
    }

    #[test]
    fn sessions_are_one_shot() {
        let home = temp_home("sessions");
        let mut state = MdmState::load(&home).expect("load");
        state
            .create_session(
                "tok".to_string(),
                "iphone-1",
                Enrollment::EnrolledSupervised,
                100,
            )
            .expect("create");
        assert!(state.session("tok").is_some());
        let taken = state.take_session("tok").expect("take");
        assert_eq!(taken.device_id, "iphone-1");
        assert!(state.take_session("tok").is_none());
    }

    #[test]
    fn oversized_responses_are_bounded_not_stored() {
        let home = temp_home("bigresponse");
        let mut state = MdmState::load(&home).expect("load");
        let uuid = state
            .enqueue("udid-1", MdmCommandKind::DeviceInformation, 100)
            .expect("enqueue");
        state.next_deliverable("udid-1", 110).expect("deliver");
        let big = Value::String("x".repeat(MAX_RESPONSE_BYTES + 100));
        let record = state
            .record_response("udid-1", &uuid, true, big, 120)
            .expect("record");
        let response = record.response.expect("response");
        assert_eq!(response["truncated"], true);
        assert!(response.to_string().len() < MAX_RESPONSE_BYTES);
    }

    #[test]
    fn corrupt_state_is_an_error_not_a_reset() {
        let home = temp_home("corrupt");
        std::fs::create_dir_all(&home).expect("mkdir");
        std::fs::write(state_path(&home), "{broken").expect("write");
        match MdmState::load(&home) {
            Ok(_) => panic!("corrupt state must error"),
            Err(e) => assert_eq!(e.code, "state_parse_failed"),
        }
    }
}
