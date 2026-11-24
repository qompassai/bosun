//! The mutation gate. Every state-changing tool call passes
//! through `decide` — a pure function in the phlow/ache pattern:
//! no I/O, no clock, no ambient authority. A mutation is allowed
//! only when the target device declares the capability the action
//! needs AND the call carries an operator approval. Diagnostics
//! never come here; they are read-only by construction.
//!
//! Stage 0 approval shape: an `operator_approval` object with a
//! non-empty `approved_by`. The production approval channel (an
//! operator check the server verifies rather than trusts) is a
//! Stage 1 hardening item and is recorded as such in STAGE0.md;
//! the gate's decision structure does not change when it lands.

use serde_json::{Value, json};

use crate::capability::{Capability, DeviceRecord};

/// The gated actions. Each maps to exactly one capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    RegisterDevice,
    PackageInstall,
    PackageUpdate,
    Reboot,
}

impl Action {
    pub fn parse(raw: &str) -> Option<Action> {
        match raw {
            "register_device" => Some(Action::RegisterDevice),
            "package_install" => Some(Action::PackageInstall),
            "package_update" => Some(Action::PackageUpdate),
            "reboot" => Some(Action::Reboot),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Action::RegisterDevice => "register_device",
            Action::PackageInstall => "package_install",
            Action::PackageUpdate => "package_update",
            Action::Reboot => "reboot",
        }
    }

    /// The capability a device must declare for this action.
    /// Registration targets the inventory itself, not a device,
    /// so it needs no device capability.
    pub fn required_capability(&self) -> Option<Capability> {
        match self {
            Action::RegisterDevice => None,
            Action::PackageInstall => Some(Capability::PackageInstall),
            Action::PackageUpdate => Some(Capability::PackageUpdate),
            Action::Reboot => Some(Capability::Reboot),
        }
    }
}

/// An operator approval as presented in a tool call. Presence is
/// not proof; see the module note on the Stage 1 channel.
#[derive(Clone, Debug)]
pub struct Approval {
    pub approved_by: String,
    pub note: Option<String>,
}

impl Approval {
    /// Extract an approval from tool arguments. Returns `None`
    /// for a missing object, a missing approver, or an approver
    /// that is empty after trimming — all are "no approval".
    pub fn from_args(args: &Value) -> Option<Approval> {
        let obj = args.get("operator_approval")?;
        let by = obj.get("approved_by")?.as_str()?.trim();
        if by.is_empty() {
            return None;
        }
        Some(Approval {
            approved_by: by.to_string(),
            note: obj.get("note").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// The gate's verdict. Denials carry a stable machine code; the
/// codes are part of the tool contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny { code: &'static str, reason: String },
}

impl Decision {
    // Part of the gate's API surface: the server's dispatch
    // pattern-matches on Deny, the tests and Stage 1 callers use
    // this predicate.
    #[allow(dead_code)]
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    pub fn to_json(&self, action: Action, approval: Option<&Approval>) -> Value {
        match self {
            Decision::Allow => {
                // An allow names its approver: the verdict is an
                // audit record, not just a boolean.
                let mut body = json!({
                    "action": action.as_str(),
                    "decision": "allow",
                });
                if let Some(a) = approval {
                    body["approved_by"] = json!(a.approved_by);
                    if let Some(note) = &a.note {
                        body["note"] = json!(note);
                    }
                }
                body
            }
            Decision::Deny { code, reason } => json!({
                "action": action.as_str(),
                "decision": "deny",
                "code": code,
                "reason": reason,
            }),
        }
    }
}

/// Decide one mutation. `device` is `None` only for registration,
/// the one action that precedes any device record.
///
/// Order is deliberate: capability is checked before approval, so
/// an impossible action is refused for the structural reason even
/// when an approval is attached — an operator cannot approve a
/// device into a capability its platform does not have.
pub fn decide(
    action: Action,
    device: Option<&DeviceRecord>,
    approval: Option<&Approval>,
) -> Decision {
    if let Some(capability) = action.required_capability() {
        let Some(device) = device else {
            return Decision::Deny {
                code: "device_required",
                reason: format!("{} requires a target device", action.as_str()),
            };
        };
        if !device.has(capability) {
            return Decision::Deny {
                code: "capability_not_declared",
                reason: format!(
                    "device {} ({}) does not declare capability {}",
                    device.id,
                    device.platform.as_str(),
                    capability.as_str()
                ),
            };
        }
    }
    match approval {
        None => Decision::Deny {
            code: "operator_approval_required",
            reason: format!(
                "{} is a mutation; the call must carry operator_approval with a non-empty approved_by",
                action.as_str()
            ),
        },
        Some(_) => Decision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Enrollment, Platform};

    fn device(platform: Platform, enrollment: Enrollment) -> DeviceRecord {
        DeviceRecord {
            id: "dev-1".to_string(),
            label: "Test device".to_string(),
            platform,
            transport: "test".to_string(),
            enrollment,
        }
    }

    fn approval() -> Approval {
        Approval {
            approved_by: "operator".to_string(),
            note: None,
        }
    }

    #[test]
    fn mutation_without_approval_is_denied() {
        let d = device(Platform::Android, Enrollment::NotApplicable);
        let verdict = decide(Action::PackageInstall, Some(&d), None);
        assert!(matches!(
            verdict,
            Decision::Deny {
                code: "operator_approval_required",
                ..
            }
        ));
    }

    #[test]
    fn mutation_with_approval_and_capability_is_allowed() {
        let d = device(Platform::Windows, Enrollment::NotApplicable);
        assert!(decide(Action::PackageUpdate, Some(&d), Some(&approval())).is_allow());
        assert!(decide(Action::Reboot, Some(&d), Some(&approval())).is_allow());
        assert!(decide(Action::RegisterDevice, None, Some(&approval())).is_allow());
    }

    #[test]
    fn approval_cannot_create_a_capability() {
        // Adversarial: an approved install against an unsupervised
        // iOS device must still deny — structurally, not politely.
        let d = device(Platform::Ios, Enrollment::EnrolledUnsupervised);
        let verdict = decide(Action::PackageInstall, Some(&d), Some(&approval()));
        assert!(matches!(
            verdict,
            Decision::Deny {
                code: "capability_not_declared",
                ..
            }
        ));
    }

    #[test]
    fn capability_is_checked_before_approval() {
        // Adversarial: no approval AND no capability reports the
        // capability denial, so the caller learns the structural
        // fact rather than chasing an approval that cannot help.
        let d = device(Platform::Ios, Enrollment::Unenrolled);
        let verdict = decide(Action::Reboot, Some(&d), None);
        assert!(matches!(
            verdict,
            Decision::Deny {
                code: "capability_not_declared",
                ..
            }
        ));
    }

    #[test]
    fn device_action_without_device_is_denied() {
        let verdict = decide(Action::PackageInstall, None, Some(&approval()));
        assert!(matches!(
            verdict,
            Decision::Deny {
                code: "device_required",
                ..
            }
        ));
    }

    #[test]
    fn registration_without_approval_is_denied() {
        let verdict = decide(Action::RegisterDevice, None, None);
        assert!(matches!(
            verdict,
            Decision::Deny {
                code: "operator_approval_required",
                ..
            }
        ));
    }

    #[test]
    fn approval_parsing_rejects_empty_approvers() {
        assert!(Approval::from_args(&json!({})).is_none());
        assert!(Approval::from_args(&json!({"operator_approval": {}})).is_none());
        assert!(
            Approval::from_args(&json!({"operator_approval": {"approved_by": "  "}})).is_none()
        );
        assert!(Approval::from_args(&json!({"operator_approval": {"approved_by": 7}})).is_none());
        let ok = Approval::from_args(
            &json!({"operator_approval": {"approved_by": " op ", "note": "ticket 12"}}),
        );
        assert_eq!(ok.as_ref().map(|a| a.approved_by.as_str()), Some("op"));
        assert_eq!(ok.and_then(|a| a.note), Some("ticket 12".to_string()));
    }
}
