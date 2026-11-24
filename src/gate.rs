//! The mutation gate. Every state-changing tool call passes
//! through `decide` — a pure function in the phlow/ache pattern:
//! no I/O, no clock, no ambient authority. A mutation is allowed
//! only when the target device declares the capability the action
//! needs AND the call carries an operator approval. Diagnostics
//! never come here; they are read-only by construction.
//!
//! Stage 1 approval channel: when the server holds an approval
//! key (see `approval`), an approval counts only if it arrives
//! *verified* — the server checks the call's token against the
//! key before the gate runs and marks the approval. `decide`
//! keeps the Stage 0 presented-approval semantics for keyless
//! deployments; `decide_with_policy` with
//! `ApprovalPolicy::RequireVerified` is the verified channel.
//! The decision structure is otherwise unchanged, as promised in
//! STAGE0.md: capability first, then approval.

use serde_json::{Value, json};

use crate::capability::{Capability, DeviceRecord};

/// The gated actions. Each maps to exactly one capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    RegisterDevice,
    EnrollDevice,
    PackageInstall,
    PackageUpdate,
    Reboot,
    PushWake,
}

impl Action {
    pub fn parse(raw: &str) -> Option<Action> {
        match raw {
            "register_device" => Some(Action::RegisterDevice),
            "enroll_device" => Some(Action::EnrollDevice),
            "package_install" => Some(Action::PackageInstall),
            "package_update" => Some(Action::PackageUpdate),
            "reboot" => Some(Action::Reboot),
            "push_wake" => Some(Action::PushWake),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Action::RegisterDevice => "register_device",
            Action::EnrollDevice => "enroll_device",
            Action::PackageInstall => "package_install",
            Action::PackageUpdate => "package_update",
            Action::Reboot => "reboot",
            Action::PushWake => "push_wake",
        }
    }

    /// The capability a device must declare for this action.
    /// Registration and enrollment-profile generation target the
    /// inventory itself, not a device's live surface, so they
    /// need no device capability. A push wake asks the device to
    /// check in — any enrolled device declares diagnostics, and
    /// that is the floor the wake requires.
    pub fn required_capability(&self) -> Option<Capability> {
        match self {
            Action::RegisterDevice | Action::EnrollDevice => None,
            Action::PackageInstall => Some(Capability::PackageInstall),
            Action::PackageUpdate => Some(Capability::PackageUpdate),
            Action::Reboot => Some(Capability::Reboot),
            Action::PushWake => Some(Capability::Diagnostics),
        }
    }
}

/// An operator approval as presented in a tool call. `proof` is
/// the approval-channel token (`operator_approval.token`), and
/// `verified` is set only by the server after the token checks
/// against its key — a caller cannot set it from the wire, since
/// `from_args` always constructs with `verified: false`.
#[derive(Clone, Debug)]
pub struct Approval {
    pub approved_by: String,
    pub note: Option<String>,
    pub proof: Option<String>,
    pub verified: bool,
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
            proof: obj.get("token").and_then(Value::as_str).map(str::to_string),
            verified: false,
        })
    }
}

/// Whether the deployment requires channel-verified approvals.
/// Chosen by the server from its configuration (an approval key
/// exists or not) and passed in — the gate stays pure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalPolicy {
    /// Stage 0 semantics: a presented approval suffices.
    PresentedAccepted,
    /// Stage 1 channel: the approval must arrive verified.
    RequireVerified,
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
                    body["approval_verified"] = json!(a.verified);
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

/// Decide one mutation under the Stage 0 policy (presented
/// approvals accepted). Kept as the keyless deployment's entry
/// point; key-holding servers call `decide_with_policy`.
pub fn decide(
    action: Action,
    device: Option<&DeviceRecord>,
    approval: Option<&Approval>,
) -> Decision {
    decide_with_policy(action, device, approval, ApprovalPolicy::PresentedAccepted)
}

/// Decide one mutation. `device` is `None` only for the actions
/// that precede or bypass a device record (registration,
/// enrollment-profile generation).
///
/// Order is deliberate: capability is checked before approval, so
/// an impossible action is refused for the structural reason even
/// when an approval is attached — an operator cannot approve a
/// device into a capability its platform does not have. Under
/// `RequireVerified`, an approval the server has not verified
/// against its key is refused after the capability check with
/// `approval_not_verified`.
pub fn decide_with_policy(
    action: Action,
    device: Option<&DeviceRecord>,
    approval: Option<&Approval>,
    policy: ApprovalPolicy,
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
        Some(a) if policy == ApprovalPolicy::RequireVerified && !a.verified => Decision::Deny {
            code: "approval_not_verified",
            reason: format!(
                "{} requires a channel-verified approval on this server; mint one with `bosun approve` and pass it as operator_approval.token",
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
            proof: None,
            verified: false,
        }
    }

    fn verified_approval() -> Approval {
        Approval {
            verified: true,
            ..approval()
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

    #[test]
    fn from_args_never_constructs_a_verified_approval() {
        // Adversarial: a caller putting "verified": true (or a
        // token) in the wire object must not mark itself verified;
        // only the server's channel check sets the flag.
        let parsed = Approval::from_args(
            &json!({"operator_approval": {"approved_by": "op", "verified": true, "token": "v1.1.x"}}),
        )
        .expect("parses");
        assert!(!parsed.verified);
        assert_eq!(parsed.proof.as_deref(), Some("v1.1.x"));
    }

    #[test]
    fn require_verified_denies_presented_and_allows_verified() {
        let d = device(Platform::Android, Enrollment::NotApplicable);
        let presented = decide_with_policy(
            Action::PackageInstall,
            Some(&d),
            Some(&approval()),
            ApprovalPolicy::RequireVerified,
        );
        assert!(matches!(
            presented,
            Decision::Deny {
                code: "approval_not_verified",
                ..
            }
        ));
        assert!(
            decide_with_policy(
                Action::PackageInstall,
                Some(&d),
                Some(&verified_approval()),
                ApprovalPolicy::RequireVerified,
            )
            .is_allow()
        );
        // The same presented approval still works keyless.
        assert!(decide(Action::PackageInstall, Some(&d), Some(&approval())).is_allow());
    }

    #[test]
    fn capability_still_precedes_verification() {
        // Adversarial: a verified approval cannot create a
        // capability either — the structural denial comes first.
        let d = device(Platform::Ios, Enrollment::EnrolledUnsupervised);
        let verdict = decide_with_policy(
            Action::PackageInstall,
            Some(&d),
            Some(&verified_approval()),
            ApprovalPolicy::RequireVerified,
        );
        assert!(matches!(
            verdict,
            Decision::Deny {
                code: "capability_not_declared",
                ..
            }
        ));
    }

    #[test]
    fn new_actions_parse_and_bind() {
        assert_eq!(Action::parse("enroll_device"), Some(Action::EnrollDevice));
        assert_eq!(Action::parse("push_wake"), Some(Action::PushWake));
        assert_eq!(Action::EnrollDevice.required_capability(), None);
        assert_eq!(
            Action::PushWake.required_capability(),
            Some(Capability::Diagnostics)
        );
        // An unenrolled iOS device cannot be push-woken: it
        // declares no diagnostics capability.
        let d = device(Platform::Ios, Enrollment::Unenrolled);
        let verdict = decide(Action::PushWake, Some(&d), Some(&approval()));
        assert!(matches!(
            verdict,
            Decision::Deny {
                code: "capability_not_declared",
                ..
            }
        ));
    }
}
