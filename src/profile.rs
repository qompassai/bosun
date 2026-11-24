//! Enrollment profile generation: the `.mobileconfig` the
//! Owner installs on the test iPhone after the Configurator/ABM
//! steps. Built entirely from config — server URL, the push
//! topic (placeholder until the real certificate lands), the
//! SCEP endpoint of the fenced local CA, and a one-shot
//! enrollment session token minted with the profile, so the
//! device's first Authenticate is tied to the inventory record
//! the operator chose.
//!
//! The profile is a plist document carried in the crate's
//! JSON-shaped plist model (`plist`) and rendered by its
//! serializer. Payload UUIDs are fresh random tokens per
//! profile; nothing in the artifact is secret except the session
//! token's binding, which expires by consumption (one
//! Authenticate) rather than by time.

use serde_json::{Value, json};

use crate::capability::Enrollment;
use crate::config::MdmConfig;
use crate::plist::{self, DATA_KEY};

#[derive(Debug)]
pub struct ProfileError {
    pub code: &'static str,
    pub message: String,
}

impl ProfileError {
    fn new(code: &'static str, message: impl Into<String>) -> ProfileError {
        ProfileError {
            code,
            message: message.into(),
        }
    }
}

/// Build the profile as a plist-model value. `ca_fingerprint`
/// is the local CA's SHA-1 fingerprint when the CA exists; the
/// SCEP payload omits `CAFingerprint` without it (the device
/// then trusts the TLS chain for the SCEP fetch — acceptable on
/// the LAN, and the profile is regenerated once the CA exists).
/// A payload UUID: 128 random bits from the OS source. The
/// fallback (pid + clock) exists only so a profile render can
/// never fail on a randomness hiccup; uniqueness, not secrecy,
/// is what a payload UUID needs.
fn payload_uuid() -> String {
    crate::mdmstate::random_token().unwrap_or_else(|_| {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("fallback-{}-{n}-{nanos}", std::process::id())
    })
}

pub fn build_profile(
    config: &MdmConfig,
    session_token: &str,
    enrollment: Enrollment,
    ca_fingerprint: Option<&[u8]>,
) -> Value {
    let scep_uuid = payload_uuid();
    let mdm_uuid = payload_uuid();
    let root_uuid = payload_uuid();
    let supervised = enrollment == Enrollment::EnrolledSupervised;

    let mut scep_content = serde_json::Map::new();
    scep_content.insert("URL".to_string(), json!(config.scep_url()));
    scep_content.insert("Name".to_string(), json!("Bosun Identity"));
    scep_content.insert("Subject".to_string(), json!([[["CN", "Bosun Device"]]]));
    scep_content.insert("KeyType".to_string(), json!("RSA"));
    scep_content.insert("KeySize".to_string(), json!(2048));
    // 5 = digital signature (1) + key encipherment (4): the
    // identity signs check-ins and decrypts profile content.
    scep_content.insert("KeyUsage".to_string(), json!(5));
    if let Some(fp) = ca_fingerprint {
        scep_content.insert(
            "CAFingerprint".to_string(),
            json!({ DATA_KEY: crate::plist::base64_encode(fp) }),
        );
    }

    let mut mdm_content = serde_json::Map::new();
    mdm_content.insert("ServerURL".to_string(), json!(config.server_endpoint_url()));
    mdm_content.insert(
        "CheckInURL".to_string(),
        json!(config.checkin_url(session_token)),
    );
    mdm_content.insert("Topic".to_string(), json!(config.profile_topic()));
    mdm_content.insert("IdentityCertificateUUID".to_string(), json!(scep_uuid));
    mdm_content.insert("SignMessage".to_string(), json!(false));
    mdm_content.insert("CheckOutWhenRemoved".to_string(), json!(true));
    mdm_content.insert("SupportAppInstallation".to_string(), json!(supervised));
    mdm_content.insert("AccessRights".to_string(), json!(8191));

    json!({
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "ai.qompass.bosun.enrollment",
        "PayloadUUID": root_uuid,
        "PayloadDisplayName": "Bosun Enrollment",
        "PayloadDescription": "Enrolls this device with the household bosun MDM server.",
        "PayloadOrganization": "Qompass AI",
        "PayloadRemovalDisallowed": supervised,
        "PayloadContent": [
            {
                "PayloadType": "com.apple.security.scep",
                "PayloadVersion": 1,
                "PayloadIdentifier": "ai.qompass.bosun.scep",
                "PayloadUUID": scep_uuid,
                "PayloadDisplayName": "Bosun Identity (SCEP)",
                "PayloadContent": Value::Object(scep_content),
            },
            {
                "PayloadType": "com.apple.mdm",
                "PayloadVersion": 1,
                "PayloadIdentifier": "ai.qompass.bosun.mdm",
                "PayloadUUID": mdm_uuid,
                "PayloadDisplayName": "Bosun MDM",
                "PayloadContent": Value::Object(mdm_content),
            },
        ],
    })
}

/// Render the profile document to `.mobileconfig` text.
pub fn render_profile(
    config: &MdmConfig,
    session_token: &str,
    enrollment: Enrollment,
    ca_fingerprint: Option<&[u8]>,
) -> Result<String, ProfileError> {
    let value = build_profile(config, session_token, enrollment, ca_fingerprint);
    plist::to_string(&value).map_err(|e| ProfileError::new(e.code, e.message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> MdmConfig {
        MdmConfig::for_test(
            std::path::Path::new("/tmp/bosun-profile-test"),
            "127.0.0.1:8443".parse().expect("addr"),
        )
    }

    #[test]
    fn profile_carries_config_session_and_topic() {
        let text = render_profile(
            &config(),
            "session-token-1",
            Enrollment::EnrolledSupervised,
            Some(&[0xAB; 20]),
        )
        .expect("renders");
        // It parses back as a plist and carries the load-bearing
        // fields: server + check-in URLs with the session, the
        // topic placeholder, and the SCEP endpoint.
        let parsed = plist::parse(text.as_bytes()).expect("profile is a valid plist");
        assert_eq!(parsed["PayloadType"], "Configuration");
        let content = parsed["PayloadContent"].as_array().expect("payloads");
        assert_eq!(content.len(), 2);
        let mdm = content
            .iter()
            .find(|p| p["PayloadType"] == "com.apple.mdm")
            .expect("mdm payload");
        let body = &mdm["PayloadContent"];
        assert_eq!(body["ServerURL"], "https://127.0.0.1:8443/mdm/server");
        assert_eq!(
            body["CheckInURL"],
            "https://127.0.0.1:8443/mdm/checkin?session=session-token-1"
        );
        assert_eq!(body["Topic"], crate::config::PLACEHOLDER_TOPIC);
        assert_eq!(body["SupportAppInstallation"], true);
        let scep = content
            .iter()
            .find(|p| p["PayloadType"] == "com.apple.security.scep")
            .expect("scep payload");
        assert_eq!(scep["PayloadContent"]["URL"], "https://127.0.0.1:8443/scep");
        // The MDM payload references the SCEP identity by UUID.
        assert_eq!(body["IdentityCertificateUUID"], scep["PayloadUUID"]);
    }

    #[test]
    fn unsupervised_profile_disallows_app_install_support() {
        let value = build_profile(&config(), "tok", Enrollment::EnrolledUnsupervised, None);
        let content = value["PayloadContent"].as_array().expect("payloads");
        let mdm = content
            .iter()
            .find(|p| p["PayloadType"] == "com.apple.mdm")
            .expect("mdm payload");
        assert_eq!(mdm["PayloadContent"]["SupportAppInstallation"], false);
        assert_eq!(value["PayloadRemovalDisallowed"], false);
    }
}
