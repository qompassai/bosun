//! Stage 1 configuration: the MDM server's environment contract.
//!
//! Everything the check-in server, the enrollment profile, and
//! the APNs client need arrives through `BOSUN_MDM_*` variables,
//! resolved once into this struct. Resolution is strict where a
//! wrong value would be dangerous (the public URL must be HTTPS;
//! the bind address must parse) and explicit everywhere else:
//! an unset optional path means "not configured", and the code
//! that needs it says so with a typed error at use time rather
//! than discovering a default the operator never chose.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The topic used in enrollment profiles before a real push
/// certificate exists. It is shaped like a topic so profiles are
/// structurally valid, and it is obviously a placeholder: the
/// profile must be regenerated once the Owner's certificate
/// lands, and `STAGE1.md` says so.
pub const PLACEHOLDER_TOPIC: &str = "com.apple.mgmt.External.00000000-0000-0000-0000-000000000000";

#[derive(Debug)]
pub struct ConfigError {
    pub code: &'static str,
    pub message: String,
}

impl ConfigError {
    fn new(code: &'static str, message: impl Into<String>) -> ConfigError {
        ConfigError {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MdmConfig {
    /// The bosun home (holds inventory, MDM state, CA, keys).
    pub home: PathBuf,
    /// Public base URL devices use, e.g. `https://mdm.example:8443`.
    pub server_url: String,
    /// Socket address the MDM HTTP server binds.
    pub bind: SocketAddr,
    /// PEM paths for the server's TLS identity, when configured.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Dev/test escape hatch: serve plaintext on a loopback bind.
    /// Refused for any non-loopback bind, always.
    pub allow_plain_loopback: bool,
    /// APNs push certificate + key (PEM), once the Owner's
    /// certificate exists.
    pub push_cert: Option<PathBuf>,
    pub push_key: Option<PathBuf>,
    /// Topic override; when unset, the topic is read from the
    /// push certificate, and profiles fall back to the placeholder.
    pub topic: Option<String>,
    /// Operator-approval key file. When the file exists, the
    /// gate's verified channel is in force (see `approval`).
    pub approval_key_file: PathBuf,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

impl MdmConfig {
    /// Resolve from the environment. `home` is the already
    /// resolved bosun home (the inventory's directory).
    pub fn from_env(home: &Path) -> Result<MdmConfig, ConfigError> {
        let server_url = env_string("BOSUN_MDM_SERVER_URL")
            .unwrap_or_else(|| "https://127.0.0.1:8443".to_string());
        if !server_url.starts_with("https://") || server_url.contains(char::is_whitespace) {
            return Err(ConfigError::new(
                "config_invalid",
                format!("BOSUN_MDM_SERVER_URL must be an https:// base URL, got {server_url:?}"),
            ));
        }
        let server_url = server_url.trim_end_matches('/').to_string();
        let bind_raw = env_string("BOSUN_MDM_BIND").unwrap_or_else(|| "127.0.0.1:8443".to_string());
        let bind: SocketAddr = bind_raw.parse().map_err(|e| {
            ConfigError::new(
                "config_invalid",
                format!("BOSUN_MDM_BIND {bind_raw:?} is not a socket address: {e}"),
            )
        })?;
        let topic = env_string("BOSUN_MDM_TOPIC");
        if let Some(topic) = &topic
            && (!topic.starts_with("com.apple.mgmt.") || topic.len() > 128)
        {
            return Err(ConfigError::new(
                "config_invalid",
                format!("BOSUN_MDM_TOPIC {topic:?} is not shaped like an MDM topic"),
            ));
        }
        let approval_key_file =
            env_path("BOSUN_APPROVAL_KEY_FILE").unwrap_or_else(|| home.join("approval.key"));
        Ok(MdmConfig {
            home: home.to_path_buf(),
            server_url,
            bind,
            tls_cert: env_path("BOSUN_MDM_TLS_CERT"),
            tls_key: env_path("BOSUN_MDM_TLS_KEY"),
            allow_plain_loopback: env_string("BOSUN_MDM_ALLOW_PLAIN_LOOPBACK")
                .is_some_and(|v| v == "1"),
            push_cert: env_path("BOSUN_MDM_PUSH_CERT"),
            push_key: env_path("BOSUN_MDM_PUSH_KEY"),
            topic,
            approval_key_file,
        })
    }

    /// A config for tests and in-process use: loopback, plaintext
    /// allowed, nothing optional configured.
    pub fn for_test(home: &Path, bind: SocketAddr) -> MdmConfig {
        MdmConfig {
            home: home.to_path_buf(),
            server_url: format!("https://{bind}"),
            bind,
            tls_cert: None,
            tls_key: None,
            allow_plain_loopback: true,
            push_cert: None,
            push_key: None,
            topic: None,
            approval_key_file: home.join("approval.key"),
        }
    }

    /// The topic profiles are generated with: the override, or
    /// the placeholder until a certificate supplies the real one.
    /// (When a push certificate is configured, the MCP push path
    /// reads the topic from the certificate itself and refuses a
    /// mismatch with the override; profiles are a pre-cert
    /// artifact and use this value.)
    pub fn profile_topic(&self) -> String {
        self.topic
            .clone()
            .unwrap_or_else(|| PLACEHOLDER_TOPIC.to_string())
    }

    pub fn checkin_url(&self, session_token: &str) -> String {
        format!("{}/mdm/checkin?session={session_token}", self.server_url)
    }

    pub fn enroll_url(&self, session_token: &str) -> String {
        format!("{}/enroll?session={session_token}", self.server_url)
    }

    pub fn server_endpoint_url(&self) -> String {
        format!("{}/mdm/server", self.server_url)
    }

    pub fn scep_url(&self) -> String {
        format!("{}/scep", self.server_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_shapes_urls_and_placeholder_topic() {
        let home = PathBuf::from("/tmp/bosun-config-test");
        let bind: SocketAddr = "127.0.0.1:18443".parse().expect("addr");
        let config = MdmConfig::for_test(&home, bind);
        assert_eq!(config.profile_topic(), PLACEHOLDER_TOPIC);
        assert_eq!(
            config.checkin_url("tok123"),
            "https://127.0.0.1:18443/mdm/checkin?session=tok123"
        );
        assert_eq!(
            config.server_endpoint_url(),
            "https://127.0.0.1:18443/mdm/server"
        );
        assert_eq!(config.scep_url(), "https://127.0.0.1:18443/scep");
    }
}
