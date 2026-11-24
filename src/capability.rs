//! The capability model: what a device can be asked to do is a
//! function of its platform and (for iOS) its enrollment state,
//! declared per device and enforced before any backend is touched.
//! A call outside a device's declared capabilities is refused
//! cleanly with a typed error — never attempted, never faked.

use serde::{Deserialize, Serialize};

/// A device platform. The three backends differ fundamentally in
/// transport and in what the platform permits; the model says so.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,
    Windows,
    Ios,
}

impl Platform {
    pub fn parse(raw: &str) -> Option<Platform> {
        match raw {
            "android" => Some(Platform::Android),
            "windows" => Some(Platform::Windows),
            "ios" => Some(Platform::Ios),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Android => "android",
            Platform::Windows => "windows",
            Platform::Ios => "ios",
        }
    }
}

/// iOS enrollment state. Android and Windows devices are
/// `NotApplicable`; the distinction only carries meaning for MDM,
/// where supervision decides whether application management and
/// OS update scheduling exist at all.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Enrollment {
    #[default]
    NotApplicable,
    /// No MDM enrollment: the server knows the device, nothing more.
    Unenrolled,
    /// MDM-enrolled but unsupervised (user/account enrollment):
    /// queries answer; application management does not exist.
    EnrolledUnsupervised,
    /// MDM-enrolled and supervised (Apple Configurator or ADE):
    /// the full MDM command set is available.
    EnrolledSupervised,
}

impl Enrollment {
    pub fn parse(raw: &str) -> Option<Enrollment> {
        match raw {
            "not_applicable" => Some(Enrollment::NotApplicable),
            "unenrolled" => Some(Enrollment::Unenrolled),
            "enrolled_unsupervised" => Some(Enrollment::EnrolledUnsupervised),
            "enrolled_supervised" => Some(Enrollment::EnrolledSupervised),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Enrollment::NotApplicable => "not_applicable",
            Enrollment::Unenrolled => "unenrolled",
            Enrollment::EnrolledUnsupervised => "enrolled_unsupervised",
            Enrollment::EnrolledSupervised => "enrolled_supervised",
        }
    }
}

/// One declarable capability. Tool handlers name the capability
/// they need; the gate checks membership before anything runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    Diagnostics,
    PackageList,
    PackageInstall,
    PackageUpdate,
    Reboot,
    OsUpdateSchedule,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Diagnostics => "diagnostics",
            Capability::PackageList => "package_list",
            Capability::PackageInstall => "package_install",
            Capability::PackageUpdate => "package_update",
            Capability::Reboot => "reboot",
            Capability::OsUpdateSchedule => "os_update_schedule",
        }
    }
}

/// The declared capabilities of one device, computed from its
/// platform and enrollment state. This is the whole model:
///
/// - Android over ADB: the full set. ADB is a debug bridge with
///   shell reach; package install/update and reboot are native.
/// - Windows over SSH/WinRM + winget: the full set; OS update
///   scheduling rides the Windows Update stack.
/// - iOS: diagnostics (DeviceInformation) and the installed-app
///   query exist for any MDM-enrolled device. Package install and
///   update (InstallApplication on managed apps) and OS update
///   scheduling require supervision. An unenrolled iOS device
///   declares nothing but its inventory presence.
pub fn capabilities_for(platform: Platform, enrollment: Enrollment) -> Vec<Capability> {
    use Capability::*;
    match platform {
        Platform::Android | Platform::Windows => {
            vec![
                Diagnostics,
                PackageList,
                PackageInstall,
                PackageUpdate,
                Reboot,
                OsUpdateSchedule,
            ]
        }
        Platform::Ios => match enrollment {
            Enrollment::EnrolledSupervised => {
                vec![
                    Diagnostics,
                    PackageList,
                    PackageInstall,
                    PackageUpdate,
                    OsUpdateSchedule,
                ]
            }
            Enrollment::EnrolledUnsupervised => vec![Diagnostics, PackageList],
            Enrollment::Unenrolled | Enrollment::NotApplicable => vec![],
        },
    }
}

/// One inventoried device. `transport` is the platform address the
/// backend dials: an ADB target (`host:port` or serial) for
/// Android, an SSH/WinRM host for Windows, the MDM device UDID
/// for iOS.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceRecord {
    pub id: String,
    pub label: String,
    pub platform: Platform,
    pub transport: String,
    pub enrollment: Enrollment,
}

impl DeviceRecord {
    pub fn capabilities(&self) -> Vec<Capability> {
        capabilities_for(self.platform, self.enrollment)
    }

    pub fn has(&self, capability: Capability) -> bool {
        self.capabilities().contains(&capability)
    }

    /// The record as served: the stored fields plus the computed
    /// capability names, so a caller reads the declaration from
    /// the same object the gate enforces.
    pub fn to_json(&self) -> serde_json::Value {
        let caps: Vec<&str> = self.capabilities().iter().map(Capability::as_str).collect();
        serde_json::json!({
            "id": self.id,
            "label": self.label,
            "platform": self.platform.as_str(),
            "transport": self.transport,
            "enrollment": self.enrollment.as_str(),
            "capabilities": caps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_and_windows_declare_the_full_set() {
        for platform in [Platform::Android, Platform::Windows] {
            let caps = capabilities_for(platform, Enrollment::NotApplicable);
            assert_eq!(caps.len(), 6, "{platform:?} must declare six capabilities");
            assert!(caps.contains(&Capability::PackageInstall));
            assert!(caps.contains(&Capability::Reboot));
        }
    }

    #[test]
    fn ios_unenrolled_declares_nothing() {
        assert!(capabilities_for(Platform::Ios, Enrollment::Unenrolled).is_empty());
        assert!(capabilities_for(Platform::Ios, Enrollment::NotApplicable).is_empty());
    }

    #[test]
    fn ios_unsupervised_queries_but_never_installs() {
        let caps = capabilities_for(Platform::Ios, Enrollment::EnrolledUnsupervised);
        assert!(caps.contains(&Capability::Diagnostics));
        assert!(caps.contains(&Capability::PackageList));
        assert!(!caps.contains(&Capability::PackageInstall));
        assert!(!caps.contains(&Capability::PackageUpdate));
        assert!(!caps.contains(&Capability::OsUpdateSchedule));
        assert!(!caps.contains(&Capability::Reboot));
    }

    #[test]
    fn ios_supervised_installs_but_has_no_adb_style_reboot() {
        let caps = capabilities_for(Platform::Ios, Enrollment::EnrolledSupervised);
        assert!(caps.contains(&Capability::PackageInstall));
        assert!(caps.contains(&Capability::OsUpdateSchedule));
        // MDM has a RestartDevice command, but it is supervised-only
        // and queued, not a transport reboot; the scaffold does not
        // declare it until the MDM backend is live (Stage 1).
        assert!(!caps.contains(&Capability::Reboot));
    }

    #[test]
    fn parse_round_trips() {
        for raw in ["android", "windows", "ios"] {
            assert_eq!(Platform::parse(raw).map(|p| p.as_str()), Some(raw));
        }
        assert_eq!(Platform::parse("haiku"), None);
        for raw in [
            "not_applicable",
            "unenrolled",
            "enrolled_unsupervised",
            "enrolled_supervised",
        ] {
            assert_eq!(Enrollment::parse(raw).map(|e| e.as_str()), Some(raw));
        }
        assert_eq!(Enrollment::parse("jailbroken"), None);
    }
}
