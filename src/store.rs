//! The device inventory store: one JSON file under the server's
//! home, bounded on read, rewritten whole on change. The fleet is
//! a household, not a cloud — a file with a hard size bound and a
//! device-count bound is the honest scale, and it keeps the
//! inventory human-readable and diffable.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::capability::DeviceRecord;

/// Environment variable naming the store home. Default:
/// `~/.local/share/bosun`.
pub const ENV_HOME: &str = "BOSUN_HOME";

/// Hard bound on the inventory file. 256 KiB is thousands of
/// device records; anything larger is corruption or abuse.
pub const MAX_STORE_BYTES: u64 = 256 * 1024;

/// Hard bound on inventoried devices.
pub const MAX_DEVICES: usize = 256;

#[derive(Debug)]
pub struct StoreError {
    pub code: &'static str,
    pub message: String,
}

impl StoreError {
    fn new(code: &'static str, message: String) -> StoreError {
        StoreError { code, message }
    }
}

#[derive(Default, Deserialize, Serialize)]
struct Inventory {
    devices: Vec<DeviceRecord>,
}

pub struct Store {
    path: PathBuf,
    inventory: Inventory,
}

impl Store {
    /// Resolve the store path from the environment contract.
    pub fn path_from_env() -> Result<PathBuf, StoreError> {
        if let Some(home) = std::env::var_os(ENV_HOME) {
            return Ok(PathBuf::from(home).join("inventory.json"));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| {
            StoreError::new(
                "store_home_unresolved",
                "neither BOSUN_HOME nor HOME is set".to_string(),
            )
        })?;
        Ok(PathBuf::from(home).join(".local/share/bosun/inventory.json"))
    }

    /// Load the inventory, or start empty when the file does not
    /// exist yet. A file over the size bound, or one that does not
    /// parse, is an error — never a silent reset of the inventory.
    pub fn load(path: PathBuf) -> Result<Store, StoreError> {
        let inventory = match std::fs::metadata(&path) {
            Ok(meta) => {
                if meta.len() > MAX_STORE_BYTES {
                    return Err(StoreError::new(
                        "store_too_large",
                        format!(
                            "inventory file is {} bytes; bound is {MAX_STORE_BYTES}",
                            meta.len()
                        ),
                    ));
                }
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    StoreError::new(
                        "store_read_failed",
                        format!("cannot read {}: {e}", path.display()),
                    )
                })?;
                serde_json::from_str::<Inventory>(&text).map_err(|e| {
                    StoreError::new(
                        "store_parse_failed",
                        format!("cannot parse {}: {e}", path.display()),
                    )
                })?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Inventory::default(),
            Err(e) => {
                return Err(StoreError::new(
                    "store_read_failed",
                    format!("cannot stat {}: {e}", path.display()),
                ));
            }
        };
        if inventory.devices.len() > MAX_DEVICES {
            return Err(StoreError::new(
                "store_too_many_devices",
                format!(
                    "inventory holds {} devices; bound is {MAX_DEVICES}",
                    inventory.devices.len()
                ),
            ));
        }
        Ok(Store { path, inventory })
    }

    /// The server home: the directory holding the inventory
    /// file, and therefore every other per-server state file
    /// (MDM state, approval key, profiles).
    pub fn home_dir(&self) -> PathBuf {
        self.path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    pub fn list(&self) -> &[DeviceRecord] {
        &self.inventory.devices
    }

    pub fn get(&self, id: &str) -> Option<&DeviceRecord> {
        self.inventory.devices.iter().find(|d| d.id == id)
    }

    /// Add a device and persist. Ids are unique; a duplicate id is
    /// a refusal, not an overwrite.
    pub fn register(&mut self, record: DeviceRecord) -> Result<(), StoreError> {
        if self.get(&record.id).is_some() {
            return Err(StoreError::new(
                "device_id_taken",
                format!("a device with id {} is already registered", record.id),
            ));
        }
        if self.inventory.devices.len() >= MAX_DEVICES {
            return Err(StoreError::new(
                "store_full",
                format!("inventory bound of {MAX_DEVICES} devices reached"),
            ));
        }
        self.inventory.devices.push(record);
        self.save()
    }

    fn save(&self) -> Result<(), StoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                StoreError::new(
                    "store_write_failed",
                    format!("cannot create {}: {e}", parent.display()),
                )
            })?;
        }
        let text = serde_json::to_string_pretty(&self.inventory).map_err(|e| {
            StoreError::new(
                "store_write_failed",
                format!("cannot serialize inventory: {e}"),
            )
        })?;
        // Write-then-rename so a crash mid-write cannot leave a
        // torn inventory behind.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| {
            StoreError::new(
                "store_write_failed",
                format!("cannot write {}: {e}", tmp.display()),
            )
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            StoreError::new(
                "store_write_failed",
                format!("cannot replace {}: {e}", self.path.display()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Enrollment, Platform};

    fn record(id: &str) -> DeviceRecord {
        DeviceRecord {
            id: id.to_string(),
            label: format!("Device {id}"),
            platform: Platform::Android,
            transport: "192.0.2.1:5555".to_string(),
            enrollment: Enrollment::NotApplicable,
        }
    }

    fn temp_store(tag: &str) -> (PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!("bosun-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("inventory.json");
        let store = Store::load(path.clone()).expect("fresh store loads");
        (path, store)
    }

    #[test]
    fn register_get_list_round_trip_through_disk() {
        let (path, mut store) = temp_store("roundtrip");
        assert!(store.list().is_empty());
        store.register(record("dev-a")).expect("register a");
        store.register(record("dev-b")).expect("register b");
        assert_eq!(store.list().len(), 2);
        let reloaded = Store::load(path).expect("reload");
        assert_eq!(
            reloaded.get("dev-a").map(|d| d.label.as_str()),
            Some("Device dev-a")
        );
        assert!(reloaded.get("dev-nope").is_none());
    }

    #[test]
    fn duplicate_id_is_refused_not_overwritten() {
        let (_path, mut store) = temp_store("dup");
        store.register(record("dev-a")).expect("first register");
        let err = store
            .register(record("dev-a"))
            .expect_err("duplicate must refuse");
        assert_eq!(err.code, "device_id_taken");
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn corrupt_inventory_is_an_error_not_a_reset() {
        let dir = std::env::temp_dir().join(format!("bosun-test-{}-corrupt", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("inventory.json");
        std::fs::write(&path, "{not json").expect("write corrupt file");
        match Store::load(path) {
            Ok(_) => panic!("corrupt file must error, not load"),
            Err(e) => assert_eq!(e.code, "store_parse_failed"),
        }
    }
}
