//! Device registry (ТЗ §7.3 config-gen, §10.3, §10.4).
//!
//! hearthd knows *that* a device exists and when it was issued a bundle. It does not
//! know the device's contacts, profile or address — the relay does not have that
//! information and neither should the control plane.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::slugify;
use crate::store;

/// Client platform. Drives which onboarding instructions hearthd emits (ТЗ §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Kotlin config-fork, imports the bundle from one QR (ТЗ §8.2 п.7).
    Android,
    /// Stock app in v1: needs the manual 6-step checklist (ТЗ §9).
    Ios,
    /// Stock desktop app, manual config.
    Desktop,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Platform::Android => "android",
            Platform::Ios => "ios",
            Platform::Desktop => "desktop",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for Platform {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "android" => Ok(Platform::Android),
            "ios" | "iphone" | "ipad" => Ok(Platform::Ios),
            "desktop" | "pc" => Ok(Platform::Desktop),
            other => Err(Error::invalid(format!(
                "unknown platform `{other}` (android|ios|desktop)"
            ))),
        }
    }
}

/// One enrolled device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Slug used in URLs and bundles, e.g. `mama-pixel-8`.
    pub id: String,
    /// Human name as the owner typed it, e.g. `Мама — Pixel 8`.
    pub name: String,
    pub platform: Platform,
    #[serde(with = "crate::model::rfc3339")]
    pub created: DateTime<Utc>,
    /// Set by `hearthctl device revoke` (ТЗ §10.4).
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub revoked: Option<DateTime<Utc>>,
    #[serde(default)]
    pub bundles_issued: u32,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub last_bundle: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Device {
    pub fn is_active(&self) -> bool {
        self.revoked.is_none()
    }
}

/// The persisted registry (`/etc/hearth/devices.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceRegistry {
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(skip)]
    path: PathBuf,
}

impl DeviceRegistry {
    /// Load the registry, or start an empty one when the file does not exist yet.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut registry: DeviceRegistry = store::read_json(&path)?.unwrap_or_default();
        registry.path = path;
        Ok(registry)
    }

    pub fn save(&self) -> Result<()> {
        store::write_json_atomic(&self.path, self, store::MODE_STATE)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, id: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.id == id)
    }

    pub fn active(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().filter(|d| d.is_active())
    }

    /// Register a device. Fails on duplicate id or when the circle is full.
    pub fn add(
        &mut self,
        name: &str,
        platform: Platform,
        note: Option<String>,
        max_devices: usize,
    ) -> Result<Device> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::invalid("device name must not be empty"));
        }
        let id = slugify(name);
        if id.is_empty() {
            return Err(Error::invalid(format!(
                "device name `{name}` produces an empty id; use latin or cyrillic letters"
            )));
        }
        if self.get(&id).is_some() {
            return Err(Error::Conflict(format!("device `{id}` already exists")));
        }
        if self.active().count() >= max_devices {
            return Err(Error::Conflict(format!(
                "device limit reached ({max_devices}); revoke a device first (ТЗ §1.1)"
            )));
        }
        let device = Device {
            id,
            name: name.to_string(),
            platform,
            created: Utc::now(),
            revoked: None,
            bundles_issued: 0,
            last_bundle: None,
            note,
        };
        self.devices.push(device.clone());
        self.save()?;
        Ok(device)
    }

    /// Mark a device revoked (ТЗ §10.4 п.2). Idempotent.
    pub fn revoke(&mut self, id: &str) -> Result<Device> {
        let device = self
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
        if device.revoked.is_none() {
            device.revoked = Some(Utc::now());
        }
        let device = device.clone();
        self.save()?;
        Ok(device)
    }

    /// Record that a bundle was handed out. Refuses revoked devices.
    pub fn note_bundle_issued(&mut self, id: &str) -> Result<Device> {
        let device = self
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
        if device.revoked.is_some() {
            return Err(Error::Conflict(format!(
                "device `{id}` is revoked; a bundle must not be issued to it"
            )));
        }
        device.bundles_issued += 1;
        device.last_bundle = Some(Utc::now());
        let device = device.clone();
        self.save()?;
        Ok(device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> (tempfile::TempDir, DeviceRegistry) {
        let dir = tempfile::tempdir().expect("tempdir");
        let reg = DeviceRegistry::load(dir.path().join("devices.json")).expect("load");
        (dir, reg)
    }

    #[test]
    fn adds_and_persists() {
        let (dir, mut reg) = registry();
        let device = reg
            .add("Мама — Pixel 8", Platform::Android, None, 20)
            .expect("add");
        assert_eq!(device.id, "mama-pixel-8");
        let reloaded = DeviceRegistry::load(dir.path().join("devices.json")).expect("reload");
        assert_eq!(reloaded.devices.len(), 1);
        assert_eq!(reloaded.devices[0].name, "Мама — Pixel 8");
    }

    #[test]
    fn rejects_duplicates() {
        let (_dir, mut reg) = registry();
        reg.add("Pixel 8", Platform::Android, None, 20)
            .expect("add");
        let err = reg.add("pixel 8", Platform::Android, None, 20).unwrap_err();
        assert!(matches!(err, Error::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn enforces_the_closed_circle_limit() {
        let (_dir, mut reg) = registry();
        for i in 0..3 {
            reg.add(&format!("dev{i}"), Platform::Android, None, 3)
                .expect("add");
        }
        let err = reg.add("dev4", Platform::Android, None, 3).unwrap_err();
        assert!(
            err.to_string().contains("device limit reached"),
            "got {err}"
        );
    }

    #[test]
    fn revoking_frees_a_slot_and_blocks_bundles() {
        let (_dir, mut reg) = registry();
        reg.add("dev1", Platform::Android, None, 1).expect("add");
        reg.revoke("dev1").expect("revoke");
        assert!(reg.note_bundle_issued("dev1").is_err());
        reg.add("dev2", Platform::Android, None, 1)
            .expect("slot freed by revocation");
    }

    #[test]
    fn counts_bundles() {
        let (_dir, mut reg) = registry();
        reg.add("dev1", Platform::Android, None, 20).expect("add");
        reg.note_bundle_issued("dev1").expect("issue");
        let device = reg.note_bundle_issued("dev1").expect("issue");
        assert_eq!(device.bundles_issued, 2);
        assert!(device.last_bundle.is_some());
    }

    #[test]
    fn platform_parsing() {
        assert_eq!("android".parse::<Platform>().expect("p"), Platform::Android);
        assert_eq!("iPhone".parse::<Platform>().expect("p"), Platform::Ios);
        assert!("symbian".parse::<Platform>().is_err());
    }
}
