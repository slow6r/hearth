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
    /// Ключ установки приложения.
    ///
    /// Приложение генерирует его один раз и присылает при заведении. Нужен для
    /// идемпотентности: если ответ узла потерялся в мобильной сети и телефон
    /// повторил запрос, повтор обязан вернуть тот же bundle, а не завести второе
    /// устройство и не съесть второе использование одноразового кода.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_id: Option<String>,
    /// Кто завёл это устройство через `/enroll`.
    ///
    /// Нужен не для истории, а для отзыва: раньше телефон, заведённый с чужого
    /// устройства, переживал отзыв того устройства, и связь между ними существовала
    /// только текстом в `note`. Теперь отзыв гасит и потомков.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<String>,
    /// Секрет устройства для device API (обновления и свежие TURN-креды).
    ///
    /// Отдельный от пароля релея намеренно: пароль релея один на всю семью и внутри
    /// адреса, а этот — свой у каждого устройства. Значит потерянный телефон
    /// отзывается по-настоящему: `device revoke` гасит именно его доступ к узлу, не
    /// трогая остальных. Пароль релея так отозвать нельзя — только ротацией адреса.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
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
            install_id: None,
            enrolled_by: None,
            // Свой секрет на устройство. 32 байта: подбирать нечего, а короче делать
            // незачем — он едет в QR, который человек всё равно не набирает руками.
            token: Some(crate::store::random_hex(32)),
        };
        self.devices.push(device.clone());
        self.save()?;
        Ok(device)
    }

    /// Найти устройство по ключу установки.
    pub fn by_install_id(&self, install_id: &str) -> Option<&Device> {
        self.devices
            .iter()
            .find(|d| d.install_id.as_deref() == Some(install_id) && d.revoked.is_none())
    }

    /// Запомнить ключ установки за устройством.
    pub fn note_install_id(&mut self, id: &str, install_id: &str) -> Result<()> {
        let device = self
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
        device.install_id = Some(install_id.to_string());
        self.save()
    }

    /// Записать, кто завёл это устройство.
    pub fn note_enrolled_by(&mut self, id: &str, parent: &str) -> Result<()> {
        let device = self
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
        device.enrolled_by = Some(parent.to_string());
        self.save()
    }

    /// Физически убрать запись.
    ///
    /// Нужен только для отката: если после `add` заведение сорвалось, запись-призрак
    /// навсегда занимает и слот `max_devices`, и имя. Отзыв для этого не годится —
    /// отозванное устройство остаётся в реестре и продолжает занимать имя.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        let before = self.devices.len();
        self.devices.retain(|d| d.id != id);
        if self.devices.len() != before {
            self.save()?;
        }
        Ok(())
    }

    /// Сколько устройств завело это устройство начиная с указанного момента.
    pub fn children_since(&self, parent: &str, since: DateTime<Utc>) -> usize {
        self.devices
            .iter()
            .filter(|d| d.enrolled_by.as_deref() == Some(parent) && d.created >= since)
            .count()
    }

    /// Mark a device revoked (ТЗ §10.4 п.2). Idempotent.
    ///
    /// Отзыв транзитивен: гаснут и устройства, заведённые этим устройством через
    /// `/enroll`, и их потомки. Иначе один потерянный телефон оставался бы станком
    /// по выпуску устройств, переживающим собственный отзыв.
    pub fn revoke(&mut self, id: &str) -> Result<Device> {
        if self.get(id).is_none() {
            return Err(Error::NotFound(format!("device `{id}`")));
        }
        let now = Utc::now();
        // Обход в ширину: список устройств короткий (десятки), рекурсия не нужна.
        let mut queue = vec![id.to_string()];
        let mut seen: Vec<String> = Vec::new();
        while let Some(current) = queue.pop() {
            if seen.contains(&current) {
                continue;
            }
            seen.push(current.clone());
            let children: Vec<String> = self
                .devices
                .iter()
                .filter(|d| d.enrolled_by.as_deref() == Some(current.as_str()))
                .map(|d| d.id.clone())
                .collect();
            queue.extend(children);
            if let Some(device) = self.get_mut(&current) {
                if device.revoked.is_none() {
                    device.revoked = Some(now);
                }
            }
        }
        let device = self
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
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
    #[test]
    fn revoking_a_device_revokes_what_it_enrolled() {
        // Иначе потерянный телефон переживает собственный отзыв: заведённые им
        // устройства продолжают работать, и связь с ними видна только текстом.
        let (_dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        let child = reg.add("Ребёнок", Platform::Android, None, 10).unwrap();
        let grandchild = reg.add("Внук", Platform::Android, None, 10).unwrap();
        reg.note_enrolled_by(&child.id, &parent.id).unwrap();
        reg.note_enrolled_by(&grandchild.id, &child.id).unwrap();

        reg.revoke(&parent.id).unwrap();

        for id in [&parent.id, &child.id, &grandchild.id] {
            assert!(
                reg.get(id).unwrap().revoked.is_some(),
                "устройство {id} обязано быть отозвано вместе с родителем"
            );
        }
    }

    #[test]
    fn revoking_a_child_leaves_the_parent_alone() {
        let (_dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        let child = reg.add("Ребёнок", Platform::Android, None, 10).unwrap();
        reg.note_enrolled_by(&child.id, &parent.id).unwrap();

        reg.revoke(&child.id).unwrap();

        assert!(reg.get(&child.id).unwrap().revoked.is_some());
        assert!(reg.get(&parent.id).unwrap().revoked.is_none());
    }

    #[test]
    fn removing_frees_the_name_and_the_slot() {
        // Откат после сорвавшегося заведения: отзыв для этого не годится — имя
        // остаётся занятым, и телефон получает 409 навсегда.
        let (_dir, mut reg) = registry();
        let device = reg.add("Телефон", Platform::Android, None, 1).unwrap();
        reg.remove(&device.id).unwrap();

        assert!(reg.get(&device.id).is_none());
        assert!(
            reg.add("Телефон", Platform::Android, None, 1).is_ok(),
            "имя обязано освободиться"
        );
    }

    #[test]
    fn an_install_id_finds_its_device() {
        let (_dir, mut reg) = registry();
        let device = reg.add("Телефон", Platform::Android, None, 10).unwrap();
        reg.note_install_id(&device.id, "install-1").unwrap();

        assert_eq!(reg.by_install_id("install-1").unwrap().id, device.id);
        assert!(reg.by_install_id("install-2").is_none());

        reg.revoke(&device.id).unwrap();
        assert!(
            reg.by_install_id("install-1").is_none(),
            "отозванное устройство не должно отвечать на повтор"
        );
    }

    #[test]
    fn the_daily_budget_counts_only_recent_children() {
        let (_dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        let child = reg.add("Ребёнок", Platform::Android, None, 10).unwrap();
        reg.note_enrolled_by(&child.id, &parent.id).unwrap();

        let day_ago = Utc::now() - chrono::Duration::days(1);
        assert_eq!(reg.children_since(&parent.id, day_ago), 1);
        let tomorrow = Utc::now() + chrono::Duration::days(1);
        assert_eq!(reg.children_since(&parent.id, tomorrow), 0);
    }
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
