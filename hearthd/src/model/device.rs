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

    /// Запись об устройстве без секретов — для выгрузки аудиту.
    ///
    /// # Почему проекция, а не фильтр постфактум
    ///
    /// Выгрузка для аудита (`deploy/audit-dump.sh`) существует затем, чтобы
    /// проверяющий увидел состояние узла, не получив ничего лишнего. Наивный дамп
    /// реестра устройств был бы утечкой ровно одним полем — [`Device::token`], тем
    /// самым, которым телефон качает обновления и берёт TURN-креды.
    ///
    /// Вырезать его `jq`'ом на выходе — значит поставить защиту в место, где о ней
    /// забудут при первой правке: новое секретное поле в `Device` не заметит ни
    /// фильтр, ни человек. Проекция ведёт себя наоборот — новое поле в неё придётся
    /// ДОБАВИТЬ руками, и худшее, что даёт забывчивость, — неполный отчёт.
    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            id: self.id.clone(),
            name: self.name.clone(),
            platform: self.platform,
            created: self.created,
            revoked: self.revoked,
            bundles_issued: self.bundles_issued,
            last_bundle: self.last_bundle,
            note: self.note.clone(),
            enrolled_by: self.enrolled_by.clone(),
            has_token: self.token.is_some(),
        }
    }
}

/// Устройство без секретов: то же самое, но без [`Device::token`] и без
/// `install_id`.
///
/// `install_id` убран не как секрет (он и не секрет), а как ключ идемпотентности:
/// знание чужого `install_id` — половина того, что нужно для повтора заведения, и
/// выгрузке он не нужен ни для чего.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublic {
    pub id: String,
    pub name: String,
    pub platform: Platform,
    #[serde(with = "crate::model::rfc3339")]
    pub created: DateTime<Utc>,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub revoked: Option<DateTime<Utc>>,
    #[serde(default)]
    pub bundles_issued: u32,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub last_bundle: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<String>,
    /// Выдан ли устройству токен device API. Сам токен не выдаётся никогда.
    pub has_token: bool,
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

    /// Действует ли доступ устройства — с учётом того, кто его завёл.
    ///
    /// Собственного поля `revoked` мало. [`revoke`](Self::revoke) гасит потомков одним
    /// обходом в момент вызова, и запись, появившаяся ПОСЛЕ обхода, в него не попадёт
    /// — а больше её никто не проверит. Поэтому право предъявить токен решается по
    /// цепочке `enrolled_by`: отозван предок — отозван и потомок. Это делает исход
    /// гонки «отзыв против заведения» безвредным и без всяких блокировок.
    ///
    /// Оборванная цепочка (родителя в реестре нет) и замкнутая в кольцо (файл правят
    /// руками) обе означают отказ: держать доступ не на чем, а зацикливаться узлу
    /// нельзя.
    pub fn is_usable(&self, id: &str) -> bool {
        let mut seen: Vec<&str> = Vec::new();
        let mut current = id;
        loop {
            let Some(device) = self.get(current) else {
                return false;
            };
            if device.revoked.is_some() || seen.contains(&current) {
                return false;
            }
            seen.push(current);
            match device.enrolled_by.as_deref() {
                Some(parent) => current = parent,
                None => return true,
            }
        }
    }

    /// Устройства, чей доступ действует. Именно по ним ищется предъявленный токен.
    pub fn usable(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().filter(|d| self.is_usable(&d.id))
    }

    /// Register a device. Fails on duplicate id or when the circle is full.
    pub fn add(
        &mut self,
        name: &str,
        platform: Platform,
        note: Option<String>,
        max_devices: usize,
    ) -> Result<Device> {
        let device = self.prepare(name, platform, note, max_devices, None, None)?;
        self.commit(device)
    }

    /// Собрать запись и убедиться, что для неё есть место. Реестр не меняется.
    ///
    /// Отделено от записи ради одного: `enrolled_by` и `install_id` обязаны быть в
    /// записи СРАЗУ, а не проставляться шагом позже. Шаг позже — это мгновение, в
    /// котором запись уже есть, а родства или ключа идемпотентности у неё ещё нет: в
    /// первом случае отзыв родителя не гасит ребёнка, во втором повтор заводит
    /// дубликат. Падение процесса в этом мгновении делает такую запись вечной.
    fn prepare(
        &self,
        name: &str,
        platform: Platform,
        note: Option<String>,
        max_devices: usize,
        install_id: Option<&str>,
        enrolled_by: Option<&str>,
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
        Ok(Device {
            id,
            name: name.to_string(),
            platform,
            created: Utc::now(),
            revoked: None,
            bundles_issued: 0,
            last_bundle: None,
            note,
            install_id: install_id.map(str::to_string),
            enrolled_by: enrolled_by.map(str::to_string),
            // Свой секрет на устройство. 32 байта: подбирать нечего, а короче делать
            // незачем — он едет в QR, который человек всё равно не набирает руками.
            token: Some(crate::store::random_hex(32)),
        })
    }

    /// Записать подготовленную запись: сначала в память, следом на диск.
    ///
    /// При отказе диска запись снимается обратно. Иначе она живёт в памяти процесса
    /// до перезапуска — занимает имя и слот в круге, — а после перезапуска исчезает:
    /// то, что видит процесс, расходится с тем, что переживёт рестарт.
    fn commit(&mut self, device: Device) -> Result<Device> {
        self.devices.push(device.clone());
        if let Err(e) = self.save() {
            self.devices.pop();
            return Err(e);
        }
        Ok(device)
    }

    /// Завести устройство ПО ПРОСЬБЕ уже заведённого — одним неделимым действием.
    ///
    /// Проверка приглашающего, суточный бюджет и создание записи происходят под одним
    /// `&mut self`. Раньше это были четыре независимых захвата блокировки, и отзыв
    /// приглашающего, прошедший между ними, оставлял заведённое устройство с рабочим
    /// доступом: обход потомков его ещё не видел, а повторно приглашающего никто не
    /// проверял.
    pub fn add_child(
        &mut self,
        name: &str,
        platform: Platform,
        note: Option<String>,
        max_devices: usize,
        parent: &str,
        max_per_day: usize,
    ) -> std::result::Result<Device, EnrollError> {
        if !self.is_usable(parent) {
            return Err(EnrollError::InviterRevoked);
        }
        // Бюджет считается здесь же: снаружи он считался по другому снимку реестра.
        let since = Utc::now() - chrono::Duration::days(1);
        let recent = self.children_since(parent, since);
        if recent >= max_per_day {
            return Err(EnrollError::BudgetExhausted(recent));
        }
        let device = self
            .prepare(name, platform, note, max_devices, None, Some(parent))
            .map_err(EnrollError::Refused)?;
        self.commit(device).map_err(EnrollError::Storage)
    }

    /// Найти устройство по ключу установки — только то, чей доступ действует.
    pub fn by_install_id(&self, install_id: &str) -> Option<&Device> {
        self.devices
            .iter()
            .find(|d| d.install_id.as_deref() == Some(install_id) && self.is_usable(&d.id))
    }

    /// То же, но не глядя на отзыв.
    ///
    /// Нужен там, где «такой установки нет» и «эту установку из круга выгнали» — два
    /// разных ответа: во втором случае заводить её заново под новым именем нельзя,
    /// иначе отзыв отменяется первым же живым кодом.
    pub fn by_install_id_any(&self, install_id: &str) -> Option<&Device> {
        self.devices
            .iter()
            .find(|d| d.install_id.as_deref() == Some(install_id))
    }

    /// Завести устройство ПО ПРИГЛАШЕНИЮ — или вернуть уже заведённое.
    ///
    /// Второй элемент ответа — «это повтор»: вызывающий по нему возвращает занятое
    /// использование приглашения, потому что нового устройства не появилось.
    ///
    /// Проверка ключа установки и создание записи происходят под одним `&mut self`, а
    /// сам ключ проставляется в момент создания. Раньше это были три операции, и
    /// между ними телефон, повторивший запрос после обрыва, успевал завестись дважды.
    pub fn claim_device(
        &mut self,
        install_id: Option<&str>,
        requested_name: &str,
        platform: Platform,
        note: Option<String>,
        max_devices: usize,
    ) -> Result<(Device, bool)> {
        if let Some(install_id) = install_id {
            if let Some(device) = self.by_install_id_any(install_id).cloned() {
                if self.is_usable(&device.id) {
                    return Ok((device, true));
                }
                return Err(Error::Unauthorized(format!(
                    "установка `{install_id}` отозвана вместе с устройством `{}`",
                    device.id
                )));
            }
        }
        // Имя приходит от приложения — это модель телефона, и два одинаковых телефона
        // в семье не редкость. Совпадение имени не повод отказать человеку в
        // заведении, поэтому подбираем свободное, а не отвечаем 409, как это делает
        // `/enroll`, где имя набирает человек и повтор — почти всегда его опечатка.
        let mut attempt = 0;
        let device = loop {
            let name = if attempt == 0 {
                requested_name.to_string()
            } else {
                format!("{requested_name} {}", attempt + 1)
            };
            match self.prepare(&name, platform, note.clone(), max_devices, install_id, None) {
                Ok(device) => break device,
                Err(Error::Conflict(_)) if attempt < 9 => attempt += 1,
                Err(e) => return Err(e),
            }
        };
        let device = self.commit(device)?;
        Ok((device, false))
    }

    /// Запомнить ключ установки за устройством.
    pub fn note_install_id(&mut self, id: &str, install_id: &str) -> Result<()> {
        let device = self
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
        let previous = device.install_id.replace(install_id.to_string());
        if let Err(e) = self.save() {
            // Память обязана совпасть с тем, что переживёт перезапуск: иначе процесс
            // считает ключ записанным, а после рестарта его нет — и повтор заводит
            // дубликат ровно тогда, когда узлу и без того плохо.
            if let Some(device) = self.get_mut(id) {
                device.install_id = previous;
            }
            return Err(e);
        }
        Ok(())
    }

    /// Записать, кто завёл это устройство.
    pub fn note_enrolled_by(&mut self, id: &str, parent: &str) -> Result<()> {
        let device = self
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
        let previous = device.enrolled_by.replace(parent.to_string());
        if let Err(e) = self.save() {
            if let Some(device) = self.get_mut(id) {
                device.enrolled_by = previous;
            }
            return Err(e);
        }
        Ok(())
    }

    /// Физически убрать запись.
    ///
    /// Нужен только для отката: если после `add` заведение сорвалось, запись-призрак
    /// навсегда занимает и слот `max_devices`, и имя. Отзыв для этого не годится —
    /// отозванное устройство остаётся в реестре и продолжает занимать имя.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        let Some(index) = self.devices.iter().position(|d| d.id == id) else {
            return Ok(());
        };
        let removed = self.devices.remove(index);
        if let Err(e) = self.save() {
            // Откат отката: если запись не удалось убрать с диска, она обязана
            // остаться и в памяти. Иначе после перезапуска «убранная» запись
            // воскресает и снова занимает имя, которое процесс считал свободным.
            self.devices.insert(index, removed);
            return Err(e);
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
        let mut marked: Vec<String> = Vec::new();
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
                    marked.push(current);
                }
            }
        }
        let device = self
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
        if let Err(e) = self.save() {
            // Отзыв, оставшийся только в памяти, — худший исход из возможных: админ
            // видит ошибку и считает, что отзыв не прошёл, процесс до перезапуска
            // ведёт себя как «отозвано», а после перезапуска отзыва нет вовсе.
            // Снимаем отметку ровно с тех, кому её поставили этим вызовом.
            for id in &marked {
                if let Some(device) = self.get_mut(id) {
                    device.revoked = None;
                }
            }
            return Err(e);
        }
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
        let previous = (device.bundles_issued, device.last_bundle);
        device.bundles_issued += 1;
        device.last_bundle = Some(Utc::now());
        let device = device.clone();
        if let Err(e) = self.save() {
            if let Some(device) = self.get_mut(id) {
                (device.bundles_issued, device.last_bundle) = previous;
            }
            return Err(e);
        }
        Ok(device)
    }
}

/// Почему заведение «с уже заведённого устройства» не состоялось.
///
/// Отдельный тип, а не текст внутри [`Error`]: вызывающий отвечает на каждый случай
/// по-своему — отказ доступа, исчерпанный бюджет, занятое имя, отказ диска, — и
/// различать их разбором строки значит однажды ответить 409 там, где надо 401.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    /// Приглашающего нет, он отозван или отозван кто-то из его предков.
    #[error("приглашающее устройство отозвано или неизвестно")]
    InviterRevoked,
    /// Суточный бюджет исчерпан; внутри — сколько уже заведено за сутки.
    #[error("суточный бюджет исчерпан: за сутки заведено {0}")]
    BudgetExhausted(usize),
    /// Имя занято, пустое или круг полон — ответ запросу, а не ошибка узла.
    #[error("{0}")]
    Refused(#[source] Error),
    /// Реестр не удалось записать на диск.
    #[error("{0}")]
    Storage(#[source] Error),
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

    /// Именно этот тест отделяет выгрузку для аудита от утечки: в обезличенной
    /// проекции не должно быть токена устройства ни в каком виде.
    #[test]
    fn the_public_projection_carries_no_device_token() {
        let (_dir, mut reg) = registry();
        let device = reg
            .add("Мама — Pixel 8", Platform::Android, Some("note".into()), 10)
            .expect("add");
        let secret = device.token.clone().expect("токен выдаётся при заведении");

        let json = serde_json::to_string(&device.public()).expect("json");
        assert!(
            !json.contains(&secret),
            "секрет устройства попал в обезличенную проекцию: {json}"
        );
        assert!(
            !json.contains("\"token\""),
            "поля token быть не должно: {json}"
        );
        assert!(!json.contains("install_id"), "{json}");

        // Полезное при этом сохранено: без него отчёт бессмысленен.
        assert!(json.contains("mama-pixel-8"));
        assert!(json.contains("\"has_token\":true"));

        // И весь список целиком — тоже без секретов.
        let all: Vec<DevicePublic> = reg.devices.iter().map(Device::public).collect();
        let json = serde_json::to_string(&all).expect("json");
        assert!(!json.contains(&secret), "{json}");
    }

    fn registry() -> (tempfile::TempDir, DeviceRegistry) {
        let dir = tempfile::tempdir().expect("tempdir");
        let reg = DeviceRegistry::load(dir.path().join("devices.json")).expect("load");
        (dir, reg)
    }

    /// Сломать запись реестра: на месте файла — каталог, и переименовать временный
    /// файл поверх него нельзя ни на одной системе. Так воспроизводится отказ диска.
    fn break_writing(dir: &tempfile::TempDir) {
        let path = dir.path().join("devices.json");
        if path.is_file() {
            std::fs::remove_file(&path).expect("убрать файл");
        }
        std::fs::create_dir(&path).expect("занять имя каталогом");
    }

    #[test]
    fn a_revoked_inviter_cannot_enrol_anyone() {
        // Ровно та гонка, ради которой заведение стало одной транзакцией: раньше
        // проверка приглашающего и создание записи были разными захватами, и отзыв,
        // прошедший между ними, оставлял ребёнка с рабочим доступом.
        let (_dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        reg.revoke(&parent.id).unwrap();

        let err = reg
            .add_child("Ребёнок", Platform::Android, None, 10, &parent.id, 5)
            .unwrap_err();
        assert!(
            matches!(err, EnrollError::InviterRevoked),
            "получено {err:?}"
        );
        assert_eq!(reg.devices.len(), 1, "реестр не должен вырасти");
    }

    #[test]
    fn a_child_that_slipped_past_a_revocation_cannot_use_its_token() {
        // Исход гонки, если она всё-таки состоялась: у ребёнка собственное поле
        // revoked пустое, потому что обход потомков его не застал. Право предъявить
        // токен всё равно обязано считаться по цепочке.
        let (_dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        let child = reg.add("Ребёнок", Platform::Android, None, 10).unwrap();
        reg.note_enrolled_by(&child.id, &parent.id).unwrap();
        // Гасим родителя в обход revoke(), иначе обход потомков задел бы ребёнка.
        reg.get_mut(&parent.id).unwrap().revoked = Some(Utc::now());

        assert!(reg.get(&child.id).unwrap().revoked.is_none());
        assert!(!reg.is_usable(&child.id), "предок отозван — доступа нет");
        assert_eq!(reg.usable().count(), 0);
    }

    #[test]
    fn a_broken_parent_link_is_refused_and_a_cycle_does_not_hang() {
        let (_dir, mut reg) = registry();
        let device = reg.add("Телефон", Platform::Android, None, 10).unwrap();
        reg.note_enrolled_by(&device.id, "кого-нет").unwrap();
        assert!(!reg.is_usable(&device.id), "держать доступ не на чем");

        reg.get_mut(&device.id).unwrap().enrolled_by = Some(device.id.clone());
        assert!(
            !reg.is_usable(&device.id),
            "кольцо — это отказ, а не вечный цикл"
        );
    }

    #[test]
    fn the_daily_budget_is_spent_inside_the_same_transaction() {
        let (_dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        reg.add_child("Первый", Platform::Android, None, 10, &parent.id, 1)
            .unwrap();

        let err = reg
            .add_child("Второй", Platform::Android, None, 10, &parent.id, 1)
            .unwrap_err();
        assert!(
            matches!(err, EnrollError::BudgetExhausted(1)),
            "получено {err:?}"
        );
    }

    #[test]
    fn add_child_records_the_parent_in_the_same_write() {
        // Родство проставлялось вторым шагом, и между шагами запись существовала без
        // него: отзыв родителя такого ребёнка не находил.
        let (dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        let child = reg
            .add_child("Ребёнок", Platform::Android, None, 10, &parent.id, 5)
            .unwrap();
        assert_eq!(child.enrolled_by.as_deref(), Some(parent.id.as_str()));

        let reloaded = DeviceRegistry::load(dir.path().join("devices.json")).unwrap();
        assert_eq!(
            reloaded.get(&child.id).unwrap().enrolled_by.as_deref(),
            Some(parent.id.as_str()),
            "родство обязано быть на диске уже после первой записи"
        );
    }

    #[test]
    fn a_failed_write_leaves_no_ghost() {
        let (dir, mut reg) = registry();
        break_writing(&dir);

        assert!(reg.add("Телефон", Platform::Android, None, 10).is_err());
        assert!(
            reg.devices.is_empty(),
            "запись, не попавшая на диск, не должна занимать имя и слот в памяти"
        );
    }

    #[test]
    fn a_failed_write_does_not_revoke_in_memory_only() {
        // Худший исход кластера: админ видит ошибку и считает, что отзыв не прошёл,
        // процесс до перезапуска ведёт себя как «отозвано», а после — как будто
        // отзыва не было вовсе.
        let (dir, mut reg) = registry();
        let parent = reg.add("Родитель", Platform::Android, None, 10).unwrap();
        let child = reg
            .add_child("Ребёнок", Platform::Android, None, 10, &parent.id, 5)
            .unwrap();
        break_writing(&dir);

        assert!(reg.revoke(&parent.id).is_err());
        assert!(reg.get(&parent.id).unwrap().revoked.is_none());
        assert!(
            reg.get(&child.id).unwrap().revoked.is_none(),
            "потомку отметку тоже обязаны снять"
        );
    }

    #[test]
    fn a_failed_write_does_not_count_a_bundle_or_drop_a_record() {
        let (dir, mut reg) = registry();
        let device = reg.add("Телефон", Platform::Android, None, 10).unwrap();
        break_writing(&dir);

        assert!(reg.note_bundle_issued(&device.id).is_err());
        assert_eq!(reg.get(&device.id).unwrap().bundles_issued, 0);
        assert!(reg.get(&device.id).unwrap().last_bundle.is_none());

        assert!(reg.remove(&device.id).is_err());
        assert!(
            reg.get(&device.id).is_some(),
            "не убранная с диска запись обязана остаться и в памяти"
        );
    }

    #[test]
    fn a_claim_is_idempotent_by_install_id() {
        let (dir, mut reg) = registry();
        let (first, repeat) = reg
            .claim_device(Some("inst-1"), "Pixel 8", Platform::Android, None, 10)
            .unwrap();
        assert!(!repeat);
        assert_eq!(first.install_id.as_deref(), Some("inst-1"));
        let reloaded = DeviceRegistry::load(dir.path().join("devices.json")).unwrap();
        assert_eq!(
            reloaded.get(&first.id).unwrap().install_id.as_deref(),
            Some("inst-1"),
            "ключ обязан быть на диске уже после первой записи"
        );

        let (second, repeat) = reg
            .claim_device(Some("inst-1"), "Pixel 8", Platform::Android, None, 10)
            .unwrap();
        assert!(repeat, "повтор не заводит второе устройство");
        assert_eq!(second.id, first.id);
        assert_eq!(reg.devices.len(), 1);
    }

    #[test]
    fn a_revoked_install_does_not_come_back_under_a_new_name() {
        // Раньше отзыв держался ровно до следующего claim: ключ установки искался
        // только среди действующих, и та же установка заводилась заново.
        let (_dir, mut reg) = registry();
        let (device, _) = reg
            .claim_device(Some("inst-1"), "Pixel 8", Platform::Android, None, 10)
            .unwrap();
        reg.revoke(&device.id).unwrap();

        let err = reg
            .claim_device(Some("inst-1"), "Pixel 8", Platform::Android, None, 10)
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)), "получено {err:?}");
        assert_eq!(reg.devices.len(), 1);
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
