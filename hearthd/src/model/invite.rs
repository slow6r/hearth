//! Приглашения — то, чем новое устройство заводит себя само.
//!
//! # Зачем это есть
//!
//! В SimpleX человек ставит приложение и сразу им пользуется: серверы публичные и
//! вшиты в сборку. У нас серверы свои, поэтому телефон надо сначала на них навести —
//! и это единственный шаг, которого в оригинале нет.
//!
//! Приглашение убирает этот шаг: токен кладётся в сборку, при первом запуске
//! приложение обращается к узлу, получает СВОЮ запись в реестре и свой bundle, и
//! экран сканера не показывается вовсе.
//!
//! # Почему не вшить сразу bundle
//!
//! Потому что bundle — это пароли релеев, и вшитый он не отзывается: чтобы закрыть
//! доступ утёкшей сборке, пришлось бы менять пароль всей семье. Приглашение —
//! отдельный секрет с тремя ограничителями: срок, число использований и отзыв. Когда
//! оно кончилось, APK превращается в обычный файл, из которого ничего не достать.
//!
//! Разменивать всё равно приходится: пока приглашение живо, файл сборки ценен, и
//! получивший его войдёт в контур. Поэтому срок по умолчанию короткий, а каждое
//! использование поднимает alert — заведение устройства должно быть заметным.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store;

/// Сколько живёт приглашение, если срок не задан явно.
pub const DEFAULT_TTL_DAYS: i64 = 7;
/// Сколько устройств заводится по одному приглашению, если не задано явно.
pub const DEFAULT_MAX_USES: u32 = 1;

/// Одно приглашение.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Короткий идентификатор для `hearthctl invite revoke`.
    pub id: String,
    /// Секрет. Едет в сборку и приходит обратно заголовком.
    pub token: String,
    #[serde(with = "crate::model::rfc3339")]
    pub created: DateTime<Utc>,
    #[serde(with = "crate::model::rfc3339")]
    pub expires: DateTime<Utc>,
    pub max_uses: u32,
    #[serde(default)]
    pub uses: u32,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub revoked: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// id устройств, заведённых по этому приглашению. Нужен, чтобы при отзыве было
    /// видно, кого именно оно впустило.
    #[serde(default)]
    pub claimed: Vec<String>,
}

impl Invite {
    /// Можно ли им ещё воспользоваться.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked.is_none() && now < self.expires && self.uses < self.max_uses
    }

    /// Человекочитаемая причина отказа — для `invite list`, не для ответа клиенту.
    pub fn state_at(&self, now: DateTime<Utc>) -> &'static str {
        if self.revoked.is_some() {
            "отозвано"
        } else if now >= self.expires {
            "просрочено"
        } else if self.uses >= self.max_uses {
            "исчерпано"
        } else {
            "активно"
        }
    }
}

/// Реестр приглашений (`<state_dir>/invites.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InviteRegistry {
    #[serde(default)]
    pub invites: Vec<Invite>,
    #[serde(skip)]
    path: PathBuf,
}

impl InviteRegistry {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut registry: InviteRegistry = store::read_json(&path)?.unwrap_or_default();
        registry.path = path;
        Ok(registry)
    }

    pub fn save(&self) -> Result<()> {
        store::write_json_atomic(&self.path, self, store::MODE_STATE)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, id: &str) -> Option<&Invite> {
        self.invites.iter().find(|i| i.id == id)
    }

    /// Выписать приглашение.
    pub fn create(&mut self, max_uses: u32, ttl_days: i64, note: Option<String>) -> Result<Invite> {
        if max_uses == 0 {
            return Err(Error::invalid("max_uses must be at least 1"));
        }
        // Верхние границы намеренно жёсткие: приглашение на сто устройств и на год —
        // это уже не приглашение, а второй пароль от узла, который никто не отзовёт.
        if max_uses > 50 {
            return Err(Error::invalid(
                "max_uses above 50 makes the APK a shared key",
            ));
        }
        if !(1..=90).contains(&ttl_days) {
            return Err(Error::invalid("ttl must be between 1 and 90 days"));
        }
        let now = Utc::now();
        let invite = Invite {
            // 8 байт: идентификатор не секрет, его называют вслух при отзыве.
            id: store::random_hex(8),
            // 32 байта — столько же, сколько у токена устройства.
            token: store::random_hex(32),
            created: now,
            expires: now + Duration::days(ttl_days),
            max_uses,
            uses: 0,
            revoked: None,
            note,
            claimed: Vec::new(),
        };
        self.invites.push(invite.clone());
        self.save()?;
        Ok(invite)
    }

    /// Найти пригодное приглашение по токену.
    ///
    /// Сравнение в постоянное время и по ВСЕМ приглашениям, без раннего выхода:
    /// иначе время ответа рассказывало бы, есть ли такой токен и в какой он позиции.
    pub fn find_usable(&self, token: &str, now: DateTime<Utc>) -> Option<&Invite> {
        let mut found: Option<&Invite> = None;
        for invite in &self.invites {
            if crate::deviceapi::ct_eq(&invite.token, token) && invite.is_usable_at(now) {
                found = Some(invite);
            }
        }
        found
    }

    /// Отметить использование. Возвращает обновлённое приглашение.
    pub fn note_claim(&mut self, id: &str, device_id: &str) -> Result<Invite> {
        let invite = self
            .invites
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::NotFound(format!("invite `{id}`")))?;
        invite.uses += 1;
        invite.claimed.push(device_id.to_string());
        let invite = invite.clone();
        self.save()?;
        Ok(invite)
    }

    /// Погасить приглашение. Идемпотентно.
    pub fn revoke(&mut self, id: &str) -> Result<Invite> {
        let invite = self
            .invites
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::NotFound(format!("invite `{id}`")))?;
        if invite.revoked.is_none() {
            invite.revoked = Some(Utc::now());
        }
        let invite = invite.clone();
        self.save()?;
        Ok(invite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(dir: &tempfile::TempDir) -> InviteRegistry {
        InviteRegistry::load(dir.path().join("invites.json")).unwrap()
    }

    #[test]
    fn created_invite_is_usable_and_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(1, 7, Some("тест".into())).unwrap();
        assert!(invite.is_usable_at(Utc::now()));

        let reloaded = InviteRegistry::load(dir.path().join("invites.json")).unwrap();
        assert_eq!(reloaded.invites.len(), 1);
        assert!(reloaded.find_usable(&invite.token, Utc::now()).is_some());
    }

    #[test]
    fn a_wrong_token_finds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(1, 7, None).unwrap();
        let mut wrong = invite.token.clone();
        wrong.pop();
        wrong.push('0');
        assert!(reg.find_usable(&wrong, Utc::now()).is_none());
    }

    #[test]
    fn uses_run_out() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(2, 7, None).unwrap();
        reg.note_claim(&invite.id, "one").unwrap();
        assert!(reg.find_usable(&invite.token, Utc::now()).is_some());
        reg.note_claim(&invite.id, "two").unwrap();
        assert!(reg.find_usable(&invite.token, Utc::now()).is_none());
        assert_eq!(reg.get(&invite.id).unwrap().claimed, vec!["one", "two"]);
    }

    #[test]
    fn expiry_closes_the_invite() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(5, 1, None).unwrap();
        let later = Utc::now() + Duration::days(2);
        assert!(!invite.is_usable_at(later));
        assert!(reg.find_usable(&invite.token, later).is_none());
        assert_eq!(invite.state_at(later), "просрочено");
    }

    #[test]
    fn revoke_closes_the_invite_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(5, 7, None).unwrap();
        let revoked = reg.revoke(&invite.id).unwrap();
        let first = revoked.revoked.unwrap();
        assert!(reg.find_usable(&invite.token, Utc::now()).is_none());
        let again = reg.revoke(&invite.id).unwrap();
        assert_eq!(again.revoked.unwrap(), first);
    }

    #[test]
    fn absurd_limits_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        assert!(reg.create(0, 7, None).is_err());
        assert!(reg.create(51, 7, None).is_err());
        assert!(reg.create(1, 0, None).is_err());
        assert!(reg.create(1, 91, None).is_err());
    }
}
