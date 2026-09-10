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
//! доступ утёкшей сборке, пришлось бы менять пароль всем сразу. Приглашение гасится
//! одной командой, и заведённые по нему устройства при этом продолжают работать.
//!
//! # Чего это НЕ защищает
//!
//! Стоит назвать прямо, чтобы ограничители не выглядели строже, чем они есть.
//! Человек с чужим APK получает возможность создавать очереди на релее — то есть
//! тратить чужой трафик и диск. Он НЕ получает ничьей переписки (она зашифрована
//! от устройства до устройства, сервер её не читает), ни списка людей, ни
//! возможности кому-то написать без ссылки-приглашения от самого человека.
//!
//! Поэтому по умолчанию приглашение бессрочное и без счётчика: так это и работает в
//! SimpleX, где серверы вообще публичные. Ограничители остаются доступными, но это
//! инструмент на случай «раздали не туда», а не политика.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store;

/// Срок по умолчанию: 0 — бессрочно.
pub const DEFAULT_TTL_DAYS: i64 = 0;
/// Число устройств по умолчанию: 0 — без счётчика.
pub const DEFAULT_MAX_USES: u32 = 0;
/// Верхняя граница срока, когда он всё-таки задан. Десять лет — это «пусть будет
/// число», а не политика: бессрочное приглашение задаётся нулём, а не 3650 днями.
const MAX_TTL_DAYS: i64 = 3650;

/// Одно приглашение.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Короткий идентификатор для `hearthctl invite revoke`.
    pub id: String,
    /// Секрет. Едет в сборку и приходит обратно заголовком.
    pub token: String,
    #[serde(with = "crate::model::rfc3339")]
    pub created: DateTime<Utc>,
    /// `None` — бессрочно.
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub expires: Option<DateTime<Utc>>,
    /// `0` — без ограничения по числу устройств.
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
        self.revoked.is_none()
            && self.expires.is_none_or(|expires| now < expires)
            && (self.max_uses == 0 || self.uses < self.max_uses)
    }

    /// Человекочитаемая причина отказа — для `invite list`, не для ответа клиенту.
    pub fn state_at(&self, now: DateTime<Utc>) -> &'static str {
        if self.revoked.is_some() {
            "отозвано"
        } else if self.expires.is_some_and(|expires| now >= expires) {
            "просрочено"
        } else if self.max_uses != 0 && self.uses >= self.max_uses {
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
        // Ноль означает «без ограничения» и для срока, и для счётчика — это обычный
        // случай раздачи. Верхняя граница есть только у заданного срока, и она
        // существует ради одного: поймать `--days 100000`, то есть опечатку.
        if !(0..=MAX_TTL_DAYS).contains(&ttl_days) {
            return Err(Error::invalid(
                "ttl must be 0 (no expiry) or between 1 and 3650 days",
            ));
        }
        let now = Utc::now();
        let invite = Invite {
            // 8 байт: идентификатор не секрет, его называют вслух при отзыве.
            id: store::random_hex(8),
            // 32 байта — столько же, сколько у токена устройства.
            token: store::random_hex(32),
            created: now,
            expires: (ttl_days > 0).then(|| now + Duration::days(ttl_days)),
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
    fn expiry_closes_the_invite_when_a_term_was_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(5, 1, None).unwrap();
        let later = Utc::now() + Duration::days(2);
        assert!(!invite.is_usable_at(later));
        assert!(reg.find_usable(&invite.token, later).is_none());
        assert_eq!(invite.state_at(later), "просрочено");
    }

    #[test]
    fn the_default_invite_never_expires_and_has_no_counter() {
        // Обычный случай раздачи: сборку ставят когда захотят, в том числе через год.
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg
            .create(DEFAULT_MAX_USES, DEFAULT_TTL_DAYS, None)
            .unwrap();
        assert!(invite.expires.is_none());

        let much_later = Utc::now() + Duration::days(3650);
        assert!(invite.is_usable_at(much_later));
        for i in 0..200 {
            reg.note_claim(&invite.id, &format!("device-{i}")).unwrap();
        }
        let after = reg.get(&invite.id).unwrap();
        assert_eq!(after.uses, 200);
        assert!(after.is_usable_at(much_later));
        assert_eq!(after.state_at(much_later), "активно");
    }

    #[test]
    fn revoke_closes_the_invite_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(0, 0, None).unwrap();
        let revoked = reg.revoke(&invite.id).unwrap();
        let first = revoked.revoked.unwrap();
        assert!(reg.find_usable(&invite.token, Utc::now()).is_none());
        let again = reg.revoke(&invite.id).unwrap();
        assert_eq!(again.revoked.unwrap(), first);
    }

    #[test]
    fn revoking_does_not_touch_devices_already_enrolled() {
        // Гасим кран, а не выгоняем людей: у заведённых устройств свои токены, и
        // отзыв приглашения на них не действует — это отдельная команда.
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(0, 0, None).unwrap();
        reg.note_claim(&invite.id, "mama-pixel").unwrap();
        let revoked = reg.revoke(&invite.id).unwrap();
        assert_eq!(revoked.claimed, vec!["mama-pixel"]);
    }

    #[test]
    fn an_absurd_term_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        assert!(reg.create(0, -1, None).is_err());
        assert!(reg.create(0, 100_000, None).is_err());
        // А вот это законно: и без счётчика, и без срока.
        assert!(reg.create(0, 0, None).is_ok());
    }
}
