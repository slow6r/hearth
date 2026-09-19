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
    /// Можно ли им ещё воспользоваться — завести НОВОЕ устройство.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.is_open_at(now) && (self.max_uses == 0 || self.uses < self.max_uses)
    }

    /// Открыта ли дверь — без учёта счётчика использований.
    ///
    /// Отзыв и срок ставит человек: это решения «закрыто», и обходить их нечем.
    /// Счётчик — другое: он ограничивает, сколько НОВЫХ устройств войдёт, и к повтору
    /// после потерянного ответа отношения не имеет — повтор ничего не заводит и
    /// ничего не тратит. Если бы повтор требовал `is_usable_at`, идемпотентность не
    /// работала бы ровно там, ради чего заводилась: у одноразового кода использование
    /// к моменту повтора уже списано.
    pub fn is_open_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked.is_none() && self.expires.is_none_or(|expires| now < expires)
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
            // Код доступа: его человек получает лично и печатает руками, поэтому
            // не случайные байты, а формат из `model::code` (12 знаков, 60 бит).
            token: crate::model::code::generate(),
            created: now,
            expires: (ttl_days > 0).then(|| now + Duration::days(ttl_days)),
            max_uses,
            uses: 0,
            revoked: None,
            note,
            claimed: Vec::new(),
        };
        self.invites.push(invite.clone());
        if let Err(e) = self.save() {
            // Приглашение, которое есть в памяти и которого нет на диске, — это код,
            // работающий до ближайшего перезапуска. Человеку его уже назвали.
            self.invites.pop();
            return Err(e);
        }
        Ok(invite)
    }

    /// Найти пригодное приглашение по предъявленному коду.
    ///
    /// Сравнение в постоянное время и по ВСЕМ приглашениям, без раннего выхода:
    /// иначе время ответа рассказывало бы, есть ли такой код и в какой он позиции.
    ///
    /// Сравнений на каждое приглашение два, и оба выполняются всегда (`|`, а не `||`).
    /// Так вышло не из любви к симметрии: в реестре одновременно живут коды, которые
    /// человек печатает как умеет, и старые шестнадцатеричные токены из вшитых сборок.
    /// Первые надо приводить к каноническому виду, вторые — нет.
    pub fn find_usable(&self, token: &str, now: DateTime<Utc>) -> Option<&Invite> {
        let typed = token.trim();
        let canonical = crate::model::code::normalize(typed);
        let mut found: Option<&Invite> = None;
        for invite in &self.invites {
            let matches = crate::deviceapi::ct_eq(&invite.token, typed)
                | crate::deviceapi::ct_eq(&invite.token, &canonical);
            if matches && invite.is_usable_at(now) {
                found = Some(invite);
            }
        }
        found
    }

    /// Найти приглашение, по которому это устройство уже завелось.
    ///
    /// Этим повтор доказывает своё право на bundle. Раньше повтор не смотрел на код
    /// вовсе: любой непустой заголовок вместе с чужим `install_id` отдавал пароли
    /// релеев. `install_id` секретом не задумывался — он лежит в открытом виде на
    /// телефоне и целиком отдаётся в `GET /devices`, — поэтому предъявлять надо ТОТ
    /// ЖЕ код, по которому устройство завелось.
    ///
    /// Сравнение в постоянное время и по всем записям — та же причина, что и в
    /// [`find_usable`](Self::find_usable). Счётчик использований не смотрим, см.
    /// [`Invite::is_open_at`].
    pub fn find_repeat(&self, token: &str, device_id: &str, now: DateTime<Utc>) -> Option<&Invite> {
        let typed = token.trim();
        let canonical = crate::model::code::normalize(typed);
        let mut found: Option<&Invite> = None;
        for invite in &self.invites {
            let matches = crate::deviceapi::ct_eq(&invite.token, typed)
                | crate::deviceapi::ct_eq(&invite.token, &canonical);
            if matches && invite.is_open_at(now) && invite.claimed.iter().any(|d| d == device_id) {
                found = Some(invite);
            }
        }
        found
    }

    /// Занять использование одним неделимым действием.
    ///
    /// Раньше проверка (`find_usable` под read-lock) и списание (`note_claim` под
    /// write-lock) были двумя операциями, и между ними существовало окно. Десять
    /// одновременных запросов с одним одноразовым кодом проходили проверку все
    /// десять раз: код, выписанный «на одно устройство», заводил столько устройств,
    /// сколько запросов успело войти в окно. Здесь проверка и списание происходят
    /// под одним `&mut self`, поэтому окна нет.
    ///
    /// Если дальнейшие шаги заведения не удались, использование возвращается
    /// через [`release`](Self::release) — иначе честная попытка съедала бы код.
    pub fn reserve(&mut self, token: &str, now: DateTime<Utc>) -> Result<Invite> {
        let typed = token.trim();
        let canonical = crate::model::code::normalize(typed);
        // Проход по всем без раннего выхода — та же причина, что и в find_usable:
        // время ответа не должно рассказывать, есть ли такой код и где он лежит.
        let mut found: Option<usize> = None;
        for (index, invite) in self.invites.iter().enumerate() {
            let matches = crate::deviceapi::ct_eq(&invite.token, typed)
                | crate::deviceapi::ct_eq(&invite.token, &canonical);
            if matches && invite.is_usable_at(now) {
                found = Some(index);
            }
        }
        let index = found.ok_or_else(|| Error::NotFound("invite".to_string()))?;
        self.invites[index].uses += 1;
        if let Err(e) = self.save() {
            // Отказ диска не должен съедать использование: снаружи он отличается от
            // «неизвестный код» только типом ошибки, а для человека с одноразовым
            // кодом разница между ними — войдёт он в контур или нет.
            self.invites[index].uses -= 1;
            return Err(e);
        }
        Ok(self.invites[index].clone())
    }

    /// Вернуть занятое использование: заведение не состоялось.
    pub fn release(&mut self, id: &str) -> Result<()> {
        if let Some(invite) = self.invites.iter_mut().find(|i| i.id == id) {
            let previous = invite.uses;
            invite.uses = invite.uses.saturating_sub(1);
            if let Err(e) = self.save() {
                if let Some(invite) = self.invites.iter_mut().find(|i| i.id == id) {
                    invite.uses = previous;
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Привязать заведённое устройство к приглашению.
    ///
    /// Отдельно от списания: списание обязано произойти до заведения (иначе гонка),
    /// а id устройства появляется только после него.
    pub fn note_device(&mut self, id: &str, device_id: &str) -> Result<()> {
        let invite = self
            .invites
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::NotFound(format!("invite `{id}`")))?;
        invite.claimed.push(device_id.to_string());
        if let Err(e) = self.save() {
            if let Some(invite) = self.invites.iter_mut().find(|i| i.id == id) {
                invite.claimed.pop();
            }
            return Err(e);
        }
        Ok(())
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
        if let Err(e) = self.save() {
            if let Some(invite) = self.invites.iter_mut().find(|i| i.id == id) {
                invite.uses -= 1;
                invite.claimed.pop();
            }
            return Err(e);
        }
        Ok(invite)
    }

    /// Погасить приглашение. Идемпотентно.
    pub fn revoke(&mut self, id: &str) -> Result<Invite> {
        let invite = self
            .invites
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::NotFound(format!("invite `{id}`")))?;
        let previous = invite.revoked;
        if invite.revoked.is_none() {
            invite.revoked = Some(Utc::now());
        }
        let invite = invite.clone();
        if let Err(e) = self.save() {
            // Погашенный только в памяти код после перезапуска снова свежий, а
            // человек уже услышал «отозвано».
            if let Some(invite) = self.invites.iter_mut().find(|i| i.id == id) {
                invite.revoked = previous;
            }
            return Err(e);
        }
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
        let last = wrong.pop().unwrap();
        wrong.push(if last == '0' { '1' } else { '0' });
        assert!(reg.find_usable(&wrong, Utc::now()).is_none());
    }

    #[test]
    fn an_issued_token_is_an_access_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(5, 0, None).unwrap();
        assert!(
            crate::model::code::is_code(&invite.token),
            "выписан не код: {}",
            invite.token
        );
    }

    #[test]
    fn a_code_is_accepted_the_way_a_person_types_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(5, 0, None).unwrap();
        let now = Utc::now();
        for typed in [
            crate::model::code::format_groups(&invite.token),
            invite.token.to_lowercase(),
            format!("  {}  ", crate::model::code::format_groups(&invite.token)),
        ] {
            assert_eq!(
                reg.find_usable(&typed, now).map(|i| i.id.clone()),
                Some(invite.id.clone()),
                "ввод: {typed:?}"
            );
        }
    }

    #[test]
    fn an_old_hex_token_still_works() {
        // Вшитые сборки предъявляют шестнадцатеричный токен. Пока они в руках у людей,
        // реестр обязан принимать оба вида.
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let mut invite = reg.create(0, 0, None).unwrap();
        invite.token = store::random_hex(32);
        reg.invites[0] = invite.clone();
        assert!(reg.find_usable(&invite.token, Utc::now()).is_some());
    }

    #[test]
    fn a_single_use_code_can_be_reserved_only_once() {
        // Ровно тот случай, ради которого появился reserve: раньше проверка и
        // списание были двумя операциями, и одновременные запросы проходили обе.
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(1, 0, None).unwrap();
        let now = Utc::now();

        assert!(reg.reserve(&invite.token, now).is_ok());
        assert!(
            reg.reserve(&invite.token, now).is_err(),
            "второе списание одноразового кода обязано быть отказом"
        );
        assert_eq!(reg.get(&invite.id).unwrap().uses, 1);
    }

    #[test]
    fn a_released_use_comes_back() {
        // Заведение сорвалось — код не должен быть потрачен.
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(1, 0, None).unwrap();
        let now = Utc::now();

        reg.reserve(&invite.token, now).unwrap();
        reg.release(&invite.id).unwrap();

        assert_eq!(reg.get(&invite.id).unwrap().uses, 0);
        assert!(
            reg.reserve(&invite.token, now).is_ok(),
            "после отката код обязан снова работать"
        );
    }

    #[test]
    fn a_reservation_survives_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(1, 0, None).unwrap();
        reg.reserve(&invite.token, Utc::now()).unwrap();

        let reloaded = InviteRegistry::load(dir.path().join("invites.json")).unwrap();
        assert_eq!(reloaded.get(&invite.id).unwrap().uses, 1);
        assert!(reloaded.find_usable(&invite.token, Utc::now()).is_none());
    }

    #[test]
    fn a_device_is_recorded_against_the_invite() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(0, 0, None).unwrap();
        reg.reserve(&invite.token, Utc::now()).unwrap();
        reg.note_device(&invite.id, "pixel-8").unwrap();
        assert_eq!(reg.get(&invite.id).unwrap().claimed, vec!["pixel-8"]);
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
    fn a_failed_write_does_not_spend_a_use() {
        // Отказ диска снаружи отличается от «неизвестный код» только типом ошибки, а
        // для человека с одноразовым кодом разница — войдёт он в контур или нет.
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(1, 0, None).unwrap();
        let path = dir.path().join("invites.json");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(reg.reserve(&invite.token, Utc::now()).is_err());
        assert_eq!(
            reg.get(&invite.id).unwrap().uses,
            0,
            "использование не должно списаться в память, минуя диск"
        );
    }

    #[test]
    fn a_repeat_may_present_a_spent_code_but_not_a_closed_one() {
        // Повтор ничего не заводит и ничего не тратит, поэтому исчерпанный счётчик
        // ему не помеха: у одноразового кода использование к этому моменту уже
        // списано, и требовать «код ещё годен» — значит отменить идемпотентность
        // ровно там, ради чего она есть. Отзыв и срок — другое дело.
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let invite = reg.create(1, 1, None).unwrap();
        let now = Utc::now();
        reg.reserve(&invite.token, now).unwrap();
        reg.note_device(&invite.id, "pixel-8").unwrap();

        assert!(
            reg.find_usable(&invite.token, now).is_none(),
            "на НОВОЕ устройство код больше не годится"
        );
        assert!(reg.find_repeat(&invite.token, "pixel-8", now).is_some());
        assert!(
            reg.find_repeat(&invite.token, "iphone", now).is_none(),
            "повтор обязан предъявлять код, по которому завелось именно это устройство"
        );

        let later = now + Duration::days(2);
        assert!(
            reg.find_repeat(&invite.token, "pixel-8", later).is_none(),
            "просроченное приглашение повтор не принимает"
        );
        reg.revoke(&invite.id).unwrap();
        assert!(
            reg.find_repeat(&invite.token, "pixel-8", now).is_none(),
            "отозванное приглашение повтор не принимает"
        );
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
