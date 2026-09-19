//! Аудиторский токен — узкий и срочный доступ к тому, что раздаётся телефонам.
//!
//! # Зачем понадобилась третья сущность
//!
//! Аудит обязан своими руками скачать с боевого узла манифест обновления, его подпись
//! и сам APK — и сверить байты. Способов дать такой доступ было ровно два, и оба
//! плохи.
//!
//! Первый — отдать действующий токен члена семьи. Он бессрочный, снимается только
//! `device revoke`, и открывает заодно `/turn-credentials` (то есть выдачу
//! креденшелов для звонков) и стикеры.
//!
//! Второй — завести «устройство-аудитор». Оно съест слот `max_devices`, получит
//! bundle, то есть пароли релеев, — а bundle это вход в контур семьи, не право
//! читать три файла.
//!
//! Третьего варианта не было. Он здесь: срок обязателен, счётчик обязателен, область
//! перечислена поимённо, слот устройства не расходуется и bundle не выпускается.
//!
//! # Почему не расширить токен устройства
//!
//! Потому что тогда область и срок пришлось бы добавить КАЖДОМУ устройству семьи, и
//! ошибка в этой логике стоила бы доступа к узлу всей семье. Отдельный тип не может
//! сломать то, чего не касается: маршруты, к которым он не подключён, о нём не знают.
//!
//! # Чего он НЕ даёт
//!
//! Ни создания очередей на релее, ни bundle, ни TURN-креденшелов, ни стикеров, ни
//! чтения реестра устройств. Раздаётся тем же способом, что и обновления телефонам, —
//! то есть ничего нового наружу не открывает, только даёт войти в уже открытую дверь
//! без прав члена семьи.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store;

/// Потолок срока. Аудит — мероприятие на дни, а не на месяцы; бессрочного варианта
/// здесь нет вовсе, в отличие от приглашения (там бессрочность — штатный режим
/// раздачи сборки семье).
pub const MAX_TTL_HOURS: i64 = 30 * 24;
/// Потолок счётчика. Скачать три файла, ошибиться и повторить — это единицы попыток;
/// четырёхзначное число означало бы опечатку.
pub const MAX_USES: u32 = 1000;

/// Что именно позволено аудиторскому токену.
///
/// Перечисление, а не строка и не битовая маска: новый маршрут не появляется в
/// области сам, его приходится назвать здесь и в обработчике. Это ровно то свойство,
/// которого не хватало токену устройства — там все семь маршрутов ходили под одной
/// проверкой, и добавление восьмого расширяло доступ молча.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    /// `GET /updates/manifest.json`.
    UpdatesManifest,
    /// `GET /updates/manifest.json.sig`.
    ManifestSignature,
    /// `GET /updates/<файл>.apk`.
    UpdatesFile,
}

impl AuditScope {
    /// Область по умолчанию: ровно то, что нужно, чтобы проверить раздаваемую сборку
    /// целиком — манифест, подпись и сам файл. Уже минимальна: убери любой пункт, и
    /// проверка байтов перестанет быть проверкой.
    pub fn updates() -> Vec<AuditScope> {
        vec![
            AuditScope::UpdatesManifest,
            AuditScope::ManifestSignature,
            AuditScope::UpdatesFile,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            AuditScope::UpdatesManifest => "updates-manifest",
            AuditScope::ManifestSignature => "manifest-signature",
            AuditScope::UpdatesFile => "updates-file",
        }
    }

    /// Разбор значения `--scope`.
    pub fn parse(raw: &str) -> Result<Vec<AuditScope>> {
        match raw.trim() {
            "updates" => Ok(Self::updates()),
            "updates-manifest" => Ok(vec![AuditScope::UpdatesManifest]),
            "manifest-signature" => Ok(vec![AuditScope::ManifestSignature]),
            "updates-file" => Ok(vec![AuditScope::UpdatesFile]),
            other => Err(Error::invalid(format!(
                "неизвестная область `{other}`; допустимо: updates, updates-manifest, \
                 manifest-signature, updates-file"
            ))),
        }
    }
}

/// Один аудиторский токен.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditToken {
    /// Короткий идентификатор для `audit-token revoke`. Не секрет.
    pub id: String,
    /// Секрет. Приходит заголовком `x-hearth-audit-token`.
    pub token: String,
    #[serde(with = "crate::model::rfc3339")]
    pub created: DateTime<Utc>,
    /// Срок. Обязателен и не `Option` — в этом весь смысл типа: доступ, который
    /// нужно не забыть отозвать, рано или поздно не отзывают.
    #[serde(with = "crate::model::rfc3339")]
    pub expires: DateTime<Utc>,
    /// Разрешённое число обращений. Тоже обязательно; нуля («без счётчика») здесь
    /// нет, в отличие от приглашения.
    pub max_uses: u32,
    #[serde(default)]
    pub uses: u32,
    /// Что именно позволено. Пустой список невозможен — см. [`AuditTokenRegistry::issue`].
    pub scope: Vec<AuditScope>,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub revoked: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl AuditToken {
    /// Можно ли им ещё воспользоваться.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked.is_none() && now < self.expires && self.uses < self.max_uses
    }

    /// Входит ли область в разрешённые.
    pub fn allows(&self, scope: AuditScope) -> bool {
        self.scope.contains(&scope)
    }

    /// Человекочитаемая причина отказа — для `audit-token list`, не для ответа клиенту.
    pub fn state_at(&self, now: DateTime<Utc>) -> &'static str {
        if self.revoked.is_some() {
            "отозван"
        } else if now >= self.expires {
            "просрочен"
        } else if self.uses >= self.max_uses {
            "исчерпан"
        } else {
            "активен"
        }
    }

    /// Проекция без секрета — для списков и для выгрузки аудита.
    ///
    /// Отдельный тип, а не вырезание поля на месте: «забыл вырезать» — это утечка,
    /// а «забыл добавить поле в проекцию» — всего лишь неполный отчёт.
    pub fn public(&self, now: DateTime<Utc>) -> AuditTokenPublic {
        AuditTokenPublic {
            id: self.id.clone(),
            created: self.created,
            expires: self.expires,
            max_uses: self.max_uses,
            uses: self.uses,
            scope: self.scope.clone(),
            revoked: self.revoked,
            note: self.note.clone(),
            state: self.state_at(now).to_string(),
        }
    }
}

/// Аудиторский токен без секрета.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTokenPublic {
    pub id: String,
    #[serde(with = "crate::model::rfc3339")]
    pub created: DateTime<Utc>,
    #[serde(with = "crate::model::rfc3339")]
    pub expires: DateTime<Utc>,
    pub max_uses: u32,
    pub uses: u32,
    pub scope: Vec<AuditScope>,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub revoked: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// `активен` / `просрочен` / `исчерпан` / `отозван`.
    pub state: String,
}

/// Реестр аудиторских токенов (`<state_dir>/audit-tokens.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditTokenRegistry {
    #[serde(default)]
    pub tokens: Vec<AuditToken>,
    #[serde(skip)]
    path: PathBuf,
}

impl AuditTokenRegistry {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut registry: AuditTokenRegistry = store::read_json(&path)?.unwrap_or_default();
        registry.path = path;
        Ok(registry)
    }

    pub fn save(&self) -> Result<()> {
        store::write_json_atomic(&self.path, self, store::MODE_STATE)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, id: &str) -> Option<&AuditToken> {
        self.tokens.iter().find(|t| t.id == id)
    }

    /// Выписать токен.
    ///
    /// Каждый ограничитель обязателен и проверяется здесь, а не в CLI: реестр — это
    /// то место, мимо которого не пройти, а CLI у нас не один (есть ещё admin API).
    pub fn issue(
        &mut self,
        ttl_hours: i64,
        max_uses: u32,
        scope: Vec<AuditScope>,
        note: Option<String>,
    ) -> Result<AuditToken> {
        if !(1..=MAX_TTL_HOURS).contains(&ttl_hours) {
            return Err(Error::invalid(format!(
                "срок обязателен и не больше {MAX_TTL_HOURS} часов"
            )));
        }
        if !(1..=MAX_USES).contains(&max_uses) {
            return Err(Error::invalid(format!(
                "число обращений обязательно и не больше {MAX_USES}"
            )));
        }
        if scope.is_empty() {
            return Err(Error::invalid(
                "токен без области не открывает ничего; укажите --scope",
            ));
        }

        let now = Utc::now();
        let token = AuditToken {
            // Идентификатор не секрет: его называют вслух при отзыве.
            id: store::random_hex(8),
            // 32 байта: этот секрет не печатают руками, его копируют, поэтому берём
            // размер, а не читаемость (в отличие от кода приглашения).
            token: store::random_hex(32),
            created: now,
            expires: now + Duration::hours(ttl_hours),
            max_uses,
            uses: 0,
            scope,
            revoked: None,
            note,
        };
        self.tokens.push(token.clone());
        if let Err(e) = self.save() {
            // Токен, который есть в памяти и которого нет на диске, — это доступ до
            // ближайшего перезапуска, уже названный человеку.
            self.tokens.pop();
            return Err(e);
        }
        Ok(token)
    }

    /// Занять обращение: проверка и списание одним неделимым действием.
    ///
    /// Проверка и списание раздельно означали бы окно, в котором одновременные
    /// запросы проходят счётчик все сразу, — ровно та ошибка, что уже была у
    /// приглашений (см. `invite::InviteRegistry::reserve`). Здесь оба шага под одним
    /// `&mut self`.
    ///
    /// Сравнение в постоянное время и по ВСЕМ записям, без раннего выхода: иначе
    /// время ответа рассказывало бы, есть ли такой токен и в какой он позиции.
    pub fn reserve(
        &mut self,
        token: &str,
        scope: AuditScope,
        now: DateTime<Utc>,
    ) -> Result<AuditToken> {
        let mut found: Option<usize> = None;
        for (index, candidate) in self.tokens.iter().enumerate() {
            let matches = crate::deviceapi::ct_eq(&candidate.token, token);
            if matches && candidate.is_usable_at(now) && candidate.allows(scope) {
                found = Some(index);
            }
        }
        let index = found.ok_or_else(|| Error::NotFound("audit token".to_string()))?;
        self.tokens[index].uses += 1;
        if let Err(e) = self.save() {
            // Отказ диска не должен съедать обращение — но и пропускать запрос при
            // несохранённом счётчике нельзя: тогда счётчик перестаёт быть счётчиком.
            // Поэтому откат в памяти И ошибка наружу.
            self.tokens[index].uses -= 1;
            return Err(e);
        }
        Ok(self.tokens[index].clone())
    }

    /// Погасить токен. Идемпотентно.
    pub fn revoke(&mut self, id: &str) -> Result<AuditToken> {
        let token = self
            .tokens
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| Error::NotFound(format!("audit token `{id}`")))?;
        let previous = token.revoked;
        if token.revoked.is_none() {
            token.revoked = Some(Utc::now());
        }
        let token = token.clone();
        if let Err(e) = self.save() {
            // Отозванный только в памяти токен после перезапуска снова действует, а
            // человек уже услышал «отозван».
            if let Some(token) = self.tokens.iter_mut().find(|t| t.id == id) {
                token.revoked = previous;
            }
            return Err(e);
        }
        Ok(token)
    }

    /// Список без секретов.
    pub fn public(&self, now: DateTime<Utc>) -> Vec<AuditTokenPublic> {
        self.tokens.iter().map(|t| t.public(now)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(dir: &tempfile::TempDir) -> AuditTokenRegistry {
        AuditTokenRegistry::load(dir.path().join("audit-tokens.json")).unwrap()
    }

    #[test]
    fn an_issued_token_is_bounded_in_time_and_in_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let token = reg
            .issue(48, 5, AuditScope::updates(), Some("аудит 2026-09".into()))
            .unwrap();

        assert_eq!(token.token.len(), 64, "32 байта секрета");
        assert_eq!(token.max_uses, 5);
        assert!(token.expires > token.created);
        assert!(token.is_usable_at(Utc::now()));
        assert_eq!(token.state_at(Utc::now()), "активен");
    }

    /// Бессрочного и безлимитного аудиторского токена не бывает — это и есть
    /// отличие от приглашения, ради которого заведён отдельный тип.
    #[test]
    fn a_token_without_limits_cannot_be_issued() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        assert!(reg.issue(0, 5, AuditScope::updates(), None).is_err());
        assert!(reg.issue(-1, 5, AuditScope::updates(), None).is_err());
        assert!(reg
            .issue(MAX_TTL_HOURS + 1, 5, AuditScope::updates(), None)
            .is_err());
        assert!(reg.issue(48, 0, AuditScope::updates(), None).is_err());
        assert!(reg
            .issue(48, MAX_USES + 1, AuditScope::updates(), None)
            .is_err());
        assert!(reg.issue(48, 5, Vec::new(), None).is_err());
        assert!(reg.tokens.is_empty(), "ни одна неудача не оставила следа");
    }

    #[test]
    fn an_expired_token_is_not_usable() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let token = reg.issue(1, 5, AuditScope::updates(), None).unwrap();
        let later = token.expires + Duration::seconds(1);
        assert!(!token.is_usable_at(later));
        assert_eq!(token.state_at(later), "просрочен");
        assert!(reg
            .reserve(&token.token, AuditScope::UpdatesManifest, later)
            .is_err());
    }

    #[test]
    fn a_spent_token_is_not_usable() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let token = reg.issue(48, 2, AuditScope::updates(), None).unwrap();
        let now = Utc::now();
        for _ in 0..2 {
            reg.reserve(&token.token, AuditScope::UpdatesFile, now)
                .expect("в пределах счётчика");
        }
        assert!(
            reg.reserve(&token.token, AuditScope::UpdatesFile, now)
                .is_err(),
            "третье обращение по токену на два — отказ"
        );
        assert_eq!(reg.get(&token.id).unwrap().state_at(now), "исчерпан");
    }

    #[test]
    fn a_revoked_token_is_not_usable() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let token = reg.issue(48, 5, AuditScope::updates(), None).unwrap();
        reg.revoke(&token.id).expect("отзыв");
        assert!(reg
            .reserve(&token.token, AuditScope::UpdatesManifest, Utc::now())
            .is_err());
        // Идемпотентность: повторный отзыв не ошибка и не меняет отметку.
        let first = reg.get(&token.id).unwrap().revoked;
        reg.revoke(&token.id).expect("повторный отзыв");
        assert_eq!(reg.get(&token.id).unwrap().revoked, first);
    }

    /// Область — это замок, а не подпись. Токен на манифест не открывает APK.
    #[test]
    fn a_scope_outside_the_grant_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let token = reg
            .issue(48, 5, vec![AuditScope::UpdatesManifest], None)
            .unwrap();
        let now = Utc::now();
        assert!(reg
            .reserve(&token.token, AuditScope::UpdatesManifest, now)
            .is_ok());
        assert!(
            reg.reserve(&token.token, AuditScope::UpdatesFile, now)
                .is_err(),
            "область вне выданной обязана быть отказом"
        );
        assert_eq!(
            reg.get(&token.id).unwrap().uses,
            1,
            "отказ не расходует обращение"
        );
    }

    /// Счётчик обязан пережить перезапуск демона: иначе «пять обращений» означает
    /// «пять обращений между перезапусками», то есть не означает ничего.
    #[test]
    fn the_counter_survives_a_restart_and_never_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-tokens.json");
        let issued = {
            let mut reg = AuditTokenRegistry::load(&path).unwrap();
            let token = reg.issue(48, 5, AuditScope::updates(), None).unwrap();
            reg.reserve(&token.token, AuditScope::UpdatesFile, Utc::now())
                .unwrap();
            token
        };

        let reloaded = AuditTokenRegistry::load(&path).unwrap();
        let token = reloaded.get(&issued.id).expect("пережил перезагрузку");
        assert_eq!(token.uses, 1);
        assert_eq!(token.token, issued.token);
        assert_eq!(token.scope, AuditScope::updates());
    }

    /// Проекция для списков и выгрузок не должна нести секрет: это единственное
    /// поле, из-за которого наивный дамп состояния был бы утечкой.
    #[test]
    fn the_public_projection_carries_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(&dir);
        let token = reg.issue(48, 5, AuditScope::updates(), None).unwrap();
        let json = serde_json::to_string(&reg.public(Utc::now())).unwrap();
        assert!(
            !json.contains(&token.token),
            "секрет попал в проекцию: {json}"
        );
        assert!(json.contains(&token.id), "идентификатор нужен для отзыва");
    }

    #[test]
    fn scopes_parse_from_the_command_line() {
        assert_eq!(AuditScope::parse("updates").unwrap(), AuditScope::updates());
        assert_eq!(
            AuditScope::parse(" updates-file ").unwrap(),
            vec![AuditScope::UpdatesFile]
        );
        assert!(AuditScope::parse("turn-credentials").is_err());
        assert!(AuditScope::parse("").is_err());
    }
}
