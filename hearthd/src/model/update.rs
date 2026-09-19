//! Манифест обновлений приложения и его СРОК ГОДНОСТИ.
//!
//! # Зачем здесь срок
//!
//! Клиент больше не верит манифесту бесконечно (`HearthUpdateTrust`): есть поле
//! `expires` — верит ему и возрастом не судит; нет поля — работает запас в
//! [`MAX_MANIFEST_AGE_DAYS`] дней от `issued`, а с [`QUIET_NODE_AFTER_DAYS`] дней
//! человеку показывается «узел молчит».
//!
//! Ключ подписи манифеста лежит на рабочей станции, а не на узле (docs/runbook-release.md),
//! поэтому узел ПЕРЕПОДПИСАТЬ манифест не может — ни сам, ни по команде. Значит, срок
//! назначает оператор в момент подписи, а узел может только одно: заметить, что срок
//! кончается, и сказать об этом оператору РАНЬШЕ, чем семья увидит отказ в телефоне.
//! Ради этого здесь и живёт вердикт: без него истечение срока становится видно в тот
//! же момент, когда оно уже случилось.
//!
//! # Почему пороги повторяют клиентские
//!
//! Оператор смотрит в `hearthctl status`, а отказ получает семья. Если узел считает
//! свежесть по своим порогам, эти два взгляда разъедутся, и разговор «у меня всё
//! зелёное» — «а у меня не обновляется» станет обычным делом. Поэтому константы ниже
//! — зеркало `HearthUpdateTrust`, и расхождение между ними обязано ломать тест, а не
//! выясняться по телефону.
//!
//! # Чего это НЕ делает
//!
//! Не блокирует раздачу. Просроченный манифест узел по-прежнему отдаёт: подписанный
//! документ — власть оператора, а не узла, у клиента своя политика (в том числе у
//! старых сборок, которые про `expires` не знают), и молча отобрать у семьи уже
//! выложенное обновление узел права не имеет. Но отдаёт он его ГРОМКО: в журнал,
//! в статус и в алерты.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::health::HealthState;

/// Версия формата манифеста, которую понимает клиент (`HearthUpdateManifest.SUPPORTED_VERSION`).
pub const UPDATE_MANIFEST_VERSION: u32 = 1;

/// Предельный возраст манифеста БЕЗ поля `expires`
/// (`HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS`). Старше — клиент отказывает.
///
/// Полгода, а не месяц: правило работает только на манифестах, подписанных ДО
/// появления `expires`, а спокойный месяц-другой без релиза в семейном контуре —
/// обычное дело, и объявлять его отказом не за что. Источник числа — клиент; узел
/// его повторяет, и расхождение ловит `the_thresholds_mirror_the_client`.
///
/// Заметность держится не на этой границе, а на [`QUIET_NODE_AFTER_DAYS`]: молчание
/// узла видно человеку через неделю, задолго до любого отказа.
pub const MAX_MANIFEST_AGE_DAYS: i64 = 180;

/// Насколько отметка выпуска может опережать часы
/// (`HearthUpdateTrust.FUTURE_TOLERANCE_DAYS`). Дальше клиент отвергает манифест.
pub const FUTURE_TOLERANCE_DAYS: i64 = 1;

/// Когда молчание узла становится видно человеку
/// (`HearthUpdateTrust.QUIET_NODE_AFTER_DAYS`). Тот же горизонт, что у ТЗ §1.4.
pub const QUIET_NODE_AFTER_DAYS: i64 = 7;

/// Запас между «человеку сказали» и «клиент отказал» — не меньше недели, в обе стороны
/// правила: и для манифеста со сроком (предупреждение за [`QUIET_NODE_AFTER_DAYS`] дней
/// до `expires`), и для манифеста без срока (жёлтое с восьмого дня, отказ клиента — с
/// [`MAX_MANIFEST_AGE_DAYS`]). Проверяется при компиляции: правка одного числа не должна
/// молча съесть чужой запас.
const _: () = assert!(QUIET_NODE_AFTER_DAYS >= 7);
const _: () = assert!(MAX_MANIFEST_AGE_DAYS - QUIET_NODE_AFTER_DAYS >= 7);

/// Срок по умолчанию для `hearthctl release sign`.
///
/// Месяц — срок, который оператор успевает продлить в свой обычный ритм: узел говорит
/// о приближении конца за неделю (`QUIET_NODE_AFTER_DAYS`), а переподпись занимает
/// один заход на рабочую станцию. Дольше — соблазн забыть, что срок вообще есть.
pub const DEFAULT_VALID_FOR_DAYS: i64 = 30;

/// Дальше этого срок назначать нельзя.
///
/// Год — граница, за которой «срок годности» перестаёт отличаться от бесконечности:
/// манифест переживёт и телефон, и память оператора о том, что он его подписывал.
/// ТЗ §1.4 требует доставлять security-релиз за неделю; год вместо этого требования
/// ставит обещание, которое никто не собирается держать.
pub const MAX_VALID_FOR_DAYS: i64 = 365;

/// Больше этого манифест на диске быть не может — читать такой файл незачем.
pub const MANIFEST_SIZE_LIMIT: u64 = 64 * 1024;

/// Манифест обновления приложения (`updates_dir/manifest.json`).
///
/// Имена полей — ровно те, что читает Android (`HearthUpdateManifest`), и менять их
/// здесь в одиночку нельзя: разойдутся — телефон перестанет разбирать документ.
///
/// `extra` держит ключи, которых мы не знаем: подпись накрывает файл целиком, и
/// переподписать документ, потеряв часть его содержимого, значит подписать не то, что
/// написал оператор. Клиент неизвестные ключи игнорирует (`ignoreUnknownKeys`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Версия формата самого манифеста, а не приложения.
    pub v: u32,
    #[serde(rename = "versionName")]
    pub version_name: String,
    #[serde(rename = "versionCode")]
    pub version_code: u32,
    /// sha256 файла APK в нижнем регистре hex.
    pub sha256: String,
    /// Имя файла рядом с манифестом. Не URL — см. [`UpdateManifest::validate`].
    pub file: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    /// Когда манифест выпущен, RFC 3339.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issued: String,
    /// До какого момента манифесту верить, RFC 3339. Пусто — поля нет.
    ///
    /// Необязательное ПРИ ЧТЕНИИ: манифесты, подписанные до появления срока, обязаны
    /// разбираться и дальше — иначе выкатка этой версии узла означала бы, что семья
    /// осталась без обновлений до следующего визита оператора к рабочей станции.
    /// Обязательное ПРИ ПОДПИСИ: новый манифест без срока не выпускается
    /// (`hearthctl release sign` всегда его проставляет).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expires: String,
    /// Всё остальное, что оператор написал в файле.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl UpdateManifest {
    /// Разобрать файл манифеста.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        serde_json::from_slice(raw).map_err(|e| Error::Parse(format!("манифест обновления: {e}")))
    }

    /// Те же требования, что предъявляет клиент (`HearthUpdateManifest.validate`).
    ///
    /// Проверяются они здесь для того, чтобы подпись не ставилась на документ, который
    /// телефон заведомо отвергнет: узнать об этом на раскатке — значит узнать об этом
    /// от семьи.
    pub fn validate(&self) -> Result<()> {
        if self.v != UPDATE_MANIFEST_VERSION {
            return Err(Error::invalid(format!(
                "версия манифеста {} — клиент понимает только {UPDATE_MANIFEST_VERSION}",
                self.v
            )));
        }
        if self.version_code == 0 {
            return Err(Error::invalid("versionCode обязан быть положительным"));
        }
        if self.version_name.trim().is_empty() {
            return Err(Error::invalid("пустой versionName"));
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Error::invalid(
                "sha256 обязан быть 64 шестнадцатеричными символами в нижнем регистре",
            ));
        }
        if self.file.is_empty()
            || self.file.contains("://")
            || self.file.contains("..")
            || self.file.starts_with('/')
            || !self.file.ends_with(".apk")
        {
            return Err(Error::invalid(format!(
                "`file` обязан быть именем .apk рядом с манифестом, а не адресом: {}",
                self.file
            )));
        }
        // Отметка выпуска обязательна: клиент без неё отказывает («в манифесте нет
        // отметки времени»), и подписывать такой документ значит выпускать заведомый
        // отказ.
        if self.issued_at()?.is_none() {
            return Err(Error::invalid(
                "в манифесте нет `issued` (RFC 3339) — клиент такой манифест отвергнет",
            ));
        }
        self.expires_at()?;
        Ok(())
    }

    /// Отметка выпуска. `None` — поля нет.
    pub fn issued_at(&self) -> Result<Option<DateTime<Utc>>> {
        parse_stamp("issued", &self.issued)
    }

    /// Назначенный срок годности. `None` — поля нет (манифест прежних версий).
    ///
    /// Неразобранная строка — ОШИБКА, а не «поля нет»: так же поступает клиент. Иначе
    /// проверку свежести выключала бы опечатка — тем же способом, каким её выключали
    /// бы нарочно.
    pub fn expires_at(&self) -> Result<Option<DateTime<Utc>>> {
        parse_stamp("expires", &self.expires)
    }

    /// Проставить срок годности и отдать файл в том виде, в каком его подпишут.
    pub fn with_expiry(mut self, expires: DateTime<Utc>) -> Self {
        self.expires = crate::model::fmt_ts(expires);
        self
    }

    /// Сериализовать так, как манифест лежит на диске: с отступами и переводом строки.
    ///
    /// Подписываются байты файла, поэтому форма важна: сначала пишем, потом подписываем
    /// ровно записанное.
    pub fn to_file_bytes(&self) -> Result<Vec<u8>> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text.into_bytes())
    }
}

/// Разобрать отметку RFC 3339; пустая строка — «поля нет».
fn parse_stamp(field: &str, raw: &str) -> Result<Option<DateTime<Utc>>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    DateTime::parse_from_rfc3339(raw)
        .map(|ts| Some(ts.with_timezone(&Utc)))
        .map_err(|e| Error::invalid(format!("поле `{field}` не является RFC 3339 ({raw}): {e}")))
}

/// Свежесть манифеста обновлений глазами узла (`/status`, `hearthctl status`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatesStatus {
    /// Вердикт: `Ok` — верить будут, `Degraded` — скоро перестанут, `Down` — уже нет.
    pub state: HealthState,
    /// Лежит ли на узле манифест вообще.
    pub published: bool,
    /// Назначен ли оператором срок (есть ли в подписанном документе `expires`).
    pub dated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_code: Option<u32>,
    #[serde(
        default,
        with = "crate::model::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub issued: Option<DateTime<Utc>>,
    #[serde(
        default,
        with = "crate::model::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires: Option<DateTime<Utc>>,
    /// Сколько дней клиенты ещё будут верить манифесту. Отрицательное — уже не верят.
    ///
    /// Считается в ДНЯХ и по UTC, потому что именно так считает клиент
    /// (`hearthEpochDaysOf`): день истечения — ещё рабочий, отказ наступает со
    /// следующего.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_left: Option<i64>,
    /// Что это значит и что делать. Уходит в алерт дословно.
    pub note: String,
}

impl Default for UpdatesStatus {
    /// Состояние, о котором ещё ничего не известно, — не `Ok`.
    fn default() -> Self {
        Self {
            state: HealthState::Degraded,
            published: false,
            dated: false,
            version_name: None,
            version_code: None,
            issued: None,
            expires: None,
            days_left: None,
            note: "свежесть манифеста обновлений ещё не проверялась".into(),
        }
    }
}

impl UpdatesStatus {
    /// Манифест на месте, но прочитать его нельзя.
    ///
    /// Это отказ, а не «ничего не выложено»: файл есть, устройства его запрашивают, и
    /// то, что узел не может его прочитать, — новость для оператора.
    pub fn unreadable(note: impl Into<String>) -> Self {
        Self {
            state: HealthState::Down,
            published: true,
            note: note.into(),
            ..Self::default()
        }
    }

    /// Ничего не выложено. Это НОРМА, а не отказ.
    ///
    /// Узел без опубликованного обновления — обычное состояние (свежепоставленный,
    /// например), и красный статус здесь приучал бы не смотреть на красное.
    fn nothing_published() -> Self {
        Self {
            state: HealthState::Ok,
            published: false,
            dated: false,
            version_name: None,
            version_code: None,
            issued: None,
            expires: None,
            days_left: None,
            note: "обновление не публиковалось".into(),
        }
    }
}

/// День эпохи UTC — ровно то, чем считает клиент (`hearthEpochDaysOf`).
fn epoch_day(ts: DateTime<Utc>) -> i64 {
    ts.timestamp().div_euclid(86_400)
}

/// Вердикт по свежести манифеста.
///
/// `raw = None` — файла нет. Чистая функция: время приходит параметром, чтобы границу
/// «сегодня» можно было проверить тестом, а не дождаться её на боевом узле.
pub fn updates_status(now: DateTime<Utc>, raw: Option<&[u8]>) -> UpdatesStatus {
    let Some(raw) = raw else {
        return UpdatesStatus::nothing_published();
    };
    let manifest = match UpdateManifest::parse(raw) {
        Ok(manifest) => manifest,
        Err(e) => {
            return UpdatesStatus {
                state: HealthState::Down,
                published: true,
                note: format!(
                    "манифест обновлений не разбирается ({e}); клиенты обновиться не смогут"
                ),
                ..UpdatesStatus::default()
            }
        }
    };

    let mut status = UpdatesStatus {
        state: HealthState::Ok,
        published: true,
        dated: false,
        version_name: Some(manifest.version_name.clone()),
        version_code: Some(manifest.version_code),
        issued: None,
        expires: None,
        days_left: None,
        note: String::new(),
    };

    let issued = match manifest.issued_at() {
        Ok(issued) => issued,
        Err(e) => {
            status.state = HealthState::Down;
            status.note = format!("{e}; клиент такой манифест отвергнет");
            return status;
        }
    };
    status.issued = issued;

    let expires = match manifest.expires_at() {
        Ok(expires) => expires,
        Err(e) => {
            // Поле есть и оно не то — для клиента это отказ, а не «поля нет».
            status.state = HealthState::Down;
            status.note = format!("{e}; клиент такой манифест отвергнет");
            return status;
        }
    };
    status.expires = expires;
    status.dated = expires.is_some();

    let today = epoch_day(now);
    // Манифест, датированный будущим, клиент отвергает независимо от срока годности:
    // так выглядят либо сбитые часы на рабочей станции, либо попытка выиграть запас по
    // возрасту. Проверяется до всего остального — иначе узел показывал бы зелёный
    // манифест, который телефон уже не берёт.
    if let Some(issued) = issued {
        if epoch_day(issued) - today > FUTURE_TOLERANCE_DAYS {
            status.state = HealthState::Down;
            status.note = format!(
                "манифест обновлений датирован будущим ({}): клиент его отвергнет. Проверьте \
                 часы на рабочей станции и переподпишите манифест",
                crate::model::fmt_ts(issued)
            );
            return status;
        }
    }
    match expires {
        Some(expires) => {
            let left = epoch_day(expires) - today;
            status.days_left = Some(left);
            if left < 0 {
                status.state = HealthState::Down;
                status.note = format!(
                    "срок годности манифеста обновлений истёк {} дн. назад ({}); клиенты \
                     обновления не ставят. Переподпишите манифест на рабочей станции: \
                     hearthctl release sign manifest.json --key <ключ> --valid-for {DEFAULT_VALID_FOR_DAYS}d",
                    -left,
                    crate::model::fmt_ts(expires)
                );
            } else if left <= QUIET_NODE_AFTER_DAYS {
                status.state = HealthState::Degraded;
                status.note = format!(
                    "срок годности манифеста обновлений истекает через {left} дн. ({}); \
                     переподпишите его на рабочей станции, пока клиенты ещё обновляются",
                    crate::model::fmt_ts(expires)
                );
            } else {
                status.note = format!(
                    "манифест действует ещё {left} дн. (до {})",
                    crate::model::fmt_ts(expires)
                );
            }
        }
        None => {
            // Срока нет — клиент судит такой манифест по возрасту. Повторяем его
            // арифметику, чтобы оператор видел то же, что увидит семья.
            let Some(issued) = issued else {
                status.state = HealthState::Down;
                status.note = "в манифесте обновлений нет ни `expires`, ни `issued`; клиент \
                               такой манифест отвергнет"
                    .into();
                return status;
            };
            let age = today - epoch_day(issued);
            let left = MAX_MANIFEST_AGE_DAYS - age;
            status.days_left = Some(left);
            if left < 0 {
                status.state = HealthState::Down;
                status.note = format!(
                    "манифест обновлений без срока годности старше {MAX_MANIFEST_AGE_DAYS} дн. \
                     (выпущен {}); клиенты обновления не ставят. Переподпишите его: \
                     hearthctl release sign manifest.json --key <ключ> --valid-for {DEFAULT_VALID_FOR_DAYS}d",
                    crate::model::fmt_ts(issued)
                );
            } else if age > QUIET_NODE_AFTER_DAYS {
                status.state = HealthState::Degraded;
                status.note = format!(
                    "манифест обновлений без срока годности, выпущен {age} дн. назад: телефоны \
                     уже показывают «узел молчит», через {left} дн. перестанут обновляться. \
                     Переподпишите манифест с --valid-for",
                );
            } else {
                status.note = format!(
                    "манифест обновлений без срока годности (выпущен {age} дн. назад): клиенты \
                     судят его по возрасту и перестанут верить через {left} дн. Назначьте срок \
                     при следующей подписи: --valid-for {DEFAULT_VALID_FOR_DAYS}d"
                );
            }
        }
    }

    status
}

/// Разобрать `--valid-for`: `30d`, `6w` или просто число дней.
///
/// Часов и минут нет намеренно: клиент считает свежесть ДНЯМИ, и срок «на 12 часов»
/// он округлил бы до суток, то есть означал бы не то, что написано.
pub fn parse_valid_for(spec: &str) -> Result<Duration> {
    let spec = spec.trim();
    let (digits, days_per_unit) = match spec.strip_suffix(['d', 'D']) {
        Some(digits) => (digits, 1),
        None => match spec.strip_suffix(['w', 'W']) {
            Some(digits) => (digits, 7),
            None => (spec, 1),
        },
    };
    let value: i64 = digits
        .trim()
        .parse()
        .map_err(|_| Error::invalid(format!("срок `{spec}` не разобран; ожидается 30d или 6w")))?;
    let days = value
        .checked_mul(days_per_unit)
        .ok_or_else(|| Error::invalid(format!("срок `{spec}` не помещается в разумные пределы")))?;
    if days < 1 {
        return Err(Error::invalid(
            "срок обязан быть не меньше суток: манифест, просроченный в момент подписи, \
             оставит семью без обновлений сразу",
        ));
    }
    if days > MAX_VALID_FOR_DAYS {
        return Err(Error::invalid(format!(
            "срок {days} дн. больше предельных {MAX_VALID_FOR_DAYS}: срок длиннее года \
             не отличается от бесконечности, ради отказа от которой поле и заведено"
        )));
    }
    Ok(Duration::days(days))
}

/// Разобрать `--expires`: полный RFC 3339 либо `ГГГГ-ММ-ДД`.
///
/// Голая дата понимается как «годен весь этот день» — так же, как её читает человек,
/// и так же, как её считает клиент (он сравнивает дни, а не моменты).
pub fn parse_expires_arg(spec: &str) -> Result<DateTime<Utc>> {
    let spec = spec.trim();
    if let Ok(ts) = DateTime::parse_from_rfc3339(spec) {
        return Ok(ts.with_timezone(&Utc));
    }
    let date = chrono::NaiveDate::parse_from_str(spec, "%Y-%m-%d").map_err(|_| {
        Error::invalid(format!(
            "`{spec}` не дата: ожидается 2026-10-18 или 2026-10-18T12:00:00Z"
        ))
    })?;
    date.and_hms_opt(23, 59, 59)
        .map(|naive| naive.and_utc())
        .ok_or_else(|| Error::invalid(format!("`{spec}` не дата")))
}

/// Выбрать срок годности для подписи и проверить, что он осмыслен.
///
/// Ни один из флагов — умолчание в [`DEFAULT_VALID_FOR_DAYS`] дней: подпись без срока
/// больше не выпускается, а требовать флаг на каждой подписи значит получить его
/// копипастой из runbook с чужим числом.
pub fn resolve_expiry(
    now: DateTime<Utc>,
    valid_for: Option<&str>,
    expires: Option<&str>,
) -> Result<DateTime<Utc>> {
    let expiry = match (valid_for, expires) {
        (Some(_), Some(_)) => {
            return Err(Error::invalid(
                "--valid-for и --expires задают одно и то же двумя способами; оставьте один",
            ))
        }
        (Some(spec), None) => now + parse_valid_for(spec)?,
        (None, Some(spec)) => parse_expires_arg(spec)?,
        (None, None) => now + Duration::days(DEFAULT_VALID_FOR_DAYS),
    };
    if expiry <= now {
        return Err(Error::invalid(format!(
            "срок {} уже в прошлом: такой манифест семья не поставит ни разу",
            crate::model::fmt_ts(expiry)
        )));
    }
    if expiry - now > Duration::days(MAX_VALID_FOR_DAYS) {
        return Err(Error::invalid(format!(
            "срок {} дальше предельных {MAX_VALID_FOR_DAYS} дн.: это бессрочный манифест, \
             написанный другими словами",
            crate::model::fmt_ts(expiry)
        )));
    }
    Ok(expiry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0)
            .single()
            .expect("дата")
    }

    fn manifest_json(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"v":1,"versionName":"7.0.1-h16","versionCode":387,
                 "sha256":"{}","file":"hearth-7.0.1-h16.apk",
                 "issued":"2026-09-01T00:00:00Z"{extra}}}"#,
            "a".repeat(64)
        )
        .into_bytes()
    }

    /// Манифест, подписанный до появления срока, обязан читаться и дальше: иначе
    /// выкатка этой версии узла означала бы «никто не обновляется до визита оператора».
    #[test]
    fn an_old_manifest_without_expires_still_parses() {
        let manifest = UpdateManifest::parse(&manifest_json("")).expect("разбирается");
        assert_eq!(manifest.version_code, 387);
        assert_eq!(manifest.expires_at().expect("срок"), None);
        manifest.validate().expect("валиден");

        // И вердикт по нему — не отказ, пока он молод.
        let status = updates_status(at(2026, 9, 3), Some(&manifest_json("")));
        assert_eq!(status.state, HealthState::Ok);
        assert!(!status.dated);
    }

    /// Возраст без срока считается ровно так же, как его считает клиент.
    #[test]
    fn an_undated_manifest_goes_yellow_at_a_week_and_red_at_half_a_year() {
        let raw = manifest_json("");
        assert_eq!(
            updates_status(at(2026, 9, 9), Some(&raw)).state,
            HealthState::Degraded,
            "восьмой день — телефоны уже говорят «узел молчит»"
        );
        assert_eq!(
            updates_status(at(2027, 2, 28), Some(&raw)).state,
            HealthState::Degraded,
            "полгода ещё не прошло: телефоны продолжают ставить обновления"
        );
        assert_eq!(
            updates_status(at(2027, 3, 3), Some(&raw)).state,
            HealthState::Down,
            "сто восемьдесят первый день — клиент отказывает"
        );
    }

    /// Пороги узла — зеркало клиентских, и расхождение обязано ломать тест, а не
    /// выясняться по телефону («у меня всё зелёное» — «а у меня не обновляется»).
    ///
    /// Читается файлом, а не `include_str!`: hearthd публикуется аудитору отдельным
    /// деревом (deploy/publish-src.sh), и там соседнего форка просто нет.
    #[test]
    fn the_thresholds_mirror_the_client() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../android/overlay/common/src/commonMain/kotlin/chat/hearth/HearthUpdateTrust.kt"
        );
        let Ok(kotlin) = std::fs::read_to_string(path) else {
            // Дерева форка рядом нет — сверять не с чем, и это не провал.
            return;
        };
        for (name, ours) in [
            ("MAX_MANIFEST_AGE_DAYS", MAX_MANIFEST_AGE_DAYS),
            ("QUIET_NODE_AFTER_DAYS", QUIET_NODE_AFTER_DAYS),
            ("FUTURE_TOLERANCE_DAYS", FUTURE_TOLERANCE_DAYS),
        ] {
            let needle = format!("const val {name}: Long = ");
            let theirs: i64 = kotlin
                .split_once(&needle)
                .and_then(|(_, tail)| tail.split_whitespace().next())
                .and_then(|value| {
                    value
                        .trim_end_matches(|c: char| !c.is_ascii_digit())
                        .parse()
                        .ok()
                })
                .unwrap_or_else(|| panic!("в HearthUpdateTrust.kt не найдено `{needle}`"));
            assert_eq!(
                ours, theirs,
                "порог {name} разъехался с клиентом: узел {ours}, клиент {theirs}"
            );
        }
    }

    /// Граница «сегодня»: день истечения ещё рабочий, отказ — со следующего.
    /// До правки поля `expires` не было вовсе, и этот тест не компилировался бы.
    #[test]
    fn the_day_of_expiry_is_still_a_working_day() {
        let raw = manifest_json(r#","expires":"2026-09-20T23:59:59Z""#);

        let today = updates_status(at(2026, 9, 20), Some(&raw));
        assert_eq!(
            today.state,
            HealthState::Degraded,
            "последний день — жёлтый"
        );
        assert_eq!(today.days_left, Some(0));
        assert!(today.dated);

        let tomorrow = updates_status(at(2026, 9, 21), Some(&raw));
        assert_eq!(tomorrow.state, HealthState::Down);
        assert_eq!(tomorrow.days_left, Some(-1));
        assert!(tomorrow.note.contains("release sign"), "{}", tomorrow.note);

        // Разные часовые пояса одного и того же дня ничего не меняют: считаются дни
        // UTC, как у клиента.
        let same_day = updates_status(
            Utc.with_ymd_and_hms(2026, 9, 20, 22, 0, 0)
                .single()
                .expect("дата"),
            Some(&raw),
        );
        assert_eq!(same_day.state, HealthState::Degraded);
    }

    /// Замечание 24: предупреждение оператору обязано приходить заведомо раньше, чем
    /// клиенты начнут отказываться. Проверяется по всему окну, а не по одной дате.
    #[test]
    fn the_operator_is_warned_a_full_week_before_the_clients_stop() {
        let raw = manifest_json(r#","expires":"2026-09-20T23:59:59Z""#);

        // Ровно за неделю — уже жёлтый, и текст зовёт к действию, а не описывает беду.
        let week = updates_status(at(2026, 9, 13), Some(&raw));
        assert_eq!(week.state, HealthState::Degraded);
        assert_eq!(week.days_left, Some(QUIET_NODE_AFTER_DAYS));
        assert!(
            week.note.contains("пока клиенты ещё обновляются"),
            "{}",
            week.note
        );
        // Днём раньше — зелёный: окно ровно недельное, не длиннее.
        assert_eq!(
            updates_status(at(2026, 9, 12), Some(&raw)).state,
            HealthState::Ok
        );

        // И ни одного дня, когда клиенты уже отказывают, а узел ещё молчит.
        for day in 13..=20 {
            let status = updates_status(at(2026, 9, day), Some(&raw));
            assert_ne!(status.state, HealthState::Ok, "день {day}");
            assert!(
                status.days_left.unwrap_or(-1) >= 0,
                "клиенты в этот день ещё обновляются: день {day}"
            );
        }

        // И это описано там, куда человек придёт читать.
        let runbook = include_str!("../../../docs/runbook-updates.md");
        assert!(runbook.contains("за 7 дней"), "runbook обязан назвать срок");
        assert!(
            runbook.contains("после срока"),
            "runbook обязан сказать, что будет после"
        );
    }

    #[test]
    fn a_manifest_in_good_standing_is_green() {
        let raw = manifest_json(r#","expires":"2026-10-15T23:59:59Z""#);
        let status = updates_status(at(2026, 9, 18), Some(&raw));
        assert_eq!(status.state, HealthState::Ok);
        assert_eq!(status.days_left, Some(27));
    }

    /// Поле есть, но не разобралось, — это отказ, а не «поля нет». Иначе проверку
    /// свежести выключала бы опечатка.
    #[test]
    fn an_unparsable_expiry_is_a_failure_not_an_absence() {
        let raw = manifest_json(r#","expires":"скоро""#);
        let status = updates_status(at(2026, 9, 18), Some(&raw));
        assert_eq!(status.state, HealthState::Down);
        assert!(status.note.contains("expires"), "{}", status.note);
    }

    /// Отметка выпуска из будущего — отказ у клиента, значит и у узла.
    #[test]
    fn a_manifest_dated_in_the_future_is_an_alarm() {
        let raw = manifest_json(r#","expires":"2026-12-31T23:59:59Z""#);
        // Манифест выпущен 2026-09-01, а «сегодня» на узле — 2026-08-20.
        let status = updates_status(at(2026, 8, 20), Some(&raw));
        assert_eq!(status.state, HealthState::Down);
        assert!(status.note.contains("будущим"), "{}", status.note);

        // Сутки допуска (часовые пояса, релиз в другом полушарии) отказом не считаются.
        assert_eq!(
            updates_status(at(2026, 8, 31), Some(&raw)).state,
            HealthState::Ok
        );
    }

    #[test]
    fn nothing_published_is_not_an_alarm() {
        let status = updates_status(at(2026, 9, 18), None);
        assert_eq!(status.state, HealthState::Ok);
        assert!(!status.published);
    }

    #[test]
    fn garbage_in_the_updates_dir_is_an_alarm() {
        let status = updates_status(at(2026, 9, 18), Some("не json".as_bytes()));
        assert_eq!(status.state, HealthState::Down);
        assert!(status.published);
    }

    #[test]
    fn unknown_keys_survive_a_re_signature() {
        let raw = manifest_json(r#","минимальнаяВерсия":"7.0.0""#);
        let manifest = UpdateManifest::parse(&raw).expect("разбирается");
        let bytes = manifest
            .with_expiry(at(2026, 10, 18))
            .to_file_bytes()
            .expect("сериализуется");
        let text = String::from_utf8(bytes).expect("utf-8");
        assert!(text.contains("минимальнаяВерсия"), "{text}");
        assert!(
            text.contains(r#""expires": "2026-10-18T12:00:00Z""#),
            "{text}"
        );
        assert!(
            text.ends_with('\n'),
            "файл обязан кончаться переводом строки"
        );
    }

    #[test]
    fn a_manifest_the_client_would_refuse_is_not_signed() {
        // URL вместо имени файла.
        let bad = UpdateManifest::parse(&manifest_json(""))
            .map(|mut m| {
                m.file = "https://example.org/hearth.apk".into();
                m
            })
            .expect("разбирается");
        assert!(bad.validate().is_err());

        // Нет отметки выпуска — клиент отвергнет.
        let raw = format!(
            r#"{{"v":1,"versionName":"x","versionCode":1,"sha256":"{}","file":"a.apk"}}"#,
            "a".repeat(64)
        );
        assert!(UpdateManifest::parse(raw.as_bytes())
            .expect("разбирается")
            .validate()
            .is_err());
    }

    #[test]
    fn durations_are_read_the_way_they_are_written() {
        assert_eq!(parse_valid_for("30d").expect("30d"), Duration::days(30));
        assert_eq!(parse_valid_for("6w").expect("6w"), Duration::days(42));
        assert_eq!(parse_valid_for("45").expect("45"), Duration::days(45));
        assert!(parse_valid_for("0d").is_err());
        assert!(parse_valid_for("-1d").is_err());
        assert!(parse_valid_for("400d").is_err(), "год — предел");
        assert!(parse_valid_for("завтра").is_err());
    }

    #[test]
    fn a_bare_date_means_the_whole_day() {
        let parsed = parse_expires_arg("2026-10-18").expect("дата");
        assert_eq!(crate::model::fmt_ts(parsed), "2026-10-18T23:59:59Z");
        assert_eq!(
            parse_expires_arg("2026-10-18T12:00:00Z").expect("момент"),
            at(2026, 10, 18)
        );
        assert!(parse_expires_arg("18.10.2026").is_err());
    }

    /// Срок в прошлом и срок «навсегда» — обе крайности отвергаются при подписи.
    #[test]
    fn signing_refuses_a_past_and_an_absurd_expiry() {
        let now = at(2026, 9, 18);
        assert!(resolve_expiry(now, None, Some("2026-09-01")).is_err());
        assert!(resolve_expiry(now, None, Some("2030-01-01")).is_err());
        assert!(resolve_expiry(now, Some("30d"), Some("2026-10-18")).is_err());

        // Умолчание — месяц.
        assert_eq!(
            resolve_expiry(now, None, None).expect("умолчание"),
            now + Duration::days(DEFAULT_VALID_FOR_DAYS)
        );
        // Сегодняшний день ещё можно назначить: манифест проживёт до полуночи.
        assert!(resolve_expiry(now, None, Some("2026-09-18")).is_ok());
    }
}
