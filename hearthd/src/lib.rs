//! `hearthd` — control plane for a private, home-only SimpleX relay node.
//!
//! # What this crate is
//!
//! ТЗ §0 draws a hard line: the SimpleX protocol, the relays and the crypto stay
//! upstream Haskell, untouched. This crate is only the part that has no predecessor —
//! the node's own plumbing:
//!
//! * [`supervisor`] — keep the stock relays running, with backoff and alerting;
//! * [`egress`] — watch nftables counters and live sockets so a "phone home" attempt
//!   is *observed*, not merely blocked (ТЗ §2.1 "Verify, don't trust");
//! * [`integrity`] — sha256 every pinned binary against [`model::manifest`];
//! * [`backup`] — daily age-encrypted archive pushed to the second machine at home;
//! * [`configgen`] — mint client bundles (ТЗ Приложение B) and QR codes;
//! * [`migrate`] — the ПК → mini-PC move that keeps the relay address constant;
//! * [`api`] — mTLS admin API on the WG-only admin subnet.
//!
//! # What this crate must never do
//!
//! * read relay message content or client addresses (ТЗ §7.4);
//! * open a connection outside `node.home_networks` — see [`net::EgressPolicy`];
//! * update itself, or reach any external service for any reason.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]
#![warn(clippy::all, missing_debug_implementations, rust_2018_idioms)]

pub mod alerts;
pub mod api;
pub mod backup;
pub mod config;
pub mod configgen;
pub mod deviceapi;
pub mod egress;
pub mod error;
pub mod integrity;
pub mod migrate;
pub mod model;
pub mod net;
pub mod pki;
pub mod qr;
pub mod release;
pub mod state;
pub mod store;
pub mod supervisor;
pub mod sys;

/// Version of the daemon, reported by `/health` and stamped into backups.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Паспорт сборки: из какого дерева исходников собран этот бинарник.
///
/// # Зачем поверх `VERSION`
///
/// `VERSION` — это строка из `Cargo.toml`, одинаковая у всех сборок всех коммитов
/// ветки. Ею нельзя ответить на единственный вопрос, который задаёт аудит: «работает
/// ли на узле тот код, который лежит в репозитории». Здесь — то, чем можно: коммит,
/// признак чистоты дерева и хеш самого дерева.
///
/// # Откуда берутся значения
///
/// Все поля вшиваются на этапе сборки скриптом `build.rs`, который спрашивает их у
/// git прямо в момент компиляции. Ни одно из них не приходит из переменной окружения
/// сборщика: подставленное руками значение доказывало бы ровно ничего. Подробности и
/// команда независимой проверки — в `build.rs`.
///
/// # Предел утверждения
///
/// Паспорт доказывает «собрано из такого дерева», а НЕ «в дереве нет закладки».
/// Второе доказывается чтением исходников; хеш только гарантирует, что читать надо
/// именно их.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BuildInfo {
    /// `CARGO_PKG_VERSION`.
    pub version: String,
    /// `git rev-parse HEAD` на момент сборки либо `unknown`.
    pub commit: String,
    /// Было ли дерево изменено относительно коммита.
    ///
    /// `true` означает в том числе «проверить не удалось»: сборка без git не может
    /// утверждать чистоту, а умолчание в пользу чистоты как раз и было бы ложным
    /// утверждением. Отличить одно от другого можно по `commit == "unknown"`.
    pub dirty: bool,
    /// Хеш дерева исходников, из которого собран бинарник (см. `build.rs`).
    pub tree_sha256: String,
    /// Триплет цели, например `x86_64-unknown-linux-musl`.
    pub target: String,
    /// Компилятор одной строкой, как её печатает `rustc -V`.
    pub rustc: String,
    /// Отметка времени сборки (`SOURCE_DATE_EPOCH` либо дата коммита). В
    /// `tree_sha256` НЕ входит: иначе два прогона одного коммита давали бы разные
    /// хеши и сверять было бы нечего.
    pub source_date_epoch: String,
}

impl BuildInfo {
    /// Паспорт в виде `ключ=значение`, по строке на поле.
    ///
    /// Формат тот же, что у паспорта Android-сборки
    /// (`android/scripts/build-release.sh`): человеку читается без инструмента, а
    /// `grep` и `cut -d=` разбирают его одинаково в обоих случаях.
    pub fn to_key_values(&self) -> String {
        format!(
            "version={}\ncommit={}\ndirty={}\ntree_sha256={}\ntarget={}\nrustc={}\nsource_date_epoch={}\n",
            self.version,
            self.commit,
            self.dirty,
            self.tree_sha256,
            self.target,
            self.rustc,
            self.source_date_epoch,
        )
    }
}

/// Паспорт этой сборки.
pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: VERSION.to_string(),
        commit: env!("HEARTH_GIT_COMMIT").to_string(),
        // Строку сравниваем, а не разбираем: всё, что не «точно чисто», — грязно.
        dirty: env!("HEARTH_GIT_DIRTY") != "false",
        tree_sha256: env!("HEARTH_TREE_SHA256").to_string(),
        target: env!("HEARTH_BUILD_TARGET").to_string(),
        rustc: env!("HEARTH_RUSTC").to_string(),
        source_date_epoch: env!("HEARTH_SOURCE_DATE_EPOCH").to_string(),
    }
}

/// Значение полей паспорта, которые выяснить не удалось.
pub const UNKNOWN: &str = "unknown";

/// sha256 файла, которым запущен этот процесс.
///
/// # Зачем демону считать себя
///
/// Связать работающий процесс с файлом на диске снаружи нечем: `readlink
/// /proc/<pid>/exe` требует `PTRACE_MODE_READ`, то есть того же uid или
/// `CAP_SYS_PTRACE`, а аудитор — посторонний пользователь. Выдавать ptrace ради этого
/// нельзя тем более: он же открывает чтение памяти процессов, то есть содержимого
/// переписки (ТЗ §7.4). Поэтому доказательство идёт изнутри: себя процессу читать
/// разрешено всегда, и он публикует хеш в `/health` и в журнал при старте. Цепочка
/// «журнал → файл на диске → коммит» замыкается без единого нового права.
///
/// # Что это доказывает
///
/// Что запущен именно тот файл, чей sha256 назван. Подменённый бинарник назовёт свой
/// хеш честно — и разойдётся с манифестом и с записью установки, а это и есть
/// наблюдаемое событие.
///
/// Считается один раз за время жизни процесса: файл весит десятки мегабайт, а на
/// каждый `/health` его перечитывать незачем — под работающим процессом он не
/// меняется.
pub fn self_sha256() -> &'static str {
    static CACHED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CACHED.get_or_init(|| {
        // `current_exe` на Linux читает /proc/self/exe, на рабочих машинах —
        // соответствующий механизм своей ОС; поэтому тесты идут везде одинаково.
        match std::env::current_exe() {
            Ok(path) => model::manifest::sha256_file(path).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "не удалось посчитать sha256 собственного файла");
                UNKNOWN.to_string()
            }),
            Err(e) => {
                tracing::warn!(error = %e, "неизвестен собственный путь");
                UNKNOWN.to_string()
            }
        }
    })
}

/// Default configuration path on the node.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/hearth/hearthd.toml";

/// Файл режима узла при ПОСТАВОЧНОЙ конфигурации — `<state_dir>/node-mode.json`.
///
/// Это подсказка для человека (сообщения об ошибках, runbook, аварийная команда
/// `hearthctl mode clear --local --file …`), а не источник истины. Гейт и демон берут
/// путь из `paths.state_dir` конфигурации узла (`model::mode::resolve_mode_file`):
/// зашитая константа расходилась с боевым `state_dir` молча — гейт не находил файла и
/// разрешал старт релея в карантине. Совпадение константы с поставочным hearthd.toml
/// проверяется тестом в `model::mode`.
pub const DEFAULT_NODE_MODE_FILE: &str = "/var/lib/hearth/node-mode.json";

#[cfg(test)]
mod tests {
    use super::*;

    /// Паспорт обязан быть заполнен чем-то осмысленным в любой сборке, включая
    /// сборку без git. До появления build.rs полей не было вовсе — тест не
    /// компилировался бы.
    #[test]
    fn the_build_passport_is_stamped_in() {
        let info = build_info();
        assert_eq!(info.version, VERSION);

        assert!(
            info.commit == UNKNOWN
                || (info.commit.len() == 40 && info.commit.chars().all(|c| c.is_ascii_hexdigit())),
            "коммит: 40 hex либо `unknown`, получено `{}`",
            info.commit
        );
        assert!(
            info.tree_sha256 == UNKNOWN
                || (info.tree_sha256.len() == 64
                    && info.tree_sha256.chars().all(|c| c.is_ascii_hexdigit())),
            "хеш дерева: 64 hex либо `unknown`, получено `{}`",
            info.tree_sha256
        );
        for (name, value) in [
            ("target", &info.target),
            ("rustc", &info.rustc),
            ("source_date_epoch", &info.source_date_epoch),
        ] {
            assert!(!value.is_empty(), "поле `{name}` пусто");
        }
    }

    /// Сборка без git не имеет права утверждать чистоту дерева.
    #[test]
    fn an_unknown_commit_is_never_reported_clean() {
        let info = build_info();
        if info.commit == UNKNOWN {
            assert!(info.dirty, "нет git — значит `dirty`, а не «чисто»");
        }
    }

    /// Формат `ключ=значение` разбирается тем же `cut -d=`, что и паспорт APK.
    #[test]
    fn key_values_carry_every_field() {
        let text = build_info().to_key_values();
        for key in [
            "version=",
            "commit=",
            "dirty=",
            "tree_sha256=",
            "target=",
            "rustc=",
            "source_date_epoch=",
        ] {
            assert!(text.contains(key), "в паспорте нет `{key}`:\n{text}");
        }
        assert!(text.ends_with('\n'));
    }

    /// Демон обязан уметь назвать хеш файла, которым он запущен: снаружи связать
    /// процесс с файлом нечем (см. [`self_sha256`]).
    #[test]
    fn the_process_can_measure_its_own_file() {
        let digest = self_sha256();
        assert_eq!(digest.len(), 64, "sha256 собственного файла: {digest}");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        // Повтор берётся из кеша и обязан совпасть.
        assert_eq!(digest, self_sha256());
    }
}
