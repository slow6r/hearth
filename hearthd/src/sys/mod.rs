//! Thin, auditable wrappers around the few host tools hearthd is allowed to call.
//!
//! Design rule: every wrapper is split into "run the command" and "parse the output".
//! The parsers are pure functions with unit tests, so the interesting logic is testable
//! on any machine — including a Windows dev box with no nftables in sight.
//!
//! hearthd shells out to exactly four programs: `systemctl`, `nft`, `ss`, `journalctl`
//! (plus `rsync`/`ssh` in the backup module). None of them may take attacker-controlled
//! arguments; everything comes from the validated configuration.

pub mod journal;
pub mod nft;
pub mod ss;
pub mod systemd;

#[cfg(test)]
use std::collections::VecDeque;
use std::ffi::OsStr;
#[cfg(test)]
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, Result};

/// Captured result of a subprocess.
#[derive(Debug, Clone)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    /// Успешный ответ с заданным stdout — для подменённых ответов в тестах.
    ///
    /// Под `cfg(test)`: на узле такого конструктора нет вовсе. Ответ, собранный не
    /// процессом, а кодом, — это инструмент проверки, и в боевой сборке он не должен
    /// существовать даже как возможность.
    #[cfg(test)]
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
}

/// Сколько команд dry-run хранит журнал оснастки.
///
/// Кольцо, а не растущий список: `hearthd run --dry-run` — долгоживущий процесс,
/// надзор тикает каждые 15 секунд, и журнал без предела был бы утечкой, растущей ровно
/// со временем работы. Проверяют по журналу последние шаги, а не всю историю.
#[cfg(test)]
const RECORDED_CAPACITY: usize = 256;

/// Оснастка тестов: журнал dry-run и таблица подменённых ответов.
///
/// Отдельным типом и целиком под `cfg(test)` — чтобы на узле её не было. Раньше оба
/// поля жили в боевом `Sys`: каждый `capture` брал мьютекс и сверялся с таблицей
/// подмен, а заполнить таблицу мог любой код в процессе — и настоящий ответ
/// `systemctl show` молча заменился бы подставным.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
struct TestHarness {
    /// Что было бы выполнено в dry-run, по порядку, последние [`RECORDED_CAPACITY`].
    ///
    /// Без этого журнала «релеи остановлены» нечем проверить нигде, кроме живого узла:
    /// dry-run молча возвращал успех, и тесты вокруг карантина закрепляли намерение, а
    /// не действие. Общий на все клоны `Sys` — модули получают его через `state.sys`.
    recorded: Arc<Mutex<VecDeque<String>>>,
    /// Подменённые ответы `capture`, по префиксу команды. Нужны, чтобы `systemd::show`
    /// отдавал заданное состояние юнита там, где systemd нет вовсе.
    stubs: Arc<Mutex<Vec<(String, Output)>>>,
}

/// Subprocess runner. `dry_run` short-circuits mutating commands so the daemon can be
/// exercised on a developer machine without a systemd or nftables in sight.
#[derive(Debug, Clone)]
pub struct Sys {
    dry_run: bool,
    timeout: Duration,
    #[cfg(test)]
    harness: TestHarness,
}

impl Default for Sys {
    fn default() -> Self {
        Self {
            dry_run: false,
            timeout: Duration::from_secs(30),
            #[cfg(test)]
            harness: TestHarness::default(),
        }
    }
}

impl Sys {
    pub fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            ..Self::default()
        }
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Run a command and capture its output. Non-zero exit is *not* an error here.
    pub async fn capture<S: AsRef<OsStr>>(&self, program: &str, args: &[S]) -> Result<Output> {
        // В боевой сборке этой ветки нет: ни мьютекса на каждый вызов, ни таблицы,
        // способной подменить ответ systemd.
        #[cfg(test)]
        if let Some(out) = self.stubbed(&describe(program, args)) {
            return Ok(out);
        }
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args.iter().map(AsRef::as_ref));
        cmd.stdin(std::process::Stdio::null());
        cmd.kill_on_drop(true);

        let fut = cmd.output();
        let out = match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(Error::Command {
                    cmd: describe(program, args),
                    status: "spawn-failed".into(),
                    stderr: e.to_string(),
                })
            }
            Err(_) => {
                return Err(Error::Command {
                    cmd: describe(program, args),
                    status: "timeout".into(),
                    stderr: format!("no result after {:?}", self.timeout),
                })
            }
        };
        Ok(Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Run a command and fail on a non-zero exit status.
    pub async fn run<S: AsRef<OsStr>>(&self, program: &str, args: &[S]) -> Result<Output> {
        let out = self.capture(program, args).await?;
        if out.ok() {
            Ok(out)
        } else {
            Err(Error::Command {
                cmd: describe(program, args),
                status: out.code.to_string(),
                stderr: out.stderr.trim().to_string(),
            })
        }
    }

    /// Run a mutating command; in dry-run mode only log what would have happened.
    pub async fn run_mutating<S: AsRef<OsStr>>(&self, program: &str, args: &[S]) -> Result<Output> {
        if self.dry_run {
            let cmd = describe(program, args);
            tracing::info!(command = %cmd, "dry-run: not executing");
            #[cfg(test)]
            self.record(cmd);
            return Ok(Output {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        self.run(program, args).await
    }
}

/// Работает ли процесс с эффективным uid 0.
///
/// `None` — определить не удалось: не Linux, нет `/proc`, строка `Uid:` не разобрана.
/// Что делать с неизвестностью, решает вызывающий: у аварийной команды и у проверки
/// прав в тесте ответы на это разные.
///
/// Почему не `geteuid(3)`. Прямой вызов — это `extern "C"` и `unsafe`-блок, а в крейте
/// стоит `#![forbid(unsafe_code)]`: такой код здесь просто не собирается (на Windows
/// это пряталось за `#[cfg(unix)]`, на узле — нет). Заводить `libc` ради одного числа
/// — плата не по товару, тем более что ядро отдаёт то же самое текстом: в
/// `/proc/self/status` строка `Uid:` перечисляет real, effective, saved и fs (proc(5)).
pub fn effective_uid_is_root() -> Option<bool> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    effective_uid(&status).map(|uid| uid == 0)
}

/// Эффективный uid из текста `/proc/self/status` — вторая колонка строки `Uid:`.
///
/// Отдельной чистой функцией, потому что иначе это не проверяется нигде: на машине
/// разработчика `/proc` нет, а на узле тест уже не запускают.
fn effective_uid(status: &str) -> Option<u32> {
    let line = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Оснастка тестов. В боевой сборке этого блока не существует.
#[cfg(test)]
impl Sys {
    /// Команды, которые dry-run не выполнил, по порядку (последние
    /// [`RECORDED_CAPACITY`]).
    ///
    /// Отравленный мьютекс не повод ронять процесс: журнал — диагностика, а не
    /// решение.
    pub fn recorded(&self) -> Vec<String> {
        match self.harness.recorded.lock() {
            Ok(log) => log.iter().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().iter().cloned().collect(),
        }
    }

    /// Забыть записанное — чтобы тест проверял один шаг, а не всю историю.
    pub fn forget_recorded(&self) {
        if let Ok(mut log) = self.harness.recorded.lock() {
            log.clear();
        }
    }

    /// Отвечать на команды с этим началом заданным выводом, не запуская процесс.
    ///
    /// Последний добавленный ответ побеждает: тест может сначала объявить общий случай,
    /// а потом переопределить один юнит.
    pub fn stub_capture(&self, prefix: impl Into<String>, out: Output) {
        if let Ok(mut stubs) = self.harness.stubs.lock() {
            stubs.push((prefix.into(), out));
        }
    }

    fn stubbed(&self, cmd: &str) -> Option<Output> {
        let stubs = self.harness.stubs.lock().ok()?;
        stubs
            .iter()
            .rev()
            .find(|(prefix, _)| cmd.starts_with(prefix.as_str()))
            .map(|(_, out)| out.clone())
    }

    /// Дописать команду в кольцевой журнал, вытеснив самую старую.
    fn record(&self, cmd: String) {
        let mut log = match self.harness.recorded.lock() {
            Ok(log) => log,
            Err(poisoned) => poisoned.into_inner(),
        };
        if log.len() == RECORDED_CAPACITY {
            log.pop_front();
        }
        log.push_back(cmd);
    }
}

fn describe<S: AsRef<OsStr>>(program: &str, args: &[S]) -> String {
    let mut out = program.to_string();
    for a in args {
        out.push(' ');
        out.push_str(&a.as_ref().to_string_lossy());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_skips_mutating_commands() {
        let sys = Sys::new(true);
        let out = sys
            .run_mutating("definitely-not-a-real-program", &["--boom"])
            .await
            .expect("dry-run succeeds without executing");
        assert!(out.ok());
    }

    #[tokio::test]
    async fn dry_run_records_what_it_would_have_run() {
        // Комментарии в тестах утверждали «is recorded, not executed», а записи не
        // было: dry-run молча возвращал успех, и проверить «релеи остановлены» было
        // нечем.
        let sys = Sys::new(true);
        sys.run_mutating("systemctl", &["stop", "smp-server.service"])
            .await
            .expect("dry-run");
        assert_eq!(sys.recorded(), vec!["systemctl stop smp-server.service"]);
        sys.forget_recorded();
        assert!(sys.recorded().is_empty());
    }

    #[tokio::test]
    async fn a_stubbed_capture_does_not_spawn_anything() {
        let sys = Sys::new(true);
        sys.stub_capture(
            "systemctl show smp-server.service",
            Output::success("ActiveState=active\n"),
        );
        let out = sys
            .capture("systemctl", &["show", "smp-server.service", "--property=X"])
            .await
            .expect("stub");
        assert!(out.ok());
        assert!(out.stdout.contains("active"));
    }

    #[tokio::test]
    async fn the_dry_run_log_is_a_ring_and_does_not_grow_forever() {
        // `hearthd run --dry-run` живёт неделями, а надзор тикает каждые 15 секунд:
        // журнал без предела — утечка, растущая ровно со временем работы узла.
        let sys = Sys::new(true);
        let overflow = RECORDED_CAPACITY + 10;
        for i in 0..overflow {
            let unit = format!("unit-{i}.service");
            sys.run_mutating("systemctl", &["stop", unit.as_str()])
                .await
                .expect("dry-run");
        }
        let log = sys.recorded();
        assert_eq!(log.len(), RECORDED_CAPACITY, "журнал обязан быть ограничен");
        let newest = format!("unit-{}.service", overflow - 1);
        assert!(
            log.iter().any(|cmd| cmd.ends_with(&newest)),
            "последняя команда обязана остаться: {log:?}"
        );
        assert!(
            !log.iter().any(|cmd| cmd.ends_with("unit-0.service")),
            "самые старые записи обязаны вытесняться: {log:?}"
        );
    }

    /// Оснастка обязана оставаться в тестовой сборке.
    ///
    /// Проверяется по исходнику, потому что иначе это не проверяется никак: в тестовой
    /// сборке подмены доступны по определению, а изнутри теста утверждать «в боевой
    /// сборке их нет» нечем. Тест падает ровно тогда, когда подмена ответа `systemctl`
    /// снова окажется доступна на боевом узле.
    #[test]
    fn the_test_harness_never_reaches_a_live_node() {
        let src = include_str!("mod.rs").replace("\r\n", "\n");
        let (live, harness) = src
            .split_once("#[cfg(test)]\nimpl Sys {")
            .expect("оснастка обязана лежать в отдельном impl под cfg(test)");
        for name in [
            "fn recorded(",
            "fn forget_recorded(",
            "fn stub_capture(",
            "fn stubbed(",
        ] {
            assert!(!live.contains(name), "{name} снова объявлен в боевом пути");
            assert!(harness.contains(name), "{name} потерялся при переносе");
        }
        assert!(
            src.contains("#[cfg(test)]\n    pub fn success("),
            "Output::success — оснастка тестов и обязана оставаться под cfg(test)"
        );
    }

    #[tokio::test]
    async fn missing_program_is_a_command_error() {
        let sys = Sys::new(false);
        let err = sys
            .capture("definitely-not-a-real-program", &["--boom"])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Command { .. }), "got {err:?}");
    }

    /// Дефект 5: единственный `unsafe` в дереве (объявленный `geteuid`) заменён
    /// чтением `/proc/self/status`. Разбор обязан брать ИМЕННО эффективный uid —
    /// вторую колонку: у команды под `sudo` real uid остаётся пользовательским, и
    /// ошибка в колонке означала бы «root не распознан».
    #[test]
    fn the_effective_uid_is_the_second_column() {
        let root = "Name:\thearthctl\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
        assert_eq!(effective_uid(root), Some(0));

        // sudo: real uid — того, кто позвал, effective — 0.
        let sudo = "Name:\thearthctl\nUid:\t1000\t0\t0\t0\n";
        assert_eq!(effective_uid(sudo), Some(0));

        // Обычный запуск: root'а нет ни в одной колонке.
        let plain = "Name:\thearthctl\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(effective_uid(plain), Some(1000));

        // Ни строки `Uid:`, ни второй колонки — не выдумываем ответ.
        assert_eq!(effective_uid("Name:\thearthctl\n"), None);
        assert_eq!(effective_uid("Uid:\t0\n"), None);
        assert_eq!(effective_uid("Uid:\tx\ty\n"), None);
    }

    /// На машине разработчика `/proc/self/status` не читается, и ответ обязан быть
    /// «не знаю», а не «не root»: вызывающий отличает одно от другого.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn without_proc_the_answer_is_unknown() {
        assert_eq!(effective_uid_is_root(), None);
    }
}
