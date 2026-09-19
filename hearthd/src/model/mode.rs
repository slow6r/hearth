//! Режим узла — единственное место, где решается, каким службам сейчас можно работать.
//!
//! # Зачем он понадобился
//!
//! Раньше «эти службы запрещены» существовало тремя несвязанными признаками в памяти
//! процесса: `IntegrityChecker::stopped_relays`, `MigrateStatus::relays_stopped` и
//! ничем для обслуживания. Supervisor о них не знал, и на ближайшем тике —
//! `check_interval_secs = 15` — поднимал релеи обратно.
//!
//! Из этого следовали две вещи, каждая из которых хуже отсутствия механизма:
//!
//!  * карантина по целостности фактически не было. Подменённый бинарь останавливался,
//!    через пятнадцать секунд возвращался в строй, порт отвечал, состояние снова
//!    считалось нормальным — и повторно остановить его было уже некому, потому что
//!    флаг «уже останавливали» подавлял вторую попытку;
//!  * перенос узла заканчивался двумя живыми релеями с одним CA и одним адресом.
//!    Клиенты их не различают, часть сообщений уходит на выводимую машину. Модуль
//!    миграции называет это недопустимым — и сам же это создавал.
//!
//! # Как устроено теперь
//!
//! Решение принимается ровно здесь, хранится на диске и переживает перезапуск демона
//! и перезагрузку машины. Снимается только человеком: причина, по которой службы
//! остановлены, не исчезает оттого, что процесс перезапустился.
//!
//! # Чего это НЕ делает
//!
//! Не мешает оператору поднять службу руками через `systemctl`. Узел не воюет с
//! человеком за клавиатурой — он лишь не поднимает запрещённое сам и говорит в
//! `hearthctl status`, в каком он режиме и почему.
//!
//! # Почему у запрета обязан быть локальный выход
//!
//! Это узел семьи, а не стенд. Любая блокировка, которую нельзя снять на самой машине,
//! однажды превратится в «связи нет и не будет»: сетевое снятие (`hearthctl mode clear`)
//! требует работающего hearthd и админского сертификата, а именно их и не бывает в тот
//! вечер, когда узел не поднялся. Поэтому рядом с запретом живёт [`write_normal`] —
//! локальное снятие с правами root, без демона, без сети и без PKI (см.
//! `hearthctl mode clear --local` и docs/runbook-node-mode.md).

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// В каком состоянии узел.
///
/// Список намеренно короткий: каждый режим отвечает на один вопрос — можно ли сейчас
/// держать релеи. Расширять его стоит только тогда, когда появится сценарий, которому
/// нужен другой набор разрешённых служб, а не другое название для того же запрета.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeMode {
    /// Обычная работа.
    #[default]
    Normal,
    /// Целостность не подтверждена: хеш не совпал либо манифест не прочитан.
    Quarantine,
    /// Обслуживание по решению оператора.
    Maintenance,
    /// Идёт перенос на другой узел; второй живой релей здесь недопустим.
    Migration,
}

impl NodeMode {
    /// Можно ли supervisor'у поднимать релеи.
    ///
    /// Разрешено ровно в одном режиме. Это и есть весь смысл типа: любое новое
    /// состояние по умолчанию запрещает, а не разрешает.
    pub fn relays_allowed(self) -> bool {
        matches!(self, NodeMode::Normal)
    }

    /// Как назвать режим человеку.
    pub fn label(self) -> &'static str {
        match self {
            NodeMode::Normal => "норма",
            NodeMode::Quarantine => "карантин",
            NodeMode::Maintenance => "обслуживание",
            NodeMode::Migration => "перенос",
        }
    }
}

/// Режим вместе с тем, почему он наступил.
///
/// Причина хранится рядом с самим режимом не для красоты: человек, увидевший
/// остановленные релеи через неделю после инцидента, должен узнать причину из узла, а
/// не из своей памяти.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeState {
    pub mode: NodeMode,
    /// Когда режим установлен.
    #[serde(with = "crate::model::rfc3339")]
    pub since: DateTime<Utc>,
    /// Почему. Пустая строка допустима только для нормы.
    #[serde(default)]
    pub reason: String,
    /// Что именно не сошлось — для карантина по целостности.
    #[serde(default)]
    pub findings: Vec<String>,
}

impl Default for NodeState {
    fn default() -> Self {
        Self::normal()
    }
}

impl NodeState {
    pub fn normal() -> Self {
        Self {
            mode: NodeMode::Normal,
            since: Utc::now(),
            reason: String::new(),
            findings: Vec::new(),
        }
    }

    /// Перевести узел в режим с причиной.
    pub fn enter(mode: NodeMode, reason: impl Into<String>, findings: Vec<String>) -> Self {
        Self {
            mode,
            since: Utc::now(),
            reason: reason.into(),
            findings,
        }
    }

    pub fn relays_allowed(&self) -> bool {
        self.mode.relays_allowed()
    }

    /// Строка для `hearthctl status`.
    pub fn summary(&self) -> String {
        if self.mode == NodeMode::Normal {
            return "режим: норма".to_string();
        }
        format!(
            "режим: {} с {} — {}",
            self.mode.label(),
            self.since.format("%Y-%m-%d %H:%M UTC"),
            if self.reason.is_empty() {
                "причина не записана"
            } else {
                &self.reason
            }
        )
    }
}

/// Что гейт отвечает systemd перед стартом релейного юнита.
///
/// Гейт нужен потому, что решение «запускать ли службу» принимает не только hearthd.
/// Релейные юниты стоят в `multi-user.target` и стартуют при каждой загрузке — до
/// того, как демон вообще успел прочитать режим. Без гейта карантин снимался первой
/// же перезагрузкой, а домашний узел перезагружается от любого сбоя питания.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    /// Режим не запрещает работу релеев — юнит стартует как обычно.
    Allow,
    /// Стартовать нельзя; строка объясняет человеку в `journalctl`, почему.
    Deny(String),
}

impl GateVerdict {
    pub fn allowed(&self) -> bool {
        matches!(self, GateVerdict::Allow)
    }
}

/// Решение гейта по содержимому `node-mode.json`.
///
/// Чистая функция, потому что ошибиться здесь дороже всего: неверный ответ оставляет
/// семью без мессенджера после обычной перезагрузки, и выглядит это в журнале как
/// безобидное `condition failed`.
///
/// Правила ровно три:
///
///  * файла нет (`None`) — обычный узел. Запрет должен быть записан ЯВНО, иначе
///    первый же запуск на чистой машине встанет колом;
///  * файл читается и режим `normal` — разрешаем;
///  * всё остальное, включая нечитаемый JSON, — запрещаем. Битый файл режима не
///    отличим от подчищенного, а fail-closed важнее удобства.
pub fn gate_verdict(raw: Option<&str>) -> GateVerdict {
    let Some(raw) = raw else {
        return GateVerdict::Allow;
    };
    match serde_json::from_str::<NodeState>(raw) {
        Ok(state) if state.relays_allowed() => GateVerdict::Allow,
        Ok(state) => GateVerdict::Deny(state.summary()),
        Err(e) => GateVerdict::Deny(format!(
            "файл режима узла не разобран ({e}); \
             пока он не исправлен, релеи не запускаются"
        )),
    }
}

/// Имя файла режима внутри `paths.state_dir`.
///
/// Одно на весь код: и `Paths::node_mode_file`, и гейт собирают путь из него, поэтому
/// разъехаться им негде.
pub const NODE_MODE_FILE_NAME: &str = "node-mode.json";

/// Локальный выход из запрета. Печатается всюду, где запрет виден человеку.
///
/// Текст один и тот же в журнале systemd, в `hearthctl status` и в документации
/// намеренно: человек, читающий `journalctl` в темноте, не должен искать команду в
/// другом месте.
pub const LOCAL_EXIT_HINT: &str = "снять режим на самом узле (root, без hearthd и без \
     сертификата): hearthctl mode clear --local — см. docs/runbook-node-mode.md";

/// Откуда гейт берёт путь к файлу режима.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeFile {
    /// Путь известен: из `--file` либо из `paths.state_dir` конфигурации узла.
    At(PathBuf),
    /// Конфигурация недоступна, взят путь по умолчанию; строка объясняет, почему.
    ///
    /// # Почему не отказ
    ///
    /// Раньше здесь был `Unknown`, и гейт отвечал `Deny` ВСЕМ четырём юнитам: не
    /// знаем, где режим, — не знаем, что он `normal`. Цена этого fail-closed —
    /// переименованный или недописанный `hearthd.toml` кладёт связь семьи целиком, и
    /// `mode clear --local` из этого состояния не выводит: гейт всё равно не знает,
    /// куда смотреть.
    ///
    /// Между «ошибка администратора» и «атака» здесь выбрана доступность, и вот
    /// почему это не дыра: подчистить `hearthd.toml` может только тот, кто пишет в
    /// `/etc/hearth`, то есть root, — а он тем же движением снимет и сам файл режима,
    /// от чего fail-closed всё равно не спасает (отсутствие файла разрешает старт по
    /// построению). Зато записанный на диск запрет по стандартному пути продолжает
    /// действовать и при сломанной конфигурации, а причина подмены пути громко уходит
    /// в journal при КАЖДОМ решении гейта — и при разрешающем тоже.
    ///
    /// Остаточный риск назван честно: узел с нестандартным `paths.state_dir` и
    /// сломанной конфигурацией будет судим по пустому пути по умолчанию, то есть
    /// запрет с него слетит. Это записано в docs/runbook-node-mode.md §3.
    Fallback(PathBuf, String),
}

impl ModeFile {
    /// Файл, по которому будет принято решение, независимо от того, откуда взят путь.
    pub fn path(&self) -> &Path {
        match self {
            ModeFile::At(path) => path,
            ModeFile::Fallback(path, _) => path,
        }
    }

    /// Почему путь пришлось брать по умолчанию. `None` — путь взят штатно.
    pub fn fallback_reason(&self) -> Option<&str> {
        match self {
            ModeFile::At(_) => None,
            ModeFile::Fallback(_, why) => Some(why),
        }
    }
}

/// Ровно то, что гейту нужно от hearthd.toml, и ничего больше.
///
/// Разбирать здесь полную `Config` нельзя: она проходит `validate()`, и любая будущая
/// проверка (или опечатка в постороннем разделе) превратилась бы в «релеи не
/// стартуют». Нам нужен один путь — его и читаем, остальные разделы serde пропустит.
#[derive(Debug, Deserialize)]
struct StateDirOnly {
    paths: StateDirSection,
}

#[derive(Debug, Deserialize)]
struct StateDirSection {
    state_dir: PathBuf,
}

/// Найти файл режима так же, как его находит демон.
///
/// Раньше путь был зашит константой и в коде, и в drop-in'е. На узле, где
/// `paths.state_dir` отличается от поставочного, гейт смотрел в пустоту, не находил
/// файла и МОЛЧА разрешал старт релея в карантине — то есть запрета не было вовсе.
/// Поэтому путь берётся оттуда же, откуда его берёт hearthd: из конфигурации.
pub fn resolve_mode_file(explicit: Option<&Path>, config_path: &Path) -> ModeFile {
    // Явный `--file` сильнее конфигурации: им пользуются приёмочные проверки и
    // аварийное снятие на узле, где hearthd.toml как раз и сломан.
    if let Some(path) = explicit {
        return ModeFile::At(path.to_path_buf());
    }
    let raw = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(e) => {
            return fallback(format!("{} не прочитан: {e}", config_path.display()));
        }
    };
    match toml::from_str::<StateDirOnly>(&raw) {
        Ok(cfg) => ModeFile::At(cfg.paths.state_dir.join(NODE_MODE_FILE_NAME)),
        Err(e) => fallback(format!(
            "в {} не разобран paths.state_dir: {e}",
            config_path.display()
        )),
    }
}

/// Путь по умолчанию плюс причина, по которой пришлось его взять.
fn fallback(why: String) -> ModeFile {
    ModeFile::Fallback(
        PathBuf::from(crate::DEFAULT_NODE_MODE_FILE),
        format!(
            "{why}; решение принято по пути по умолчанию {} \u{2014} почините \
             /etc/hearth/hearthd.toml (docs/runbook-node-mode.md, \u{00A7}3)",
            crate::DEFAULT_NODE_MODE_FILE
        ),
    )
}

/// Ответ гейта целиком: куда он смотрел и что решил.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateDecision {
    /// Файл, по которому принято решение.
    pub file: PathBuf,
    /// Заполнено, если путь взят по умолчанию, а не из конфигурации узла. Эту строку
    /// обязан напечатать КАЖДЫЙ вызов гейта, включая разрешающий: тихая подмена пути
    /// и есть тот случай, ради которого путь стали брать из конфигурации.
    pub fallback: Option<String>,
    pub verdict: GateVerdict,
}

/// Решение гейта: найти файл режима, прочитать его, ответить systemd.
///
/// Вся логика здесь, а не в `hearthctl`, чтобы её можно было проверить тестом, не
/// поднимая ни systemd, ни узел: ошибка в этой функции стоит семье связи.
///
/// Недоступная конфигурация — НЕ запрет: решение принимается по файлу режима на пути
/// по умолчанию, а причина подмены пути громко печатается при каждом вызове (см.
/// [`ModeFile::Fallback`]). Записанный на диск запрет при этом продолжает
/// действовать; чтобы он не стал вечным, к каждому отказу прикладывается
/// [`LOCAL_EXIT_HINT`].
pub fn decide_gate(explicit: Option<&Path>, config_path: &Path) -> GateDecision {
    let resolved = resolve_mode_file(explicit, config_path);
    let fallback = resolved.fallback_reason().map(str::to_string);
    let path = resolved.path().to_path_buf();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => Some(raw),
        // Файла нет — обычный узел. Единственная ошибка чтения, которая
        // разрешает старт: запрет обязан быть записан ЯВНО.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return GateDecision {
                verdict: GateVerdict::Deny(format!(
                    "{} не прочитан ({e}); пока это не исправлено, релеи не запускаются",
                    path.display()
                )),
                file: path,
                fallback,
            };
        }
    };
    GateDecision {
        verdict: gate_verdict(raw.as_deref()),
        file: path,
        fallback,
    }
}

/// Записать «норма» прямо в файл режима.
///
/// Локальный выход из любого запрета: работает с правами root на самом узле, без
/// демона, без сети и без админского сертификата. Единственный писатель файла режима —
/// и в этой функции, и в `AppState::clear_mode`, чтобы права и атомарность записи не
/// разъехались между двумя путями снятия.
pub fn write_normal(path: &Path) -> crate::error::Result<NodeState> {
    let next = NodeState::normal();
    // ТОЛЬКО с наследованием владельца. `hearthctl mode clear --local` требует root,
    // атомарная запись создаёт НОВЫЙ файл, и обычная `write_json_atomic` оставляла
    // здесь `root:root`: hearthd под пользователем `hearth` переставал читать файл
    // режима. Аварийный выход приводил узел в состояние «релеи есть, управляющего
    // контура нет» — см. тест `the_mode_file_is_written_with_the_owning_writer`.
    crate::store::write_json_atomic_inheriting_owner(path, &next, crate::store::MODE_STATE)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_mode_file_lets_the_node_boot() {
        // Единственный разрешающий ответ, который гейт даёт без чтения режима.
        assert_eq!(gate_verdict(None), GateVerdict::Allow);
    }

    #[test]
    fn the_gate_lets_a_normal_node_start() {
        let raw = serde_json::to_string(&NodeState::normal()).expect("json");
        assert!(gate_verdict(Some(&raw)).allowed());
    }

    #[test]
    fn the_gate_stops_every_restricting_mode() {
        for mode in [
            NodeMode::Quarantine,
            NodeMode::Maintenance,
            NodeMode::Migration,
        ] {
            let raw =
                serde_json::to_string(&NodeState::enter(mode, "инцидент", vec![])).expect("json");
            let verdict = gate_verdict(Some(&raw));
            assert!(!verdict.allowed(), "{mode:?} обязан запрещать старт");
            match verdict {
                GateVerdict::Deny(text) => assert!(text.contains("инцидент"), "{text}"),
                GateVerdict::Allow => unreachable!(),
            }
        }
    }

    #[test]
    fn an_unreadable_mode_file_forbids_the_start() {
        // Битый файл не отличим от подчищенного. Разрешать по нему — значит сделать
        // обход карантина вопросом одной усечённой записи.
        let verdict = gate_verdict(Some("{это не json"));
        assert!(!verdict.allowed());
        let verdict = gate_verdict(Some(""));
        assert!(!verdict.allowed());
    }

    /// Drop-in, который install.sh кладёт каждому релейному юниту.
    const GATE_DROPIN: &str = include_str!("../../deploy/systemd/relay.service.d-hearth-mode.conf");

    #[test]
    fn the_shipped_units_ask_the_gate_before_starting() {
        // Поставка — половина механизма: гейт, которого нет в юните, не работает.
        assert!(
            GATE_DROPIN.contains(&format!(
                "ExecCondition=+/usr/local/bin/hearthctl --config {} mode gate",
                crate::DEFAULT_CONFIG_PATH
            )),
            "{GATE_DROPIN}"
        );
        // Префикс «+» обязателен: без него гейт читает 0750 hearth:hearth из-под
        // simplex, получает EACCES и запрещает старт ВСЕГДА.
        assert!(GATE_DROPIN.contains("ExecCondition=+"));
        // ExecStartPre перевёл бы юнит в failed: Restart=on-failure, лавина алертов и
        // красный узел вместо тихо пропущенного юнита. Комментарии не в счёт — в них
        // как раз объясняется, почему не он.
        let directives: Vec<&str> = GATE_DROPIN
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .collect();
        assert!(
            !directives.iter().any(|line| line.contains("ExecStartPre")),
            "{directives:?}"
        );
        // Путь к файлу режима в drop-in'е НЕ зашивается: он берётся из конфигурации
        // узла. Зашитый путь расходился с боевым `paths.state_dir` молча — гейт не
        // находил файла и разрешал старт в карантине.
        assert!(
            !directives.iter().any(|line| line.contains("--file")),
            "{directives:?}"
        );
        // Локальный выход обязан быть назван там же, где запрет: человек читает этот
        // файл именно тогда, когда релеи не поднялись.
        assert!(
            GATE_DROPIN.contains("mode clear --local"),
            "drop-in обязан называть локальный выход"
        );
    }

    #[test]
    fn the_gate_does_not_take_its_config_from_the_environment() {
        // Дефект 4: ExecCondition наследует окружение юнита, а hearthctl понимает
        // HEARTHD_CONFIG. Переменная, заданная в юните релея или в /etc/default, молча
        // увела бы гейт на чужую конфигурацию — то есть на чужой файл режима. Защита
        // двойная: путь в командной строке (он сильнее переменной) и снятие самой
        // переменной с юнита.
        assert!(
            GATE_DROPIN.contains(&format!("--config {}", crate::DEFAULT_CONFIG_PATH)),
            "{GATE_DROPIN}"
        );
        assert!(
            GATE_DROPIN.contains("UnsetEnvironment=HEARTHD_CONFIG"),
            "{GATE_DROPIN}"
        );
    }

    #[test]
    fn the_gate_waits_for_the_state_directory_mount() {
        // Остаточный fail-open: если paths.state_dir на отдельном разделе, релейный
        // юнит стартовал ДО монтирования, гейт не находил файла режима на ещё не
        // смонтированном разделе и МОЛЧА разрешал старт в карантине.
        assert!(GATE_DROPIN.contains("[Unit]"), "{GATE_DROPIN}");
        assert!(
            GATE_DROPIN.contains("RequiresMountsFor=/var/lib/hearth"),
            "{GATE_DROPIN}"
        );
        // Нестандартный state_dir дописывает установщик — иначе строка была бы верна
        // только для поставочной конфигурации.
        assert!(
            INSTALL_SH.contains("RequiresMountsFor=$STATE_DIR"),
            "установщик обязан дописать реальный state_dir"
        );
    }

    #[test]
    fn the_skipped_unit_without_a_hearth_line_is_explained() {
        // Замечание 22: пропавший hearthctl даёт ExecCondition код 203, юнит помечается
        // пропущенным, и в журнале НЕТ ни одной строки `hearth:`. Исправить это из
        // юнита нельзя — значит признак обязан быть описан там, где его будут искать.
        assert!(GATE_DROPIN.contains("203"), "{GATE_DROPIN}");
        let runbook = include_str!("../../../docs/runbook-node-mode.md");
        assert!(runbook.contains("203"), "runbook обязан назвать код 203");
        assert!(
            runbook.contains("Skipped due to 'exec-condition'"),
            "runbook обязан показать, как это выглядит в журнале"
        );
        let docs = include_str!("../../../docs/acceptance-tests.md");
        assert!(docs.contains("203"), "A15 обязан назвать код 203");
    }

    #[test]
    fn the_daemon_unit_does_not_restart_a_terminal_failure() {
        // Петля «preflight → карантин → рестарт через 5 с» наматывала алерты вечно и
        // не давала выйти локально: снятие режима переживало ровно пять секунд.
        let unit = include_str!("../../deploy/systemd/hearthd.service");
        assert!(
            unit.contains("RestartPreventExitStatus=78"),
            "терминальный отказ не должен перезапускаться: {unit}"
        );
    }

    #[test]
    fn the_gate_follows_the_configured_state_dir() {
        // Дефект, который это стережёт: путь был зашит константой, боевой hearthd.toml
        // задавал другой state_dir, гейт не находил файла — и МОЛЧА разрешал старт
        // релея в карантине.
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join("своё-место");
        std::fs::create_dir_all(&state_dir).expect("state_dir");
        let config_path = dir.path().join("hearthd.toml");
        std::fs::write(
            &config_path,
            // `{:?}` экранирует обратные слэши ровно так, как требует TOML: тесты
            // идут и на Windows, где путь выглядит как C:\Users\...
            format!("[paths]\nstate_dir = {:?}\n", state_dir.to_string_lossy()),
        )
        .expect("config");

        let resolved = resolve_mode_file(None, &config_path);
        assert_eq!(
            resolved,
            ModeFile::At(state_dir.join(NODE_MODE_FILE_NAME)),
            "гейт обязан смотреть туда же, куда пишет демон"
        );

        // На чистом узле файла нет — старт разрешён.
        assert!(decide_gate(None, &config_path).verdict.allowed());

        // Записали карантин ТУДА, КУДА УКАЗЫВАЕТ КОНФИГУРАЦИЯ — гейт обязан его увидеть.
        let quarantine = NodeState::enter(NodeMode::Quarantine, "подмена бинаря", vec![]);
        std::fs::write(
            state_dir.join(NODE_MODE_FILE_NAME),
            serde_json::to_string(&quarantine).expect("json"),
        )
        .expect("write");
        let decision = decide_gate(None, &config_path);
        assert!(!decision.verdict.allowed(), "{decision:?}");
        assert_eq!(decision.file, state_dir.join(NODE_MODE_FILE_NAME));
    }

    #[test]
    fn the_reference_config_and_the_default_path_agree() {
        // Поставочный конфиг обязан давать тот же путь, что и константа по умолчанию:
        // иначе документация и аварийные команды в runbook укажут не на тот файл.
        let raw = include_str!("../../deploy/hearthd.toml");
        let config: crate::config::Config = toml::from_str(raw).expect("reference config");
        assert_eq!(
            config.paths.node_mode_file(),
            std::path::Path::new(crate::DEFAULT_NODE_MODE_FILE)
        );
    }

    #[test]
    fn a_broken_config_no_longer_silences_every_relay() {
        // Дефект: нечитаемый или неразбираемый hearthd.toml давал гейту `Deny` для
        // ВСЕХ четырёх юнитов, и `mode clear --local` из этого состояния не выводил —
        // гейт всё равно не знал, куда смотреть. Опечатка администратора стоила семье
        // связи целиком. Теперь путь берётся по умолчанию, и причина громко называется.
        let dir = tempfile::tempdir().expect("tempdir");
        let default_file = Path::new(crate::DEFAULT_NODE_MODE_FILE);

        for config in [
            dir.path().join("нет-такого.toml"),
            dir.path().join("hearthd.toml"),
        ] {
            if config.file_name() == Some(std::ffi::OsStr::new("hearthd.toml")) {
                // Конфигурация есть, но раздела paths в ней нет.
                std::fs::write(&config, "[node]\nname = \"дом\"\n").expect("config");
            }
            let resolved = resolve_mode_file(None, &config);
            assert_eq!(
                resolved.path(),
                default_file,
                "при недоступной конфигурации смотрим путь по умолчанию"
            );
            let why = resolved
                .fallback_reason()
                .expect("причина подмены пути обязана быть названа");
            assert!(why.contains("hearthd.toml"), "{why}");
            assert!(why.contains("runbook-node-mode.md"), "{why}");

            let decision = decide_gate(None, &config);
            assert_eq!(decision.file, default_file);
            assert_eq!(decision.fallback.as_deref(), Some(why));
            // Отказ, если он и будет, — только по СОДЕРЖИМОМУ файла режима, а не по
            // самому факту сломанной конфигурации.
            if let GateVerdict::Deny(text) = &decision.verdict {
                assert!(
                    !text.contains("путь к файлу режима не определён"),
                    "сломанный конфиг сам по себе больше не запрещает старт: {text}"
                );
            }
        }
    }

    #[test]
    fn the_way_out_of_a_ban_stays_executable_on_the_node() {
        // Выход из запрета обязан быть исполним на узле: root, без демона и без mTLS.
        assert!(
            LOCAL_EXIT_HINT.contains("mode clear --local"),
            "{LOCAL_EXIT_HINT}"
        );
        assert!(!LOCAL_EXIT_HINT.contains("API"));
    }

    #[test]
    fn a_ban_on_the_default_path_survives_a_broken_config() {
        // Обратная сторона той же монеты: доступность выбрана, но ЗАПИСАННЫЙ запрет
        // обязан продолжать действовать. Проверяем чистую часть решения — ту, что не
        // зависит от содержимого /var на машине, где идут тесты.
        let raw = serde_json::to_string(&NodeState::enter(
            NodeMode::Quarantine,
            "подмена бинаря",
            vec![],
        ))
        .expect("json");
        assert!(!gate_verdict(Some(&raw)).allowed());
    }

    /// Исходник этого модуля — для теста о выборе функции записи.
    const THIS_FILE: &str = include_str!("mode.rs");

    #[test]
    fn the_mode_file_is_written_with_the_owning_writer() {
        // Дефект, который это стережёт, лечился одной строкой и стоил узлу управления:
        // `write_normal` писала файл режима обычной `write_json_atomic`, то есть БЕЗ
        // наследования владельца. Из `AppState::clear_mode` это безвредно (пишет сам
        // hearth), а из `sudo hearthctl mode clear --local` файл получал `root:root` —
        // и демон под пользователем `hearth` переставал его читать.
        //
        // Тест смотрит именно на ВЫБОР функции: поведенчески отличить наследование
        // владельца можно только на unix и только под двумя разными пользователями,
        // то есть не в юнит-тесте.
        let body = THIS_FILE
            .split_once("pub fn write_normal(")
            .expect("write_normal на месте")
            .1;
        let body = body.split_once("\n}").expect("тело функции").0;
        assert!(
            body.contains("write_json_atomic_inheriting_owner"),
            "файл режима обязан писаться с наследованием владельца: {body}"
        );
        assert!(
            !body.contains("store::write_json_atomic(") && !body.contains("store::write_atomic("),
            "запись без наследования владельца оставит файл root:root: {body}"
        );
    }

    #[test]
    fn a_local_clear_refuses_when_there_is_no_owner_to_inherit() {
        // Если каталога состояния нет, наследовать владельца не от кого. Создать файл
        // молча — значит отдать его root и сломать следующий старт демона. Человеку,
        // который стоит перед узлом, лучше внятный отказ.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("нет-каталога").join(NODE_MODE_FILE_NAME);
        let err = write_normal(&path).expect_err("отказ вместо молчаливого root-файла");
        let text = err.to_string();
        assert!(text.contains("владельца"), "{text}");
        assert!(!path.exists(), "файл не должен появиться");
    }

    #[test]
    fn a_local_clear_writes_a_mode_the_gate_accepts() {
        // Локальное снятие — единственный путь, когда hearthd не работает, а
        // админский сертификат недоступен. Проверяем именно связку: то, что записала
        // `write_normal`, гейт обязан принять.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join(NODE_MODE_FILE_NAME);
        std::fs::write(
            &file,
            serde_json::to_string(&NodeState::enter(NodeMode::Quarantine, "инцидент", vec![]))
                .expect("json"),
        )
        .expect("write");
        assert!(!decide_gate(Some(&file), Path::new("нет.toml"))
            .verdict
            .allowed());

        let cleared = write_normal(&file).expect("локальное снятие");
        assert!(cleared.relays_allowed());
        assert!(decide_gate(Some(&file), Path::new("нет.toml"))
            .verdict
            .allowed());
    }

    /// Установщик узла.
    const INSTALL_SH: &str = include_str!("../../deploy/install.sh");

    #[test]
    fn the_installer_checks_the_gate_before_touching_the_node() {
        // Дефект: проверка стояла на шаге 6 — после замены бинарников, конфигов и
        // юнитов и до daemon-reload. Обновление, при котором собрали не всё,
        // обрывалось посередине и оставляло узел полусобранным.
        let check = INSTALL_SH
            .find("предполётная проверка")
            .expect("проверка обязана быть отдельным шагом 0");
        // Первое изменение на узле — создание пользователей на шаге 1.
        let first_change = INSTALL_SH
            .find("useradd")
            .expect("установщик заводит пользователей");
        assert!(
            check < first_change,
            "проверка обязана идти ДО любых изменений на узле"
        );
        let block = &INSTALL_SH[check..first_change];
        assert!(block.contains("exit 1"), "{block}");
        // И она обязана оставаться проверкой: ничего не ставит и не создаёт.
        assert!(
            !block.contains("install -"),
            "предполётная проверка не должна ничего менять: {block}"
        );
    }

    #[test]
    fn the_installer_refuses_to_deploy_a_gate_nobody_can_run() {
        // Дефект: drop-in с ExecCondition ставился и там, где hearthctl не установлен.
        // systemd отвечает на такой ExecCondition кодом 203, юнит помечается
        // пропущенным — релеи молча не стартуют ни сейчас, ни после перезагрузки.
        let check = INSTALL_SH
            .find("hearthctl не установлен")
            .expect("установщик обязан проверять hearthctl перед раскладкой гейта");
        let dropin = INSTALL_SH
            .find("hearth-mode.conf")
            .expect("drop-in гейта ставится установщиком");
        assert!(
            check < dropin,
            "проверка обязана идти ДО раскладки drop-in'а"
        );
        // Именно ошибка установки, а не предупреждение.
        let block = &INSTALL_SH[check..dropin];
        assert!(block.contains("exit 1"), "{block}");
    }

    #[test]
    fn the_installer_gates_coturn_too() {
        // ADR 0013 обещает, что в не-normal режиме не работает НИ ОДНА служба узла.
        // Без этого drop-in'а coturn поднимался бы при каждой загрузке.
        assert!(
            INSTALL_SH.contains("coturn.service.d/hearth-mode.conf"),
            "coturn обязан спрашивать гейт режима"
        );
    }

    #[test]
    fn the_acceptance_section_the_script_points_at_exists() {
        // Скрипт A15 отсылает за разрушающей половиной проверки в раздел A15
        // docs/acceptance-tests.md. Раздела не было — то есть единственное настоящее
        // доказательство работы гейта не описано нигде.
        let script = include_str!("../../../tests/acceptance/a15-mode-gate.sh");
        assert!(script.contains("раздел A15"), "{script}");
        let docs = include_str!("../../../docs/acceptance-tests.md");
        assert!(docs.contains("\n## A15 "), "раздел A15 обязан существовать");
        assert!(
            docs.contains("| A15 |"),
            "A15 обязан быть в сводной таблице"
        );
    }

    #[test]
    fn the_runbook_matches_what_happens_in_both_daemon_states() {
        // Дефект 12/18: §2 давала последовательность `mode clear --local` →
        // `systemctl start ... hearthd`, которая не работает ни при живом демоне (на
        // работающем это no-op), ни при падающем в петле (нужен stop ПЕРЕД снятием).
        let runbook = include_str!("../../../docs/runbook-node-mode.md");
        assert!(
            runbook.contains("hearthd работает"),
            "runbook обязан разобрать случай живого демона"
        );
        assert!(
            runbook.contains("systemctl stop hearthd"),
            "runbook обязан назвать остановку демона перед снятием"
        );
        assert!(
            runbook.contains("перечитывает файл режима"),
            "runbook обязан сказать, что перезапуск демона не нужен"
        );
        // И случай, ради которого демон вообще перестали ронять.
        assert!(
            runbook.contains("hearthd не стартует вовсе"),
            "runbook обязан описать битый node-mode.json"
        );
    }

    #[test]
    fn the_runbook_describes_the_local_exit() {
        // Выход, о котором знает только код, выходом не является.
        let runbook = include_str!("../../../docs/runbook-node-mode.md");
        assert!(runbook.contains("mode clear --local"), "{runbook}");
        // И аварийный случай, когда не определяется даже путь к файлу режима.
        assert!(runbook.contains("--file"), "{runbook}");
        let adr = include_str!("../../../docs/adr/0013-node-mode.md");
        assert!(
            adr.contains("mode clear --local"),
            "ADR обязан назвать выход"
        );
    }

    #[test]
    fn the_relay_units_wait_for_their_data_mounts() {
        // Без этого при неудачном порядке загрузки состояние релея пишется в каталог
        // ПОД точкой монтирования, и перенос узла увозит не те данные.
        for (unit, path) in [
            (
                include_str!("../../deploy/systemd/smp-server.service"),
                "/var/opt/simplex",
            ),
            (
                include_str!("../../deploy/systemd/xftp-server.service"),
                "/var/opt/simplex-xftp",
            ),
            (
                include_str!("../../deploy/systemd/ntf-server.service"),
                "/var/opt/simplex-ntf",
            ),
        ] {
            assert!(
                unit.contains(&format!("RequiresMountsFor={path}")),
                "юнит обязан дождаться {path}"
            );
        }
    }

    #[test]
    fn only_normal_lets_the_relays_run() {
        assert!(NodeMode::Normal.relays_allowed());
        for mode in [
            NodeMode::Quarantine,
            NodeMode::Maintenance,
            NodeMode::Migration,
        ] {
            assert!(!mode.relays_allowed(), "{mode:?} не должен пускать релеи");
        }
    }

    #[test]
    fn a_new_mode_forbids_by_default() {
        // Тест стережёт не сегодняшний код, а завтрашний: добавивший режим обязан
        // осознанно разрешить релеи, а не получить разрешение по умолчанию.
        let all = [
            NodeMode::Normal,
            NodeMode::Quarantine,
            NodeMode::Maintenance,
            NodeMode::Migration,
        ];
        assert_eq!(
            all.iter().filter(|m| m.relays_allowed()).count(),
            1,
            "релеи разрешает ровно один режим"
        );
    }

    #[test]
    fn a_mode_survives_a_round_trip_through_json() {
        let state = NodeState::enter(
            NodeMode::Quarantine,
            "хеш smp-server не совпал",
            vec!["smp-server: mismatch".into()],
        );
        let json = serde_json::to_string(&state).unwrap();
        let back: NodeState = serde_json::from_str(&json).unwrap();
        // Сравниваем по полям, а не целиком: rfc3339 хранит время до секунды, и
        // доли секунды теряются при записи — для решения «пускать ли релеи» это
        // безразлично, а падающий тест на равенство структур только мешает.
        assert_eq!(back.mode, state.mode);
        assert_eq!(back.reason, state.reason);
        assert_eq!(back.findings, state.findings);
        assert_eq!(back.since.timestamp(), state.since.timestamp());
        assert!(!back.relays_allowed());
    }

    #[test]
    fn an_unknown_file_reads_as_normal() {
        // Отсутствие файла — это обычный узел, а не «неизвестно, поэтому запретим».
        // Запрет должен быть записан явно, иначе первый же запуск встанет колом.
        let state: NodeState =
            serde_json::from_str(r#"{"mode":"normal","since":"2026-09-11T00:00:00Z"}"#).unwrap();
        assert_eq!(state.mode, NodeMode::Normal);
        assert!(state.relays_allowed());
        assert!(state.findings.is_empty());
    }

    #[test]
    fn summary_names_the_reason() {
        let state = NodeState::enter(NodeMode::Migration, "идёт перенос на новый узел", vec![]);
        let text = state.summary();
        assert!(text.contains("перенос"), "{text}");
        assert!(text.contains("идёт перенос на новый узел"), "{text}");
    }
}
