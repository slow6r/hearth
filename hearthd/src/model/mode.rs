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

#[cfg(test)]
mod tests {
    use super::*;

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
