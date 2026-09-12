//! Supervisor (ТЗ §7.3).
//!
//! Watches the stock relay units, probes their sockets, restarts them with a backoff
//! ladder, and raises an alert when a unit flaps (≥ N restarts inside a window).
//!
//! Two independent health signals per service, on purpose:
//!
//! * systemd's own `ActiveState` — cheap, but a process can be "active" and wedged;
//! * a TCP probe on the service port inside the home network, plus one on the loopback
//!   control port — that is what a client actually depends on.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::config::Config;
use crate::model::alert::Alert;
use crate::model::health::{HealthSnapshot, HealthState, ServiceHealth};
use crate::state::AppState;
use crate::sys::systemd;

/// One supervised unit and its restart bookkeeping.
#[derive(Debug)]
struct Watched {
    name: String,
    unit: String,
    listen: std::net::SocketAddr,
    control: Option<std::net::SocketAddr>,
    /// Timestamps of restarts hearthd performed, newest last.
    restarts: VecDeque<DateTime<Utc>>,
    /// Index into the backoff ladder.
    backoff_step: usize,
    /// Do not restart again before this instant.
    hold_until: Option<DateTime<Utc>>,
    /// Whether we already alerted about the current flap window.
    flap_alerted: bool,
}

impl Watched {
    fn new(
        name: &str,
        unit: &str,
        listen: std::net::SocketAddr,
        control: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            name: name.to_string(),
            unit: unit.to_string(),
            listen,
            control,
            restarts: VecDeque::new(),
            backoff_step: 0,
            hold_until: None,
            flap_alerted: false,
        }
    }

    /// Restarts inside the flap window, dropping older entries.
    fn restarts_in_window(&mut self, window: Duration, now: DateTime<Utc>) -> u32 {
        let cutoff = now - chrono::Duration::from_std(window).unwrap_or_default();
        while self.restarts.front().is_some_and(|ts| *ts < cutoff) {
            self.restarts.pop_front();
        }
        if self.restarts.is_empty() {
            self.flap_alerted = false;
        }
        self.restarts.len() as u32
    }
}

/// The supervisor task.
#[derive(Debug)]
pub struct Supervisor {
    state: Arc<AppState>,
    watched: Vec<Watched>,
    /// Про удержание релеев сообщаем один раз на инцидент, а не каждые 15 секунд.
    held_logged: bool,
}

impl Supervisor {
    pub fn new(state: Arc<AppState>) -> Self {
        let config = state.config.clone();
        let mut watched = Vec::new();
        for relay in config.relays() {
            if relay.enabled {
                // The relay binds every interface, so loopback is the honest probe.
                watched.push(Watched::new(
                    &relay.scheme,
                    &relay.unit,
                    relay.probe_addr(),
                    relay.control,
                ));
            }
        }
        if config.turn.enabled {
            // coturn's signalling port is UDP; a TCP probe would always fail, so the
            // systemd state is the only signal. The address is kept for reporting.
            watched.push(Watched::new(
                "turn",
                &config.turn.unit,
                std::net::SocketAddr::from(([127, 0, 0, 1], config.turn.port)),
                None,
            ));
        }
        Self {
            state,
            watched,
            held_logged: false,
        }
    }

    /// Run until `shutdown` resolves.
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.state.config.supervisor.check_interval_secs);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => self.tick().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("supervisor stopping");
                        return;
                    }
                }
            }
        }
    }

    /// One supervision pass.
    pub async fn tick(&mut self) {
        let config = self.state.config.clone();
        let now = Utc::now();
        let mut services = Vec::with_capacity(self.watched.len());
        let mut overall = HealthState::Ok;

        // Режим читается один раз на тик. Решение «можно ли поднимать релей»
        // принимается не здесь, а в model::mode, и надзор обязан ему подчиняться:
        // без этого карантин по целостности и остановка на время переноса
        // отменялись сами собой через check_interval_secs.
        let node = self.state.mode.read().await.clone();
        let relay_units: Vec<String> = config
            .relays()
            .iter()
            .map(|relay| relay.unit.clone())
            .collect();
        if node.relays_allowed() {
            self.held_logged = false;
        }
        let mut any_held = false;

        for watched in &mut self.watched {
            let health = probe(&self.state, watched, &config, now).await;
            overall = overall.worst(health.state);
            let held = !may_restart(node.mode, &watched.unit, &relay_units);
            if held {
                // Не поднимаем и не сбрасываем backoff: узел не воюет с оператором,
                // который поднял службу руками, но сам её не возвращает.
                any_held = true;
            } else if health.state != HealthState::Ok {
                maybe_restart(&self.state, watched, &config, now).await;
            } else {
                watched.backoff_step = 0;
                watched.hold_until = None;
            }
            services.push(health);
        }

        if any_held && !self.held_logged {
            self.held_logged = true;
            tracing::error!(
                mode = node.mode.label(),
                reason = %node.reason,
                "релеи удерживаются остановленными: режим узла запрещает их работу"
            );
        }

        let snapshot = HealthSnapshot {
            node: config.node.name.clone(),
            address: config.node.host.clone(),
            checked: now,
            state: overall,
            services,
            uptime_secs: self.state.uptime_secs(),
            version: crate::VERSION.to_string(),
        };
        *self.state.health.write().await = snapshot;
    }
}

/// Можно ли надзору поднимать этот юнит сейчас.
///
/// Отдельная функция, а не условие по месту: это решение принимается в двух точках
/// (обход в `tick` и сама `maybe_restart`), и разъехавшиеся копии одного правила —
/// именно то, из-за чего карантин когда-то не работал. Здесь его можно проверить
/// тестом, не поднимая ни systemd, ни узел.
fn may_restart(mode: crate::model::mode::NodeMode, unit: &str, relay_units: &[String]) -> bool {
    mode.relays_allowed() || !relay_units.iter().any(|relay| relay == unit)
}

/// Collect the health of one unit.
async fn probe(
    state: &AppState,
    watched: &mut Watched,
    config: &Config,
    now: DateTime<Utc>,
) -> ServiceHealth {
    let timeout = Duration::from_secs(config.supervisor.probe_timeout_secs);
    let unit_state = systemd::show(&state.sys, &watched.unit)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(unit = %watched.unit, error = %e, "systemctl show failed");
            systemd::UnitState::unknown()
        });

    // coturn is UDP-only; a TCP probe would always fail, so it is skipped.
    let tcp_probed = watched.name != "turn";
    let listening = if tcp_probed {
        state.policy.probe(watched.listen, timeout).await
    } else {
        unit_state.is_active()
    };
    let control_ok = match watched.control {
        Some(addr) => Some(state.policy.probe(addr, timeout).await),
        None => None,
    };

    let restarts_in_window = watched.restarts_in_window(
        Duration::from_secs(config.supervisor.restart_window_secs),
        now,
    );

    let (health_state, message) = classify(&unit_state, listening, control_ok, tcp_probed);

    ServiceHealth {
        name: watched.name.clone(),
        unit: watched.unit.clone(),
        active_state: unit_state.active_state,
        sub_state: unit_state.sub_state,
        listen: watched.listen,
        listening,
        control_ok,
        restarts_in_window,
        last_restart: watched.restarts.back().copied(),
        state: health_state,
        message,
    }
}

/// Turn raw signals into a verdict.
fn classify(
    unit: &systemd::UnitState,
    listening: bool,
    control_ok: Option<bool>,
    tcp_probed: bool,
) -> (HealthState, Option<String>) {
    if unit.is_failed() {
        return (HealthState::Down, Some("unit failed".into()));
    }
    if !listening {
        let msg = if tcp_probed {
            "service port is not accepting connections"
        } else {
            "unit is not active"
        };
        return (HealthState::Down, Some(msg.into()));
    }
    if unit.active_state == "unknown" {
        // Раньше здесь возвращался Ok: отвалившийся dbus, переименованный юнит или
        // отобранное право спрашивать systemctl давали зелёный экран при единственном
        // подтверждении — что TCP-порт отвечает. Это ровно то состояние, в котором
        // подменённая служба выглядит здоровой. Неизвестность — Degraded.
        return (
            HealthState::Degraded,
            Some("systemd state unavailable".into()),
        );
    }
    if !unit.is_active() {
        return (
            HealthState::Degraded,
            Some(format!("unit is {}", unit.active_state)),
        );
    }
    if control_ok == Some(false) {
        return (
            HealthState::Degraded,
            Some("control port is not responding".into()),
        );
    }
    (HealthState::Ok, None)
}

/// Restart with backoff, and alert on flapping.
async fn maybe_restart(
    state: &AppState,
    watched: &mut Watched,
    config: &Config,
    now: DateTime<Utc>,
) {
    // Второй замок на той же двери. Проверка есть и в `tick`, но перезапуск —
    // необратимое действие с точки зрения карантина: подменённый бинарь, поднятый
    // один раз, снова начинает обслуживать трафик. Поэтому решение проверяется и в
    // самой точке действия, а не только у вызывающего.
    let relay_units: Vec<String> = config
        .relays()
        .iter()
        .map(|relay| relay.unit.clone())
        .collect();
    if !may_restart(state.node_mode().await, &watched.unit, &relay_units) {
        return;
    }
    if !config.supervisor.restart_enabled {
        return;
    }
    if watched.hold_until.is_some_and(|until| now < until) {
        return;
    }

    tracing::warn!(unit = %watched.unit, "restarting unhealthy unit");
    match systemd::restart(&state.sys, &watched.unit).await {
        Ok(()) => {
            watched.restarts.push_back(now);
            state
                .alerts
                .emit(
                    Alert::warning(
                        "supervisor",
                        format!("restarted {} after a failed health check", watched.unit),
                    )
                    .with_details(serde_json::json!({ "unit": watched.unit })),
                )
                .await;
        }
        Err(e) => {
            state
                .alerts
                .emit(
                    Alert::critical(
                        "supervisor",
                        format!("cannot restart {}: {e}", watched.unit),
                    )
                    .with_details(serde_json::json!({ "unit": watched.unit })),
                )
                .await;
        }
    }

    let ladder = &config.supervisor.restart_backoff_secs;
    let wait = ladder
        .get(watched.backoff_step)
        .copied()
        .unwrap_or_else(|| ladder.last().copied().unwrap_or(60));
    watched.backoff_step = (watched.backoff_step + 1).min(ladder.len().saturating_sub(1));
    watched.hold_until = Some(now + chrono::Duration::seconds(wait as i64));

    let window = Duration::from_secs(config.supervisor.restart_window_secs);
    let restarts = watched.restarts_in_window(window, now);
    if restarts >= config.supervisor.restart_alert_threshold && !watched.flap_alerted {
        watched.flap_alerted = true;
        state
            .alerts
            .emit(
                Alert::critical(
                    "supervisor",
                    format!(
                        "{} restarted {restarts} times in {} minutes",
                        watched.unit,
                        window.as_secs() / 60
                    ),
                )
                .with_details(serde_json::json!({
                    "unit": watched.unit,
                    "restarts": restarts,
                    "window_secs": window.as_secs(),
                })),
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::systemd::UnitState;

    fn active() -> UnitState {
        UnitState {
            active_state: "active".into(),
            sub_state: "running".into(),
            unit_file_state: "enabled".into(),
            n_restarts: 0,
            start_timestamp: String::new(),
        }
    }

    fn relays() -> Vec<String> {
        vec![
            "smp-server.service".to_string(),
            "xftp-server.service".to_string(),
        ]
    }

    #[test]
    fn quarantine_holds_the_relays_down() {
        // Главный блокер: раньше supervisor поднимал остановленный по целостности
        // релей на ближайшем тике, то есть карантин жил пятнадцать секунд.
        for mode in [
            crate::model::mode::NodeMode::Quarantine,
            crate::model::mode::NodeMode::Maintenance,
            crate::model::mode::NodeMode::Migration,
        ] {
            assert!(
                !may_restart(mode, "smp-server.service", &relays()),
                "{mode:?} обязан удерживать релей остановленным"
            );
            assert!(
                !may_restart(mode, "xftp-server.service", &relays()),
                "{mode:?} обязан удерживать релей остановленным"
            );
        }
    }

    #[test]
    fn a_quarantine_does_not_freeze_the_rest_of_the_node() {
        // Карантин про релеи. Управляющий контур и TURN под запрет не попадают:
        // иначе узел, потерявший целостность, становится ещё и неуправляемым.
        assert!(may_restart(
            crate::model::mode::NodeMode::Quarantine,
            "coturn.service",
            &relays()
        ));
    }

    #[test]
    fn normal_mode_restarts_everything_as_before() {
        for unit in [
            "smp-server.service",
            "xftp-server.service",
            "coturn.service",
        ] {
            assert!(may_restart(
                crate::model::mode::NodeMode::Normal,
                unit,
                &relays()
            ));
        }
    }

    #[test]
    fn healthy_unit_is_ok() {
        let (state, msg) = classify(&active(), true, Some(true), true);
        assert_eq!(state, HealthState::Ok);
        assert!(msg.is_none());
    }

    #[test]
    fn failed_unit_is_down() {
        let mut unit = active();
        unit.active_state = "failed".into();
        assert_eq!(classify(&unit, true, Some(true), true).0, HealthState::Down);
    }

    #[test]
    fn active_but_not_listening_is_down() {
        // The exact case a bare systemd check would miss.
        let (state, msg) = classify(&active(), false, Some(true), true);
        assert_eq!(state, HealthState::Down);
        assert!(msg.expect("message").contains("not accepting"));
    }

    #[test]
    fn dead_control_port_is_degraded_not_down() {
        let (state, msg) = classify(&active(), true, Some(false), true);
        assert_eq!(state, HealthState::Degraded);
        assert!(msg.expect("message").contains("control port"));
    }

    #[test]
    fn an_unavailable_systemd_is_not_reported_as_ok() {
        // Тест раньше закреплял обратное: при недоступном systemd состояние считалось
        // Ok, если отвечает порт. Но отвечающий порт — единственное подтверждение,
        // и ровно так выглядит подменённая служба. Неизвестность обязана быть видна.
        let (state, msg) = classify(&UnitState::unknown(), true, None, true);
        assert_eq!(state, HealthState::Degraded);
        assert!(msg.expect("message").contains("systemd"));
        // Молчащий порт по-прежнему важнее неизвестности.
        let (state, _) = classify(&UnitState::unknown(), false, None, true);
        assert_eq!(state, HealthState::Down);
    }

    #[test]
    fn restart_window_drops_stale_entries() {
        let mut watched = Watched::new(
            "smp",
            "smp-server.service",
            "10.66.10.10:5223".parse().expect("addr"),
            None,
        );
        let now = Utc::now();
        watched
            .restarts
            .push_back(now - chrono::Duration::minutes(30));
        watched
            .restarts
            .push_back(now - chrono::Duration::minutes(2));
        watched.restarts.push_back(now);
        assert_eq!(
            watched.restarts_in_window(Duration::from_secs(600), now),
            2,
            "the 30-minute-old restart is outside a 10 minute window"
        );
    }

    #[tokio::test]
    async fn tick_publishes_a_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        // No systemd and nothing listening on this dev machine: expect Down, not a panic.
        config.supervisor.restart_enabled = false;
        config.supervisor.probe_timeout_secs = 1;
        let state = AppState::new(config, crate::sys::Sys::new(true)).expect("state");
        let mut supervisor = Supervisor::new(state.clone());
        supervisor.tick().await;

        let health = state.health.read().await.clone();
        assert_eq!(
            health.services.len(),
            3,
            "smp, xftp and turn are supervised"
        );
        assert_eq!(health.state, HealthState::Down);
        assert!(health.services.iter().any(|s| s.name == "smp"));
    }
}
