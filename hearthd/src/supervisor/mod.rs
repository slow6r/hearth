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
    /// Юниты, про принудительную остановку которых алерт уже отправлен.
    ///
    /// Влияет ТОЛЬКО на алерты: сама остановка повторяется на каждом тике, пока
    /// служба жива. Сбрасывается, когда режим возвращается в норму.
    held_alerted: std::collections::HashSet<String>,
    /// Вердикт по свежести манифеста обновлений, о котором уже сказано алертом.
    ///
    /// Алерт шлётся на ПЕРЕХОД, а не на каждый тик: срок годности истекает раз, а
    /// тиков до визита оператора будет несколько тысяч, и журнал алертов, забитый
    /// одной и той же строкой, — это журнал, в который перестают смотреть.
    /// `None` — с запуска демона вердикт ещё не сообщался.
    updates_alerted: Option<HealthState>,
    /// Про нечитаемый файл режима уже сказано в журнале.
    ///
    /// Файл перечитывается каждые 15 секунд, а повреждение живёт до визита человека:
    /// без этого признака журнал состоял бы из одной строки.
    mode_read_failed: bool,
    /// Про незапинённые бинари, из-за которых релеи не поднимаются, уже сказано.
    unproven_logged: bool,
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
            held_alerted: std::collections::HashSet::new(),
            updates_alerted: None,
            mode_read_failed: false,
            unproven_logged: false,
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

        // Файл режима перечитывается с диска на каждом тике. Раньше он читался ровно
        // один раз — при старте, — и аварийное снятие `hearthctl mode clear --local`
        // не доходило до ЖИВОГО демона: на диске норма, в памяти карантин, релеи
        // «поднимаются и умирают» каждые 15 секунд. Диск здесь источник истины: в него
        // пишут оба пути снятия, и он же переживает перезапуск.
        self.reload_mode().await;

        // Режим читается один раз на тик. Решение «можно ли поднимать релей»
        // принимается не здесь, а в model::mode, и надзор обязан ему подчиняться:
        // без этого карантин по целостности и остановка на время переноса
        // отменялись сами собой через check_interval_secs.
        let node = self.state.mode.read().await.clone();
        // Бинари, которые ещё никто не запинил. Это НЕ запрет режима: работающее не
        // гасим, на диск ничего не пишем. Но поднимать релей, про который узел не
        // может сказать, что именно на нём лежит, надзор не станет — см.
        // `integrity::IntegrityChecker::report_unpinned`.
        let unproven: Vec<String> = self
            .state
            .integrity
            .read()
            .await
            .unpinned()
            .into_iter()
            .map(str::to_string)
            .collect();
        let gated_units = config.mode_gated_units();
        if node.relays_allowed() {
            self.held_logged = false;
            self.held_alerted.clear();
        }
        let mut any_held = false;
        // Про незапинённые бинари — одна строка на тик, а не по одной на юнит.
        // Локальная переменная, потому что `self` занят обходом `watched`.
        let mut unproven_logged = self.unproven_logged;
        // Останавливаем после обхода, а не внутри: обход держит `&mut self.watched`.
        let mut to_stop: Vec<String> = Vec::new();

        for watched in &mut self.watched {
            let health = probe(&self.state, watched, &config, now).await;
            overall = overall.worst(health.state);
            let held = !may_restart(node.mode, &watched.unit, &gated_units);
            // Незапинённый бинарь удерживает от ПОДЪЁМА, но не от работы: гасить
            // работающий релей из-за невыполненного шага установки значит оставить
            // семью без связи по ошибке администратора, а не по улике подмены.
            let unproven_hold =
                !held && !may_raise(node.mode, &watched.unit, &gated_units, &unproven);
            if held {
                any_held = true;
                // Не поднимаем и не сбрасываем backoff. Но если служба ЖИВА вопреки
                // режиму — её надо остановить, а не только не поднимать: после
                // перезагрузки релеи стартуют по WantedBy=multi-user.target, в обход
                // режима, и «не поднимаем» тут не помогает ничем. Это единственный
                // контур с периодом в 15 секунд; проверка целостности заметила бы то
                // же самое только через час.
                if serving(health.state) {
                    to_stop.push(watched.unit.clone());
                }
            } else if unproven_hold {
                if health.state != HealthState::Ok && !unproven_logged {
                    unproven_logged = true;
                    tracing::error!(
                        unit = %watched.unit,
                        binaries = %unproven.join(", "),
                        "не поднимаю службу: в манифесте нулевые плейсхолдеры, \
                         запинить — hearthctl manifest pin --name <имя>"
                    );
                }
            } else if health.state != HealthState::Ok {
                maybe_restart(&self.state, watched, &config, now).await;
            } else {
                watched.backoff_step = 0;
                watched.hold_until = None;
            }
            services.push(health);
        }

        self.unproven_logged = unproven_logged && !unproven.is_empty();

        for unit in &to_stop {
            self.stop_held(unit, &node).await;
        }

        if any_held && !self.held_logged {
            self.held_logged = true;
            tracing::error!(
                mode = node.mode.label(),
                reason = %node.reason,
                "релеи удерживаются остановленными: режим узла запрещает их работу"
            );
        }

        // Вердикт по бэкапу поднимается в общий. `GET /health` — единственное, что
        // видит внешний контроль, и он складывался из одних лишь состояний юнитов:
        // узел с архивом недельной давности отвечал `ok`. «Здоров» для семейного узла
        // — это и «службы работают», и «потеря диска не уносит переписку».
        //
        // Считается на каждом тике, а не берётся из сохранённого статуса: давность
        // успеха меняется сама по себе, без событий.
        let backup = {
            let status = self.state.backup.read().await;
            crate::model::health::backup_verdict(
                now,
                &status,
                config.backup.enabled,
                &config.backup.required_paths,
            )
        };
        // В общий вердикт бэкап входит слагаемым НЕ ВЫШЕ `Degraded` — ровно как
        // обновления ниже. Само поле `backup` при этом говорит правду до конца
        // (`Down` виден и в `/health`, и в `hearthctl status`, и в `/backup/status`).
        //
        // Почему так. `state: "down"` снаружи читается как «узел не обслуживает
        // семью», и по нему поднимают дежурного ночью. Узел, у которого связь
        // работает, а последнего архива нет двое суток, обслуживает семью полностью:
        // потеряна не связь, а запас прочности на случай потери диска. Ночной вызов
        // на это — самый быстрый способ научить не смотреть на красное.
        //
        // Замечание «бэкап не виден снаружи вообще» это НЕ возвращает: вклад в общий
        // вердикт остаётся (`ok` на узле без архивов невозможен), а полное состояние
        // публикуется отдельным полем — за ним и заведённым.
        overall = overall.worst(backup.min(HealthState::Degraded));

        // Свежесть манифеста обновлений. Тоже на каждом тике и по той же причине, что
        // и бэкап: срок годности истекает от хода времени, а не от события, которое
        // кто-нибудь записал бы в статус.
        let updates = self.state.updates_status(now).await;
        // В общий вердикт входит слагаемым НЕ ВЫШЕ `Degraded`, хотя само поле
        // `updates` говорит правду до конца. Просроченный манифест означает «семья не
        // получит новую версию», а не «связи нет»; поставить это в одну строку с
        // упавшим релеем значит научить читать общий `state` как фоновый шум. Куда
        // именно смотреть, говорит отдельное поле снимка.
        overall = overall.worst(updates.state.min(HealthState::Degraded));
        self.report_updates(&updates).await;

        let build = crate::build_info();
        let snapshot = HealthSnapshot {
            node: config.node.name.clone(),
            address: config.node.host.clone(),
            checked: now,
            state: overall,
            backup,
            updates: updates.state,
            services,
            uptime_secs: self.state.uptime_secs(),
            version: build.version,
            commit: build.commit,
            tree_sha256: build.tree_sha256,
            self_sha256: crate::self_sha256().to_string(),
        };
        *self.state.health.write().await = snapshot;
    }

    /// Перечитать файл режима с диска и сказать, если он изменился или сломан.
    ///
    /// Молчание здесь было бы хуже ошибки: смена режима «снаружи» — это всегда
    /// действие человека у железа, и оно обязано быть видно в журнале узла.
    async fn reload_mode(&mut self) {
        match self.state.reload_mode_from_disk().await {
            Ok(None) => self.mode_read_failed = false,
            Ok(Some(next)) => {
                self.mode_read_failed = false;
                tracing::warn!(
                    mode = next.mode.label(),
                    reason = %next.reason,
                    "режим узла изменён на диске — принят без перезапуска демона"
                );
                if next.relays_allowed() {
                    // Снятие пришло с диска (`hearthctl mode clear --local`): надзор
                    // поднимет релеи сам на этом же тике, и человеку об этом сказано.
                    self.state
                        .alerts
                        .emit(crate::model::alert::Alert::warning(
                            "mode",
                            "режим снят на самом узле; надзор поднимает релеи",
                        ))
                        .await;
                }
            }
            Err(e) => {
                if self.mode_read_failed {
                    return;
                }
                self.mode_read_failed = true;
                // Память не трогаем: запрет по нечитаемому файлу не снимается, а
                // ужесточать по нему значит отдать релеи любому сбою диска.
                tracing::error!(
                    error = %e,
                    "файл режима не перечитан; действует режим из памяти демона"
                );
                self.state
                    .alerts
                    .emit(
                        crate::model::alert::Alert::critical(
                            "mode",
                            format!(
                                "файл режима узла не читается ({e}); действует режим из \
                                 памяти демона. Починить: sudo hearthctl mode clear \
                                 --local (docs/runbook-node-mode.md)"
                            ),
                        )
                        .sticky(true),
                    )
                    .await;
            }
        }
    }

    /// Сказать оператору про срок годности манифеста обновлений.
    ///
    /// Смысл алерта именно здесь, а не в маршруте выдачи: обратиться к маршруту может
    /// только телефон, а телефон обращается тогда, когда обновление УЖЕ нужно. Надзор
    /// же смотрит на файл каждые 15 секунд и потому успевает предупредить за неделю до
    /// истечения — ровно тот горизонт, который ТЗ §1.4 отводит на доставку
    /// security-релиза.
    ///
    /// Переподписать манифест узел не может: ключ лежит на рабочей станции. Поэтому
    /// алерт — единственное, что узел вообще способен сделать, и текст в нём называет
    /// команду, которую оператор выполнит у себя.
    async fn report_updates(&mut self, updates: &crate::model::update::UpdatesStatus) {
        if self.updates_alerted == Some(updates.state) {
            return;
        }
        let previous = self.updates_alerted.replace(updates.state);
        let details = serde_json::json!({
            "state": updates.state,
            "expires": updates.expires.map(crate::model::fmt_ts),
            "days_left": updates.days_left,
            "dated": updates.dated,
        });
        let alert = match updates.state {
            // Возврат к норме сообщается только тому, кто уже слышал о поломке:
            // «манифест в порядке» на каждом старте демона — это шум.
            HealthState::Ok => match previous {
                None => return,
                Some(HealthState::Ok) => return,
                Some(_) => Alert::info("updates", format!("обновления: {}", updates.note)),
            },
            HealthState::Degraded => Alert::warning("updates", updates.note.clone()),
            // Sticky: семья осталась без обновлений, и запись об этом обязана пережить
            // выдавливание из кольца последних алертов.
            HealthState::Down => Alert::critical("updates", updates.note.clone()).sticky(true),
        };
        self.state.alerts.emit(alert.with_details(details)).await;
    }

    /// Остановить службу, которую режим узла запрещает.
    ///
    /// Оговорка ADR 0013 «узел не воюет с оператором» относится к режиму `normal`:
    /// пока узел в карантине или переносе, работающий релей — не воля оператора, а
    /// обход запрета. Чтобы поднять его сознательно, сначала снимают режим:
    /// `hearthctl mode clear`.
    ///
    /// Останавливаем на каждом тике, пока служба жива, а алерт шлём один раз на юнит
    /// за инцидент: действие повторять обязательно, сообщение — нет.
    async fn stop_held(&mut self, unit: &str, node: &crate::model::mode::NodeState) {
        tracing::error!(
            unit = %unit,
            mode = node.mode.label(),
            "служба работает вопреки режиму узла: останавливаю"
        );
        let outcome = systemd::stop(&self.state.sys, unit).await;
        if !self.held_alerted.insert(unit.to_string()) {
            return;
        }
        let summary = match &outcome {
            Ok(()) => format!(
                "{unit} работал в режиме «{}» и остановлен повторно",
                node.mode.label()
            ),
            Err(e) => format!("{unit} работает вопреки режиму узла и не остановлен: {e}"),
        };
        self.state
            .alerts
            .emit(
                Alert::critical("supervisor", summary)
                    .with_details(serde_json::json!({
                        "unit": unit,
                        "mode": node.mode.label(),
                        "reason": node.reason,
                    }))
                    .sticky(true),
            )
            .await;
    }
}

/// Можно ли надзору поднимать этот юнит сейчас.
///
/// Отдельная функция, а не условие по месту: это решение принимается в двух точках
/// (обход в `tick` и сама `maybe_restart`), и разъехавшиеся копии одного правила —
/// именно то, из-за чего карантин когда-то не работал. Здесь его можно проверить
/// тестом, не поднимая ни systemd, ни узел.
///
/// `gated_units` — то, что режим узла запрещает: релеи и TURN
/// (`Config::mode_gated_units`). Управляющий контур в список не входит: узел,
/// потерявший целостность, не должен становиться ещё и неуправляемым.
fn may_restart(mode: crate::model::mode::NodeMode, unit: &str, gated_units: &[String]) -> bool {
    mode.relays_allowed() || !is_gated(unit, gated_units)
}

/// Входит ли юнит в то, что режим узла и проверка целостности вправе удерживать.
fn is_gated(unit: &str, gated_units: &[String]) -> bool {
    gated_units.iter().any(|gated| gated == unit)
}

/// Можно ли ПОДНИМАТЬ этот юнит сейчас — с учётом и режима, и незапинённых бинарей.
///
/// Разница с [`may_restart`] ровно одна и она принципиальная. Запрет режима —
/// основание ОСТАНОВИТЬ работающую службу: карантин по целостности означает улику
/// подмены. Нулевой плейсхолдер в манифесте улики не содержит: он означает, что
/// оператор не выполнил шаг установки. За это отнимать у семьи связь не за что —
/// поэтому работающее не трогаем, но и поднимать то, про что узел не может сказать,
/// что на нём лежит, не станем. Разбираться придётся человеку, и алерт ему об этом
/// скажет (`integrity::IntegrityChecker::report_unpinned`).
fn may_raise(
    mode: crate::model::mode::NodeMode,
    unit: &str,
    gated_units: &[String],
    unpinned: &[String],
) -> bool {
    may_restart(mode, unit, gated_units) && !(!unpinned.is_empty() && is_gated(unit, gated_units))
}

/// Обслуживает ли служба трафик, несмотря на запрет.
///
/// `Down` — порт молчит или юнит упал, останавливать нечего. Всё остальное, включая
/// `Degraded` (например, недоступен systemd, а порт отвечает), означает, что клиенты
/// семьи прямо сейчас разговаривают с запрещённой службой. Fail-closed: неизвестность
/// считается работой.
fn serving(state: HealthState) -> bool {
    state != HealthState::Down
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
    let gated_units = config.mode_gated_units();
    if !may_restart(state.node_mode().await, &watched.unit, &gated_units) {
        return;
    }
    // Та же вторая дверь для незапинённых бинарей: поднять релей, про который узел не
    // может сказать, что на нём лежит, — значит вернуть в строй непроверенный файл.
    let unpinned: Vec<String> = state
        .integrity
        .read()
        .await
        .unpinned()
        .into_iter()
        .map(str::to_string)
        .collect();
    if !may_raise(
        state.node_mode().await,
        &watched.unit,
        &gated_units,
        &unpinned,
    ) {
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

    /// Юниты, которых касается режим: релеи и TURN (`Config::mode_gated_units`).
    fn gated() -> Vec<String> {
        vec![
            "smp-server.service".to_string(),
            "xftp-server.service".to_string(),
            "coturn.service".to_string(),
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
                !may_restart(mode, "smp-server.service", &gated()),
                "{mode:?} обязан удерживать релей остановленным"
            );
            assert!(
                !may_restart(mode, "xftp-server.service", &gated()),
                "{mode:?} обязан удерживать релей остановленным"
            );
        }
    }

    #[test]
    fn an_unpinned_binary_stops_the_lifting_but_not_the_serving() {
        // Дефект 19: свежеустановленный узел через час объявлял себе подмену из-за
        // нулевых плейсхолдеров (в том числе turnserver, о котором не говорил ни один
        // печатный шаг) и уходил в карантин, переживающий перезагрузку. Здесь — граница
        // между «ещё не запинено» и «хеш изменился».
        let normal = crate::model::mode::NodeMode::Normal;
        let unpinned = vec!["turnserver".to_string()];

        // Режим по-прежнему норма: РАБОТАЮЩИЙ релей никто не гасит.
        assert!(
            may_restart(normal, "smp-server.service", &gated()),
            "незапинённый бинарь не повод останавливать работающую службу"
        );
        // Но поднимать то, про что узел не может сказать, что на нём лежит, — нет.
        assert!(!may_raise(
            normal,
            "smp-server.service",
            &gated(),
            &unpinned
        ));
        assert!(!may_raise(normal, "coturn.service", &gated(), &unpinned));
        // Управляющий контур не гейтится ничем: узел обязан остаться управляемым.
        assert!(may_raise(normal, "hearthd.service", &gated(), &unpinned));
        // Запинили — запрет на подъём снимается сам, без вмешательства человека.
        assert!(may_raise(normal, "smp-server.service", &gated(), &[]));
    }

    #[test]
    fn a_quarantine_still_outranks_an_unpinned_binary() {
        // Порядок важен: карантин остаётся карантином, а не «мягким» удержанием.
        assert!(!may_raise(
            crate::model::mode::NodeMode::Quarantine,
            "smp-server.service",
            &gated(),
            &[]
        ));
    }

    #[test]
    fn a_held_node_holds_turn_down_too() {
        // ADR 0013 обещает узел, который в не-normal режиме не обслуживает семью
        // ничем. coturn под это не подпадал: `migrate::export` его останавливал, а
        // надзор поднимал обратно через check_interval_secs — уже в режиме переноса.
        // Держать TURN в карантине не жалко и по существу: сигнализация звонка идёт
        // через smp-релей, который в этот момент остановлен, то есть живой coturn не
        // даёт семье ни одного звонка, зато оставляет открытый медиа-ретранслятор.
        for mode in [
            crate::model::mode::NodeMode::Quarantine,
            crate::model::mode::NodeMode::Maintenance,
            crate::model::mode::NodeMode::Migration,
        ] {
            assert!(
                !may_restart(mode, "coturn.service", &gated()),
                "{mode:?} обязан удерживать TURN остановленным"
            );
        }
    }

    #[test]
    fn a_quarantine_does_not_freeze_the_control_plane() {
        // Карантин про то, что обслуживает семью. Управляющий контур под запрет не
        // попадает: иначе узел, потерявший целостность, становится ещё и
        // неуправляемым — и снять карантин станет нечем.
        for unit in ["hearthd.service", "ntf-db-dump.service"] {
            assert!(may_restart(
                crate::model::mode::NodeMode::Quarantine,
                unit,
                &gated()
            ));
        }
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
                &gated()
            ));
        }
    }

    #[test]
    fn the_gated_list_comes_from_the_configuration() {
        // Список запрещаемого собирается из конфигурации узла, а не из констант:
        // имя юнита TURN на узле может отличаться от поставочного.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config.turn.unit = "coturn-дом.service".into();
        let units = config.mode_gated_units();
        assert!(units.iter().any(|u| u == &config.smp.unit), "{units:?}");
        assert!(units.iter().any(|u| u == &config.xftp.unit), "{units:?}");
        assert!(units.iter().any(|u| u == "coturn-дом.service"), "{units:?}");
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

    #[test]
    fn only_a_dead_service_needs_no_stopping() {
        // Degraded — это, например, «systemd недоступен, но порт отвечает». Клиенты
        // семьи в этот момент разговаривают с запрещённой службой.
        assert!(!serving(HealthState::Down));
        assert!(serving(HealthState::Degraded));
        assert!(serving(HealthState::Ok));
    }

    /// Узел с одним релеем, порт которого действительно слушают.
    ///
    /// Без живого сокета проба всегда даёт Down, то есть «останавливать нечего», и
    /// проверить обратное поведение нечем.
    fn node_with_a_live_relay(
        dir: &std::path::Path,
        listener: &std::net::TcpListener,
    ) -> crate::config::Config {
        let mut config = crate::state::tests::test_config(dir);
        config.smp.port = listener.local_addr().expect("addr").port();
        config.smp.control = None;
        config.xftp.enabled = false;
        config.turn.enabled = false;
        config.supervisor.restart_enabled = false;
        config.supervisor.probe_timeout_secs = 1;
        config
    }

    /// Ответ `systemctl show` для всех юнитов сразу: на машине разработчика systemd
    /// нет, а без него ни одна служба не бывает `Ok` и проверять нечего.
    fn all_units_are_active(state: &AppState) {
        state.sys.stub_capture(
            "systemctl show",
            crate::sys::Output::success(
                "ActiveState=active
SubState=running
UnitFileState=enabled
",
            ),
        );
    }

    #[tokio::test]
    async fn the_backup_verdict_is_part_of_the_node_verdict() {
        // Раньше `/health` складывался из одних служб: узел, у которого всё работает,
        // а бэкапа нет ни одного, отвечал внешнему контролю `state: ok`.
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let state = AppState::new(
            node_with_a_live_relay(dir.path(), &listener),
            crate::sys::Sys::new(true),
        )
        .expect("state");
        all_units_are_active(&state);

        Supervisor::new(state.clone()).tick().await;

        let health = state.health.read().await.clone();
        assert!(
            health.services.iter().all(|s| s.state == HealthState::Ok),
            "предпосылка теста: службы здоровы, получили {:?}",
            health.services
        );
        assert_eq!(
            health.backup,
            HealthState::Down,
            "успешного прогона не было ни разу"
        );
        // Вклад в общий вердикт есть (зелёным узел без архивов не бывает), но он
        // ограничен `Degraded`: связь работает, и будить дежурного нечем.
        assert_eq!(
            health.state,
            HealthState::Degraded,
            "общий вердикт обязан включать резервную копию, но не выше Degraded"
        );
        // И полный вердикт по-прежнему виден СНАРУЖИ отдельным полем — иначе потолок
        // вернул бы прежнее замечание «бэкапа в /health нет вообще».
        let json = serde_json::to_value(&health).expect("снимок сериализуется");
        assert_eq!(json.get("backup").and_then(|v| v.as_str()), Some("down"));

        // Обратная половина: свежая копия — и узел снова зелёный. Иначе проверка
        // закрепляла бы константу, а не связь.
        {
            let mut backup = state.backup.write().await;
            backup.last_success = Some(Utc::now());
        }
        Supervisor::new(state.clone()).tick().await;
        let health = state.health.read().await.clone();
        assert_eq!(health.backup, HealthState::Ok);
        assert_eq!(health.state, HealthState::Ok);
    }

    #[tokio::test]
    async fn a_failed_relay_is_down_even_next_to_a_late_backup() {
        // Потолок `Degraded` стоит на СЛАГАЕМОМ «бэкап», а не на общем вердикте:
        // упавшая служба обязана оставаться `down` и тогда, когда бэкап тоже красный.
        // Иначе ограничение, поставленное ради спокойной ночи, прятало бы обрыв связи.
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let state = AppState::new(
            node_with_a_live_relay(dir.path(), &listener),
            crate::sys::Sys::new(true),
        )
        .expect("state");
        state.sys.stub_capture(
            "systemctl show",
            crate::sys::Output::success(
                "ActiveState=failed
SubState=dead
UnitFileState=enabled
",
            ),
        );

        Supervisor::new(state.clone()).tick().await;

        let health = state.health.read().await.clone();
        assert_eq!(health.backup, HealthState::Down, "архива не было ни разу");
        assert_eq!(
            health.state,
            HealthState::Down,
            "упавший релей — это `down` независимо от бэкапа"
        );
    }

    #[tokio::test]
    async fn a_held_but_running_relay_is_stopped_by_the_tick() {
        // Раньше надзор при запрете лишь писал в журнал «релеи удерживаются
        // остановленными» — утверждение, которое в этот момент было неправдой.
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let state = AppState::new(
            node_with_a_live_relay(dir.path(), &listener),
            crate::sys::Sys::new(true),
        )
        .expect("state");
        state
            .set_mode(
                crate::model::mode::NodeMode::Quarantine,
                "хеш smp-server не совпал",
                vec![],
            )
            .await
            .expect("set mode");

        Supervisor::new(state.clone()).tick().await;

        assert!(
            state
                .sys
                .recorded()
                .contains(&"systemctl stop smp-server.service".to_string()),
            "получили {:?}",
            state.sys.recorded()
        );
    }

    #[tokio::test]
    async fn a_held_and_already_stopped_relay_is_left_alone() {
        // Порт никто не слушает: служба и так не работает, дёргать systemctl незачем.
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let config = node_with_a_live_relay(dir.path(), &listener);
        drop(listener);
        let state = AppState::new(config, crate::sys::Sys::new(true)).expect("state");
        state
            .set_mode(crate::model::mode::NodeMode::Migration, "перенос", vec![])
            .await
            .expect("set mode");

        Supervisor::new(state.clone()).tick().await;

        assert!(
            !state
                .sys
                .recorded()
                .iter()
                .any(|cmd| cmd.starts_with("systemctl stop")),
            "получили {:?}",
            state.sys.recorded()
        );
    }

    #[tokio::test]
    async fn a_node_that_boots_in_quarantine_stops_the_relays_it_finds_running() {
        // После перезагрузки релеи поднимает systemd (WantedBy=multi-user.target), и
        // сохранённый на диске карантин обязан их остановить, а не только не поднимать.
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let config = node_with_a_live_relay(dir.path(), &listener);
        {
            let state = AppState::new(config.clone(), crate::sys::Sys::new(true)).expect("state");
            state
                .set_mode(
                    crate::model::mode::NodeMode::Quarantine,
                    "хеш smp-server не совпал",
                    vec![],
                )
                .await
                .expect("set mode");
        }

        let state = AppState::new(config, crate::sys::Sys::new(true)).expect("restart");
        Supervisor::new(state.clone()).tick().await;

        assert!(
            state
                .sys
                .recorded()
                .contains(&"systemctl stop smp-server.service".to_string()),
            "получили {:?}",
            state.sys.recorded()
        );
        let alerts = state.alerts.query(None, None, 20).await;
        assert!(
            alerts.iter().any(|a| a.summary.contains("остановлен")),
            "человек обязан узнать, что релей поднимался вопреки карантину"
        );
    }

    #[tokio::test]
    async fn an_enabled_push_server_is_supervised_and_held_like_a_relay() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config
            .ntf
            .as_mut()
            .expect("the reference config carries [ntf]")
            .enabled = true;
        let state = AppState::new(config, crate::sys::Sys::new(true)).expect("state");
        let supervisor = Supervisor::new(state.clone());
        assert!(supervisor
            .watched
            .iter()
            .any(|w| w.unit == "ntf-server.service"));

        // Карантин держит и его: это тоже стоковый код upstream, а не наш.
        assert!(!may_restart(
            crate::model::mode::NodeMode::Quarantine,
            "ntf-server.service",
            &state.config.mode_gated_units()
        ));
    }
}
