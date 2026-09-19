//! `hearthd` — the daemon.
//!
//! Boot sequence:
//!   1. load and validate `/etc/hearth/hearthd.toml` (a bad config is a hard stop);
//!   2. verify the pinned binaries once, before anything else starts;
//!   3. start supervisor, egress watchdog, integrity checker and backup job;
//!   4. serve the mTLS admin API until SIGTERM.
//!
//! Everything it can do is local. There is no update channel, no telemetry, and no
//! outbound connection outside `node.home_networks` (ТЗ §7.4).

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use hearthd::config::Config;
use hearthd::error::{Error, Result};
use hearthd::model::alert::Alert;
use hearthd::state::AppState;
use hearthd::sys::Sys;
use hearthd::{api, backup, egress, integrity, pki, supervisor, DEFAULT_CONFIG_PATH, VERSION};

#[derive(Debug, Parser)]
#[command(
    name = "hearthd",
    version = VERSION,
    about = "Control plane for a private, home-only SimpleX relay node"
)]
struct Cli {
    /// Configuration file.
    #[arg(short, long, env = "HEARTHD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Log filter (`error`, `info`, `hearthd=debug`, ...).
    #[arg(long, env = "HEARTHD_LOG", default_value = "info")]
    log: String,

    /// Never execute mutating host commands (systemctl/nft/rsync); log them instead.
    #[arg(long)]
    dry_run: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the daemon (default).
    Run,
    /// Validate the configuration and exit.
    Check,
    /// Паспорт сборки: из какого дерева исходников собран ЭТОТ файл.
    ///
    /// Команда существует ради одного вопроса аудита — «тот ли код работает на
    /// узле». Раньше ответить на него было нечем: `--version` печатал `0.1.0`,
    /// одинаковое у всех сборок всех коммитов, а строк с коммитом внутри бинарника
    /// не было вовсе.
    BuildInfo {
        /// Выдать JSON вместо `ключ=значение`.
        #[arg(long)]
        json: bool,
    },
    /// Admin PKI operations.
    #[command(subcommand)]
    Ca(CaCommand),
}

#[derive(Debug, Subcommand)]
enum CaCommand {
    /// Create the admin CA and the API server certificate.
    Init {
        /// Overwrite an existing CA. Invalidates every issued admin certificate.
        #[arg(long)]
        force: bool,
    },
    /// Issue an admin client certificate.
    Issue {
        /// Admin name, e.g. `owner`.
        name: String,
        /// Validity in days.
        #[arg(long, default_value_t = pki::DEFAULT_ADMIN_DAYS)]
        days: i64,
        /// Where to write `<name>.pem` and `<name>.key`. Defaults to the PKI directory.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Выписать серверный сертификат для device API на `node.host`.
    ///
    /// Отдельный от server.pem: тот выписан на IP-литерал admin API, а телефон
    /// приходит по имени из bundle, и SAN должен совпадать.
    IssueDeviceApi,
    /// Revoke an admin client certificate.
    ///
    /// По имени гасятся ВСЕ действующие сертификаты с этим именем: после штатной
    /// ротации их бывает несколько, и «отозвать owner» обязано означать «ни один
    /// owner больше не пускает», а не «отозван первый попавшийся».
    Revoke {
        /// Admin name. Взаимоисключимо с `--fingerprint`.
        name: Option<String>,
        /// Отозвать ровно одну личность по отпечатку сертификата (64 hex).
        #[arg(long, conflicts_with = "name")]
        fingerprint: Option<String>,
    },
}

/// Код выхода, по которому systemd НЕ перезапускает демон.
///
/// # Зачем отдельный код
///
/// Провал preflight (нет `ca.pem`, нет `manifest.toml`) и сломанный `hearthd.toml` —
/// состояния, из которых узел сам не выйдет: ни файла, ни исправленной строки не
/// появится оттого, что процесс запустился ещё раз. С `Restart=on-failure` и
/// `RestartSec=5s` это давало вечный цикл: каждые пять секунд демон заново записывал
/// карантин, заново останавливал релеи и заново слал алерт, а
/// `hearthctl mode clear --local` не помогал — следующий запуск возвращал запрет через
/// пять секунд. `StartLimitBurst` при таком интервале не срабатывает никогда. У
/// сломанной конфигурации цена была другой, но не меньшей: journal заполнялся одной и
/// той же строкой разбора TOML каждые пять секунд, и настоящую причину в этой ленте
/// было не найти.
///
/// `RestartPreventExitStatus=78` в hearthd.service превращает это в ОДНУ понятную
/// остановку с инструкцией в журнале. 78 — это `EX_CONFIG` из sysexits(3): «ошибка в
/// конфигурации узла», ровно то, что здесь и произошло.
pub const EXIT_TERMINAL: u8 = 78;

/// Ошибка запуска и то, стоит ли systemd пробовать ещё раз.
enum Fatal {
    /// Повторный запуск может помочь (сеть не поднялась, порт занят).
    Retryable(Error),
    /// Повторный запуск не поможет: нужен человек.
    Terminal(Error),
}

impl From<Error> for Fatal {
    fn from(e: Error) -> Self {
        Fatal::Retryable(e)
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(Fatal::Retryable(e)) => {
            tracing::error!(error = %e, "hearthd failed");
            eprintln!("hearthd: {e}");
            std::process::ExitCode::FAILURE
        }
        Err(Fatal::Terminal(e)) => {
            tracing::error!(error = %e, "hearthd stopped for good");
            eprintln!("hearthd: {e}");
            eprintln!(
                "hearthd: перезапуск не поможет — это состояние узла, а не сбой \
                 процесса. Демон остановлен, чтобы не наматывать алерты каждые пять \
                 секунд. Порядок действий: docs/runbook-node-mode.md."
            );
            std::process::ExitCode::from(EXIT_TERMINAL)
        }
    }
}

/// Прочитать конфигурацию. Ошибка здесь ТЕРМИНАЛЬНА.
///
/// Нечитаемый или неразобранный `/etc/hearth/hearthd.toml` — это состояние узла, а не
/// сбой процесса: перезапуск через пять секунд застанет ровно тот же файл. Пока эта
/// ошибка считалась «повторяемой», systemd крутил демон в бесконечных рестартах
/// (`Restart=on-failure`, `RestartSec=5s`, при котором `StartLimitBurst` не
/// срабатывает), и в journal вместо одной внятной причины оставалась лента из одной и
/// той же строки. Выходим один раз, кодом 78 (`RestartPreventExitStatus` в юните).
///
/// Валидация внутри [`Config::load`] сюда же и относится: невыполнимые инварианты
/// (чужой отпечаток в пин-листе, порт admin API, занятый релеем) правит человек, а не
/// следующий запуск. То, что стартовать НЕ мешает, живёт в `Config::warnings`.
fn load_config(path: &std::path::Path) -> std::result::Result<Config, Fatal> {
    Config::load(path).map_err(Fatal::Terminal)
}

fn run(cli: Cli) -> std::result::Result<(), Fatal> {
    // Паспорт отвечает ДО загрузки конфигурации и до установки провайдера TLS.
    //
    // Иначе команда требовала бы /etc/hearth/hearthd.toml — то есть не работала бы
    // ровно там, где она нужнее всего: на копии бинарника, снятой с узла, и на
    // свежесобранном файле, который ещё не установлен.
    if let Some(Command::BuildInfo { json }) = cli.command {
        return print_build_info(json).map_err(Fatal::from);
    }

    // rustls needs its provider installed before any TLS object is built.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider was already installed");
    }

    let config = load_config(&cli.config)?;

    match cli.command.unwrap_or(Command::Run) {
        Command::Check => {
            println!("config {} is valid", cli.config.display());
            println!("  node:        {}", config.node.name);
            println!(
                "  public host: {}  (clients connect here)",
                config.node.host
            );
            println!(
                "  smp:         {:?}  xftp: {:?}",
                config.smp.all_ports(),
                config.xftp.all_ports()
            );
            if let Some(ntf) = config.ntf.as_ref().filter(|ntf| ntf.enabled) {
                println!(
                    "  ntf:         {:?}  (push server, ADR 0016)",
                    ntf.all_ports()
                );
            }
            println!(
                "  turn:        {} (relay {}-{})",
                config.turn.port, config.turn.relay_min_port, config.turn.relay_max_port
            );
            println!("  admin api:   {}  (LAN only)", config.api.listen);
            // Замечания печатаются здесь, а не прячутся до первой ночи: `hearthd check`
            // — то место, куда смотрят сразу после правки конфигурации.
            for warning in config.warnings() {
                println!();
                println!("ВНИМАНИЕ: {warning}");
            }
            Ok(())
        }
        Command::Ca(CaCommand::Init { force }) => {
            let info = pki::init_ca(
                &config.api.pki_dir,
                &config.node.name,
                config.api.listen.ip(),
                force,
            )?;
            println!("admin CA created in {}", config.api.pki_dir.display());
            println!("  ca fingerprint:     {}", info.ca_fingerprint);
            println!("  server fingerprint: {}", info.server_fingerprint);
            println!("Next: hearthd ca issue owner");
            Ok(())
        }
        Command::Ca(CaCommand::Issue { name, days, out }) => {
            let issued = pki::issue_admin(&config.api.pki_dir, &name, days)?;
            let dir = out.unwrap_or_else(|| config.api.pki_dir.clone());
            hearthd::store::ensure_dir(&dir)?;
            let cert_path = dir.join(format!("{name}.pem"));
            let key_path = dir.join(format!("{name}.key"));
            hearthd::store::write_atomic(
                &cert_path,
                issued.cert_pem.as_bytes(),
                hearthd::store::MODE_STATE,
            )?;
            hearthd::store::write_secret(&key_path, issued.key_pem.trim())?;
            println!("issued admin certificate for `{name}`");
            println!("  certificate: {}", cert_path.display());
            println!("  private key: {} (0600)", key_path.display());
            println!("  fingerprint: {}", issued.fingerprint);
            println!("  expires:     {}", hearthd::model::fmt_ts(issued.expires));
            println!(
                "Move the private key to the admin workstation and delete it here \
                 if this is not that machine."
            );
            Ok(())
        }
        Command::Ca(CaCommand::IssueDeviceApi) => {
            let path = pki::issue_device_api_cert(&config.api.pki_dir, &config.node.host)?;
            println!("сертификат device API выписан на `{}`", config.node.host);
            println!("  {}", path.display());
            println!();
            println!("Приложение доверяет ему через пиннинг hearth CA в network security");
            println!("config — публичный CA здесь не нужен: не будет ни записи в CT-логах,");
            println!("ни certbot'а, который однажды молча не продлится.");
            println!();
            println!("Дальше: ./deploy/fix-permissions.sh && systemctl restart hearthd");
            Ok(())
        }
        Command::Ca(CaCommand::Revoke { name, fingerprint }) => {
            let revoked = pki::AdminRegistry::update(&config.api.pki_dir, |registry| {
                match (name, fingerprint) {
                    (_, Some(fingerprint)) => {
                        Ok(vec![registry.revoke_by_fingerprint(&fingerprint)?])
                    }
                    (Some(name), None) => registry.revoke(&name),
                    (None, None) => Err(hearthd::error::Error::invalid(
                        "нужно имя администратора или --fingerprint",
                    )),
                }
            })?;
            for admin in &revoked {
                println!("revoked `{}` ({})", admin.name, admin.fingerprint);
            }
            if revoked.len() > 1 {
                println!();
                println!(
                    "Действующих сертификатов с этим именем было {} — погашены все.",
                    revoked.len()
                );
            }
            println!();
            println!("Отзыв вступает в силу для НОВЫХ соединений сразу; уже открытые");
            println!("админские соединения закрываются по таймауту. Если сертификат");
            println!("украден, перезапустите hearthd: systemctl restart hearthd");
            Ok(())
        }
        Command::Run => serve(config, cli.dry_run),
        // Отвечено выше, до загрузки конфигурации.
        Command::BuildInfo { .. } => Ok(()),
    }
}

/// Напечатать паспорт сборки.
///
/// Добавляет к вшитым полям `exe_sha256` — sha256 файла, которым запущен процесс.
/// Вшить его нельзя по построению (хеш готового файла не существует, пока файл не
/// готов), а вопрос «тот ли это файл, что лежит на узле» без него не закрывается.
fn print_build_info(json: bool) -> Result<()> {
    let info = hearthd::build_info();
    let exe_sha256 = hearthd::self_sha256();
    if json {
        let mut doc = serde_json::to_value(&info).map_err(|e| Error::Parse(e.to_string()))?;
        if let Some(map) = doc.as_object_mut() {
            map.insert(
                "exe_sha256".to_string(),
                serde_json::Value::String(exe_sha256.to_string()),
            );
        }
        let text = serde_json::to_string_pretty(&doc).map_err(|e| Error::Parse(e.to_string()))?;
        println!("{text}");
    } else {
        print!("{}", info.to_key_values());
        println!("exe_sha256={exe_sha256}");
    }
    Ok(())
}

/// Строка, которой демон представляется в журнале при старте.
///
/// Чистая функция и отдельно от места вызова — чтобы её можно было проверить тестом
/// без запуска демона. Журнал здесь не украшение: он единственное место, где аудитор
/// видит хеш РАБОТАЮЩЕГО процесса. Доступ к журналу уже описан в runbook и прав не
/// поднимает (`usermod -aG systemd-journal,adm auditor`), тогда как чтение
/// `/proc/<pid>/exe` потребовало бы ptrace, то есть права читать память релеев.
fn startup_banner(info: &hearthd::BuildInfo, exe_sha256: &str, node: &str) -> String {
    format!(
        "hearthd {version} commit={commit}{dirty} tree_sha256={tree} exe_sha256={exe} started on {node}",
        version = info.version,
        commit = info.commit,
        // Метка только у грязного дерева: строка читается глазами каждый старт, и
        // «всё в порядке» не должно занимать в ней место.
        dirty = if info.dirty { " (dirty)" } else { "" },
        tree = info.tree_sha256,
        exe = exe_sha256,
    )
}

/// Build the runtime and run every module until a signal arrives.
fn serve(config: Config, dry_run: bool) -> std::result::Result<(), Fatal> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Error::RawIo)?;

    runtime.block_on(async move {
        let sys = Sys::new(dry_run);
        let node = config.node.name.clone();
        let api_listen = config.api.listen;
        let state = AppState::new(config, sys)?;

        // Беды, найденные при открытии журнала алертов: нечитаемый alerts.jsonl,
        // root-овый каталог состояния. Стартовать они не мешают (иначе дом остался бы
        // без надзора из-за прав на один файл), но остаться незамеченными не должны —
        // и в journal, и в сам журнал алертов, и в каналы доставки.
        for complaint in state.alerts.complaints().to_vec() {
            tracing::error!("журнал алертов: {complaint}");
            state
                .alerts
                .emit(Alert::critical("alerts", complaint).sticky(true))
                .await;
        }

        // Замечания к конфигурации, которые не повод не стартовать (Config::warnings).
        // Отказ подниматься из-за опечатки в списке путей оставлял бы дом без надзора,
        // бэкапа, целостности и алертов при работающих релеях — то есть незаметно. В
        // журнал и в алерты: узнать об этом человек обязан, чинить — своим порядком.
        for warning in state.config.warnings() {
            tracing::error!("конфигурация узла: {warning}");
            state
                .alerts
                .emit(Alert::warning("config", warning).sticky(true))
                .await;
        }

        // Провал preflight обязан быть fail-closed по отношению к релеям, а не
        // только к демону. Иначе получается худшее сочетание: контрольный контур
        // мёртв (нет проверки целостности, нет надзора, нет сторожа утечки, нет
        // алертов), а мессенджер продолжает работать — и отказ незаметен. Именно так
        // выглядела бы потеря прав на manifest.toml.
        if let Err(e) = preflight(&state) {
            tracing::error!(error = %e, "preflight failed; останавливаю релеи");
            let reason = format!("проверка при старте не прошла: {e}");
            if let Err(mode_err) = state
                .set_mode(
                    hearthd::model::mode::NodeMode::Quarantine,
                    reason.clone(),
                    Vec::new(),
                )
                .await
            {
                tracing::error!(error = %mode_err, "карантин не записан на диск");
            }
            for relay in state.config.relays() {
                if !relay.enabled {
                    continue;
                }
                if let Err(stop_err) =
                    hearthd::sys::systemd::stop(&state.sys, &relay.unit).await
                {
                    tracing::error!(unit = %relay.unit, error = %stop_err, "не удалось остановить релей");
                }
            }
            state
                .alerts
                .emit(Alert::critical("hearthd", reason).sticky(true))
                .await;
            // ТЕРМИНАЛЬНО, а не «упал — перезапусти». Нет ca.pem или manifest.toml —
            // это состояние узла: следующий запуск через пять секунд застанет ровно то
            // же самое, снова запишет карантин, снова остановит релеи и снова пришлёт
            // алерт. Петля наматывалась вечно и, что хуже, не давала выйти локально:
            // `hearthctl mode clear --local` отрабатывал, а через пять секунд запрет
            // возвращался. Останавливаемся один раз, с причиной и инструкцией.
            tracing::error!(
                "hearthd остановлен и НЕ будет перезапущен: почините названное выше, \
                 затем `sudo hearthctl mode clear --local` и `systemctl start hearthd` \
                 (docs/runbook-node-mode.md)"
            );
            return Err(Fatal::Terminal(e));
        }

        // Сохранённый на диске запрет обязан что-то ДЕЛАТЬ при старте, а не только
        // подавлять будущие перезапуски. После перезагрузки машины релейные юниты
        // поднимает systemd (WantedBy=multi-user.target) параллельно с демоном, и на
        // узле, где drop-in с гейтом режима ещё не развёрнут, это единственное, что
        // возвращает карантин в силу.
        enforce_mode_at_start(&state).await;

        let banner = startup_banner(&hearthd::build_info(), hearthd::self_sha256(), &node);
        tracing::info!("{banner}");
        state.alerts.emit(Alert::info("hearthd", banner)).await;

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Verify the pinned binaries before anything is allowed to serve traffic.
        let mut checker = integrity::IntegrityChecker::new(state.clone());
        let first = checker.check().await;
        if first.state != hearthd::model::health::HealthState::Ok {
            tracing::error!("integrity check failed at start-up; relays stopped (see /alerts)");
        }

        let mut tasks = vec![
            tokio::spawn(supervisor::Supervisor::new(state.clone()).run(shutdown_rx.clone())),
            tokio::spawn(egress::EgressWatchdog::new(state.clone()).run(shutdown_rx.clone())),
            tokio::spawn(checker.run(shutdown_rx.clone())),
            tokio::spawn(backup::BackupJob::new(state.clone()).run(shutdown_rx.clone())),
        ];

        let api_state = state.clone();
        let api_shutdown = shutdown_rx.clone();
        let mut api = tokio::spawn(async move { api::serve(api_state, api_shutdown).await });

        // Device API — в отличие от admin API он ОПЦИОНАЛЕН и его падение не должно
        // ронять узел: без него телефоны не получат обновление и свежие TURN-креды,
        // но сообщения продолжат ходить. Валить из-за этого весь мессенджер — хуже,
        // чем работать с деградацией, о которой сказано в журнале и в алерте.
        if state.config.device_api.enabled {
            let device_state = state.clone();
            let device_shutdown = shutdown_rx.clone();
            let alerts = state.alerts.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = hearthd::deviceapi::serve(device_state, device_shutdown).await {
                    tracing::error!(error = %e, "device api stopped");
                    alerts
                        .emit(hearthd::model::alert::Alert::warning(
                            "deviceapi",
                            format!(
                                "device api stopped: {e}. Обновления и свежие TURN-креды \
                                 устройствам недоступны; сообщения не затронуты."
                            ),
                        ))
                        .await;
                }
            }));
        }

        tracing::info!(%api_listen, "hearthd ready");

        // The admin API is not optional. If it cannot bind, or its TLS material is
        // unreadable, the node becomes unmanageable — and doing that silently is the
        // worst outcome: everything looks healthy while nobody can issue a bundle or
        // see an alert. Whichever finishes first wins, and an API that ends by itself
        // takes the daemon down with it.
        let api_failed = tokio::select! {
            _ = wait_for_signal() => {
                tracing::info!("shutdown requested");
                None
            }
            result = &mut api => {
                let reason = match result {
                    Ok(Ok(())) => "admin api stopped on its own".to_string(),
                    Ok(Err(e)) => format!("admin api failed: {e}"),
                    Err(e) => format!("admin api task panicked: {e}"),
                };
                tracing::error!("{reason}");
                Some(reason)
            }
        };

        let _ = shutdown_tx.send(true);

        for task in tasks {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        }
        api.abort();

        match api_failed {
            // Exit non-zero so systemd restarts us and the failure is visible in
            // `systemctl status` instead of being a quietly half-running node.
            Some(reason) => Err(Fatal::Retryable(Error::Config(reason))),
            None => Ok(()),
        }
    })
}

/// Привести реальность в соответствие с сохранённым режимом узла.
///
/// Узел мог загрузиться в карантине или переносе — и обнаружить, что релеи уже
/// работают: systemd запустил их по `WantedBy=multi-user.target`, не спросив никого.
/// Раньше демон в этом случае только писал в журнал «релеи удерживаются
/// остановленными» — утверждение, которое в этот момент было ложью. Теперь он их
/// останавливает.
///
/// Ошибки здесь не фатальны: узел без права остановить релей всё равно полезнее
/// узла без контрольного контура. Но молчать о них нельзя — алерт sticky.
async fn enforce_mode_at_start(state: &Arc<AppState>) {
    let node = state.mode.read().await.clone();
    if node.relays_allowed() {
        return;
    }
    // Список — из конфигурации (`mode_gated_units`): релеи и TURN. Про `enabled` не
    // спрашиваем, спрашиваем про `running`: остановить надо то, что прямо сейчас
    // обслуживает семью вопреки запрету, а не то, что значится включённым.
    for unit in state.config.mode_gated_units() {
        if !hearthd::sys::systemd::running(&state.sys, &unit).await {
            continue;
        }
        let summary = match hearthd::sys::systemd::stop(&state.sys, &unit).await {
            Ok(()) => {
                tracing::error!(
                    unit = %unit,
                    mode = node.mode.label(),
                    "узел поднялся в запрещающем режиме: служба остановлена повторно"
                );
                format!(
                    "узел поднялся в режиме «{}», работавший {unit} остановлен повторно",
                    node.mode.label()
                )
            }
            Err(e) => {
                tracing::error!(unit = %unit, error = %e, "служба не остановлена");
                format!(
                    "узел поднялся в режиме «{}», а {unit} не удалось остановить: {e}",
                    node.mode.label()
                )
            }
        };
        state
            .alerts
            .emit(
                Alert::critical("hearthd", summary)
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

/// Fail fast on the mistakes that would otherwise show up as a silent non-service.
fn preflight(state: &Arc<AppState>) -> Result<()> {
    let config = &state.config;
    for dir in [&config.paths.state_dir, &config.paths.hearth_etc] {
        hearthd::store::ensure_dir(dir)?;
    }
    let ca = config.api.pki_dir.join(pki::CA_CERT);
    if !ca.exists() {
        return Err(Error::Config(format!(
            "{} is missing — run `hearthd ca init` before starting the daemon",
            ca.display()
        )));
    }
    if !config.paths.manifest.exists() {
        return Err(Error::Config(format!(
            "{} is missing — the node must know which binaries it is allowed to run \
             (ТЗ §6.1)",
            config.paths.manifest.display()
        )));
    }
    Ok(())
}

/// SIGTERM (systemd stop) or Ctrl-C.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!(error = %e, "cannot install SIGTERM handler");
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// journald-friendly logging: no ANSI, no timestamps (journald adds its own).
fn init_tracing(filter: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);
    if std::env::var_os("INVOCATION_ID").is_some() {
        // Running under systemd.
        builder.without_time().with_ansi(false).init();
    } else {
        builder.init();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_terminal_failure_is_not_restarted_in_a_loop() {
        // Дефект 17: провал preflight (нет ca.pem, нет manifest.toml) писал карантин,
        // останавливал релеи и возвращал ошибку — а systemd через 5 секунд запускал
        // всё заново. Цикл вечный: StartLimitBurst при интервале 5 с не срабатывает.
        // Выйти локально было нельзя — снятие режима переживало ровно пять секунд.
        let unit = include_str!("../../deploy/systemd/hearthd.service");
        assert!(
            unit.contains(&format!("RestartPreventExitStatus={EXIT_TERMINAL}")),
            "юнит обязан не перезапускать терминальный код {EXIT_TERMINAL}: {unit}"
        );
        // 78 — EX_CONFIG из sysexits(3). Число зашито в юните, поэтому меняться оно
        // может только вместе с ним.
        assert_eq!(EXIT_TERMINAL, 78);
    }

    #[test]
    fn a_broken_config_stops_the_daemon_once_instead_of_looping() {
        // Дефект: Config::load отдавал Retryable -> код 1 -> Restart=on-failure с
        // RestartSec=5s. StartLimitBurst при таком интервале не срабатывает, и journal
        // заполнялся одной и той же строкой разбора TOML вечно. Сломанный конфиг —
        // состояние узла: его чинит человек, а не следующий запуск.
        let dir = tempfile::tempdir().expect("tempdir");

        let missing = dir.path().join("нет-такого.toml");
        assert!(
            matches!(load_config(&missing), Err(Fatal::Terminal(_))),
            "отсутствующий конфиг обязан быть терминальным"
        );

        let broken = dir.path().join("hearthd.toml");
        std::fs::write(&broken, "[node]\nname = \"без закрывающей кавычки\n").expect("write");
        assert!(
            matches!(load_config(&broken), Err(Fatal::Terminal(_))),
            "неразобранный TOML обязан быть терминальным"
        );

        // Невыполненный инвариант (Config::validate) — тоже состояние узла: его правит
        // человек, а не следующий запуск. Здесь это отсутствующая обязательная секция.
        let invalid = dir.path().join("невалидный.toml");
        std::fs::write(&invalid, "[node]\nname = \"узел\"\n").expect("write");
        assert!(
            matches!(load_config(&invalid), Err(Fatal::Terminal(_))),
            "невыполнимая конфигурация обязана быть терминальной"
        );
    }

    #[test]
    fn the_daemon_unit_waits_for_its_own_directories() {
        // Дефект: RequiresMountsFor добавили гейтовому drop-in'у, а самому демону —
        // нет. /var/lib/hearth и /var/opt/hearth на боевом узле — отдельные точки
        // монтирования (deploy/systemd/var-opt-hearth.mount). Без ожидания демон
        // стартует раньше монтирования и видит пустой каталог состояния: режим узла
        // «потерян», журналы начинаются заново, бэкап пишет мимо раздела.
        let unit = include_str!("../../deploy/systemd/hearthd.service");
        let line = unit
            .lines()
            .find(|l| l.starts_with("RequiresMountsFor="))
            .expect("юнит обязан ждать свои каталоги");
        for dir in ["/var/lib/hearth", "/var/opt/hearth"] {
            assert!(line.contains(dir), "{line} обязан называть {dir}");
        }
    }

    use super::*;

    /// Стартовая строка — единственное, что связывает работающий процесс с файлом
    /// для того, кто не может прочитать `/proc/<pid>/exe`. Раньше в ней стояла
    /// только версия `0.1.0`.
    #[test]
    fn the_startup_banner_names_the_commit_and_the_running_file() {
        let info = hearthd::BuildInfo {
            version: "0.1.0".into(),
            commit: "a".repeat(40),
            dirty: false,
            tree_sha256: "b".repeat(64),
            target: "x86_64-unknown-linux-musl".into(),
            rustc: "rustc 1.97.1".into(),
            source_date_epoch: "1789668394".into(),
        };
        let line = startup_banner(&info, &"c".repeat(64), "hearth-node");
        assert!(
            line.contains(&format!("commit={}", "a".repeat(40))),
            "{line}"
        );
        assert!(
            line.contains(&format!("exe_sha256={}", "c".repeat(64))),
            "{line}"
        );
        assert!(line.contains("tree_sha256="), "{line}");
        assert!(line.contains("started on hearth-node"), "{line}");
        assert!(!line.contains("dirty"), "чистое дерево не метится: {line}");
    }

    /// Сборка из изменённого дерева обязана говорить об этом в журнале: иначе
    /// черновик неотличим от выпуска.
    #[test]
    fn a_dirty_build_says_so_in_the_journal() {
        let info = hearthd::BuildInfo {
            version: "0.1.0".into(),
            commit: "a".repeat(40),
            dirty: true,
            tree_sha256: "b".repeat(64),
            target: "x86_64-unknown-linux-musl".into(),
            rustc: "rustc 1.97.1".into(),
            source_date_epoch: "1789668394".into(),
        };
        let line = startup_banner(&info, &"c".repeat(64), "hearth-node");
        assert!(line.contains("(dirty)"), "{line}");
    }
}
