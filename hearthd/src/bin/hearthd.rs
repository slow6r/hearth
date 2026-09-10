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
    Revoke {
        /// Admin name.
        name: String,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "hearthd failed");
            eprintln!("hearthd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    // rustls needs its provider installed before any TLS object is built.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider was already installed");
    }

    let config = Config::load(&cli.config)?;

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
            println!(
                "  turn:        {} (relay {}-{})",
                config.turn.port, config.turn.relay_min_port, config.turn.relay_max_port
            );
            println!("  admin api:   {}  (LAN only)", config.api.listen);
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
        Command::Ca(CaCommand::Revoke { name }) => {
            let mut registry = pki::AdminRegistry::load(&config.api.pki_dir)?;
            let admin = registry.revoke(&name)?;
            println!("revoked `{}` ({})", admin.name, admin.fingerprint);
            Ok(())
        }
        Command::Run => serve(config, cli.dry_run),
    }
}

/// Build the runtime and run every module until a signal arrives.
fn serve(config: Config, dry_run: bool) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Error::RawIo)?;

    runtime.block_on(async move {
        let sys = Sys::new(dry_run);
        let node = config.node.name.clone();
        let api_listen = config.api.listen;
        let state = AppState::new(config, sys)?;

        preflight(&state)?;

        state
            .alerts
            .emit(Alert::info(
                "hearthd",
                format!("hearthd {VERSION} started on {node}"),
            ))
            .await;

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
                                "device api stopped: {e}. Обновления и свежие TURN-креды                                  устройствам недоступны; сообщения не затронуты."
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
            Some(reason) => Err(Error::Config(reason)),
            None => Ok(()),
        }
    })
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
