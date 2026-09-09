//! `hearthctl` — the admin CLI (ТЗ §7.3: "Веб-UI в v1 нет; CLI `hearthctl`").
//!
//! Most commands are thin calls into the admin API over mTLS. Two are deliberately
//! local-only, because they need material the daemon must never hold:
//!
//! * `migrate import` and `restore` need the offline age identity;
//! * `manifest pin` edits the pinned-hash file, which is a human decision.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use hearthd::api::client::{self, AdminClient};
use hearthd::config::Config;
use hearthd::error::{Error, Result};
use hearthd::model::bundle::Bundle;
use hearthd::model::device::Device;
use hearthd::model::health::{HealthSnapshot, HealthState, NodeStatus};
use hearthd::{DEFAULT_CONFIG_PATH, VERSION};

#[derive(Debug, Parser)]
#[command(name = "hearthctl", version = VERSION, about = "Admin CLI for a hearth node")]
struct Cli {
    /// Configuration file (used for the API address and the PKI directory).
    #[arg(short, long, env = "HEARTHD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Admin identity: uses `<pki_dir>/<name>.pem` and `<name>.key`.
    #[arg(long, env = "HEARTHCTL_ADMIN", default_value = "owner")]
    admin: String,

    /// Override the API address (`ip:port`).
    #[arg(long)]
    addr: Option<SocketAddr>,

    /// Override the CA / certificate / key paths.
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,

    /// Print raw JSON instead of the human-readable rendering.
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Service health (ТЗ §10.2 п.6).
    Health,
    /// Everything at once: health, egress, integrity, backup, devices.
    Status,
    /// Recent alerts.
    Alerts(AlertArgs),
    /// Egress watchdog state — the number that must stay zero (ТЗ §5.4, A2).
    Egress {
        /// Show the permanent incident history instead of the current state.
        #[arg(long)]
        incidents: bool,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Device registry and bundles (ТЗ §10.3, §10.4).
    #[command(subcommand)]
    Device(DeviceCommand),
    /// Rotate the coturn static secret (ТЗ §6.4).
    #[command(subcommand)]
    Rotate(RotateCommand),
    /// Backups (ТЗ §7.3).
    #[command(subcommand)]
    Backup(BackupCommand),
    /// Node migration (ТЗ §10.2).
    #[command(subcommand)]
    Migrate(MigrateCommand),
    /// Pinned binaries (ТЗ §6.1).
    #[command(subcommand)]
    Manifest(ManifestCommand),
}

#[derive(Debug, Args)]
struct AlertArgs {
    /// Minimum severity: info | warning | critical.
    #[arg(long)]
    severity: Option<String>,
    /// Only alerts at or after this RFC 3339 timestamp.
    #[arg(long)]
    since: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// List registered devices.
    List,
    /// Register a device and print its bundle QR.
    Add {
        /// Human name, e.g. "Мама — Pixel 8".
        name: String,
        /// android | ios | desktop.
        #[arg(long, default_value = "android")]
        platform: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Revoke a device (ТЗ §10.4).
    Revoke { id: String },
    /// Show a device's bundle: QR in the terminal, JSON on request.
    Bundle {
        id: String,
        /// Print the bundle JSON as well. It contains relay passwords.
        #[arg(long)]
        show_json: bool,
        /// Write the QR PNG to a file. Avoid: ТЗ Приложение B says the QR is not saved.
        #[arg(long)]
        write_png: Option<PathBuf>,
    },
    /// Manual setup checklist for a stock client (ТЗ §9).
    Checklist { id: String },
}

#[derive(Debug, Subcommand)]
enum RotateCommand {
    /// New coturn static secret; existing client credentials stop working.
    TurnSecret,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Run a backup now.
    Now,
    /// Show the last backup status.
    Status,
    /// List archives in the local spool.
    List,
    /// Decrypt an archive into a directory (quarterly restore drill, ТЗ §10.7).
    Restore {
        archive: PathBuf,
        /// Offline age identity file.
        #[arg(long)]
        identity: PathBuf,
        /// Destination directory. Use `/` only on a machine you intend to overwrite.
        #[arg(long)]
        into: PathBuf,
        /// Only list the archive contents.
        #[arg(long)]
        list: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MigrateCommand {
    /// Stop the relays and produce the final encrypted archive (ТЗ §10.2 п.3).
    Export,
    /// Restore an exported archive on the new node (ТЗ §10.2 п.4).
    Import {
        archive: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// Destination root. `/` on a real migration.
        #[arg(long, default_value = "/")]
        into: PathBuf,
        /// Expected sha256 of the archive, as printed by `migrate export`.
        #[arg(long)]
        sha256: Option<String>,
    },
    /// Show the migration status of this node.
    Status,
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    /// Verify every pinned binary against the manifest (A12).
    Verify,
    /// Measure a binary and write its hash into the manifest.
    Pin {
        /// Entry name, e.g. `smp-server`.
        #[arg(long)]
        name: String,
        /// File to measure. Defaults to the path in the manifest.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Also set the version field.
        #[arg(long)]
        version: Option<String>,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        // Already installed; nothing to do.
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("hearthctl: cannot start the runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hearthctl: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config = Config::load(&cli.config)?;

    match &cli.command {
        // ---- local-only commands (no daemon, no network) ----------------------
        Command::Backup(BackupCommand::List) => {
            let archives = hearthd::backup::list_archives(&config.backup.spool_dir)?;
            if archives.is_empty() {
                println!("no archives in {}", config.backup.spool_dir.display());
            }
            for archive in archives {
                println!("{}", archive.display());
            }
            return Ok(());
        }
        Command::Backup(BackupCommand::Restore {
            archive,
            identity,
            into,
            list,
        }) => {
            if *list {
                for member in hearthd::backup::archive::list_members(archive, identity)? {
                    println!("{}", member.display());
                }
            } else {
                let restored =
                    hearthd::backup::archive::decrypt_and_extract(archive, identity, into)?;
                println!(
                    "restored {} entries into {}",
                    restored.len(),
                    into.display()
                );
            }
            return Ok(());
        }
        Command::Migrate(MigrateCommand::Import {
            archive,
            identity,
            into,
            sha256,
        }) => {
            let state =
                hearthd::state::AppState::new(config.clone(), hearthd::sys::Sys::new(false))?;
            let report =
                hearthd::migrate::import(&state, archive, identity, into, sha256.as_deref())
                    .await?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "restored {} entries into {}",
                    report.restored.len(),
                    into.display()
                );
                println!(
                    "binary integrity: {}",
                    if report.integrity_ok {
                        "ok"
                    } else {
                        "NOT VERIFIED"
                    }
                );
                for note in &report.integrity_notes {
                    println!("  {note}");
                }
                println!("\nnext steps:");
                for (i, step) in report.next_steps.iter().enumerate() {
                    println!("  {}. {step}", i + 1);
                }
            }
            return Ok(());
        }
        Command::Manifest(ManifestCommand::Verify) => {
            let manifest = hearthd::model::manifest::Manifest::load(&config.paths.manifest)?;
            let findings = manifest.verify_all();
            if cli.json {
                print_json(&findings)?;
            } else {
                for finding in &findings {
                    println!(
                        "{:<14} {:?}  {}",
                        finding.name,
                        finding.status,
                        finding.path.display()
                    );
                }
            }
            let ok = findings
                .iter()
                .all(|f| f.status == hearthd::model::manifest::IntegrityStatus::Ok);
            if !ok {
                return Err(Error::Integrity(
                    "one or more binaries do not match the manifest".into(),
                ));
            }
            return Ok(());
        }
        Command::Manifest(ManifestCommand::Pin {
            name,
            path,
            version,
        }) => {
            let raw = std::fs::read_to_string(&config.paths.manifest)
                .map_err(|e| Error::io(&config.paths.manifest, e))?;
            let manifest: hearthd::model::manifest::Manifest = toml::from_str(&raw)?;
            let entry = manifest
                .binary(name)
                .ok_or_else(|| Error::NotFound(format!("manifest entry `{name}`")))?;
            let target = path.clone().unwrap_or_else(|| entry.path.clone());
            let digest = hearthd::model::manifest::sha256_file(&target)?;
            let updated = hearthd::model::manifest::pin(&raw, name, &digest, version.as_deref())?;
            hearthd::store::write_atomic(
                &config.paths.manifest,
                updated.as_bytes(),
                hearthd::store::MODE_STATE,
            )?;
            println!("pinned {name} = {digest}");
            println!("  measured: {}", target.display());
            println!("  manifest: {}", config.paths.manifest.display());
            return Ok(());
        }
        _ => {}
    }

    // ---- everything else goes through the admin API -------------------------
    let addr = cli.addr.unwrap_or(config.api.listen);
    let api = client::connect(
        addr,
        &config.api.pki_dir,
        &cli.admin,
        cli.ca.as_deref(),
        cli.cert.as_deref(),
        cli.key.as_deref(),
    )?;

    match cli.command {
        Command::Health => {
            let health: HealthSnapshot = api.get_json("/health").await?;
            if cli.json {
                print_json(&health)?;
            } else {
                print_health(&health);
            }
            if health.state == HealthState::Down {
                return Err(Error::Conflict("node is unhealthy".into()));
            }
        }
        Command::Status => {
            let status: NodeStatus = api.get_json("/status").await?;
            if cli.json {
                print_json(&status)?;
            } else {
                print_status(&status);
            }
        }
        Command::Alerts(args) => {
            let mut path = format!("/alerts?limit={}", args.limit);
            if let Some(severity) = &args.severity {
                path.push_str(&format!("&severity={}", percent_encode(severity)));
            }
            if let Some(since) = &args.since {
                // RFC 3339 offsets contain '+', which a query string decodes as a
                // space — `--since 2026-01-01T00:00:00+03:00` would reach the server
                // as a timestamp with a space in it and be rejected as unparseable.
                path.push_str(&format!("&since={}", percent_encode(since)));
            }
            let alerts: Vec<hearthd::model::alert::Alert> = api.get_json(&path).await?;
            if cli.json {
                print_json(&alerts)?;
            } else if alerts.is_empty() {
                println!("no alerts");
            } else {
                for alert in alerts {
                    println!(
                        "{}  {:<8} {:<11} {}",
                        hearthd::model::fmt_ts(alert.ts),
                        alert.severity.to_string(),
                        alert.module,
                        alert.summary
                    );
                }
            }
        }
        Command::Egress { incidents, limit } => {
            if incidents {
                let history: Vec<hearthd::model::alert::Alert> = api
                    .get_json(&format!("/egress/incidents?limit={limit}"))
                    .await?;
                if cli.json {
                    print_json(&history)?;
                } else if history.is_empty() {
                    println!("no egress incidents have ever been recorded on this node");
                } else {
                    for alert in history {
                        println!("{}  {}", hearthd::model::fmt_ts(alert.ts), alert.summary);
                    }
                }
            } else {
                let egress: hearthd::model::health::EgressSnapshot =
                    api.get_json("/egress").await?;
                if cli.json {
                    print_json(&egress)?;
                } else {
                    print_egress(&egress);
                }
                if egress.state != HealthState::Ok {
                    return Err(Error::Conflict(
                        "egress watchdog is not clean — see `hearthctl egress --incidents`".into(),
                    ));
                }
            }
        }
        Command::Device(DeviceCommand::List) => {
            let devices: Vec<Device> = api.get_json("/devices").await?;
            if cli.json {
                print_json(&devices)?;
            } else if devices.is_empty() {
                println!("no devices registered");
            } else {
                for device in devices {
                    println!(
                        "{:<20} {:<8} {:<24} {}",
                        device.id,
                        device.platform.to_string(),
                        device.name,
                        match device.revoked {
                            Some(ts) => format!("revoked {}", hearthd::model::fmt_ts(ts)),
                            None => "active".to_string(),
                        }
                    );
                }
            }
        }
        Command::Device(DeviceCommand::Add {
            name,
            platform,
            note,
        }) => {
            let device: Device = api
                .post_json(
                    "/devices",
                    Some(serde_json::json!({
                        "name": name,
                        "platform": platform,
                        "note": note,
                    })),
                )
                .await?;
            println!("registered `{}` ({})", device.id, device.platform);
            println!();
            show_bundle(&api, &device.id, false, None).await?;
        }
        Command::Device(DeviceCommand::Revoke { id }) => {
            let device: Device = api
                .post_json(&format!("/devices/{id}/revoke"), None)
                .await?;
            println!("revoked `{}`", device.id);
            println!("Remaining steps (ТЗ §10.4):");
            println!("  1. Other family members delete the contact/participant.");
            println!("  2. Возможности отрезать устройство по сети больше нет: релей публичен.");
            println!("     Работают только удаление контактов остальными и отзыв выше.");
            println!("  3. If the relay password may have leaked: rotate the address (ТЗ §10.5).");
        }
        Command::Device(DeviceCommand::Bundle {
            id,
            show_json,
            write_png,
        }) => {
            show_bundle(&api, &id, show_json, write_png.as_deref()).await?;
        }
        Command::Device(DeviceCommand::Checklist { id }) => {
            let text = api
                .get_bytes(&format!("/devices/{id}/checklist.txt"))
                .await?;
            print!("{}", String::from_utf8_lossy(&text));
        }
        Command::Rotate(RotateCommand::TurnSecret) => {
            let report: serde_json::Value = api.post_json("/rotate/turn-secret", None).await?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("TURN static secret rotated.");
                let stale = report
                    .get("reissue_bundles_for")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if stale.is_empty() {
                    println!("No device has been issued a bundle yet — nothing to re-issue.");
                } else {
                    println!(
                        "\nCredentials from the old secret are dead. Calls will fail for these\n\
                         devices while messages keep working — an easy symptom to misread.\n\
                         Re-issue a bundle for each:\n"
                    );
                    for device in stale {
                        if let Some(id) = device.as_str() {
                            println!("    hearthctl device bundle {id}");
                        }
                    }
                }
            }
        }
        Command::Backup(BackupCommand::Now) => {
            let info: hearthd::backup::archive::ArchiveInfo =
                api.post_json("/backup/now", None).await?;
            println!("archive:  {}", info.path.display());
            println!("size:     {} bytes", info.size_bytes);
            println!("sha256:   {}", info.sha256);
            if !info.unreadable.is_empty() {
                // Не предупреждение «на всякий случай»: это список того, чего в архиве
                // НЕТ. Восстановление из него эти файлы не вернёт.
                println!(
                    "\nНЕ ПОПАЛО В АРХИВ — демону не разрешено это читать ({}):",
                    info.unreadable.len()
                );
                for path in &info.unreadable {
                    println!("  {path}");
                }
                println!(
                    "Храните их отдельно, вместе с приватным age-ключом. Ключ admin CA\n\
                     закрыт от демона намеренно (deploy/fix-permissions.sh)."
                );
            }
        }
        Command::Backup(BackupCommand::Status) => {
            let status: hearthd::model::health::BackupStatus =
                api.get_json("/backup/status").await?;
            print_json(&status)?;
        }
        Command::Migrate(MigrateCommand::Export) => {
            let report: hearthd::migrate::ExportReport =
                api.post_json("/migrate/export", None).await?;
            println!("archive: {}", report.archive.display());
            println!("sha256:  {}", report.sha256);
            println!("size:    {} bytes", report.size_bytes);
            println!("stopped: {}", report.relays_stopped.join(", "));
            println!("\nnext steps:");
            for (i, step) in report.next_steps.iter().enumerate() {
                println!("  {}. {step}", i + 1);
            }
        }
        Command::Migrate(MigrateCommand::Status) => {
            let status: hearthd::model::health::MigrateStatus =
                api.get_json("/migrate/export").await?;
            print_json(&status)?;
        }
        // Handled above, before the client was built.
        Command::Backup(_) | Command::Migrate(_) | Command::Manifest(_) => {}
    }
    Ok(())
}

/// Fetch a bundle and render the QR in the terminal.
async fn show_bundle(
    api: &AdminClient,
    id: &str,
    show_json: bool,
    write_png: Option<&Path>,
) -> Result<()> {
    let bundle: Bundle = api.get_json(&format!("/devices/{id}/bundle.json")).await?;
    let json = bundle.to_json()?;

    println!("{}", hearthd::qr::terminal(&json)?);
    println!("Scan this from the hearth app: Настройки узла → Сканировать QR.");
    println!("The QR carries relay passwords: show it in person, never forward it.");

    if show_json {
        println!("\n{}", bundle.to_json_pretty()?);
    }
    if let Some(path) = write_png {
        let png = hearthd::qr::png(&json, hearthd::qr::DEFAULT_SCALE)?;
        hearthd::store::write_atomic(path, &png, hearthd::store::MODE_SECRET)?;
        println!(
            "\nWARNING: wrote {} — ТЗ Приложение B says the QR is not saved anywhere. \
             Delete it as soon as the device is enrolled.",
            path.display()
        );
    }
    Ok(())
}

fn print_health(health: &HealthSnapshot) {
    println!(
        "{} ({})  state={:?}  uptime={}s  hearthd {}",
        health.node, health.address, health.state, health.uptime_secs, health.version
    );
    for service in &health.services {
        println!(
            "  {:<6} {:<10} {:<8} listening={:<5} control={:<7} restarts(10m)={} {}",
            service.name,
            service.active_state,
            service.sub_state,
            service.listening,
            match service.control_ok {
                Some(true) => "ok",
                Some(false) => "DOWN",
                None => "-",
            },
            service.restarts_in_window,
            service.message.as_deref().unwrap_or("")
        );
    }
}

fn print_egress(egress: &hearthd::model::health::EgressSnapshot) {
    println!("egress watchdog: state={:?}", egress.state);
    println!(
        "  counters readable: {}   (if false, the leak detector is blind)",
        egress.counters_readable
    );
    println!(
        "  egress_drop: {} packets / {} bytes   delta since start: {}",
        egress.egress_drop_packets, egress.egress_drop_bytes, egress.egress_drop_delta
    );
    println!(
        "  input_drop:  {} packets / {} bytes",
        egress.input_drop_packets, egress.input_drop_bytes
    );
    if !egress.informational.is_empty() {
        // Permitted egress on a multi-purpose host (ADR 0008). These are expected to
        // grow; showing them next to egress_drop is what keeps the zero readable.
        let counters: Vec<String> = egress
            .informational
            .iter()
            .map(|(name, packets)| format!("{name}={packets}"))
            .collect();
        println!(
            "  permitted:   {}   (expected to grow)",
            counters.join("  ")
        );
    }
    println!("  incidents ever: {}", egress.incidents_total);
    if !egress.scanner_ok {
        println!(
            "  socket scan: DEGRADED — `ss` could not name the owning processes, \
             so the scan proves nothing"
        );
    } else if egress.foreign_sockets.is_empty() {
        println!("  socket scan: ok, no relay socket dialling out");
    }
    for socket in &egress.foreign_sockets {
        println!(
            "  RELAY DIALLED OUT {} {} -> {} ({})",
            socket.process, socket.local, socket.peer, socket.state
        );
    }
    println!(
        "\nExpected over 24h (A2): egress_drop delta = 0 and no relay socket dialling out.\n\
         `egress_drop` means the RELAY STACK tried to reach the internet — other services\n\
         on this host are permitted by name and counted separately (ADR 0008)."
    );
}

fn print_status(status: &NodeStatus) {
    print_health(&status.health);
    println!();
    print_egress(&status.egress);
    println!();
    println!(
        "integrity: state={:?}  simplexmq={}  simplex-chat={}",
        status.integrity.state, status.integrity.simplexmq_tag, status.integrity.simplex_chat_tag
    );
    for finding in &status.integrity.findings {
        println!("  {:<14} {:?}", finding.name, finding.status);
    }
    println!();
    println!(
        "backup: last success={}  remote_ok={}  archives={}",
        status
            .backup
            .last_success
            .map(hearthd::model::fmt_ts)
            .unwrap_or_else(|| "never".into()),
        status.backup.remote_ok,
        status.backup.archives_kept
    );
    if let Some(error) = &status.backup.last_error {
        println!("  last error: {error}");
    }
    println!();
    println!(
        "devices: {} active / {} total   critical alerts retained: {}",
        status.devices_active, status.devices_total, status.alerts_critical_open
    );
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Percent-encode a query-string value.
///
/// Only unreserved characters (RFC 3986 §2.3) pass through untouched; everything else
/// is escaped. That matters most for `+` in RFC 3339 offsets, which a query parser
/// would otherwise decode as a space.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::percent_encode;

    #[test]
    fn encodes_rfc3339_offsets() {
        // The case that actually broke: `+` in a timezone offset.
        assert_eq!(
            percent_encode("2026-01-01T00:00:00+03:00"),
            "2026-01-01T00%3A00%3A00%2B03%3A00"
        );
        assert_eq!(
            percent_encode("2026-01-01T00:00:00Z"),
            "2026-01-01T00%3A00%3A00Z"
        );
    }

    #[test]
    fn leaves_unreserved_characters_alone() {
        assert_eq!(percent_encode("critical"), "critical");
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn escapes_separators_that_would_change_the_query() {
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("a b"), "a%20b");
    }
}
