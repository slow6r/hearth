//! `hearthctl` — the admin CLI (ТЗ §7.3: "Веб-UI в v1 нет; CLI `hearthctl`").
//!
//! Most commands are thin calls into the admin API over mTLS. Two are deliberately
//! local-only, because they need material the daemon must never hold:
//!
//! * `migrate import` and `restore` need the offline age identity;
//! * `manifest pin` edits the pinned-hash file, which is a human decision.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use chrono::Utc;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use hearthd::api::client::{self, AdminClient};
use hearthd::config::Config;
use hearthd::error::{Error, Result};
use hearthd::model::bundle::Bundle;
use hearthd::model::device::Device;
use hearthd::model::health::{HealthSnapshot, HealthState, NodeStatus};
use hearthd::model::invite::Invite;
use hearthd::model::mode::GateVerdict;
use hearthd::{DEFAULT_CONFIG_PATH, VERSION};

#[derive(Debug, Parser)]
#[command(name = "hearthctl", version = VERSION, about = "Admin CLI for a hearth node")]
struct Cli {
    /// Configuration file (used for the API address and the PKI directory).
    ///
    /// Переменная окружения `HEARTHD_CONFIG` действует на обычные команды, но НЕ на
    /// решения, принимаемые без демона (`mode gate`, `mode clear --local`):
    /// см. `config_for_local_decision`.
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
    /// Паспорт сборки ЭТОГО файла: коммит, хеш дерева, хеш самого файла.
    ///
    /// Локальная команда: ни демона, ни сети, ни конфигурации узла. Так и задумано —
    /// её запускают на копии бинарника, снятой с узла, и на свежесобранном файле,
    /// который ещё не установлен. Паспорт работающего ПРОЦЕССА берётся из
    /// `hearthctl health`: там те же поля, но их называет сам демон.
    BuildInfo {
        /// Выдать JSON вместо `ключ=значение`.
        #[arg(long)]
        json: bool,
    },
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
        /// Подтвердить инцидент: вы его увидели и разобрались.
        ///
        /// До подтверждения статус остаётся красным даже после перезапуска демона —
        /// иначе единственное событие, ради которого сторож существует, стиралось бы
        /// рестартом.
        #[arg(long)]
        acknowledge: bool,
    },
    /// Device registry and bundles (ТЗ §10.3, §10.4).
    #[command(subcommand)]
    Device(DeviceCommand),
    /// Приглашения: ими сборка заводит устройство сама (ADR 0010).
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Аудиторские токены: срочный доступ проверяющего к раздаче обновлений.
    #[command(subcommand)]
    AuditToken(AuditTokenCommand),
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
    /// Режим узла: карантин, обслуживание, перенос.
    #[command(subcommand)]
    Mode(ModeCommand),
    /// Подпись манифеста обновлений (ключ на рабочей станции, не на узле).
    #[command(subcommand)]
    Release(ReleaseCommand),
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    /// Выписать пару ключей для подписи манифестов.
    ///
    /// Закрытый ключ кладите туда же, где лежит ключ подписи APK, и НИКОГДА не
    /// копируйте на узел: весь смысл подписи в том, что захваченный узел не может
    /// её поставить. Открытый вшивается в сборку (bake-node.sh).
    Keygen {
        /// Куда положить `release-sign.key` и `release-sign.pub`.
        #[arg(long)]
        out: PathBuf,
        /// Перезаписать существующую пару.
        #[arg(long)]
        force: bool,
    },
    /// Подписать файл манифеста. Рядом появится `<файл>.sig`.
    ///
    /// Подпись проставляет и СРОК ГОДНОСТИ: манифест перезаписывается полем `expires`,
    /// и подписываются уже новые байты. Срок назначает оператор, потому что узел этого
    /// сделать не может — ключ живёт здесь, а не на узле, и «переподписать манифест»
    /// означает «дойти до этой машины». Бессрочный манифест больше не выпускается:
    /// именно он позволял захваченному узлу годами держать семью на старой версии.
    Sign {
        /// Файл манифеста (`manifest.json`).
        manifest: PathBuf,
        /// Закрытый ключ подписи.
        #[arg(long)]
        key: PathBuf,
        /// Сколько манифесту жить с этого момента: `30d`, `6w`. По умолчанию 30 дней.
        ///
        /// Ставьте столько, через сколько реально дойдут руки до следующей подписи:
        /// когда срок выйдет, телефоны перестанут ставить обновления, а переписка и
        /// звонки продолжат работать.
        #[arg(long, value_name = "СРОК", conflicts_with = "expires")]
        valid_for: Option<String>,
        /// Точная дата окончания: `2026-10-18` или `2026-10-18T12:00:00Z`.
        ///
        /// Голая дата означает «годен весь этот день»: клиент сравнивает дни, а не
        /// моменты.
        #[arg(long, value_name = "ДАТА")]
        expires: Option<String>,
    },
    /// Проверить подпись — тем же способом, что и приложение.
    Verify {
        manifest: PathBuf,
        #[arg(long)]
        sig: Option<PathBuf>,
        #[arg(long)]
        pubkey: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ModeCommand {
    /// Показать режим и причину, по которой он наступил.
    Show,
    /// Снять режим и вернуть узел в норму.
    ///
    /// Только вручную: узел не снимает карантин сам, даже если проверка целостности
    /// снова сошлась — причина могла быть устранена и подменой манифеста.
    Clear {
        /// Снять режим ПРЯМО НА УЗЛЕ, не обращаясь к admin API.
        ///
        /// Аварийный выход, и он обязан существовать. Обычное снятие идёт через
        /// работающий hearthd и админский mTLS-сертификат — то есть ровно через то,
        /// чего не бывает в тот вечер, когда узел не поднялся: демон падает на
        /// сломанном hearthd.toml, сертификат просрочен, каталог PKI снесён. Без
        /// локального выхода записанный на диск карантин означал бы «релеи не
        /// поднимутся никогда».
        ///
        /// Требует root: файл режима лежит в 0750 hearth:hearth, и снятие запрета —
        /// не то действие, которое должно получаться у случайного пользователя.
        /// Событие записывается в журнал алертов узла.
        #[arg(long)]
        local: bool,
        /// Файл режима узла (только с `--local`).
        ///
        /// По умолчанию берётся из `paths.state_dir` конфигурации. Указывать явно
        /// нужно в одном случае: когда сломана сама конфигурация и путь из неё не
        /// читается.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Гейт для systemd: можно ли сейчас стартовать релейному юниту.
    ///
    /// Выход 0 — можно, 1 — нельзя (причина уходит в journal). Вызывается из
    /// `ExecCondition=` в drop-in'ах релейных юнитов, то есть ДО hearthd и в отрыве
    /// от него: демон в этот момент может быть не запущен вовсе.
    ///
    /// Поэтому команда нарочно тупая: ни сети, ни mTLS, ни поднятия демона — только
    /// один путь из конфигурации и чтение одного JSON-файла. Из hearthd.toml читается
    /// РОВНО `paths.state_dir` (см. `model::mode::resolve_mode_file`): полный разбор
    /// конфигурации здесь означал бы, что опечатка в постороннем разделе оставляет
    /// дом без связи.
    Gate {
        /// Файл режима узла. По умолчанию — из конфигурации узла.
        #[arg(long)]
        file: Option<PathBuf>,
    },
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
    List {
        /// Обезличенный вывод: без токенов устройств и без `install_id`.
        ///
        /// Ровно этим `--json` попадает в выгрузку для аудита
        /// (`deploy/audit-dump.sh`): токен устройства — это доступ к раздаче
        /// обновлений и к TURN-кредам, и в отчёт проверяющему он попадать не должен.
        #[arg(long)]
        redacted: bool,
    },
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
enum InviteCommand {
    /// Выписать приглашение и напечатать токен для вшивания в сборку.
    Create {
        /// Сколько устройств можно завести. 0 — без ограничения (по умолчанию).
        #[arg(long, default_value_t = 0)]
        uses: u32,
        /// Сколько дней оно живо. 0 — бессрочно (по умолчанию).
        #[arg(long, default_value_t = 0)]
        days: i64,
        #[arg(long)]
        note: Option<String>,
        /// Записать токен в файл (0600) вместо печати на экран.
        ///
        /// Печать удобна у своего терминала, но токен оседает в истории и в логах
        /// сессии. Для сборки нужен именно файл.
        #[arg(long)]
        write_token: Option<PathBuf>,
        /// Сколько кодов выписать разом.
        #[arg(long, default_value_t = 1)]
        count: u32,
        /// Куда сложить выписанные коды — список для раздачи (0600).
        ///
        /// Для пачки это единственный разумный вывод: полсотни кодов на экране
        /// останутся в истории терминала, а раздавать их всё равно с бумаги.
        #[arg(long)]
        write_codes: Option<PathBuf>,
    },
    /// Показать приглашения и их состояние.
    List,
    /// Погасить приглашение. Уже заведённые по нему устройства не трогает.
    Revoke { id: String },
}

/// Аудиторский токен (см. `hearthd::model::audit_token`).
///
/// Отдельно от `device` и от `invite` намеренно: это не устройство семьи и не
/// приглашение в контур, а право скачать три файла раздачи в течение нескольких
/// суток. Слот `max_devices` он не расходует и bundle не выпускает.
#[derive(Debug, Subcommand)]
enum AuditTokenCommand {
    /// Выписать токен. Секрет печатается один раз — в списке его уже не будет.
    Issue {
        /// Срок в часах. Обязателен: бессрочного аудиторского доступа не бывает.
        #[arg(long)]
        ttl_hours: i64,
        /// Сколько обращений разрешено. Обязательно, нуля («без счётчика») нет.
        #[arg(long)]
        max_uses: u32,
        /// Область: `updates` (по умолчанию — манифест, подпись и файл),
        /// `updates-manifest`, `manifest-signature`, `updates-file`.
        #[arg(long, default_value = "updates")]
        scope: String,
        /// Кому и зачем выдан — это читают через полгода.
        #[arg(long)]
        note: Option<String>,
        /// Записать секрет в файл (0600) вместо печати на экран.
        ///
        /// Печать удобна у своего терминала, но секрет оседает в истории оболочки и
        /// в логах сессии — а передавать его всё равно отдельным каналом.
        #[arg(long)]
        write_token: Option<PathBuf>,
    },
    /// Показать выписанные токены и их состояние. Секретов в выводе нет.
    List,
    /// Погасить токен немедленно.
    Revoke { id: String },
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
        /// Коммит, из которого собран измеряемый файл (40 hex).
        ///
        /// Для `hearthd` и `hearthctl` заполняется сам — у них есть `build-info`.
        /// Для остальных записей указывается руками или не указывается вовсе.
        #[arg(long, requires = "tree_sha256")]
        commit: Option<String>,
        /// Хеш дерева исходников той же сборки (64 hex). Только вместе с `--commit`.
        #[arg(long, requires = "commit")]
        tree_sha256: Option<String>,
    },
}

/// Умеет ли этот файл рассказать о себе сам.
///
/// Список закрытый и по имени записи, а не «попробуем запустить что дали»: pin
/// работает под sudo и меряет произвольный путь из `--path`. Запускать произвольный
/// файл от root ради красивой строчки в манифесте — цена, несопоставимая с выгодой.
/// Для этих двух имён вопрос не стоит: их и так запускает systemd от имени службы.
fn speaks_build_info(name: &str) -> bool {
    matches!(name, "hearthd" | "hearthctl")
}

/// Спросить у измеряемого файла его паспорт сборки.
///
/// Ошибка здесь НЕ отменяет пин: без записанного sha256 манифест остаётся с нулевым
/// плейсхолдером, а это проверка целостности, которая валит узел в карантин при
/// первом же обходе. Поэтому отсутствие паспорта — громкое предупреждение и запись
/// без провенанса (прежний провенанс при этом стирается, см. `manifest::pin`).
fn ask_for_provenance(binary: &Path) -> Option<hearthd::model::manifest::EntryProvenance> {
    let out = match std::process::Command::new(binary)
        .args(["build-info", "--json"])
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            eprintln!(
                "ВНИМАНИЕ: {} build-info завершился с {}: происхождение не записано",
                binary.display(),
                out.status
            );
            return None;
        }
        Err(e) => {
            eprintln!(
                "ВНИМАНИЕ: не удалось спросить паспорт у {}: {e}",
                binary.display()
            );
            return None;
        }
    };
    match hearthd::model::manifest::EntryProvenance::from_build_info_json(&String::from_utf8_lossy(
        &out.stdout,
    )) {
        Ok(provenance) => Some(provenance),
        Err(e) => {
            eprintln!("ВНИМАНИЕ: паспорт сборки не разобран ({e}): происхождение не записано");
            None
        }
    }
}

/// Ответ systemd на вопрос «можно ли стартовать релею».
///
/// Отдельная функция и ранний выход из `main` — не стиль, а требование: гейт обязан
/// работать там, где не работает ничего остального. Ни tokio, ни rustls, ни
/// `Config::load` здесь не участвуют.
fn mode_gate(file: Option<&Path>, config: &Path) -> std::process::ExitCode {
    let decision = hearthd::model::mode::decide_gate(file, config);
    // Подмена пути печатается ВСЕГДА, в том числе при разрешающем ответе: молчаливое
    // «решил по другому файлу» — это ровно тот дефект, из-за которого путь стали
    // брать из конфигурации узла.
    if let Some(why) = &decision.fallback {
        eprintln!("hearth: ВНИМАНИЕ: конфигурация узла недоступна — {why}");
    }
    match decision.verdict {
        GateVerdict::Allow => std::process::ExitCode::SUCCESS,
        GateVerdict::Deny(reason) => {
            eprintln!("hearth: старт запрещён — {reason}");
            eprintln!("hearth: файл режима: {}", decision.file.display());
            // Строка про локальный выход обязательна: журнал systemd — единственное
            // место, куда человек смотрит, когда релеи не поднялись, а работающего
            // hearthd и админского сертификата у него в этот момент может не быть.
            eprintln!("hearth: {}", hearthd::model::mode::LOCAL_EXIT_HINT);
            std::process::ExitCode::from(1)
        }
    }
}

/// Аварийное снятие режима на самом узле: без admin API, без mTLS, без hearthd.
///
/// Единственный выход из запрета, исполнимый тогда, когда сломано всё остальное.
/// См. `ModeCommand::Clear` и docs/runbook-node-mode.md.
fn mode_clear_local(file: Option<&Path>, config: &Path) -> std::process::ExitCode {
    match clear_mode_locally(file, config) {
        Ok(path) => {
            println!("режим снят локально: {}", path.display());
            // Половина команды — сказать человеку, что произойдёт дальше. Без этого
            // она молча делала половину дела: диск снят, а живой демон об этом не
            // знает, и релеи «поднимаются и умирают».
            for line in what_happens_next(hearthd_is_running()) {
                println!("{line}");
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hearthctl: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Работает ли прямо сейчас hearthd.
///
/// `None` — спросить не у кого (нет systemctl, не unix, systemd не отвечает): тогда
/// печатаются оба случая, а не выдуманный один.
fn hearthd_is_running() -> Option<bool> {
    let out = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "hearthd"])
        .output()
        .ok()?;
    match out.status.code() {
        Some(0) => Some(true),
        // `is-active` отвечает 3 на «не запущен». Любой другой код — это уже не
        // ответ про службу (нет юнита, systemd не отвечает), и врать по нему нельзя.
        Some(3) => Some(false),
        _ => None,
    }
}

/// Что человек обязан сделать после локального снятия — в каждом из двух состояний.
///
/// Вынесено отдельно и проверяется тестом: текст здесь важнее кода. Ночью у узла
/// читают именно его, а не runbook.
fn what_happens_next(running: Option<bool>) -> Vec<String> {
    let alive = "hearthd работает: надзор перечитывает файл режима на каждом тике и \
                 поднимет релеи сам, в пределах check_interval_secs (по умолчанию 15 с). \
                 Перезапускать демон не нужно; если через минуту релеи не поднялись — \
                 systemctl restart hearthd."
        .to_string();
    let dead = "hearthd не работает: запустите службы вручную — \
                systemctl start smp-server xftp-server coturn hearthd."
        .to_string();
    match running {
        Some(true) => vec![alive],
        Some(false) => vec![dead],
        None => vec![
            "состояние hearthd определить не удалось (нет systemctl или он не \
             ответил) — верен один из двух случаев:"
                .to_string(),
            format!("  * {alive}"),
            format!("  * {dead}"),
        ],
    }
}

fn clear_mode_locally(file: Option<&Path>, config: &Path) -> Result<PathBuf> {
    if !running_as_root() {
        return Err(Error::Conflict(
            "локальное снятие режима требует root: sudo hearthctl mode clear --local".into(),
        ));
    }
    let resolved = hearthd::model::mode::resolve_mode_file(file, config);
    // Конфигурация сломана — и это как раз тот случай, ради которого команда
    // существует. Поэтому не отказ, а работа по пути по умолчанию (туда же смотрит и
    // гейт) плюс громкая строка о том, что путь взят не из конфигурации.
    if let Some(why) = resolved.fallback_reason() {
        eprintln!("hearthctl: ВНИМАНИЕ: конфигурация узла недоступна — {why}");
        eprintln!(
            "hearthctl: если paths.state_dir на этом узле нестандартный, укажите файл явно: \
             sudo hearthctl mode clear --local --file <state_dir>/{}",
            hearthd::model::mode::NODE_MODE_FILE_NAME
        );
    }
    let path = resolved.path().to_path_buf();
    // Root-овый КАТАЛОГ состояния — тот же владельческий тупик, только раньше и молча.
    // Наследование владельца берёт его у каталога; если root-овым стал сам каталог,
    // наследовать нечего: и node-mode.json, и журналы создаются root:root, команда
    // отчитывается успехом, а демон при следующем старте их не прочитает — и человек
    // видит уже не эту причину, а её последствие. Говорим здесь: он стоит у узла.
    if let Some(state_dir) = path.parent() {
        if let Some(complaint) = hearthd::store::root_owned_dir_complaint(state_dir) {
            eprintln!("hearthctl: ВНИМАНИЕ: {complaint}");
        }
    }
    // Прежний режим читаем «как получится»: файл мог быть и битым — снятие обязано
    // работать и по нему, иначе аварийный выход отказывает ровно в аварии.
    let before = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<hearthd::model::mode::NodeState>(&raw).ok());

    hearthd::model::mode::write_normal(&path)?;

    // Журнал — после записи и только как попытка: узел без связи хуже узла без записи
    // в журнале. Но сама запись обязана быть: карантин, снятый руками, не должен
    // выглядеть в разборе как исчезнувший сам собой.
    if let Some(state_dir) = path.parent() {
        let summary = match &before {
            Some(state) => format!("режим «{}» снят локально на узле", state.mode.label()),
            None => "режим снят локально на узле".to_string(),
        };
        let alert = hearthd::model::alert::Alert::warning("mode", summary)
            .with_details(serde_json::json!({
                "file": path.display().to_string(),
                "previous_mode": before.as_ref().map(|s| s.mode.label()),
                "previous_reason": before.as_ref().map(|s| s.reason.clone()),
                "how": "hearthctl mode clear --local",
            }))
            .sticky(true);
        match hearthd::alerts::record_offline(state_dir, alert) {
            // Запись удалась — но могла удаться «через силу»: нечитаемый прежний
            // журнал, root-овый каталог. У hearthctl нет ни journald, ни tracing, и
            // единственное место, где это увидят, — экран перед узлом.
            Ok(recorded) => {
                for complaint in recorded.complaints {
                    eprintln!("hearthctl: ВНИМАНИЕ: {complaint}");
                }
            }
            Err(e) => {
                eprintln!("hearthctl: режим снят, но запись в журнал алертов не удалась: {e}")
            }
        }
    }
    Ok(path)
}

/// Выполняется ли команда с правами root.
///
/// Эффективный uid берётся из `/proc/self/status` — без `unsafe` и без новой
/// зависимости (`libc` ради одного вызова `geteuid` в дерево не заводим; в hearthd
/// стоит `#![forbid(unsafe_code)]`, и разнобой здесь был бы хуже пользы).
///
/// Определить не удалось (нет `/proc`, не-Linux, сборка разработчика) — считаем, что
/// права есть, и идём дальше: узел семьи не должен оставаться без аварийного снятия
/// режима из-за того, что мы не смогли спросить про uid. Настоящего запрета это не
/// снимает — запись в `/var/lib/hearth` просто не удастся, и причина будет названа.
fn running_as_root() -> bool {
    hearthd::sys::effective_uid_is_root().unwrap_or(true)
}

/// Разобрать аргументы и заодно запомнить, откуда взялся путь к конфигурации.
///
/// `clap::Parser::parse` этого не сообщает, а гейту разница важна: см.
/// [`config_for_local_decision`].
fn parse_cli() -> (Cli, bool) {
    let matches = Cli::command().get_matches();
    let from_env = matches.value_source("config") == Some(clap::parser::ValueSource::EnvVariable);
    match Cli::from_arg_matches(&matches) {
        Ok(cli) => (cli, from_env),
        // clap сам печатает диагностику и выбирает код возврата.
        Err(e) => e.exit(),
    }
}

/// Путь к конфигурации для решений, принимаемых без демона: гейт и аварийное снятие.
///
/// `--config` уважаем, переменную окружения — нет. `ExecCondition` наследует окружение
/// юнита, поэтому `HEARTHD_CONFIG`, заданный в юните релея или в `/etc/default`, молча
/// увёл бы гейт на чужую конфигурацию, а значит — на чужой файл режима: снаружи это
/// выглядит как самостоятельно снявшийся карантин. Ровно тот же довод относится и к
/// `mode clear --local`: снимать режим надо там же, куда смотрит гейт, иначе команда
/// отработает успешно и не изменит ничего.
///
/// Возвращает путь и, если окружение пришлось проигнорировать, строку для журнала:
/// молчаливая подмена пути — это и есть дефект, от которого мы защищаемся.
fn config_for_local_decision(config: &Path, from_env: bool) -> (&Path, Option<String>) {
    if !from_env {
        return (config, None);
    }
    (
        Path::new(DEFAULT_CONFIG_PATH),
        Some(format!(
            "HEARTHD_CONFIG={} из окружения не учитывается: решение принимается по \
             {DEFAULT_CONFIG_PATH}. Нужен другой файл — передайте --config явно.",
            config.display()
        )),
    )
}

fn main() -> std::process::ExitCode {
    let (cli, config_from_env) = parse_cli();
    // До всего остального: см. `mode_gate`.
    if let Command::Mode(ModeCommand::Gate { file }) = &cli.command {
        let (config, ignored) = config_for_local_decision(&cli.config, config_from_env);
        if let Some(why) = ignored {
            eprintln!("hearth: ВНИМАНИЕ: {why}");
        }
        return mode_gate(file.as_deref(), config);
    }
    // Тоже до всего: аварийное снятие обязано работать на узле, где не поднимается ни
    // демон, ни рантайм, ни TLS. Ни одной зависимости, кроме файловой системы.
    if let Command::Mode(ModeCommand::Clear { local: true, file }) = &cli.command {
        let (config, ignored) = config_for_local_decision(&cli.config, config_from_env);
        if let Some(why) = ignored {
            eprintln!("hearthctl: ВНИМАНИЕ: {why}");
        }
        return mode_clear_local(file.as_deref(), config);
    }
    // Паспорт — тоже до всего: он обязан отвечать на машине без /etc/hearth и без
    // сети, иначе бесполезен там, где нужнее всего (копия файла у аудитора).
    if let Command::BuildInfo { json } = &cli.command {
        return match print_build_info(*json) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("hearthctl: {e}");
                std::process::ExitCode::FAILURE
            }
        };
    }
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
        Command::Mode(ModeCommand::Gate { file }) => {
            // Обычно сюда не попадаем: `main` отвечает на гейт раньше, ничего не
            // загружая. Ветка оставлена, чтобы ответ был одинаковым по любому пути.
            return match hearthd::model::mode::decide_gate(file.as_deref(), &cli.config).verdict {
                GateVerdict::Allow => Ok(()),
                GateVerdict::Deny(reason) => Err(Error::Conflict(reason)),
            };
        }
        Command::Mode(ModeCommand::Clear { local: true, file }) => {
            // Как и гейт: обычно перехвачено в `main`. Здесь — ради одинакового ответа.
            clear_mode_locally(file.as_deref(), &cli.config)?;
            return Ok(());
        }
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
        Command::Release(ReleaseCommand::Keygen { out, force }) => {
            let key_path = out.join("release-sign.key");
            let pub_path = out.join("release-sign.pub");
            if key_path.exists() && !force {
                return Err(Error::Conflict(format!(
                    "{} уже существует; --force перезапишет и сделает НЕПРОВЕРЯЕМЫМИ все \
                     сборки, в которые вшит прежний открытый ключ",
                    key_path.display()
                )));
            }
            hearthd::store::ensure_dir(out)?;
            let (private, public) = hearthd::release::generate()?;
            hearthd::store::write_secret(&key_path, &hearthd::release::encode_base64(&private))?;
            hearthd::store::write_atomic(
                &pub_path,
                hearthd::release::encode_base64(&public).as_bytes(),
                hearthd::store::MODE_STATE,
            )?;
            println!("ключ подписи манифестов выписан");
            println!("  закрытый: {} (0600)", key_path.display());
            println!("  открытый: {}", pub_path.display());
            println!();
            println!("Закрытый ключ НЕ копируйте на узел: захваченный узел не должен");
            println!("уметь подписать манифест. Открытый вшивается в сборку:");
            println!("  android/scripts/bake-node.sh <host> <port>");
            return Ok(());
        }
        Command::Release(ReleaseCommand::Sign {
            manifest,
            key,
            valid_for,
            expires,
        }) => {
            let raw = std::fs::read(manifest).map_err(|e| Error::io(manifest, e))?;
            let parsed = hearthd::model::update::UpdateManifest::parse(&raw)?;
            // Проверяем ДО подписи то же, что проверит телефон: подписанный манифест,
            // который клиент отвергнет, выясняется иначе только на раскатке — то есть
            // от семьи.
            parsed.validate()?;

            let now = chrono::Utc::now();
            let expiry = hearthd::model::update::resolve_expiry(
                now,
                valid_for.as_deref(),
                expires.as_deref(),
            )?;
            // Порядок важен: подписываются БАЙТЫ ФАЙЛА, поэтому сначала манифест
            // перезаписывается со сроком, и только потом подписывается — ровно то, что
            // легло на диск.
            let body = parsed.with_expiry(expiry).to_file_bytes()?;
            hearthd::store::write_atomic(manifest, &body, hearthd::store::MODE_STATE)?;

            let private = hearthd::release::load_key(key)?;
            let signature = hearthd::release::sign(&private, &body)?;
            let sig_path = manifest.with_extension(
                manifest
                    .extension()
                    .map(|e| format!("{}.sig", e.to_string_lossy()))
                    .unwrap_or_else(|| "sig".to_string()),
            );
            hearthd::store::write_atomic(
                &sig_path,
                hearthd::release::encode_base64(&signature).as_bytes(),
                hearthd::store::MODE_STATE,
            )?;
            println!("подписано: {}", sig_path.display());
            println!(
                "срок годности: до {} (через {} дн.)",
                hearthd::model::fmt_ts(expiry),
                (expiry - now).num_days()
            );
            println!("Положите рядом с манифестом в updates_dir — клиент качает оба файла.");
            // Обязанность оператора называется здесь, а не только в runbook: читать
            // будут этот вывод, а не документ.
            println!(
                "ПЕРЕПОДПИШИТЕ манифест до этой даты. Позже телефоны перестанут ставить \
                 обновления (переписка и звонки продолжат работать), а узел сделать это \
                 за вас не может: ключ лежит здесь."
            );
            return Ok(());
        }
        Command::Release(ReleaseCommand::Verify {
            manifest,
            sig,
            pubkey,
        }) => {
            let body = std::fs::read(manifest).map_err(|e| Error::io(manifest, e))?;
            let sig_path = sig.clone().unwrap_or_else(|| {
                manifest.with_extension(
                    manifest
                        .extension()
                        .map(|e| format!("{}.sig", e.to_string_lossy()))
                        .unwrap_or_else(|| "sig".to_string()),
                )
            });
            let sig_raw =
                std::fs::read_to_string(&sig_path).map_err(|e| Error::io(&sig_path, e))?;
            let signature = hearthd::release::decode_base64(sig_raw.trim())
                .ok_or_else(|| Error::invalid("подпись не является base64"))?;
            let public_raw = std::fs::read_to_string(pubkey).map_err(|e| Error::io(pubkey, e))?;
            let public = hearthd::release::decode_base64(public_raw.trim())
                .ok_or_else(|| Error::invalid("открытый ключ не является base64"))?;
            hearthd::release::verify(&public, &body, &signature)?;
            println!("подпись верна: {}", manifest.display());
            // Верная подпись — ещё не «манифест примут»: срок годности лежит ВНУТРИ
            // подписанного документа, и просроченный манифест телефон отвергнет, не
            // усомнившись в подписи. Печатаем то же, что увидит узел в статусе.
            let freshness = hearthd::model::update::updates_status(chrono::Utc::now(), Some(&body));
            println!("свежесть: {:?} — {}", freshness.state, freshness.note);
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
            commit,
            tree_sha256,
        }) => {
            let raw = std::fs::read_to_string(&config.paths.manifest)
                .map_err(|e| Error::io(&config.paths.manifest, e))?;
            let manifest: hearthd::model::manifest::Manifest = toml::from_str(&raw)?;
            let entry = manifest
                .binary(name)
                .ok_or_else(|| Error::NotFound(format!("manifest entry `{name}`")))?;
            let target = path.clone().unwrap_or_else(|| entry.path.clone());
            let digest = hearthd::model::manifest::sha256_file(&target)?;

            // Происхождение: сказанное руками важнее угаданного, поэтому `--commit`
            // проверяется первым. Для своих бинарников — спрашиваем у самого файла:
            // пересказ человеком того, что файл знает о себе сам, ничего не
            // доказывает и расходится при первой же спешке.
            let provenance = match (commit, tree_sha256) {
                (Some(commit), Some(tree)) => {
                    let stated = hearthd::model::manifest::EntryProvenance {
                        commit: commit.clone(),
                        tree_sha256: tree.clone(),
                    };
                    stated.validate()?;
                    Some(stated)
                }
                _ if speaks_build_info(name) => ask_for_provenance(&target),
                _ => None,
            };

            let updated = hearthd::model::manifest::pin(
                &raw,
                name,
                &digest,
                version.as_deref(),
                provenance.as_ref(),
            )?;
            // С сохранением владельца: pin запускают через sudo, а читает манифест
            // служба по группе hearth (см. store::write_atomic_keep_owner).
            hearthd::store::write_atomic_keep_owner(
                &config.paths.manifest,
                updated.as_bytes(),
                hearthd::store::MODE_STATE,
            )?;
            println!("pinned {name} = {digest}");
            println!("  measured: {}", target.display());
            println!("  manifest: {}", config.paths.manifest.display());
            match &provenance {
                Some(provenance) => {
                    println!("  commit:      {}", provenance.commit);
                    println!("  tree_sha256: {}", provenance.tree_sha256);
                }
                None if speaks_build_info(name) => {
                    println!();
                    println!("ПРОИСХОЖДЕНИЕ НЕ ЗАПИСАНО: файл не назвал свой коммит.");
                    println!("Манифест теперь доказывает «файл тот же, что запинен», но не");
                    println!("«запинен файл из коммита X». Соберите через");
                    println!("deploy/build-reproducible.sh и перепиньте.");
                }
                None => {}
            }
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
        Command::Mode(ModeCommand::Show) => {
            let mode: hearthd::model::mode::NodeState = api.get_json("/mode").await?;
            if cli.json {
                print_json(&mode)?;
            } else {
                println!("{}", mode.summary());
                for finding in &mode.findings {
                    println!("  {finding}");
                }
                if mode.mode != hearthd::model::mode::NodeMode::Normal {
                    println!();
                    println!("Релеи удерживаются остановленными. Разберитесь с причиной,");
                    println!("затем снимите режим: hearthctl mode clear");
                    println!(
                        "Если hearthd не поднимается — {}",
                        hearthd::model::mode::LOCAL_EXIT_HINT
                    );
                }
            }
        }
        Command::Mode(ModeCommand::Clear { local: false, .. }) => {
            // Сюда доходит только сетевое снятие: `--local` перехвачен в `main`.
            let mode: hearthd::model::mode::NodeState = api.post_json("/mode", None).await?;
            println!("{}", mode.summary());
            println!("Надзор снова поднимет релеи на ближайшем тике.");
        }
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
        Command::Egress {
            incidents,
            limit,
            acknowledge,
        } => {
            if acknowledge {
                let result: serde_json::Value = api.post_json("/egress/acknowledge", None).await?;
                match result.get("acknowledged").and_then(|v| v.as_str()) {
                    Some(since) => println!("инцидент от {since} подтверждён"),
                    None => println!("неподтверждённых инцидентов не было"),
                }
            } else if incidents {
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
        Command::Device(DeviceCommand::List { redacted }) => {
            let devices: Vec<Device> = api.get_json("/devices").await?;
            if cli.json {
                // Обезличивание — это ПРОЕКЦИЯ, а не вырезание поля постфактум: см.
                // `Device::public`. Секрет не покидает память hearthctl.
                if redacted {
                    let public: Vec<hearthd::model::device::DevicePublic> =
                        devices.iter().map(Device::public).collect();
                    print_json(&public)?;
                } else {
                    print_json(&devices)?;
                }
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
        Command::Invite(InviteCommand::Create {
            uses,
            days,
            note,
            write_token,
            count,
            write_codes,
        }) => {
            if !(1..=500).contains(&count) {
                return Err(Error::invalid("count must be between 1 and 500"));
            }
            let mut issued: Vec<Invite> = Vec::with_capacity(count as usize);
            for n in 0..count {
                // Пометка нумеруется, иначе полсотни одинаковых строк в `invite list`
                // не дают понять, какой код кому ушёл.
                let note = match (&note, count) {
                    (Some(note), 1) => Some(note.clone()),
                    (Some(note), _) => Some(format!("{note} #{}", n + 1)),
                    (None, _) => None,
                };
                let invite: Invite = api
                    .post_json(
                        "/invites",
                        Some(serde_json::json!({
                                "max_uses": uses,
                                "ttl_days": days,
                                "note": note,
                        })),
                    )
                    .await?;
                issued.push(invite);
            }

            let limits = format!(
                "{}, {}",
                match uses {
                    0 => "без ограничения по числу устройств".to_string(),
                    n => format!("до {n} устройств на код"),
                },
                match issued[0].expires {
                    Some(expires) => format!("до {}", expires.format("%Y-%m-%d %H:%M UTC")),
                    None => "бессрочно".to_string(),
                }
            );
            println!("выписано кодов: {} — {}", issued.len(), limits);

            if let Some(path) = &write_codes {
                let mut list = String::new();
                list.push_str(
                    "Коды доступа Hearth — выдавать лично, по одному человеку на код.
",
                );
                list.push_str(&format!(
                    "Выписано {}. Ограничения: {}.

",
                    Utc::now().format("%Y-%m-%d %H:%M UTC"),
                    limits
                ));
                for (n, invite) in issued.iter().enumerate() {
                    list.push_str(&format!(
                        "{:>3}. {}   id {}   кому: ______________________
",
                        n + 1,
                        hearthd::model::code::format_groups(&invite.token),
                        invite.id
                    ));
                }
                list.push_str(
                    "
Отозвать один код: hearthctl invite revoke <id>
",
                );
                list.push_str(
                    "Кто заведён по коду — hearthctl invite list.
",
                );
                hearthd::store::write_secret(path, &list)?;
                println!("список записан в {} (0600)", path.display());
            } else if let Some(path) = &write_token {
                hearthd::store::write_secret(path, &issued[0].token)?;
                println!("токен записан в {} (0600)", path.display());
            } else {
                println!();
                println!("коды (видны один раз):");
                for invite in &issued {
                    println!(
                        "  {}   id {}",
                        hearthd::model::code::format_groups(&invite.token),
                        invite.id
                    );
                }
            }
            println!();
            println!("Код впускает в контур: по нему заводится устройство и получает");
            println!("адреса релеев. Переписки это не открывает — она зашифрована от");
            println!("устройства до устройства, узел её не читает.");
            println!("Если код ушёл не туда — `hearthctl invite revoke <id>`.");
            println!("Уже заведённые по нему устройства отзыв не трогает.");
        }
        Command::AuditToken(AuditTokenCommand::Issue {
            ttl_hours,
            max_uses,
            scope,
            note,
            write_token,
        }) => {
            // Область разбирается ЗДЕСЬ, до обращения к узлу: опечатка в `--scope`
            // должна стоить сообщения об ошибке, а не выписанного токена с не той
            // областью.
            let parsed = hearthd::model::audit_token::AuditScope::parse(&scope)?;
            let token: hearthd::model::audit_token::AuditToken = api
                .post_json(
                    "/audit-tokens",
                    Some(serde_json::json!({
                        "ttl_hours": ttl_hours,
                        "max_uses": max_uses,
                        "scope": scope,
                        "note": note,
                    })),
                )
                .await?;

            println!("выписан аудиторский токен {}", token.id);
            println!("  действует до: {}", hearthd::model::fmt_ts(token.expires));
            println!("  обращений:    не больше {}", token.max_uses);
            println!(
                "  область:      {}",
                parsed
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            match write_token {
                Some(path) => {
                    hearthd::store::write_secret(&path, &token.token)?;
                    println!("  секрет:       {} (0600)", path.display());
                }
                None => {
                    println!("  секрет:       {}", token.token);
                }
            }
            println!();
            println!("Проверяющий предъявляет его заголовком:");
            println!("  curl -H 'x-hearth-audit-token: <секрет>' \\");
            println!("       https://<узел>:<порт device api>/updates/manifest.json");
            println!();
            println!("Токен не открывает ни /turn-credentials, ни стикеры, ни реестр");
            println!("устройств, слот семьи не занимает и bundle не выпускает.");
            println!(
                "Отозвать досрочно: hearthctl audit-token revoke {}",
                token.id
            );
        }
        Command::AuditToken(AuditTokenCommand::List) => {
            let tokens: Vec<hearthd::model::audit_token::AuditTokenPublic> =
                api.get_json("/audit-tokens").await?;
            if cli.json {
                print_json(&tokens)?;
            } else {
                if tokens.is_empty() {
                    println!("аудиторских токенов нет");
                }
                for token in tokens {
                    println!(
                        "{:<18} {:<10} {:<22} {:<22} {}",
                        token.id,
                        token.state,
                        format!("{}/{} обращений", token.uses, token.max_uses),
                        hearthd::model::fmt_ts(token.expires),
                        token.note.as_deref().unwrap_or("")
                    );
                    println!(
                        "    область: {}",
                        token
                            .scope
                            .iter()
                            .map(|s| s.label())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
        }
        Command::AuditToken(AuditTokenCommand::Revoke { id }) => {
            let token: hearthd::model::audit_token::AuditTokenPublic = api
                .post_json(&format!("/audit-tokens/{id}/revoke"), None)
                .await?;
            println!("аудиторский токен {} отозван", token.id);
            println!("Отзыв действует немедленно: реестр проверяется на каждом запросе.");
        }
        Command::Invite(InviteCommand::List) => {
            let invites: Vec<Invite> = api.get_json("/invites").await?;
            if invites.is_empty() {
                println!("приглашений нет");
            }
            let now = Utc::now();
            for invite in invites {
                println!(
                    "{:<18} {:<10} {:<22} {:<12} {}",
                    invite.id,
                    invite.state_at(now),
                    if invite.max_uses == 0 {
                        format!("{} заведено", invite.uses)
                    } else {
                        format!("{}/{} использований", invite.uses, invite.max_uses)
                    },
                    match invite.expires {
                        Some(expires) => expires.format("до %Y-%m-%d").to_string(),
                        None => "бессрочно".to_string(),
                    },
                    invite.note.as_deref().unwrap_or("")
                );
                if !invite.claimed.is_empty() {
                    println!("    завело: {}", invite.claimed.join(", "));
                }
            }
        }
        Command::Invite(InviteCommand::Revoke { id }) => {
            let invite: Invite = api
                .post_json(&format!("/invites/{id}/revoke"), None)
                .await?;
            println!("приглашение `{}` погашено", invite.id);
            if !invite.claimed.is_empty() {
                println!(
                    "по нему уже завелись: {} — они продолжают работать,",
                    invite.claimed.join(", ")
                );
                println!("отзывать их надо отдельно: `hearthctl device revoke <id>`");
            }
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
            if !info.members.is_empty() {
                // Что вошло — такая же часть контракта, как и что не вошло: «архив
                // сделан» не отвечает на вопрос «архив чего».
                println!("\nВ архив вошли ({}):", info.members.len());
                for member in &info.members {
                    println!("  {member}");
                }
            }
            if !info.missing.is_empty() {
                println!(
                    "\nНЕТ НА ДИСКЕ — источник настроен, но отсутствует ({}):",
                    info.missing.len()
                );
                for path in &info.missing {
                    println!("  {path}");
                }
            }
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
        Command::BuildInfo { .. }
        | Command::Mode(ModeCommand::Gate { .. })
        | Command::Mode(ModeCommand::Clear { local: true, .. })
        | Command::Backup(_)
        | Command::Migrate(_)
        | Command::Manifest(_)
        | Command::Release(_) => {}
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

/// Паспорт сборки самого hearthctl.
///
/// Тот же формат и тот же состав полей, что у `hearthd build-info`: аудитор сверяет
/// два установленных файла одной и той же командой.
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
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| Error::Parse(e.to_string()))?
        );
    } else {
        print!("{}", info.to_key_values());
        println!("exe_sha256={exe_sha256}");
    }
    Ok(())
}

fn print_health(health: &HealthSnapshot) {
    println!(
        "{} ({})  state={:?}  uptime={}s  hearthd {}",
        health.node, health.address, health.state, health.uptime_secs, health.version
    );
    // Паспорт РАБОТАЮЩЕГО процесса. Пустые поля означают «демон старой версии их не
    // сообщил» — говорим об этом прямо, а не печатаем пустоту, которую легко принять
    // за ответ.
    println!(
        "  commit={}  tree_sha256={}",
        or_unreported(&health.commit),
        or_unreported(&health.tree_sha256)
    );
    println!(
        "  exe_sha256={}   (sha256sum /usr/local/bin/hearthd обязан совпасть)",
        or_unreported(&health.self_sha256)
    );
    // Почему общий state бывает хуже, чем у всех служб: вердикт по резервной копии
    // входит в него слагаемым. Здесь печатается ПОЛНЫЙ вердикт (в общий он входит не
    // выше Degraded — связь работает, будить дежурного нечем), поэтому строка
    // `backup=Down` при `state=Degraded` — не ошибка, а разделение «нет запаса
    // прочности» и «нет связи».
    println!(
        "  backup={:?}   (подробности: hearthctl backup status)",
        health.backup
    );
    // Вторая причина, по которой общий state бывает хуже, чем у всех служб. Здесь
    // печатается полный вердикт (в общий он входит не выше Degraded), поэтому строка
    // `updates=Down` при `state=Degraded` — не ошибка, а разделение «семья без
    // обновлений» и «семья без связи».
    println!(
        "  updates={:?}   (подробности ниже: срок годности манифеста обновлений)",
        health.updates
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

/// «Не сообщено» вместо пустой строки: пустое место в отчёте читается как ответ.
fn or_unreported(value: &str) -> &str {
    if value.is_empty() {
        "не сообщено (демон старой версии)"
    } else {
        value
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
    if !egress.missing_counters.is_empty() {
        println!(
            "  НЕТ В RULESET: {} — показания по ним отсутствуют, а не равны нулю",
            egress.missing_counters.join("  ")
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
    // Режим печатается первым: если релеи остановлены, это главное, что человек
    // должен узнать, а не двадцатая строка под списком служб.
    println!("{}", status.mode.summary());
    if !status.mode.findings.is_empty() {
        for finding in &status.mode.findings {
            println!("  {finding}");
        }
    }
    if status.mode.mode != hearthd::model::mode::NodeMode::Normal {
        println!("  снять: hearthctl mode clear");
        // Второй путь называется здесь же: если демон перестанет отвечать, эта строка
        // уже прочитана человеком, и искать её будет негде.
        println!("  если hearthd не поднимается: hearthctl mode clear --local (root, на узле)");
    }
    println!();
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
        "backup: state={:?}  last success={}  archives={}",
        status.backup.state,
        status
            .backup
            .last_success
            .map(hearthd::model::fmt_ts)
            .unwrap_or_else(|| "never".into()),
        status.backup.archives_kept
    );
    println!(
        "  внешняя копия: {}",
        if !status.backup.remote_configured {
            "не настроена ([backup.remote] отсутствует)".to_string()
        } else if status.backup.remote_ok {
            "подтверждена".to_string()
        } else {
            "НЕ ПОДТВЕРЖДЕНА — архив есть только на самом узле".to_string()
        }
    );
    // Чем подтверждена или почему нет: «не доехало», «доехало испорченным» и «приёмник
    // не отвечает на sha256sum» требуют разных действий, а выглядели одинаково.
    if let Some(note) = &status.backup.remote_note {
        println!("    {note}");
    }
    if !status.backup.members.is_empty() {
        println!("  В архив вошли ({}):", status.backup.members.len());
        for member in &status.backup.members {
            println!("    {member}");
        }
    }
    if !status.backup.missing.is_empty() {
        // Источник настроен и отсутствует — это не «пропустили каталог», это дыра
        // ровно в том размере, в каком её не видно при обычном взгляде на статус.
        println!("  НЕТ НА ДИСКЕ ({}):", status.backup.missing.len());
        for path in &status.backup.missing {
            // Обязательный источник и необязательный — разные факты, и раньше список
            // был общий. Каталоги push-сервера на узле без push отсутствуют законно;
            // отсутствие /var/opt/simplex означает архив без переписки.
            if status.backup.missing_required.contains(path) {
                println!("    {path}   ← ОБЯЗАТЕЛЬНЫЙ: прогон провален");
            } else {
                println!("    {path}   (не обязателен: вердикта не меняет)");
            }
        }
    }
    if !status.backup.unreadable.is_empty() {
        // Неполный архив — не успех. Ключ admin CA недоступен демону намеренно, и
        // оператор обязан знать, что хранит его отдельно, а не полагаться на копию.
        println!("  В архив НЕ попали ({}):", status.backup.unreadable.len());
        for path in &status.backup.unreadable {
            println!("    {path}");
        }
    }
    if let Some(error) = &status.backup.last_error {
        println!("  last error: {error}");
    }
    println!();
    // Обновления печатаются отдельным блоком, а не строкой в health: оператор должен
    // увидеть не только вердикт, но и ЧТО ДЕЛАТЬ, — переподписать манифест может
    // только он, и только на рабочей станции.
    println!(
        "updates: state={:?}  версия={}  срок={}",
        status.updates.state,
        status
            .updates
            .version_name
            .as_deref()
            .unwrap_or("не опубликована"),
        match status.updates.expires {
            Some(expires) => hearthd::model::fmt_ts(expires),
            None if status.updates.published => "не назначен (манифест прежнего образца)".into(),
            None => "-".into(),
        }
    );
    println!("  {}", status.updates.note);
    if status.updates.state != hearthd::model::health::HealthState::Ok {
        println!("  переподписывают НА РАБОЧЕЙ СТАНЦИИ (ключа на узле нет):");
        println!("    hearthctl release sign manifest.json --key <ключ> --valid-for 30d");
        println!("    и выложить manifest.json и manifest.json.sig в updates_dir");
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
    use super::what_happens_next;

    /// Исходник этого файла — для тестов о ВЫБОРЕ, а не о поведении.
    const THIS_FILE: &str = include_str!("hearthctl.rs");

    /// Тело функции по её имени: от сигнатуры до закрывающей скобки первого уровня.
    fn body_of(name: &str) -> &'static str {
        let after = THIS_FILE
            .split_once(name)
            .unwrap_or_else(|| panic!("{name} на месте"))
            .1;
        after
            .split_once("\n}")
            .unwrap_or_else(|| panic!("тело {name}"))
            .0
    }

    #[test]
    fn a_local_clear_names_a_root_owned_state_dir() {
        // Дефект: наследование владельца берётся у каталога состояния, и если
        // root-овым стал сам каталог, команда печатала успех, создавала root:root-файл
        // — а демон при следующем старте снова не мог его прочитать. Исходный дефект
        // воспроизводился молча. Поведенчески различить владельцев можно только на
        // unix и только под двумя пользователями, поэтому проверяется ВЫБОР.
        let body = body_of("fn clear_mode_locally(");
        assert!(
            body.contains("root_owned_dir_complaint"),
            "команда обязана спросить про владельца каталога состояния: {body}"
        );
        assert!(
            body.contains("ВНИМАНИЕ"),
            "беда обязана быть видна человеку, а не только в коде: {body}"
        );
        // И жалобы самой записи в журнал — тоже на экран: journald у hearthctl нет.
        assert!(
            body.contains("recorded.complaints"),
            "жалобы записи обязаны дойти до человека: {body}"
        );
    }

    #[test]
    fn a_local_clear_tells_the_operator_what_happens_next() {
        // Дефект 13/18: команда молча делала половину дела — диск снят, живой демон об
        // этом не знает. Человек видел релеи, которые «поднимаются и умирают».
        let alive = what_happens_next(Some(true)).join("\n");
        assert!(alive.contains("hearthd работает"), "{alive}");
        assert!(alive.contains("Перезапускать демон не нужно"), "{alive}");
        assert!(alive.contains("надзор"), "{alive}");

        let dead = what_happens_next(Some(false)).join("\n");
        assert!(dead.contains("hearthd не работает"), "{dead}");
        assert!(dead.contains("systemctl start"), "{dead}");

        // Спросить не у кого — печатаем оба случая, а не выдуманный один.
        let unknown = what_happens_next(None).join("\n");
        assert!(unknown.contains("hearthd работает"), "{unknown}");
        assert!(unknown.contains("hearthd не работает"), "{unknown}");
    }

    use super::config_for_local_decision;
    use std::path::Path;

    #[test]
    fn the_gate_ignores_the_config_path_that_came_from_the_environment() {
        // Дефект 4: ExecCondition наследует окружение юнита, и HEARTHD_CONFIG,
        // заданный в юните релея или в /etc/default, увёл бы гейт на чужую
        // конфигурацию — а значит, на чужой файл режима.
        let (path, warning) = config_for_local_decision(Path::new("/tmp/чужой.toml"), true);
        assert_eq!(path, Path::new(hearthd::DEFAULT_CONFIG_PATH));
        let warning = warning.expect("подмену обязаны назвать вслух");
        assert!(warning.contains("HEARTHD_CONFIG"), "{warning}");
        assert!(warning.contains("--config"), "{warning}");

        // Явный --config — решение человека у железа, и оно уважается молча.
        let (path, warning) = config_for_local_decision(Path::new("/tmp/явный.toml"), false);
        assert_eq!(path, Path::new("/tmp/явный.toml"));
        assert!(warning.is_none());
    }

    /// Окружение отличается от `--config` только источником значения, и разбор обязан
    /// это сообщать. Проверяется на настоящем разборщике, а не на вере в clap.
    #[test]
    fn clap_tells_an_explicit_flag_from_an_inherited_variable() {
        use clap::parser::ValueSource;
        use clap::CommandFactory as _;

        let matches = super::Cli::command().get_matches_from([
            "hearthctl",
            "--config",
            "/tmp/явный.toml",
            "mode",
            "gate",
        ]);
        assert_eq!(
            matches.value_source("config"),
            Some(ValueSource::CommandLine)
        );

        // Переменная, выставленная тому, кто запустил тесты, — не предмет проверки.
        if std::env::var_os("HEARTHD_CONFIG").is_none() {
            let matches = super::Cli::command().get_matches_from(["hearthctl", "mode", "gate"]);
            assert_eq!(
                matches.value_source("config"),
                Some(ValueSource::DefaultValue),
                "без флага и без переменной — умолчание"
            );
        }
    }

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
