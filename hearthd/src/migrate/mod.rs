//! Node migration (ТЗ §10.2): move the node from the ПК to the mini-PC without the
//! relay address changing, so no client has to do anything.
//!
//! What actually migrates is the *identity* of the node: the relay CA and its private
//! key, the queue-creation passwords, the store log, and the hearth state. The address
//! `smp://<fp>:<pass>@10.66.10.10:5223` is built from exactly those, which is why
//! moving them (and the port forwarding) is enough — ТЗ §2.5.
//!
//! Export refuses to leave the relays running: two nodes answering on one CA with one
//! address would be a split brain that clients cannot detect. The old node stays down
//! (ТЗ §10.2 п.5).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::backup::archive::{self, ArchiveInfo};
use crate::error::{Error, Result};
use crate::model::alert::Alert;
use crate::state::AppState;
use crate::store;
use crate::sys::systemd;

/// Result of `hearthctl migrate export`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportReport {
    pub archive: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub members: Vec<String>,
    pub relays_stopped: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copied_to: Option<String>,
    /// Reminders the operator must not skip.
    pub next_steps: Vec<String>,
}

/// Result of `hearthctl migrate import`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub restored: Vec<PathBuf>,
    pub destination: PathBuf,
    pub integrity_ok: bool,
    pub integrity_notes: Vec<String>,
    pub next_steps: Vec<String>,
}

/// Причина режима на время импорта. Одна строка на обе точки, где она ставится.
const IMPORT_REASON: &str = "перенос узла: идёт импорт архива на этот узел";

/// Stop the relays and produce the final encrypted archive (ТЗ §10.2 п.3).
///
/// Запрет ставится ПЕРВЫМ действием, до единой команды `systemctl stop`. Раньше он
/// стоял в конце, рядом с записью статуса, и всё время шифрования архива и rsync —
/// на живом узле это минуты и десятки минут — режим оставался `normal`. Надзор с его
/// пятнадцатисекундным тиком видел молчащий порт и поднимал релей обратно: store log
/// менялся прямо во время чтения архиватором, а отчёт рапортовал об остановке,
/// которой уже не было.
///
/// Fail-closed на всех путях: если режим не записался, экспорт не начинается вовсе и
/// ничего не остановлено; если оборвался любой следующий шаг, режим НЕ снимается —
/// релеи остаются стоять, пока человек не разберётся и не выполнит
/// `hearthctl mode clear`.
pub async fn export(state: &Arc<AppState>) -> Result<ExportReport> {
    state
        .set_mode(
            crate::model::mode::NodeMode::Migration,
            "перенос узла: начат `hearthctl migrate export`",
            Vec::new(),
        )
        .await?;

    match export_held(state).await {
        Ok(report) => Ok(report),
        Err(e) => {
            state
                .alerts
                .emit(
                    Alert::critical(
                        "migrate",
                        format!(
                            "экспорт переноса прерван: {e}. Узел остался в режиме переноса, \
                             релеи не поднимутся сами — разберитесь и снимите режим: \
                             hearthctl mode clear"
                        ),
                    )
                    .sticky(true),
                )
                .await;
            Err(e)
        }
    }
}

/// Сам экспорт. Вызывается только после того, как узел уже удержан.
async fn export_held(state: &Arc<AppState>) -> Result<ExportReport> {
    let config = state.config.clone();
    let started = Utc::now();

    // 1. Stop the relays: the store log must not change while it is being copied.
    let mut stopped = Vec::new();
    for relay in config.relays() {
        if !relay.enabled {
            continue;
        }
        systemd::stop(&state.sys, &relay.unit).await?;
        stopped.push(relay.unit.clone());
    }
    if config.turn.enabled {
        systemd::stop(&state.sys, &config.turn.unit).await?;
        stopped.push(config.turn.unit.clone());
    }

    // 2. Archive the three ТЗ §10.1 directories plus hearth state.
    store::ensure_dir(&config.backup.spool_dir)?;
    let name = format!(
        "hearth-migrate-{}-{}.tar.gz.age",
        config.node.name,
        started.format("%Y%m%dT%H%M%SZ")
    );
    let output = config.backup.spool_dir.join(name);
    let info: ArchiveInfo =
        archive::create_encrypted(&config.backup.paths, &output, &config.backup.recipients)?;

    // 3. Push it to hearth-backup (ТЗ §10.2 п.3). The archive must not live only on a
    //    machine that is about to be wiped — but a failed copy does not invalidate a
    //    good archive, so this is a warning, not an error.
    let copied_to = match crate::backup::BackupJob::new(state.clone())
        .sync_remote()
        .await
    {
        Ok(destination) => destination,
        Err(e) => {
            state
                .alerts
                .emit(Alert::warning(
                    "migrate",
                    format!("export archive was not copied to hearth-backup: {e}"),
                ))
                .await;
            None
        }
    };

    {
        let mut status = state.migrate.write().await;
        status.exported_at = Some(started);
        status.archive = Some(info.path.clone());
        status.sha256 = Some(info.sha256.clone());
        status.size_bytes = info.size_bytes;
        status.relays_stopped = true;
        status.copied_to = copied_to.clone();
    }
    state.save_migrate_status().await?;

    state
        .alerts
        .emit(
            Alert::warning(
                "migrate",
                "migration export complete; the relays are stopped and must stay stopped",
            )
            .with_details(serde_json::json!({
                "archive": info.path.display().to_string(),
                "sha256": info.sha256,
            }))
            .sticky(true),
        )
        .await;

    Ok(ExportReport {
        archive: info.path,
        sha256: info.sha256,
        size_bytes: info.size_bytes,
        members: info.members,
        relays_stopped: stopped,
        copied_to,
        next_steps: next_steps_after_export(&config),
    })
}

/// Everything the router has to forward to this node, as one readable list.
///
/// Built from the configuration rather than written out: the hard-coded list here had
/// already lost 8443 and 7444, and a move that forgets a port looks like a broken phone,
/// not a broken router.
fn forwarded_ports(config: &crate::config::Config) -> String {
    let mut tcp: Vec<u16> = config
        .relays()
        .into_iter()
        .filter(|relay| relay.enabled)
        .flat_map(|relay| relay.all_ports())
        .collect();
    if config.device_api.enabled {
        tcp.push(config.device_api.public_port);
    }
    tcp.sort_unstable();
    tcp.dedup();
    let mut parts: Vec<String> = tcp.iter().map(|port| format!("{port}/tcp")).collect();
    if config.turn.enabled {
        parts.push(format!("{}/udp+tcp", config.turn.port));
        parts.push(format!(
            "{}-{}/udp",
            config.turn.relay_min_port, config.turn.relay_max_port
        ));
    }
    parts.join(", ")
}

/// Steps the operator still owns after an export — printed by `hearthctl`, so they
/// cannot be forgotten halfway through an evening's move.
fn next_steps_after_export(config: &crate::config::Config) -> Vec<String> {
    let mut steps = vec![
        format!(
            "Point the router's port forwarding for {} ({}) at the mini-PC — while the \
             old node is still running.",
            config.node.host,
            forwarded_ports(config)
        ),
        "Copy the archive to the mini-PC (hearth-backup or a USB stick).".into(),
    ];
    if config.ntf.as_ref().is_some_and(|ntf| ntf.enabled) {
        // Каталоги push-сервера в архиве, его база — нет: это PostgreSQL, а ночной дамп
        // устарел ровно на время с последней ночи. Сейчас ntf-server уже остановлен,
        // и свежий дамп будет согласованным.
        steps.push(
            "ntf-server keeps device tokens in PostgreSQL, which this archive does not \
             contain: take a fresh dump now and restore it on the mini-PC \
             (docs/runbook-ntf.md, «Перенос узла»). The APNs key in /etc/credstore is \
             not archived either — bring it from its offline copy."
                .into(),
        );
    }
    steps.push("On the mini-PC: hearthctl migrate import <archive> --identity <age key>.".into());
    steps.push("Verify the sha256 printed above on the destination before importing.".into());
    steps.push(
        "Do NOT start the relays on this machine again: two nodes with one CA and one \
         address is a split brain (ТЗ §10.2 п.5)."
            .into(),
    );
    // Почему `systemctl start` здесь теперь ничего не поднимает — иначе это выглядит
    // как поломка узла, а не как работающий запрет.
    steps.push(
        "Узел остаётся в режиме переноса: релеи не поднимутся ни надзором, ни после \
         перезагрузки, ни по `systemctl start` (гейт режима пометит юнит пропущенным). \
         Снимается только вручную: hearthctl mode clear."
            .into(),
    );
    steps.push(
        "After the new node is verified: cryptsetup luksErase (or destroy) this disk \
         (ТЗ §10.2 п.7)."
            .into(),
    );
    steps
}

/// Restore an exported archive onto this machine (ТЗ §10.2 п.4).
///
/// `destination` is `/` on a real migration; tests and rehearsals (A13) pass a
/// scratch directory.
pub async fn import(
    state: &Arc<AppState>,
    archive_path: &Path,
    identity_file: &Path,
    destination: &Path,
    expected_sha256: Option<&str>,
) -> Result<ImportReport> {
    if let Some(expected) = expected_sha256 {
        let actual = crate::model::manifest::sha256_file(archive_path)?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(Error::Integrity(format!(
                "archive sha256 mismatch: expected {expected}, got {actual}"
            )));
        }
    }

    let live = is_live_import(destination);
    if live {
        hold_for_import(state).await?;
    }

    let restored = archive::decrypt_and_extract(archive_path, identity_file, destination)?;

    if live {
        // В архиве лежит node-mode.json ЧУЖОГО узла — state_dir целиком входит в
        // backup.paths, — и распаковка только что затёрла им наш. Режим узла это
        // свойство ЭТОЙ машины и этого переноса, а не переносимая часть личности:
        // иначе новый узел стартует с чужой причиной в `hearthctl status`, а при
        // экспорте из карантина — ещё и с чужим карантином.
        state
            .set_mode(
                crate::model::mode::NodeMode::Migration,
                IMPORT_REASON,
                Vec::new(),
            )
            .await?;
    }

    // Verify the binaries on THIS machine against the manifest that just arrived
    // (ТЗ §10.2 п.4: "проверка sha256 бинарей").
    let manifest_path = if destination == Path::new("/") {
        state.config.paths.manifest.clone()
    } else {
        destination.join(relative(&state.config.paths.manifest))
    };
    let (integrity_ok, integrity_notes) = verify_binaries(&manifest_path);

    {
        let mut status = state.migrate.write().await;
        status.imported_at = Some(Utc::now());
        status.archive = Some(archive_path.to_path_buf());
    }
    state.save_migrate_status().await?;

    // Службы — из конфигурации, а не списком в тексте: иначе узел с push-сервером
    // переезжал бы без него. Архив проверяется тоже — конфиг этого узла мог ещё не знать
    // про [ntf], а в архиве его каталоги уже есть.
    let config = &state.config;
    let archived_ntf = restored
        .iter()
        .any(|path| path.to_string_lossy().contains("simplex-ntf"));
    let ntf = archived_ntf || config.ntf.as_ref().is_some_and(|ntf| ntf.enabled);
    let mut units: Vec<&str> = config
        .relays()
        .into_iter()
        .filter(|relay| relay.enabled)
        .map(|relay| relay.unit.trim_end_matches(".service"))
        .collect();
    if ntf && !units.contains(&"ntf-server") {
        units.push("ntf-server");
    }
    if config.turn.enabled {
        units.push(config.turn.unit.trim_end_matches(".service"));
    }
    let mut next_steps =
        vec!["Load the nftables ruleset: nft -f /etc/hearth/nftables/hearth.nft".to_string()];
    if ntf {
        next_steps.push(
            "Before starting ntf-server: create its PostgreSQL role and database, restore \
             the dump and put the APNs key back into /etc/credstore \
             (docs/runbook-ntf.md, «Перенос узла»). Do NOT run init-ntf.sh: a new \
             fingerprint breaks push in every installed iOS build."
                .into(),
        );
    }
    // Снятие режима — отдельным шагом ПЕРЕД стартом служб: узел удерживается в
    // переносе намеренно, и без этой строки оператор увидит юниты, которые «стартуют
    // и молчат» (гейт помечает их пропущенными), без единой подсказки почему.
    //
    // Именно ЛОКАЛЬНОЕ снятие. Сетевое (`hearthctl mode clear`) идёт в admin API
    // работающего hearthd, а на этом шаге его заведомо нет: импорт сам отказывается
    // идти при живом демоне, и запускают его только следующей строкой. Раньше здесь
    // стояла сетевая команда — обязательный шаг, который оператор физически не мог
    // выполнить, и получал ошибку соединения посреди переезда.
    next_steps.push(
        "sudo hearthctl mode clear --local — узел удерживается в режиме переноса, \
         пока вы не убедились, что старый выключен и проброс портов переключён. \
         Снимается на самом узле: hearthd ещё не запущен, admin API отвечать некому"
            .into(),
    );
    next_steps.push(format!(
        "systemctl enable --now {} hearthd",
        units.join(" ")
    ));
    next_steps.push("hearthctl health — every service must be ok".into());
    next_steps.push(
        "Send one message from a phone; the client must not notice anything \
         (ТЗ §10.2 п.6)."
            .into(),
    );
    next_steps
        .push("Confirm the old node is powered off and will not come back with these keys.".into());

    Ok(ImportReport {
        restored,
        destination: destination.to_path_buf(),
        integrity_ok,
        integrity_notes,
        next_steps,
    })
}

/// Импорт на ЭТОТ узел, а не репетиция в отдельный каталог (A13).
///
/// Отличие принципиальное. Живой импорт заменяет каталоги работающего узла — перед
/// ним узел обязан быть удержан, а после распаковки удержан повторно. Репетиция не
/// трогает ни одну работающую службу и не должна ни останавливать релеи, ни менять
/// режим рабочего узла: раньше она делала и то и другое.
fn is_live_import(destination: &Path) -> bool {
    destination == Path::new("/")
}

/// Удержать узел на время импорта.
///
/// Порядок обязателен: сначала запрет, потом остановка. Если режим не записался,
/// импорт не начинается и ничего не остановлено — противоречивого состояния нет.
async fn hold_for_import(state: &Arc<AppState>) -> Result<()> {
    refuse_if_the_daemon_is_running(state).await?;
    state
        .set_mode(
            crate::model::mode::NodeMode::Migration,
            IMPORT_REASON,
            Vec::new(),
        )
        .await?;

    // Relays must not be running while their state directory is replaced.
    for relay in state.config.relays() {
        if relay.enabled {
            systemd::stop(&state.sys, &relay.unit).await?;
        }
    }
    // TURN — тоже часть контура режима (ADR 0013): на узле, который прямо сейчас
    // принимает чужое состояние, не должно остаться ни одной службы, отвечающей
    // семье. `export` останавливает его по тем же причинам.
    if state.config.turn.enabled {
        systemd::stop(&state.sys, &state.config.turn.unit).await?;
    }
    Ok(())
}

/// Отказаться импортировать при живом hearthd.
///
/// `migrate import` идёт отдельным процессом со своим `AppState`, а работающий демон
/// держит свою копию режима в памяти и читает файл только при старте (state.rs). Наша
/// запись режима до него не дойдёт, и его надзор поднимет релей прямо во время
/// распаковки его каталога. Проверяем самое простое, что нельзя перепутать: отвечает
/// ли admin API. Fail-closed — если по адресу кто-то есть, импорт не начинается.
async fn refuse_if_the_daemon_is_running(state: &Arc<AppState>) -> Result<()> {
    let addr = state.config.api.listen;
    let probe = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(addr),
    )
    .await;
    if matches!(probe, Ok(Ok(_))) {
        return Err(Error::Conflict(format!(
            "admin API отвечает на {addr}: hearthd работает. Импорт заменяет каталоги \
             релеев под работающим демоном — остановите его и повторите: \
             systemctl stop hearthd"
        )));
    }
    Ok(())
}

/// Hash the manifest's binaries on this machine.
fn verify_binaries(manifest_path: &Path) -> (bool, Vec<String>) {
    match crate::model::manifest::Manifest::load(manifest_path) {
        Ok(manifest) => {
            let findings = manifest.verify_all();
            let notes: Vec<String> = findings
                .iter()
                .map(|f| format!("{}: {:?}", f.name, f.status))
                .collect();
            let ok = findings
                .iter()
                .all(|f| f.status == crate::model::manifest::IntegrityStatus::Ok);
            (ok, notes)
        }
        Err(e) => (
            false,
            vec![format!(
                "cannot read the imported manifest {}: {e}",
                manifest_path.display()
            )],
        ),
    }
}

/// `/etc/hearth/manifest.toml` -> `etc/hearth/manifest.toml`, for rehearsals that
/// extract into a scratch directory rather than onto `/`.
fn relative(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        if let std::path::Component::Normal(part) = component {
            out.push(part);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Sys;
    use age::secrecy::ExposeSecret as _;

    fn seed_node(dir: &Path) -> crate::config::Config {
        let mut config = crate::state::tests::test_config(dir);
        let etc_simplex = dir.join("etc/opt/simplex");
        std::fs::create_dir_all(&etc_simplex).expect("mkdir");
        std::fs::write(etc_simplex.join("ca.key"), b"RELAY-CA").expect("write");
        std::fs::write(etc_simplex.join("fingerprint"), b"FINGERPRINT").expect("write");

        let etc_hearth = dir.join("etc-hearth");
        std::fs::create_dir_all(&etc_hearth).expect("mkdir");
        std::fs::write(etc_hearth.join("devices.json"), b"{\"devices\":[]}").expect("write");

        config.backup.paths = vec![etc_simplex, etc_hearth];
        config
    }

    fn keyfile(dir: &Path) -> (String, PathBuf) {
        let identity = age::x25519::Identity::generate();
        let path = dir.join("age-key.txt");
        std::fs::write(&path, identity.to_string().expose_secret()).expect("write");
        (identity.to_public().to_string(), path)
    }

    /// Адрес, на котором НЕ МОЖЕТ никто слушать.
    ///
    /// Раньше здесь брали свободный порт: `bind("127.0.0.1:0")` и тут же отпускали
    /// его вместе с сокетом. Это не «заведомо никто», а гонка с операционной системой
    /// — отпущенный порт успевал занять кто-то другой, проба «демон жив» отвечала да,
    /// и тест падал на ожидании запрета изредка и без объяснений.
    ///
    /// Порт 0 — не адресат: он означает «любой свободный» только при `bind`, а при
    /// `connect` отвергается ядром сразу и на всех системах, где идут эти тесты. Ни
    /// одного сокета для этого не создаётся, значит и занять его некому.
    fn a_dead_address() -> std::net::SocketAddr {
        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0))
    }

    /// Сделать запись файла режима невозможной, не трогая права.
    fn break_the_mode_file(state: &AppState) {
        let path = state.config.paths.node_mode_file();
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&path).expect("каталог на месте файла режима");
    }

    fn stops(state: &AppState) -> Vec<String> {
        state
            .sys
            .recorded()
            .into_iter()
            .filter(|cmd| cmd.starts_with("systemctl stop "))
            .collect()
    }

    #[tokio::test]
    async fn the_dead_address_never_answers() {
        // Дефект: «мёртвый» адрес получали как bind("127.0.0.1:0") + немедленный drop
        // сокета, и отпущенный порт изредка успевал занять кто-то другой. Проба «жив
        // ли демон» отвечала да, hold_for_import отказывался ставить запрет, и тест
        // import_does_not_inherit_the_old_nodes_mode падал раз в несколько прогонов —
        // то есть проверял удачу, а не код. Проверяем само свойство адреса.
        for _ in 0..32 {
            let addr = a_dead_address();
            assert_eq!(addr.port(), 0, "порт 0 не адресат — занять его некому");
            assert!(
                tokio::net::TcpStream::connect(addr).await.is_err(),
                "адрес обязан быть мёртвым по построению, а не по удаче: {addr}"
            );
        }
    }

    #[tokio::test]
    async fn export_holds_the_node_before_it_stops_anything() {
        // Порядок «сначала запрет, потом остановка» проверяется с той стороны, где
        // его видно наверняка: если запрет записать нельзя, не должно быть выдано ни
        // одной команды остановки.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, _key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        break_the_mode_file(&state);

        export(&state)
            .await
            .expect_err("экспорт без запрета недопустим");
        assert!(stops(&state).is_empty(), "получили {:?}", stops(&state));
    }

    #[tokio::test]
    async fn a_failed_archive_leaves_the_node_in_migration() {
        // Ошибка на любом шаге не снимает запрет: релеи уже остановлены, и поднимать
        // их обратно — значит получить два живых релея с одним CA.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        // Получателей нет — age не примет такой архив.
        config.backup.recipients = Vec::new();

        let state = AppState::new(config, Sys::new(true)).expect("state");
        export(&state).await.expect_err("архив без получателей");

        assert_eq!(
            state.node_mode().await,
            crate::model::mode::NodeMode::Migration
        );
        let alerts = state.alerts.query(None, None, 20).await;
        assert!(
            alerts
                .iter()
                .any(|a| a.summary.contains("hearthctl mode clear")),
            "человек обязан узнать, почему узел молчит: {alerts:?}"
        );
    }

    #[tokio::test]
    async fn import_holds_the_relays_too() {
        // Импорт заменяет каталоги релеев, и до первой остановки узел обязан быть
        // удержан: иначе надзор поднимет релей прямо во время распаковки.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        config.api.listen = a_dead_address();
        let state = AppState::new(config, Sys::new(true)).expect("state");

        hold_for_import(&state).await.expect("hold");

        assert_eq!(
            state.node_mode().await,
            crate::model::mode::NodeMode::Migration
        );
        // coturn стоит в том же списке, и это не косметика: ADR 0013 обещает узел,
        // который в не-normal режиме не обслуживает семью НИЧЕМ. Пока TURN не
        // останавливали, на узле, принимающем чужое состояние, оставался открытый
        // медиа-ретранслятор, и надзор поднимал его обратно через check_interval_secs.
        assert_eq!(
            stops(&state),
            vec![
                "systemctl stop smp-server.service".to_string(),
                "systemctl stop xftp-server.service".to_string(),
                "systemctl stop coturn.service".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn an_import_that_cannot_hold_the_node_stops_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        config.api.listen = a_dead_address();
        let state = AppState::new(config, Sys::new(true)).expect("state");
        break_the_mode_file(&state);

        hold_for_import(&state)
            .await
            .expect_err("импорт без запрета недопустим");
        assert!(stops(&state).is_empty(), "получили {:?}", stops(&state));
    }

    #[tokio::test]
    async fn an_import_refuses_to_run_under_a_live_daemon() {
        // hearthd держит режим в памяти и перечитывает файл только при старте: наша
        // запись до него не дойдёт, а его надзор поднимет релей во время распаковки.
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut config = seed_node(dir.path());
        config.api.listen = listener.local_addr().expect("addr");
        let state = AppState::new(config, Sys::new(true)).expect("state");

        let err = hold_for_import(&state)
            .await
            .expect_err("живой демон обязан остановить импорт");
        assert!(matches!(err, Error::Conflict(_)), "got {err:?}");
        assert!(stops(&state).is_empty());
        assert!(state.node_mode().await.relays_allowed());
    }

    #[tokio::test]
    async fn import_does_not_inherit_the_old_nodes_mode() {
        // node-mode.json лежит в state_dir, а state_dir целиком уезжает в архив.
        // Распаковка приносит режим ЧУЖОГО узла и затирает наш.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        config.api.listen = a_dead_address();
        let state = AppState::new(config.clone(), Sys::new(true)).expect("state");
        hold_for_import(&state).await.expect("hold");

        // Так выглядит распаковка архива узла, который экспортировали из карантина.
        let foreign = crate::model::mode::NodeState::enter(
            crate::model::mode::NodeMode::Quarantine,
            "хеш smp-server не совпал на СТАРОМ узле",
            vec!["smp-server".into()],
        );
        crate::store::write_json_atomic(
            state.config.paths.node_mode_file(),
            &foreign,
            crate::store::MODE_STATE,
        )
        .expect("write");

        // Ровно то, что делает `import` сразу после decrypt_and_extract.
        state
            .set_mode(
                crate::model::mode::NodeMode::Migration,
                IMPORT_REASON,
                Vec::new(),
            )
            .await
            .expect("re-assert");
        drop(state);

        let state = AppState::new(config, Sys::new(true)).expect("restart");
        let node = state.mode.read().await.clone();
        assert_eq!(node.mode, crate::model::mode::NodeMode::Migration);
        assert!(
            node.reason.contains("импорт"),
            "причина обязана говорить про импорт, а не про чужой инцидент: {}",
            node.reason
        );
        assert!(node.findings.is_empty());
    }

    #[tokio::test]
    async fn a_rehearsal_into_a_scratch_dir_does_not_touch_the_live_mode() {
        // Репетиция (A13) распаковывает архив в отдельный каталог. Останавливать из-за
        // неё релеи работающего узла и менять его режим — значит устроить дома
        // настоящий простой ради проверки.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");
        state.clear_mode().await.expect("оператор снял режим");
        state.sys.forget_recorded();

        import(
            &state,
            &report.archive,
            &key,
            &dir.path().join("rehearsal"),
            None,
        )
        .await
        .expect("import");

        assert!(state.node_mode().await.relays_allowed());
        assert!(stops(&state).is_empty(), "получили {:?}", stops(&state));
    }

    #[test]
    fn only_the_real_root_counts_as_a_live_import() {
        assert!(is_live_import(Path::new("/")));
        assert!(!is_live_import(Path::new("/tmp/rehearsal")));
        assert!(!is_live_import(Path::new("new-node")));
    }

    #[tokio::test]
    async fn export_stops_relays_and_produces_a_verifiable_archive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, _key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        assert!(report.archive.exists());
        assert_eq!(report.sha256.len(), 64);
        assert_eq!(
            report.relays_stopped,
            vec![
                "smp-server.service".to_string(),
                "xftp-server.service".to_string(),
                "coturn.service".to_string()
            ]
        );
        assert!(report
            .next_steps
            .iter()
            .any(|s| s.contains("port forwarding")));
        assert!(report.next_steps.iter().any(|s| s.contains("split brain")));

        assert!(
            !state.node_mode().await.relays_allowed(),
            "к моменту возврата узел обязан быть удержан, иначе отчёт врёт про остановку"
        );
        let status = state.migrate.read().await;
        assert!(status.relays_stopped);
        assert_eq!(status.sha256.as_deref(), Some(report.sha256.as_str()));
    }

    #[tokio::test]
    async fn export_copies_the_archive_to_hearth_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, _key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];
        config.backup.remote = Some(crate::config::BackupRemote {
            host: "192.168.1.20".parse().expect("ip"),
            port: 22,
            user: "hearth-backup".into(),
            path: "/srv/hearth-backup".into(),
            ssh_key: dir.path().join("id_ed25519"),
            verify_digest: true,
            max_delete: 3,
        });

        // dry-run Sys: rsync is recorded, not executed.
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        assert_eq!(
            report.copied_to.as_deref(),
            Some("hearth-backup@192.168.1.20:/srv/hearth-backup"),
            "ТЗ §10.2 п.3: the archive must not stay only on the machine being retired"
        );
        assert_eq!(
            state.migrate.read().await.copied_to.as_deref(),
            report.copied_to.as_deref()
        );
    }

    #[tokio::test]
    async fn import_restores_the_identity_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        let dest = dir.path().join("new-node");
        let imported = import(&state, &report.archive, &key, &dest, Some(&report.sha256))
            .await
            .expect("import");

        // Archive members keep the source path minus its root, so in this fixture they
        // sit under the temp directory's path. On a real node the source is
        // /etc/opt/simplex and the member is etc/opt/simplex.
        let ca_member = imported
            .restored
            .iter()
            .find(|p| p.ends_with("ca.key"))
            .expect("the relay CA must survive the move");
        assert!(ca_member.to_string_lossy().contains("etc/opt/simplex"));
        let restored_ca = dest.join(ca_member);
        assert_eq!(std::fs::read(restored_ca).expect("read"), b"RELAY-CA");
        assert!(imported.next_steps.iter().any(|s| s.contains("nftables")));
        // Без этой строки оператор увидит юниты, которые «стартуют и молчат».
        let clear = imported
            .next_steps
            .iter()
            .position(|s| s.contains("hearthctl mode clear"))
            .expect("шаг со снятием режима");
        let enable = imported
            .next_steps
            .iter()
            .position(|s| s.contains("systemctl enable"))
            .expect("шаг со стартом служб");
        assert!(clear < enable, "снятие режима идёт до старта служб");
        // И этот шаг обязан быть ИСПОЛНИМ в этот момент. Сетевое снятие идёт в admin
        // API, которого до старта hearthd нет: инструкция с ним отправляла оператора
        // за ошибкой соединения посреди переезда.
        assert!(
            imported.next_steps[clear].contains("mode clear --local"),
            "{}",
            imported.next_steps[clear]
        );
        assert!(
            !imported
                .next_steps
                .iter()
                .take(enable)
                .any(|s| s.contains("mode clear") && !s.contains("--local")),
            "до старта демона сетевого снятия режима быть не может: {:?}",
            imported.next_steps
        );
        // The manifest is not part of this fixture, so integrity cannot be confirmed.
        assert!(!imported.integrity_ok);
    }

    #[tokio::test]
    async fn import_refuses_a_tampered_archive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        let err = import(
            &state,
            &report.archive,
            &key,
            &dir.path().join("out"),
            Some(&"f".repeat(64)),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Integrity(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn import_refuses_the_wrong_age_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, _key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        let other = age::x25519::Identity::generate();
        let wrong = dir.path().join("wrong-key.txt");
        std::fs::write(&wrong, other.to_string().expose_secret()).expect("write");

        let err = import(
            &state,
            &report.archive,
            &wrong,
            &dir.path().join("out2"),
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("decrypt"), "got {err}");
    }

    #[test]
    fn next_steps_follow_the_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        let steps = next_steps_after_export(&config).join("\n");
        // Порты — из конфигурации: вписанный руками список уже терял 8443.
        assert!(steps.contains("8443/tcp"), "got {steps}");
        assert!(
            !steps.contains("2053/tcp"),
            "push is off in the reference config"
        );
        assert!(!steps.contains("PostgreSQL"));

        config
            .ntf
            .as_mut()
            .expect("the reference config carries [ntf]")
            .enabled = true;
        let steps = next_steps_after_export(&config).join("\n");
        assert!(steps.contains("2053/tcp"), "got {steps}");
        assert!(
            steps.contains("PostgreSQL"),
            "the push server's database is not in the archive, and the operator must hear it"
        );
    }

    #[test]
    fn relative_strips_the_root() {
        assert_eq!(
            relative(Path::new("/etc/hearth/manifest.toml")),
            PathBuf::from("etc/hearth/manifest.toml")
        );
    }
}
