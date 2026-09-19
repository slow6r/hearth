//! Daily encrypted backup (ТЗ §7.3 `backup`, §10.7).
//!
//! Once a day: tar the state directories, encrypt to the owner's age public key, drop
//! the result in a local spool, mirror the spool to `hearth-backup` over ssh, and prune
//! anything older than the retention window.
//!
//! The private age key is **not** on this machine, by design — hearthd can create a
//! backup it cannot read back. Restoring is an owner-with-the-key operation
//! (`hearthctl restore`), which is also what makes the quarterly restore drill (ТЗ
//! §10.7) meaningful.

pub mod archive;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Timelike, Utc};

use crate::config::BackupRemote;
use crate::error::{Error, Result};
use crate::model::alert::Alert;
use crate::state::AppState;
use crate::store;

use self::archive::ArchiveInfo;

/// Prefix of every archive this node writes.
const ARCHIVE_PREFIX: &str = "hearth-";
/// Suffix of every archive this node writes.
const ARCHIVE_SUFFIX: &str = ".tar.gz.age";
/// Код возврата rsync «предел `--max-delete` остановил удаление» (rsync(1), 25).
const RSYNC_MAX_DELETE: &str = "25";

/// Чем кончилось прореживание внешней копии.
///
/// Отдельный исход, а не ошибка: с `--delete-after` передача заканчивается ДО удаления,
/// поэтому «предел остановил удаление» означает «архив доехал, каталог не прорежен».
/// Раньше это было неотличимо от «rsync не прошёл» — и несколько пропущенных ночей
/// подряд (просроченных архивов стало больше `max_delete`) давали `remote_ok = false` и
/// `Degraded` при исправной внешней копии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PruneOutcome {
    /// Удалять было нечего или всё лишнее удалено.
    Done,
    /// Предел `--max-delete` остановил удаление.
    LimitReached,
}

/// The backup task.
#[derive(Debug)]
pub struct BackupJob {
    state: Arc<AppState>,
}

impl BackupJob {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Sleep until the configured hour, run, repeat.
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        if !self.state.config.backup.enabled {
            tracing::warn!("backup is disabled in the configuration");
            // Выключенный бэкап выглядел в статусе как «ещё не запускался»: last_run
            // навсегда None, вердикта нет, экран зелёный. Это разные вещи, и та, что
            // хуже, обязана быть видна.
            {
                let mut status = self.state.backup.write().await;
                status.last_error = Some("бэкап выключен в конфигурации".into());
                status.state = crate::model::health::HealthState::Degraded;
            }
            if let Err(e) = self.state.save_backup_status().await {
                tracing::error!(error = %e, "failed to persist the backup status");
            }
            return;
        }
        if self.state.config.backup.required_paths.is_empty() {
            // Говорится один раз при старте: «осознанно пусто» и «забыли внести ключ в
            // конфиг» иначе выглядят для демона одинаково.
            tracing::warn!(
                "backup.required_paths пуст: любой архив будет считаться успешным, \
                 даже если в него не вошло ничего важного"
            );
        }
        loop {
            let wait = duration_until_next_run(Utc::now(), self.state.config.backup.hour_utc);
            tracing::info!(next_run_in_secs = wait.as_secs(), "backup scheduled");
            tokio::select! {
                _ = tokio::time::sleep(wait) => {
                    if let Err(e) = self.run_once().await {
                        tracing::error!(error = %e, "scheduled backup failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("backup job stopping");
                        return;
                    }
                }
            }
        }
    }

    /// Create one backup now. Used by the scheduler and by `POST /backup/now`.
    pub async fn run_once(&self) -> Result<ArchiveInfo> {
        let started = Utc::now();
        {
            let mut status = self.state.backup.write().await;
            status.last_run = Some(started);
            status.last_error = None;
        }

        let mut result = self.create_and_push(started).await;

        // Пропущенный обязательный путь — это провал, а не успех с замечанием.
        // Архив без состояния узла не является резервной копией: восстановиться из
        // него нельзя, а статус при этом показывал бы зелёное до самой попытки.
        if let Ok(info) = &result {
            let cfg = &self.state.config.backup;
            if let Some(report) =
                required_paths_report(&cfg.required_paths, &cfg.tolerated_unreadable, info)
            {
                result = Err(crate::error::Error::invalid(report));
            }
        }

        match &result {
            Ok(info) => {
                let kept = self.prune(started).unwrap_or_else(|e| {
                    tracing::error!(error = %e, "backup pruning failed");
                    0
                });
                {
                    let mut status = self.state.backup.write().await;
                    status.last_success = Some(Utc::now());
                    status.last_archive = Some(info.path.clone());
                    status.last_size_bytes = info.size_bytes;
                    status.last_sha256 = Some(info.sha256.clone());
                    status.archives_kept = kept;
                    status.unreadable = info.unreadable.clone();
                    // Опись вошедшего вычислялась и молча выбрасывалась: её видел
                    // только тот, кто читал ответ на синхронный POST /backup/now.
                    status.members = info.members.clone();
                    status.missing = info.missing.clone();
                    crate::model::health::apply_backup_verdict(
                        Utc::now(),
                        &mut status,
                        self.state.config.backup.enabled,
                        &self.state.config.backup.required_paths,
                    );
                }
                if !info.unreadable.is_empty() {
                    self.state
                        .alerts
                        .emit(
                            Alert::warning(
                                "backup",
                                format!(
                                    "архив создан, но {} пут(и) в него не попали",
                                    info.unreadable.len()
                                ),
                            )
                            .with_details(serde_json::json!({ "paths": info.unreadable })),
                        )
                        .await;
                }
                tracing::info!(
                    archive = %info.path.display(),
                    size = info.size_bytes,
                    "backup complete"
                );
            }
            Err(e) => {
                {
                    let mut status = self.state.backup.write().await;
                    status.last_error = Some(e.to_string());
                    status.remote_ok = false;
                    // Пометка о подтверждении относилась к прошлому прогону и рядом с
                    // remote_ok = false читалась бы как противоречие. Причина теперь
                    // одна и лежит в last_error.
                    status.remote_note = None;
                    crate::model::health::apply_backup_verdict(
                        Utc::now(),
                        &mut status,
                        self.state.config.backup.enabled,
                        &self.state.config.backup.required_paths,
                    );
                }
                self.state
                    .alerts
                    .emit(Alert::critical("backup", format!("backup failed: {e}")))
                    .await;
            }
        }

        if let Err(e) = self.state.save_backup_status().await {
            tracing::error!(error = %e, "failed to persist the backup status");
        }
        result
    }

    async fn create_and_push(&self, started: DateTime<Utc>) -> Result<ArchiveInfo> {
        let cfg = &self.state.config.backup;
        store::ensure_dir(&cfg.spool_dir)?;
        let output = cfg
            .spool_dir
            .join(archive_filename(&self.state.config.node.name, started));

        let info = archive::create_encrypted(&cfg.paths, &output, &cfg.recipients)?;

        let (remote_ok, remote_note) = match &cfg.remote {
            Some(remote) => self.push_and_confirm(remote, &info).await,
            None => (false, None),
        };
        {
            let mut status = self.state.backup.write().await;
            status.remote_ok = remote_ok;
            status.remote_note = remote_note;
            status.remote_configured = cfg.remote.is_some();
        }
        Ok(info)
    }

    /// Отправить архив на hearth-backup и подтвердить, что туда доехал именно он.
    ///
    /// Возвращает «подтверждено» и словами — чем подтверждено или почему нет. Причина
    /// нужна ровно потому, что раньше все три беды («не доехало», «доехало испорченным»
    /// и «приёмнику нельзя задать вопрос») выглядели в статусе одинаково: `remote_ok =
    /// false`, вечный `Degraded` и ни одного действия, которое из этого следует.
    async fn push_and_confirm(
        &self,
        remote: &BackupRemote,
        info: &ArchiveInfo,
    ) -> (bool, Option<String>) {
        let pruned = match self.push_remote(remote).await {
            Ok(pruned) => pruned,
            Err(e) => {
                // A local archive that never reached hearth-backup is a warning, not a
                // failed backup: the copy on this disk is still better than nothing.
                let note = format!("архив создан, но не скопирован на hearth-backup: {e}");
                self.state
                    .alerts
                    .emit(Alert::warning("backup", note.clone()))
                    .await;
                return (false, Some(note));
            }
        };

        let (ok, note) = self.confirm_copy(remote, info).await;
        match pruned {
            PruneOutcome::Done => (ok, note),
            PruneOutcome::LimitReached => {
                // `--delete-after`: передача идёт ПЕРЕД удалением, поэтому свежий архив
                // на приёмнике уже лежит, а остановлено только прореживание. Считать
                // это провалом внешней копии — врать в ту сторону, где вранья быть не
                // должно: было бы `remote_ok = false` и `Degraded` при доехавшем
                // архиве. Копится это за несколько пропущенных ночей (просроченных
                // архивов становится больше `max_delete`) и само не рассасывается.
                let warning = format!(
                    "внешняя копия доехала, но прореживание остановлено пределом \
                     backup.remote.max_delete = {}: просроченных архивов этого узла на \
                     hearth-backup накопилось больше. Уберите лишние на приёмнике или \
                     поднимите предел, иначе место кончится",
                    remote.max_delete
                );
                self.state
                    .alerts
                    .emit(Alert::warning("backup", warning.clone()))
                    .await;
                let note = match note {
                    Some(note) => format!("{note}; {warning}"),
                    None => warning,
                };
                (ok, Some(note))
            }
        }
    }

    /// Подтвердить, что на hearth-backup лежит именно этот архив.
    async fn confirm_copy(
        &self,
        remote: &BackupRemote,
        info: &ArchiveInfo,
    ) -> (bool, Option<String>) {
        if self.state.sys.is_dry_run() {
            // dry-run не отправлял ничего: подтверждать нечего, и «подтверждено» тут
            // было бы тем самым зелёным, ради которого статус и заводили.
            return (
                false,
                Some("dry-run: внешняя копия не отправлялась и не сверялась".into()),
            );
        }

        if !remote.verify_digest {
            // Сверка выключена осознанно: ключ на приёмнике ограничен
            // command="rsync ...", и `sha256sum` там невыполним. Подтверждение слабее
            // полного, и статус обязан называть его своим именем.
            return (true, Some(rsync_only_note()));
        }

        match self.remote_digest_matches(remote, info).await {
            Ok(None) => (true, Some("сверено по sha256 с hearth-backup".into())),
            Ok(Some(theirs)) => {
                // Тихая порча резервной копии: файл на hearth-backup есть, но
                // это не тот файл. Единственный случай здесь, который нельзя
                // понижать до предупреждения.
                self.state
                    .alerts
                    .emit(
                        Alert::critical("backup", "внешняя копия не совпадает с архивом узла")
                            .with_details(serde_json::json!({
                                "archive": info.path.display().to_string(),
                                "local_sha256": info.sha256,
                                "remote_sha256": theirs,
                            })),
                    )
                    .await;
                (
                    false,
                    Some(format!(
                        "на hearth-backup лежит ДРУГОЙ файл под тем же именем (его sha256 {theirs})"
                    )),
                )
            }
            Err(e) => {
                // Копия, возможно, и доехала, но подтвердить это нечем. Поле
                // remote_ok означает «подтверждено», поэтому здесь false.
                let note = unverified_note(&e.to_string());
                self.state
                    .alerts
                    .emit(Alert::warning("backup", note.clone()))
                    .await;
                (false, Some(note))
            }
        }
    }

    /// Mirror the spool directory to `hearth-backup` (ТЗ §4: 10.66.10.20).
    /// Mirror the spool to `hearth-backup`, if one is configured.
    ///
    /// Returns the destination it copied to, or `None` when no remote is configured.
    /// Used by the daily job and by `migrate export` (ТЗ §10.2 п.3: the migration
    /// archive is placed on hearth-backup, not left on a machine that is about to be
    /// wiped).
    pub async fn sync_remote(&self) -> Result<Option<String>> {
        let Some(remote) = &self.state.config.backup.remote else {
            return Ok(None);
        };
        self.push_remote(remote).await?;
        Ok(Some(format!(
            "{}@{}:{}",
            remote.user, remote.host, remote.path
        )))
    }

    async fn push_remote(&self, remote: &BackupRemote) -> Result<PruneOutcome> {
        // Belt and braces: nftables would drop it anyway, but a misconfigured backup
        // target is exactly the kind of mistake that quietly ships data off-site.
        self.state
            .policy
            .check(std::net::SocketAddr::new(remote.host, remote.port))?;

        let cfg = &self.state.config.backup;
        let ssh = format!(
            "ssh -i {key} -p {port} -o BatchMode=yes -o StrictHostKeyChecking=yes \
             -o PasswordAuthentication=no",
            key = remote.ssh_key.display(),
            port = remote.port,
        );
        let source = format!("{}/", cfg.spool_dir.display());
        let target = format!("{}@{}:{}/", remote.user, remote.host, remote.path);
        // Прореживать разрешено только собственные архивы этого узла: в
        // /srv/hearth-backup может лежать что угодно ещё, включая копии другого узла.
        let prune = (remote.max_delete > 0).then(|| {
            (
                own_archives_pattern(&self.state.config.node.name),
                remote.max_delete,
            )
        });

        let args = rsync_args(
            &ssh,
            &source,
            &target,
            prune.as_ref().map(|(p, n)| (p.as_str(), *n)),
        );
        match self.state.sys.run_mutating("rsync", &args).await {
            Ok(_) => Ok(PruneOutcome::Done),
            // Предел `--max-delete` — единственный код возврата, который НЕ означает
            // «копия не доехала»: с `--delete-after` передача уже закончилась. Отличать
            // его обязательно, иначе несколько пропущенных ночей подряд дают вечный
            // Degraded при исправной внешней копии.
            Err(Error::Command { status, .. }) if prune.is_some() && status == RSYNC_MAX_DELETE => {
                Ok(PruneOutcome::LimitReached)
            }
            Err(e) => Err(e),
        }
    }

    /// Спросить у hearth-backup sha256 только что отправленного архива.
    ///
    /// `Ok(None)` — совпал; `Ok(Some(чужой хеш))` — не совпал; `Err` — проверить не
    /// удалось. Три разных исхода потому, что «копия испорчена» и «копию не удалось
    /// проверить» требуют разной реакции, а раньше оба означали одно: ничего.
    async fn remote_digest_matches(
        &self,
        remote: &BackupRemote,
        info: &ArchiveInfo,
    ) -> Result<Option<String>> {
        if self.state.sys.is_dry_run() {
            tracing::info!("dry-run: внешняя копия не сверяется");
            return Ok(None);
        }
        let Some(name) = info.path.file_name().and_then(|n| n.to_str()) else {
            return Err(Error::invalid("имя архива не является строкой"));
        };
        let mut args = ssh_args(remote);
        args.push(format!("{}@{}", remote.user, remote.host));
        args.push(format!(
            "sha256sum -- {}/{}",
            remote.path.trim_end_matches('/'),
            name
        ));
        let out = self.state.sys.run("ssh", &args).await?;
        let theirs = parse_sha256sum(&out.stdout, name)?;
        if theirs.eq_ignore_ascii_case(&info.sha256) {
            Ok(None)
        } else {
            Ok(Some(theirs))
        }
    }

    /// Delete archives older than the retention window. Returns how many are kept.
    ///
    /// Age is taken from the filename timestamp, not the file mtime: an rsync or a
    /// restore can rewrite mtimes, and the name is what the operator reads anyway.
    pub fn prune(&self, now: DateTime<Utc>) -> Result<u32> {
        let cfg = &self.state.config.backup;
        let cutoff = now - chrono::Duration::days(cfg.retention_days as i64);
        let mut kept = 0;
        let dir = match std::fs::read_dir(&cfg.spool_dir) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(Error::io(&cfg.spool_dir, e)),
        };
        for entry in dir.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(ts) = timestamp_from_filename(name) else {
                continue;
            };
            if ts < cutoff {
                match std::fs::remove_file(&path) {
                    Ok(()) => tracing::info!(archive = %name, "pruned expired backup"),
                    Err(e) => tracing::warn!(archive = %name, error = %e, "cannot prune"),
                }
            } else {
                kept += 1;
            }
        }
        Ok(kept)
    }

    /// Archives currently in the spool, newest first.
    pub fn list_archives(&self) -> Result<Vec<PathBuf>> {
        list_archives(&self.state.config.backup.spool_dir)
    }
}

/// Выполняет ли собранный архив контракт обязательных путей.
///
/// Возвращает текст отказа или `None`, если всё на месте. Раньше проверка выглядела
/// как «строка какого-то непрочитанного ФАЙЛА содержит строку обязательного пути» и
/// врала в обе стороны: отсутствующий каталог в `unreadable` не попадал и проверку
/// проходил, а `required_paths = paths` проваливал КАЖДУЮ ночь из-за `ca.key`,
/// закрытого от демона намеренно. Здесь сравниваются нормализованные имена и
/// вложенность по компонентам пути.
pub(crate) fn required_paths_report(
    required: &[PathBuf],
    tolerated: &[PathBuf],
    info: &ArchiveInfo,
) -> Option<String> {
    let mut absent = Vec::new();
    let mut not_archived = Vec::new();
    let mut unreadable = Vec::new();

    for path in required {
        if info.missing.iter().any(|m| Path::new(m) == path.as_path()) {
            absent.push(path.display().to_string());
            continue;
        }
        // Положительная проверка: путь обязан присутствовать в описи вошедшего.
        // Раньше members не участвовали в проверке вообще.
        let name = archive::archive_name(path);
        if !info.members.iter().any(|member| member == &name) {
            not_archived.push(path.display().to_string());
            continue;
        }
        for skipped in &info.unreadable {
            let skipped = Path::new(skipped);
            if !skipped.starts_with(path) {
                continue;
            }
            if tolerated.iter().any(|t| skipped.starts_with(t)) {
                continue;
            }
            unreadable.push(skipped.display().to_string());
        }
    }

    if absent.is_empty() && not_archived.is_empty() && unreadable.is_empty() {
        return None;
    }
    // Три списка раздельно: «нет на диске», «не вошло» и «не прочитано» лечатся
    // по-разному, а прежний текст говорил только «не попали обязательные пути».
    Some(format!(
        "архив не выполняет контракт обязательных путей; не существует: [{}]; \
         не вошло в архив: [{}]; не прочитано и не объявлено допустимым \
         (backup.tolerated_unreadable): [{}]; вошло в архив: [{}]",
        absent.join(", "),
        not_archived.join(", "),
        unreadable.join(", "),
        info.members.join(", ")
    ))
}

/// Аргументы rsync для отправки спула на hearth-backup.
///
/// # Что защищает прореживание, а что нет
///
/// `--filter=R <свои архивы>` + `--filter=P *` ограничивает удаление файлами вида
/// `hearth-<имя узла>-*.tar.gz.age`. Это защита ЧУЖОГО: копий другого узла в том же
/// каталоге, документов владельца, чего угодно ещё — их rsync не тронет никогда.
///
/// От сценария «пустой спул после переустановки узла стирает внешнюю историю» маска не
/// защищает и защитить не может: под неё попадают ровно собственные архивы узла, то
/// есть ровно то, что после переустановки исчезло локально. Защита здесь другая и
/// частичная — `--max-delete`: за одну ночь уходит не больше `max_delete` файлов, и
/// каждая такая ночь громкая (код возврата 25, предупреждение в алертах). Пустой спул
/// за одну ночь историю не уносит, но за несколько ночей подряд — унесёт.
///
/// Поэтому порядок после переустановки узла такой: до первого успешного прогона либо
/// `backup.remote.max_delete = 0` (прореживания нет вовсе), либо запрет удаления на
/// самом приёмнике (`rrsync -no-del`). Это описано в docs/runbook-restore-drill.md.
///
/// Не удалять вовсе — тоже отказ, только отложенный: каталог растёт, место кончается, и
/// однажды свежий архив просто перестаёт приниматься.
fn rsync_args(ssh: &str, source: &str, target: &str, prune: Option<(&str, u32)>) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--archive".into(),
        "--partial".into(),
        "--chmod=F600".into(),
    ];
    if let Some((pattern, max_delete)) = prune {
        // Порядок правил значим: побеждает ПЕРВОЕ совпавшее. Сначала объявляем
        // удаляемыми просроченные архивы этого узла, затем защищаем всё остальное —
        // чужие архивы в том же каталоге, документы владельца, что угодно. Что именно
        // этим закрыто, а что нет, — в доке функции выше.
        args.push(format!("--filter=R {pattern}"));
        args.push("--filter=P *".into());
        // Удаление ПОСЛЕ передачи: свежий архив доезжает, даже если прореживание
        // упрётся в предел. На этом же держится разбор кода 25 в `push_remote`.
        args.push("--delete-after".into());
        // Предел за ночь: больше этого числа файлов не исчезает никогда, а попытка
        // превысить — код возврата 25, то есть громкая жалоба, а не тихая потеря.
        args.push(format!("--max-delete={max_delete}"));
    }
    args.extend(["-e".into(), ssh.into(), source.into(), target.into()]);
    args
}

/// Маска архивов, которые этот узел вправе удалять на приёмнике.
fn own_archives_pattern(node: &str) -> String {
    format!("{ARCHIVE_PREFIX}{node}-*{ARCHIVE_SUFFIX}")
}

/// Что записать в статус, когда сверка выключена настройкой.
fn rsync_only_note() -> String {
    "sha256 не сверяется (backup.remote.verify_digest = false): копия подтверждена \
     только кодом возврата rsync"
        .into()
}

/// Почему внешняя копия не подтверждена — словами, которые называют действие.
///
/// Отдельной функцией, чтобы текст проверялся тестом: самая вероятная причина отказа
/// здесь — ключ, ограниченный на приёмнике через `command="rsync ..."`, и оператор
/// обязан узнать об этом из сообщения, а не из чтения исходников.
fn unverified_note(error: &str) -> String {
    format!(
        "внешнюю копию не удалось сверить с hearth-backup: {error}. Если ssh-ключ на \
         приёмнике ограничен через command=\"rsync ...\", разрешите там sha256sum \
         (docs/runbook-restore-drill.md, «Приёмник hearth-backup») или задайте \
         backup.remote.verify_digest = false"
    )
}

/// Параметры ssh, общие для rsync и для сверки хеша.
fn ssh_args(remote: &BackupRemote) -> Vec<String> {
    vec![
        "-i".into(),
        remote.ssh_key.display().to_string(),
        "-p".into(),
        remote.port.to_string(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
    ]
}

/// Разобрать вывод `sha256sum`: строка вида `<64 hex><пробелы><путь>`.
///
/// Имя файла сверяется отдельно: ответ про другой файл — это не подтверждение, а
/// признак того, что на принимающей стороне лежит не то, о чём спрашивали.
fn parse_sha256sum(stdout: &str, expected_name: &str) -> Result<String> {
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let (Some(digest), Some(path)) = (parts.next(), parts.next()) else {
            continue;
        };
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if !path.ends_with(expected_name) {
            continue;
        }
        return Ok(digest.to_ascii_lowercase());
    }
    Err(Error::Parse(format!(
        "hearth-backup не вернул sha256 для {expected_name}: `{}`",
        stdout.trim()
    )))
}

/// `hearth-<node>-<YYYYMMDDTHHMMSSZ>.tar.gz.age`
pub fn archive_filename(node: &str, ts: DateTime<Utc>) -> String {
    format!(
        "{ARCHIVE_PREFIX}{node}-{stamp}{ARCHIVE_SUFFIX}",
        stamp = ts.format("%Y%m%dT%H%M%SZ")
    )
}

/// Recover the creation time from an archive filename.
pub fn timestamp_from_filename(name: &str) -> Option<DateTime<Utc>> {
    let rest = name.strip_prefix(ARCHIVE_PREFIX)?;
    let rest = rest.strip_suffix(ARCHIVE_SUFFIX)?;
    let stamp = rest.rsplit('-').next()?;
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|naive| Utc.from_utc_datetime(&naive))
}

/// Archives in a directory, newest first.
pub fn list_archives(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    let mut archives: Vec<(DateTime<Utc>, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            let ts = timestamp_from_filename(name)?;
            Some((ts, path))
        })
        .collect();
    archives.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
    Ok(archives.into_iter().map(|(_, path)| path).collect())
}

/// Time until the next run at `hour_utc:00`.
fn duration_until_next_run(now: DateTime<Utc>, hour_utc: u32) -> std::time::Duration {
    let today = now
        .with_hour(hour_utc.min(23))
        .and_then(|t| t.with_minute(0))
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(now);
    let next = if today > now {
        today
    } else {
        today + chrono::Duration::days(1)
    };
    (next - now)
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(3600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Sys;

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0)
            .single()
            .expect("ts")
    }

    #[test]
    fn filename_round_trips() {
        let ts = at(2026, 9, 6, 3, 0);
        let name = archive_filename("hearth-node", ts);
        assert_eq!(name, "hearth-hearth-node-20260906T030000Z.tar.gz.age");
        assert_eq!(timestamp_from_filename(&name), Some(ts));
        assert_eq!(timestamp_from_filename("random.txt"), None);
    }

    #[test]
    fn schedules_the_next_run_correctly() {
        // Before the hour: later today.
        let wait = duration_until_next_run(at(2026, 9, 6, 1, 0), 3);
        assert_eq!(wait.as_secs(), 2 * 3600);
        // After the hour: tomorrow.
        let wait = duration_until_next_run(at(2026, 9, 6, 4, 0), 3);
        assert_eq!(wait.as_secs(), 23 * 3600);
    }

    #[tokio::test]
    async fn creates_an_archive_and_records_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        let identity = age::x25519::Identity::generate();
        config.backup.recipients = vec![identity.to_public().to_string()];
        let source = dir.path().join("etc-hearth");
        std::fs::create_dir_all(&source).expect("mkdir");
        std::fs::write(source.join("hearthd.toml"), b"config").expect("write");
        config.backup.paths = vec![source.clone()];
        config.backup.required_paths = vec![source.clone()];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let job = BackupJob::new(state.clone());
        let info = job.run_once().await.expect("backup");

        assert!(info.path.exists());
        assert!(info.size_bytes > 0);
        let status = state.backup.read().await;
        assert!(status.last_success.is_some());
        assert_eq!(status.last_sha256.as_deref(), Some(info.sha256.as_str()));
        assert!(status.last_error.is_none());
        assert!(!status.remote_ok, "no remote configured in this test");
        // Что именно вошло в архив, теперь видно в ежедневном статусе, а не только
        // тому, у кого на руках age-ключ.
        assert_eq!(status.members, vec![archive::archive_name(&source)]);
        assert!(status.missing.is_empty());
        assert_eq!(
            status.state,
            crate::model::health::HealthState::Ok,
            "узел без hearth-backup не деградировал"
        );
    }

    #[tokio::test]
    async fn failure_records_an_error_and_alerts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config.backup.recipients = vec!["not-an-age-key".into()];
        config.backup.paths = vec![dir.path().join("etc-hearth")];
        config.backup.required_paths = Vec::new();
        std::fs::create_dir_all(dir.path().join("etc-hearth")).expect("mkdir");

        let state = AppState::new(config, Sys::new(true)).expect("state");
        assert!(BackupJob::new(state.clone()).run_once().await.is_err());

        let status = state.backup.read().await;
        assert!(status.last_error.is_some());
        assert_eq!(status.state, crate::model::health::HealthState::Down);
        let alerts = state.alerts.query(None, None, 10).await;
        assert!(alerts.iter().any(|a| a.summary.contains("backup failed")));
    }

    #[tokio::test]
    async fn prune_keeps_the_retention_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config.backup.retention_days = 14;
        let spool = config.backup.spool_dir.clone();
        std::fs::create_dir_all(&spool).expect("mkdir");

        let now = at(2026, 9, 6, 3, 0);
        let fresh = archive_filename("hearth-node", now - chrono::Duration::days(2));
        let stale = archive_filename("hearth-node", now - chrono::Duration::days(30));
        std::fs::write(spool.join(&fresh), b"x").expect("write");
        std::fs::write(spool.join(&stale), b"x").expect("write");
        std::fs::write(spool.join("unrelated.txt"), b"x").expect("write");

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let kept = BackupJob::new(state).prune(now).expect("prune");

        assert_eq!(kept, 1);
        assert!(spool.join(&fresh).exists());
        assert!(!spool.join(&stale).exists());
        assert!(
            spool.join("unrelated.txt").exists(),
            "foreign files are left alone"
        );
    }

    #[tokio::test]
    async fn lists_archives_newest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let spool = config.backup.spool_dir.clone();
        std::fs::create_dir_all(&spool).expect("mkdir");
        let older = archive_filename("n", at(2026, 9, 1, 3, 0));
        let newer = archive_filename("n", at(2026, 9, 5, 3, 0));
        std::fs::write(spool.join(&older), b"x").expect("write");
        std::fs::write(spool.join(&newer), b"x").expect("write");

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let archives = BackupJob::new(state).list_archives().expect("list");
        assert_eq!(archives.len(), 2);
        assert!(archives[0].to_string_lossy().contains("20260905"));
    }

    fn info_with(members: &[&str], unreadable: &[&str], missing: &[&str]) -> ArchiveInfo {
        ArchiveInfo {
            path: PathBuf::from("/var/opt/hearth/backup/a.age"),
            size_bytes: 1,
            sha256: "0".repeat(64),
            members: members.iter().map(|s| s.to_string()).collect(),
            unreadable: unreadable.iter().map(|s| s.to_string()).collect(),
            missing: missing.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn a_missing_required_path_fails_the_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        let identity = age::x25519::Identity::generate();
        config.backup.recipients = vec![identity.to_public().to_string()];
        let present = dir.path().join("etc-hearth");
        let gone = dir.path().join("var-opt-simplex");
        std::fs::create_dir_all(&present).expect("mkdir");
        std::fs::write(present.join("hearthd.toml"), b"config").expect("write");
        config.backup.paths = vec![present, gone.clone()];
        config.backup.required_paths = vec![gone];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let err = BackupJob::new(state.clone())
            .run_once()
            .await
            .expect_err("отсутствующий обязательный источник — это провал");
        assert!(err.to_string().contains("не существует"), "got {err}");

        let status = state.backup.read().await;
        assert!(status.last_error.is_some());
        assert!(
            status.last_success.is_none(),
            "неполный архив не имеет права обновлять last_success"
        );
        assert_eq!(status.state, crate::model::health::HealthState::Down);
        let alerts = state.alerts.query(None, None, 10).await;
        assert!(alerts.iter().any(|a| a.summary.contains("backup failed")));
    }

    #[tokio::test]
    async fn a_disabled_backup_is_visible_as_degraded() {
        // Раньше выключенный бэкап отличался от «ещё не запускался» только строчкой в
        // журнале: last_run оставался None навсегда, а экран — зелёным.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config.backup.enabled = false;
        let state = AppState::new(config, Sys::new(true)).expect("state");

        let (_tx, rx) = tokio::sync::watch::channel(false);
        BackupJob::new(state.clone()).run(rx).await;

        let status = state.backup.read().await;
        assert!(
            status.last_run.is_none(),
            "задача действительно не запускалась"
        );
        assert_eq!(status.state, crate::model::health::HealthState::Degraded);
        assert!(
            status
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("выключен"),
            "причина обязана называться, got {:?}",
            status.last_error
        );
    }

    /// Вторая половина замечания 10: `Config::validate` больше не роняет демон из-за
    /// обязательного пути, которого нет в `backup.paths`, — значит ночной прогон обязан
    /// поймать это сам и назвать вслух. Иначе смягчение отказа стало бы умолчанием.
    #[test]
    fn a_required_path_nobody_archives_fails_the_nightly_run() {
        let required = vec![PathBuf::from("/var/opt/nowhere")];
        // Архив собран по `backup.paths`, где этого пути нет: ни в описи, ни в missing.
        let info = info_with(&["var/lib/hearth"], &[], &[]);
        let report = required_paths_report(&required, &[], &info).expect("должен быть отказ");
        assert!(report.contains("не вошло в архив"), "got {report}");
        assert!(report.contains("/var/opt/nowhere"), "got {report}");
    }

    #[test]
    fn a_sibling_path_does_not_satisfy_a_required_path() {
        // Регрессия на сопоставление подстрок: /var/lib/hearth-old начинается с
        // /var/lib/hearth как строка, но не как путь.
        let required = vec![PathBuf::from("/var/lib/hearth")];
        let info = info_with(&["var/lib/hearth-old"], &[], &[]);
        let report = required_paths_report(&required, &[], &info).expect("должен быть отказ");
        assert!(report.contains("не вошло в архив"), "got {report}");

        let info = info_with(&["var/lib/hearth"], &[], &[]);
        assert!(required_paths_report(&required, &[], &info).is_none());
    }

    #[test]
    fn a_deliberately_unreadable_file_inside_a_required_dir_does_not_fail() {
        // ca.key закрыт от демона намеренно (deploy/fix-permissions.sh), и падать из-за
        // него каждую ночь — это backup, которого ни у кого нет.
        let required = vec![PathBuf::from("/etc/hearth")];
        let tolerated = vec![PathBuf::from("/etc/hearth/pki/ca.key")];
        let info = info_with(&["etc/hearth"], &["/etc/hearth/pki/ca.key"], &[]);
        assert!(required_paths_report(&required, &tolerated, &info).is_none());
    }

    #[test]
    fn an_untolerated_unreadable_file_inside_a_required_dir_fails() {
        // Ровно тот случай, что на узле: smp-server.ini.bak-sni не прочитан, а архив
        // считался успешным.
        let required = vec![PathBuf::from("/etc/opt/simplex")];
        let tolerated = vec![PathBuf::from("/etc/hearth/pki/ca.key")];
        let info = info_with(
            &["etc/opt/simplex"],
            &["/etc/opt/simplex/smp-server.ini.bak-sni"],
            &[],
        );
        let report =
            required_paths_report(&required, &tolerated, &info).expect("должен быть отказ");
        assert!(report.contains("smp-server.ini.bak-sni"), "got {report}");
        assert!(report.contains("вошло в архив"), "got {report}");
    }

    #[test]
    fn the_remote_copy_is_thinned_but_only_our_own_archives() {
        // Прежде выбор был между двумя отказами: голый `--delete` делал hearth-backup
        // производным от локального спула (чистый спул после переустановки узла стирал
        // бы всю внешнюю историю), а полный отказ от удаления означал, что
        // /srv/hearth-backup растёт до конца места — и свежий архив перестаёт
        // приниматься. Здесь удаляются только просроченные архивы ЭТОГО узла.
        let pattern = own_archives_pattern("hearth-node");
        let args = rsync_args(
            "ssh -i k",
            "/var/opt/hearth/backup/",
            "u@h:/srv/",
            Some((pattern.as_str(), 3)),
        );
        let risk = args
            .iter()
            .position(|a| a == &format!("--filter=R {pattern}"))
            .expect("свои архивы объявлены удаляемыми");
        let protect = args
            .iter()
            .position(|a| a == "--filter=P *")
            .expect("всё остальное на приёмнике защищено");
        assert!(
            risk < protect,
            "порядок правил значим: побеждает первое совпавшее, получили {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--delete-after"),
            "удаление только после передачи: {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--max-delete=3"),
            "второй предел на объём удаления: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "--delete"),
            "зеркалирования по-прежнему нет: {args:?}"
        );
        assert!(args.iter().any(|a| a == "--archive"));
        assert!(args.iter().any(|a| a == "--chmod=F600"));
        assert_eq!(args.last().map(String::as_str), Some("u@h:/srv/"));
    }

    #[test]
    fn thinning_can_be_switched_off_entirely() {
        // Локальный выход: приёмник со своим планировщиком (или с ключом, которому
        // удаление запрещено) настраивается через max_delete = 0, и тогда rsync не
        // получает ни одного удаляющего параметра.
        let args = rsync_args("ssh -i k", "/var/opt/hearth/backup/", "u@h:/srv/", None);
        assert!(!args.iter().any(|a| a.starts_with("--delete")), "{args:?}");
        assert!(
            !args.iter().any(|a| a.starts_with("--max-delete")),
            "{args:?}"
        );
        assert!(!args.iter().any(|a| a.starts_with("--filter")), "{args:?}");
    }

    #[test]
    fn the_thinning_pattern_covers_this_node_only() {
        // В /srv/hearth-backup может лежать копия другого узла семьи. Под маску она не
        // попадает, а всё, что под маску не попало, защищено правилом `P *`.
        let pattern = own_archives_pattern("hearth-node");
        assert_eq!(pattern, "hearth-hearth-node-*.tar.gz.age");
        let ours = archive_filename("hearth-node", at(2026, 9, 18, 3, 0));
        assert!(ours.starts_with("hearth-hearth-node-"), "got {ours}");
        assert!(ours.ends_with(".tar.gz.age"), "got {ours}");
        let theirs = archive_filename("other-node", at(2026, 9, 18, 3, 0));
        assert!(!theirs.starts_with("hearth-hearth-node-"), "got {theirs}");
    }

    #[test]
    fn an_unconfirmed_remote_copy_says_what_to_do() {
        // `remote_ok = false` без причины — отчёт, по которому ночью нечего делать.
        // Самая вероятная причина отказа сверки — ключ, ограниченный на приёмнике
        // через command="rsync ...", и сообщение обязано называть оба выхода.
        let note = unverified_note("ssh: exit 1");
        assert!(note.contains("sha256sum"), "got {note}");
        assert!(note.contains("verify_digest"), "got {note}");
        assert!(note.contains("runbook-restore-drill"), "got {note}");
        assert!(rsync_only_note().contains("кодом возврата rsync"));
    }

    #[test]
    fn a_remote_digest_is_read_from_the_receiving_side() {
        let name = "hearth-node-20260918T030000Z.tar.gz.age";
        let good = format!("{}  /srv/hearth-backup/{name}\n", "ab".repeat(32));
        assert_eq!(
            parse_sha256sum(&good, name).expect("parse"),
            "ab".repeat(32)
        );

        // Ответ про другой файл подтверждением не является.
        let other = format!("{}  /srv/hearth-backup/other.age\n", "ab".repeat(32));
        assert!(parse_sha256sum(&other, name).is_err());
        // Как и «файла нет».
        let missing = format!("sha256sum: /srv/hearth-backup/{name}: No such file\n");
        assert!(parse_sha256sum(&missing, name).is_err());
    }

    #[tokio::test]
    async fn refuses_a_remote_outside_the_home_network() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let job = BackupJob::new(state);
        let remote = BackupRemote {
            host: "203.0.113.9".parse().expect("ip"),
            port: 22,
            user: "backup".into(),
            path: "/srv".into(),
            ssh_key: "/etc/hearth/secrets/backup_ed25519".into(),
            verify_digest: true,
            max_delete: 3,
        };
        let err = job.push_remote(&remote).await.unwrap_err();
        assert!(matches!(err, Error::EgressDenied(_)), "got {err:?}");
    }

    #[test]
    fn the_runbook_says_what_the_mask_does_not_protect() {
        // Замечание 14, первая половина: комментарий обещал защиту от «пустого спула
        // после переустановки», а маска накрывает ровно собственные архивы узла. Код и
        // проза приведены в согласие; проза обязана называть и обходной путь.
        let runbook = include_str!("../../../docs/runbook-restore-drill.md");
        assert!(
            runbook.contains("Перед переустановкой узла"),
            "runbook обязан предупредить про обнулённый спул"
        );
        assert!(
            runbook.contains("max_delete = 0"),
            "runbook обязан назвать выход"
        );
        assert!(
            runbook.contains("Код 25 — не провал внешней копии."),
            "runbook обязан объяснить код 25"
        );
    }

    /// Приёмник, на котором лежит `hearth-backup` этого узла, в тестовой сети.
    fn home_remote() -> BackupRemote {
        BackupRemote {
            host: "192.168.1.20".parse().expect("ip"),
            port: 22,
            user: "hearth-backup".into(),
            path: "/srv/hearth-backup".into(),
            ssh_key: "/etc/hearth/secrets/backup_ed25519".into(),
            // Сверка sha256 — отдельный разговор с приёмником, и здесь она не предмет
            // проверки: без неё подтверждением служит код возврата rsync.
            verify_digest: false,
            max_delete: 3,
        }
    }

    #[tokio::test]
    async fn a_pruning_limit_is_not_a_failed_remote_copy() {
        // Замечание 14, вторая половина: после двух-трёх пропущенных ночей просроченных
        // архивов на приёмнике становится больше max_delete, и rsync возвращает 25
        // КАЖДУЮ ночь. Раньше это было неотличимо от «копия не доехала»: remote_ok =
        // false и вечный Degraded при исправной внешней копии. С `--delete-after`
        // передача заканчивается ДО удаления, значит архив на приёмнике есть.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(
            crate::state::tests::test_config(dir.path()),
            Sys::new(false),
        )
        .expect("state");
        state.sys.stub_capture(
            "rsync",
            crate::sys::Output {
                code: 25,
                stdout: String::new(),
                stderr: "deletions stopped due to --max-delete limit (3 skipped)".into(),
            },
        );
        let job = BackupJob::new(state.clone());
        let info = info_with(&["var/lib/hearth"], &[], &[]);

        let (ok, note) = job.push_and_confirm(&home_remote(), &info).await;
        assert!(ok, "архив доехал: удаление идёт после передачи");
        let note = note.expect("причина обязана быть названа");
        assert!(note.contains("max_delete"), "got {note}");
        let alerts = state.alerts.query(None, None, 10).await;
        assert!(
            alerts
                .iter()
                .any(|a| a.summary.contains("прореживание остановлено")),
            "человек обязан узнать о непрореженном приёмнике: {alerts:?}"
        );
    }

    #[tokio::test]
    async fn a_real_rsync_failure_is_still_a_failure() {
        // Обратная половина: послабление касается ровно кода 25 и ровно тогда, когда
        // прореживание включено. Всё остальное — по-прежнему «копия не доехала».
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(
            crate::state::tests::test_config(dir.path()),
            Sys::new(false),
        )
        .expect("state");
        state.sys.stub_capture(
            "rsync",
            crate::sys::Output {
                code: 12,
                stdout: String::new(),
                stderr: "rsync error: error in rsync protocol data stream".into(),
            },
        );
        let job = BackupJob::new(state.clone());
        let info = info_with(&["var/lib/hearth"], &[], &[]);

        let (ok, note) = job.push_and_confirm(&home_remote(), &info).await;
        assert!(!ok, "код 12 — это именно недоехавшая копия");
        let note = note.expect("причина обязана быть названа");
        assert!(note.contains("не скопирован"), "got {note}");

        // Тот же код 25 без прореживания (max_delete = 0) послаблением не пользуется:
        // удалять было нечего, значит 25 пришёл не оттуда.
        state.sys.stub_capture(
            "rsync",
            crate::sys::Output {
                code: 25,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let remote = BackupRemote {
            max_delete: 0,
            ..home_remote()
        };
        let err = job.push_remote(&remote).await.unwrap_err();
        assert!(matches!(err, Error::Command { .. }), "got {err:?}");
    }
}
