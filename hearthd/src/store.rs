//! Small persistence helpers: atomic JSON documents, append-only journals, secrets.
//!
//! Everything hearthd writes lands under one of the ТЗ §10.1 directories, is written
//! through a temp file + rename (so a power cut never leaves a half-written registry),
//! and gets restrictive permissions on unix.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};

/// `0600` — owner read/write. Used for secrets and anything holding relay passwords.
pub const MODE_SECRET: u32 = 0o600;
/// `0640` — owner write, group read. Used for state the admin group may inspect.
pub const MODE_STATE: u32 = 0o640;
/// `0640` — a secret that a DIFFERENT service has to read.
///
/// The rendered coturn config holds `static-auth-secret`, and on Debian coturn runs as
/// `User=turnserver` — not as `hearth`, and not as root. Written `0600` by `hearth`, the
/// file is unreadable by the only process that needs it, and coturn fails to start with
/// nothing but a permissions error to go on.
///
/// The mode alone would expose the secret to whatever group the file lands in, so it is
/// only half the mechanism: the containing directory is setgid `turnserver`, which is
/// what narrows "group" to exactly the service that must read it.
pub const MODE_SHARED_SECRET: u32 = 0o640;
/// `0750` — directories.
pub const MODE_DIR: u32 = 0o750;

/// Create a directory (and parents) with restrictive permissions.
pub fn ensure_dir(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if path.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))?;
    set_mode(path, MODE_DIR)?;
    Ok(())
}

/// Apply a unix mode. No-op on other platforms (dev machines only).
pub fn set_mode(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(path, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Read a JSON document. Returns `Ok(None)` when the file does not exist yet.
pub fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Option<T>> {
    let path = path.as_ref();
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let value = serde_json::from_str(&raw)
                .map_err(|e| Error::Parse(format!("{}: {e}", path.display())))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Write a JSON document atomically: temp file in the same directory, fsync, rename.
pub fn write_json_atomic<T: Serialize>(path: impl AsRef<Path>, value: &T, mode: u32) -> Result<()> {
    let path = path.as_ref();
    let body = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &body, mode)
}

/// Atomic byte write with the given mode.
pub fn write_atomic(path: impl AsRef<Path>, body: &[u8], mode: u32) -> Result<()> {
    write_atomic_owned(path.as_ref(), body, mode, None)
}

/// Как [`write_atomic`], но новый файл получает владельца и группу прежнего.
///
/// Атомарная запись создаёт НОВЫЙ файл и переименовывает его поверх старого, поэтому
/// владельцем становится тот, кто пишет. Для файлов, которые правят через `sudo`, а
/// читает служба по группе, это ломает доступ: так 2026-09-11 `hearthctl manifest pin`
/// оставил `/etc/hearth/manifest.toml` с `root:root` вместо `root:hearth`, служба при
/// следующем старте не смогла его прочитать, сочла целостность нарушенной и
/// остановила релеи.
///
/// Владелец выставляется временному файлу ДО переименования: иначе на мгновение на
/// месте старого файла лежал бы файл, который служба прочитать не может. Если сменить
/// владельца нельзя, запись отменяется и старый файл остаётся как был.
///
/// Для НОВОГО файла прежнего владельца нет, и берётся владелец каталога. Без этого
/// `hearthd ca issue` под `sudo` оставлял свежий `auditor.pem` и перезаписанный
/// `admins.json` с `root:root`: служба под пользователем `hearth` переставала читать
/// реестр админов и отвергала ВСЕ клиентские сертификаты, включая владельца. Ровно
/// это и случилось 2026-09-11 — admin API закрылся для всех после выпуска одной новой
/// личности.
pub fn write_atomic_keep_owner(path: impl AsRef<Path>, body: &[u8], mode: u32) -> Result<()> {
    let path = path.as_ref();
    write_atomic_owned(path, body, mode, inherited_owner(path))
}

/// Владелец, который должен быть у файла: его собственный, иначе — каталога.
#[cfg(unix)]
fn inherited_owner(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path)
        .ok()
        .or_else(|| {
            path.parent()
                .and_then(|parent| std::fs::metadata(parent).ok())
        })
        .map(|m| (m.uid(), m.gid()))
}

#[cfg(not(unix))]
fn inherited_owner(_path: &Path) -> Option<(u32, u32)> {
    None
}

/// Выполнить «прочитать → изменить → записать» под эксклюзивной блокировкой.
///
/// # Зачем
///
/// Реестры (`admins.json`, `devices.json`) правятся двумя путями: демоном и
/// командами `hearthd`/`hearthctl`, которые человек запускает из другой сессии. Обе
/// стороны читают файл целиком, меняют и пишут обратно. Если `ca issue` загрузил
/// реестр до того, как `ca revoke` успел записать свой, запись issue вернёт файл к
/// состоянию без отметки об отзыве — и отозванный сертификат снова начнёт пускать.
/// Обе команды при этом отрапортуют успех.
///
/// Блокировка — отдельный файл, создаваемый эксклюзивно. Это работает и на том
/// единственном классе систем, который нас интересует, и не требует держать открытый
/// дескриптор между процессами.
///
/// Зависшая блокировка снимается по возрасту: процесс, убитый в середине операции,
/// не должен закрывать доступ навсегда.
pub fn with_lock<T>(path: impl AsRef<Path>, body: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock_path = path.as_ref().with_extension("lock");
    let deadline = std::time::Instant::now() + LOCK_TIMEOUT;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Чужая блокировка. Если она старше таймаута — процесс, взявший её,
                // умер, и держать из-за него узел неуправляемым нельзя.
                let stale = std::fs::metadata(&lock_path)
                    .and_then(|m| m.modified())
                    .map(|m| m.elapsed().unwrap_or_default() > LOCK_STALE_AFTER)
                    .unwrap_or(false);
                if stale {
                    let _ = std::fs::remove_file(&lock_path);
                    continue;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(Error::Conflict(format!(
                        "{} занят другой операцией",
                        path.as_ref().display()
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(40));
            }
            Err(e) => return Err(Error::io(&lock_path, e)),
        }
    }
    let result = body();
    let _ = std::fs::remove_file(&lock_path);
    result
}

/// Сколько ждать чужую блокировку, прежде чем отказать.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// С какого возраста блокировка считается брошенной.
///
/// Заметно больше времени ожидания, и это не запас «на всякий случай»: если пороги
/// равны, то через время ожидания блокировка УГОНЯЕТСЯ у живого процесса, который
/// просто выполняет долгую операцию, — и обе стороны снова пишут файл одновременно.
/// Пять минут — это больше, чем занимает любая операция с реестром, и меньше, чем
/// человек готов ждать после падения процесса.
const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(300);

/// Как [`write_json_atomic`], но с наследованием владельца.
pub fn write_json_atomic_keep_owner<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
    mode: u32,
) -> Result<()> {
    let body = serde_json::to_vec_pretty(value)?;
    write_atomic_keep_owner(path, &body, mode)
}

/// Как [`write_secret`], но с наследованием владельца.
pub fn write_secret_keep_owner(path: impl AsRef<Path>, secret: &str) -> Result<()> {
    write_atomic_keep_owner(path, format!("{secret}\n").as_bytes(), MODE_SECRET)
}

fn write_atomic_owned(
    path: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir(parent)?;
        }
    }
    let tmp = tmp_path(path);
    {
        // The mode is applied at creation, not after writing. Creating with the default
        // umask and chmod-ing afterwards leaves a window — short, but real — where a
        // relay password or a private key is world-readable. `create_new` also refuses
        // to follow an existing file, so a predictable temp name cannot be used to
        // point the write somewhere else.
        let mut file = open_tmp(&tmp, mode)?;
        file.write_all(body).map_err(|e| Error::io(&tmp, e))?;
        file.sync_all().map_err(|e| Error::io(&tmp, e))?;
    }
    set_mode(&tmp, mode)?;
    if let Some((uid, gid)) = owner {
        if let Err(e) = set_owner(&tmp, uid, gid) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))?;
    sync_parent(path)?;
    Ok(())
}

/// Досинхронизировать КАТАЛОГ после переименования.
///
/// `sync_all` на временном файле сохраняет его содержимое, но не запись каталога,
/// которая связала это содержимое с окончательным именем. После пропадания питания
/// каталог может вернуться в состояние «нового файла ещё нет» при полностью
/// сохранном содержимом — а для node-mode.json это ровно тот случай, ради которого
/// запрет и записывается на диск: он обязан пережить не перезапуск демона, а
/// выдернутый шнур. На не-unix это no-op: там нет способа открыть каталог.
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            // Относительное имя без каталога — синхронизировать нечего, кроме «.».
            _ => Path::new("."),
        };
        let dir = std::fs::File::open(parent).map_err(|e| Error::io(parent, e))?;
        dir.sync_all().map_err(|e| Error::io(parent, e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn set_owner(path: &Path, uid: u32, gid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // Владелец уже тот, что нужен, — менять нечего. Это не оптимизация: chown на
        // самого себя под непривилегированным пользователем отказывает на части
        // файловых систем, и демон под `hearth`, переписывающий свой же файл, получал
        // бы EPERM на ровном месте.
        if let Ok(meta) = std::fs::metadata(path) {
            if (meta.uid(), meta.gid()) == (uid, gid) {
                return Ok(());
            }
        }
        std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(|e| Error::io(path, e))?;
    }
    #[cfg(not(unix))]
    let _ = (path, uid, gid);
    Ok(())
}

/// Владелец, которого ОБЯЗАН получить файл, — владелец его КАТАЛОГА.
///
/// Два отличия от [`inherited_owner`], и оба существенные.
///
/// Первое: владелец берётся у каталога, а НЕ у самого файла. Для файлов, которые
/// правят и демон под `hearth`, и человек под `sudo` (файл режима, журналы алертов),
/// нынешний владелец файла — это ровно то, что здесь чинится: на узле, пострадавшем от
/// прежней записи без наследования, `node-mode.json` уже лежит как `root:root`, и
/// наследование «от файла» увековечило бы поломку. Каталог состояния создаёт
/// установщик, и его владелец — тот самый пользователь, под которым работает демон.
///
/// Второе: неопределимый владелец здесь — ошибка, а не «пишем как есть». Молча
/// созданный `root:root` не ломает саму команду — он ломает СЛЕДУЮЩИЙ старт демона,
/// то есть проявляется позже и совсем в другом месте.
fn required_owner(path: &Path) -> Result<Option<(u32, u32)>> {
    // Проверка одинакова на всех платформах, чтобы её можно было проверить тестом там,
    // где эти тесты идут. Создавать каталог самим здесь нельзя: он достался бы тому,
    // кто пишет, то есть root.
    let anchor = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if !anchor.is_dir() {
        return Err(Error::Config(format!(
            "не удалось определить владельца для {}: каталога {} нет. Создайте каталог \
             состояния с нужным владельцем (hearthd/deploy/install.sh или \
             deploy/fix-permissions.sh) и повторите: файл, созданный под root, hearthd \
             под пользователем hearth читать не сможет",
            path.display(),
            anchor.display()
        )));
    }
    Ok(owner_of(anchor))
}

/// Владелец каталога или файла. На не-unix владельцев в этом смысле нет.
#[cfg(unix)]
fn owner_of(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).ok().map(|m| (m.uid(), m.gid()))
}

#[cfg(not(unix))]
fn owner_of(_path: &Path) -> Option<(u32, u32)> {
    None
}

/// Жалоба на каталог состояния, доставшийся `root`.
///
/// Наследование владельца берёт его у КАТАЛОГА ([`required_owner`]). Пока каталог
/// принадлежит `hearth`, это и чинит владельческие тупики. Но если root-овым стал сам
/// каталог, наследовать нечего: и файл режима, и журналы алертов создаются `root:root`,
/// команда человека отчитывается успехом — а демон под `hearth` эти файлы не прочитает.
/// Исходный дефект воспроизводится молча и всплывает позже, уже без видимой причины.
///
/// Поэтому не отказ, а названная вслух беда вместе с командой выхода: отказать здесь
/// значило бы отнять у человека аварийное снятие режима ровно в тот вечер, ради
/// которого оно написано.
pub fn root_owned_dir_complaint(dir: impl AsRef<Path>) -> Option<String> {
    let dir = dir.as_ref();
    root_owned_dir_message(dir, owner_of(dir))
}

/// Текст жалобы отдельно от способа узнать владельца: владельцев в этом смысле нет на
/// не-unix, а проверять формулировку надо там, где идут тесты.
fn root_owned_dir_message(dir: &Path, owner: Option<(u32, u32)>) -> Option<String> {
    let (uid, _gid) = owner?;
    if uid != 0 {
        return None;
    }
    Some(format!(
        "каталог состояния {} принадлежит root: всё, что в нём создаётся с \
         наследованием владельца, достаётся root:root, и hearthd под пользователем \
         hearth это не прочитает. Выход: sudo hearthd/deploy/fix-permissions.sh \
         (вернёт каталогу и его файлам hearth:hearth), затем systemctl restart hearthd",
        dir.display()
    ))
}

/// Как [`write_atomic_keep_owner`], но неопределимый владелец — ОТКАЗ.
///
/// Для файла режима и журналов алертов это единственно верное поведение: их пишет и
/// демон под `hearth`, и человек под `sudo`, и файл, доставшийся `root`, оставляет
/// узел без управляющего контура до ручного `chown`. Лучше внятный отказ команде
/// человека, который стоит перед узлом, чем успех, ломающий демон через минуту.
pub fn write_atomic_inheriting_owner(path: impl AsRef<Path>, body: &[u8], mode: u32) -> Result<()> {
    let path = path.as_ref();
    // Владелец определяется ДО `ensure_dir` внутри записи: иначе недостающий каталог
    // создался бы от имени пишущего (root), и наследовать было бы уже нечего.
    let owner = required_owner(path)?;
    write_atomic_owned(path, body, mode, owner)
}

/// Как [`write_json_atomic`], но неопределимый владелец — отказ.
/// См. [`write_atomic_inheriting_owner`].
pub fn write_json_atomic_inheriting_owner<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
    mode: u32,
) -> Result<()> {
    let body = serde_json::to_vec_pretty(value)?;
    write_atomic_inheriting_owner(path, &body, mode)
}

/// Create the temp file with its final permissions already in place.
fn open_tmp(tmp: &Path, mode: u32) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    match options.open(tmp) {
        Ok(file) => Ok(file),
        // A leftover temp file from a killed process must not block writes forever.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(tmp).map_err(|e| Error::io(tmp, e))?;
            options.open(tmp).map_err(|e| Error::io(tmp, e))
        }
        Err(e) => Err(Error::io(tmp, e)),
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

/// Append one line to a journal file (JSONL), creating it if needed.
pub fn append_line(path: impl AsRef<Path>, line: &str) -> Result<()> {
    append_line_owned(path.as_ref(), line, false)
}

/// Как [`append_line`], но НОВЫЙ файл получает владельца каталога, а неопределимый
/// владелец — отказ.
///
/// Нужна там, где журнал может быть впервые создан из-под `sudo`: `alerts.jsonl` и
/// `egress-incidents.jsonl` пишет и демон под `hearth`, и локальные команды на узле.
/// Созданный под root, журнал закрывается для демона навсегда — узел остаётся без
/// записи алертов, и заметить это можно только по их отсутствию.
pub fn append_line_keep_owner(path: impl AsRef<Path>, line: &str) -> Result<()> {
    append_line_owned(path.as_ref(), line, true)
}

fn append_line_owned(path: &Path, line: &str, inherit: bool) -> Result<()> {
    let existed = path.exists();
    // Владелец определяется ДО создания каталога: иначе каталог, созданный под root,
    // сам стал бы источником неверного владельца.
    let owner = if inherit { required_owner(path)? } else { None };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir(parent)?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    if !existed {
        set_mode(path, MODE_STATE)?;
        if let Some((uid, gid)) = owner {
            if let Err(e) = set_owner(path, uid, gid) {
                // Строку ещё не писали: пустой файл с неверным владельцем убираем,
                // чтобы следующая попытка снова начала с чистого места.
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
        }
    } else if let Some((uid, gid)) = owner {
        // Журнал уже есть, но мог достаться не тому владельцу — например, от прежней
        // записи из-под `sudo`. Чиним по возможности и НЕ отказываем: алерт, который
        // не записан, хуже алерта, записанного под неудобным владельцем.
        if let Err(e) = set_owner(path, uid, gid) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "владельца журнала исправить не удалось"
            );
        }
    }
    writeln!(file, "{line}").map_err(|e| Error::io(path, e))?;
    file.sync_data().map_err(|e| Error::io(path, e))?;
    Ok(())
}

/// Read the last `limit` lines of a JSONL journal, oldest first.
pub fn tail_lines(path: impl AsRef<Path>, limit: usize) -> Result<Vec<String>> {
    let path = path.as_ref();
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(path, e)),
    };
    let lines: Vec<String> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    let start = lines.len().saturating_sub(limit);
    Ok(lines[start..].to_vec())
}

/// Как [`tail_lines`], но НЕЧИТАЕМЫЙ журнал — не повод остановиться.
///
/// Возвращает прочитанное и, если прочитать не удалось, жалобу человеческими словами.
/// Нужна там, где журнал читают на пути старта: демон, не сумевший прочитать
/// `alerts.jsonl`, обязан подняться и объяснить беду, а не исчезнуть с узла — иначе
/// семья остаётся без надзора, целостности, бэкапа и admin API из-за прав на один
/// файл. Уже записанное не теряется: дозапись идёт в тот же файл, в конец.
pub fn tail_lines_best_effort(
    path: impl AsRef<Path>,
    limit: usize,
) -> (Vec<String>, Option<String>) {
    let path = path.as_ref();
    match tail_lines(path, limit) {
        Ok(lines) => (lines, None),
        Err(e) => (
            Vec::new(),
            Some(format!(
                "журнал {} не прочитан ({e}): нумерация алертов начнётся заново, уже \
                 записанное останется в файле. Обычная причина — владелец или права: \
                 sudo hearthd/deploy/fix-permissions.sh, затем systemctl restart hearthd",
                path.display()
            )),
        ),
    }
}

/// Привести владельца УЖЕ СУЩЕСТВУЮЩЕГО файла к владельцу его каталога — по возможности.
///
/// Нужна ровно там, где файл сначала ЧИТАЮТ, а потом дописывают.
/// [`append_line_keep_owner`] чинит владельца сама, но делает это при записи: чтение,
/// идущее раньше, успевает упереться в того же неверного владельца, и вызывающий
/// выходит с ошибкой ДО починки — то есть починка не случается никогда.
///
/// Ничего не возвращает намеренно: отсутствующий файл, неопределимый владелец и отказ
/// `chown` здесь не ошибки. Это попытка улучшить положение перед чтением, а не условие
/// работы; настоящий отказ придёт от самой записи и будет назван там.
pub fn adopt_dir_owner(path: impl AsRef<Path>) {
    let path = path.as_ref();
    if !path.exists() {
        return;
    }
    let Ok(Some((uid, gid))) = required_owner(path) else {
        return;
    };
    if let Err(e) = set_owner(path, uid, gid) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "владельца файла исправить не удалось"
        );
    }
}

/// Read a secret (relay password, TURN secret, Gotify token).
///
/// Trailing whitespace is stripped — an accidental newline in a password file would
/// otherwise change the queue-creation password and lock every client out.
pub fn read_secret(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let secret = raw.trim().to_string();
    if secret.is_empty() {
        return Err(Error::Config(format!(
            "secret file {} is empty",
            path.display()
        )));
    }
    warn_if_world_readable(path);
    Ok(secret)
}

/// Write a secret with `0600`.
pub fn write_secret(path: impl AsRef<Path>, secret: &str) -> Result<()> {
    write_atomic(path, format!("{secret}\n").as_bytes(), MODE_SECRET)
}

#[cfg(unix)]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o077;
        if mode != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", meta.permissions().mode() & 0o777),
                "secret file is readable beyond its owner"
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &Path) {}

/// Generate `n` bytes of cryptographic randomness, hex-encoded.
///
/// Used for relay passwords and the TURN static secret.
pub fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {

    #[test]
    fn write_keeping_owner_replaces_content_and_keeps_the_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.toml");
        write_atomic(&path, b"old", MODE_STATE).unwrap();
        #[cfg(unix)]
        let before = {
            use std::os::unix::fs::MetadataExt as _;
            let m = std::fs::metadata(&path).unwrap();
            (m.uid(), m.gid())
        };
        write_atomic_keep_owner(&path, b"new", MODE_STATE).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let m = std::fs::metadata(&path).unwrap();
            assert_eq!((m.uid(), m.gid()), before);
        }
    }

    #[test]
    fn write_keeping_owner_creates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.toml");
        write_atomic_keep_owner(&path, b"x", MODE_STATE).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Doc {
        a: u32,
    }

    #[test]
    fn json_round_trip_is_atomic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("doc.json");
        assert_eq!(read_json::<Doc>(&path).expect("missing ok"), None);
        write_json_atomic(&path, &Doc { a: 7 }, MODE_STATE).expect("write");
        assert_eq!(read_json::<Doc>(&path).expect("read"), Some(Doc { a: 7 }));
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().expect("parent"))
            .expect("readdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn an_overwrite_survives_the_directory_sync() {
        // После переименования синхронизируется родительский каталог — иначе запрет,
        // записанный на диск, мог бы не пережить пропадание питания. Проверить сам
        // fsync юнит-тестом нельзя; проверяем то, что можно: перезапись существующего
        // файла по-прежнему проходит целиком и не оставляет мусора.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node-mode.json");
        write_json_atomic(&path, &Doc { a: 1 }, MODE_STATE).expect("first write");
        write_json_atomic(&path, &Doc { a: 2 }, MODE_STATE).expect("overwrite");
        assert_eq!(read_json::<Doc>(&path).expect("read"), Some(Doc { a: 2 }));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, MODE_STATE);
        }
    }

    #[test]
    fn a_journal_created_from_sudo_keeps_the_directory_owner() {
        // Дефект: `record_offline` под root создавал alerts.jsonl / egress-incidents.jsonl
        // обычной `append_line`, которая владельца не наследует. На узле, где журналов
        // ещё нет, локальное снятие режима закрывало демону запись в них навсегда.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("alerts.jsonl");
        append_line_keep_owner(&path, "первая").expect("создание журнала");
        append_line_keep_owner(&path, "вторая").expect("дозапись");
        assert_eq!(
            tail_lines(&path, 10).expect("tail"),
            vec!["первая".to_string(), "вторая".to_string()]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let file = std::fs::metadata(&path).expect("stat file");
            let parent = std::fs::metadata(dir.path()).expect("stat dir");
            assert_eq!(
                (file.uid(), file.gid()),
                (parent.uid(), parent.gid()),
                "новый журнал обязан достаться владельцу каталога состояния"
            );
        }
    }

    #[test]
    fn writing_without_an_owner_to_inherit_is_refused() {
        // Молча созданный файл с чужим владельцем не ломает саму команду — он ломает
        // СЛЕДУЮЩИЙ старт демона, то есть проявляется позже и в другом месте. Человеку,
        // который стоит перед узлом, лучше внятный отказ.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("нет-каталога").join("node-mode.json");
        let err = write_atomic_inheriting_owner(&path, b"{}", MODE_STATE)
            .expect_err("отказ вместо файла с чужим владельцем");
        assert!(err.to_string().contains("владельца"), "{err}");
        assert!(!path.exists());

        let journal = dir.path().join("нет-каталога").join("alerts.jsonl");
        let err = append_line_keep_owner(&journal, "x").expect_err("тот же отказ");
        assert!(err.to_string().contains("владельца"), "{err}");
        assert!(!journal.exists());
    }

    #[test]
    fn journal_appends_and_tails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("alerts.jsonl");
        for i in 0..5 {
            append_line(&path, &format!("line{i}")).expect("append");
        }
        let tail = tail_lines(&path, 2).expect("tail");
        assert_eq!(tail, vec!["line3".to_string(), "line4".to_string()]);
        assert_eq!(
            tail_lines(dir.path().join("nope"), 10).expect("missing"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_unreadable_journal_is_a_complaint_and_not_a_dead_daemon() {
        // Дефект: демон читал alerts.jsonl оператором вопроса на пути старта. Узел, у
        // которого журнал стал root-овым или потерял права, не поднимался ВООБЩЕ —
        // семья оставалась без надзора, целостности, бэкапа и admin API из-за прав на
        // один файл. Читаемый журнал — не условие работы узла.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("alerts.jsonl");
        append_line(&path, "первая").expect("append");

        let (lines, complaint) = tail_lines_best_effort(&path, 10);
        assert_eq!(lines, vec!["первая".to_string()]);
        assert!(complaint.is_none(), "{complaint:?}");

        // Нечитаемый журнал воспроизводится переносимо и правдоподобно: оборванная
        // запись оставляет в файле байты, которые не складываются в UTF-8, и чтение
        // отказывает ровно так же, как на чужом владельце, — но дозапись возможна.
        // Чужого владельца в тесте не изобразить: он требует второго пользователя.
        let broken = dir.path().join("битый.jsonl");
        std::fs::write(&broken, [0xff, 0xfe, 0x0a]).expect("оборванная запись");
        let (lines, complaint) = tail_lines_best_effort(&broken, 10);
        assert!(lines.is_empty());
        let complaint = complaint.expect("нечитаемый журнал обязан быть назван");
        assert!(complaint.contains("битый.jsonl"), "{complaint}");
        assert!(
            complaint.contains("fix-permissions.sh"),
            "жалоба обязана назвать команду выхода: {complaint}"
        );

        // Уже записанное не теряется: дозапись идёт в конец того же файла.
        append_line(&path, "вторая").expect("append");
        assert_eq!(tail_lines(&path, 10).expect("tail").len(), 2);
    }

    #[test]
    fn a_root_owned_state_dir_is_named_together_with_the_way_out() {
        // Root-овый КАТАЛОГ состояния воспроизводит владельческий тупик молча:
        // наследовать владельца не у кого, файл создаётся root:root, команда человека
        // отчитывается успехом, а демон при следующем старте снова его не прочитает.
        // Владельцев в этом смысле нет на не-unix, поэтому проверяется сам текст.
        let dir = std::path::Path::new("/var/lib/hearth");
        assert!(
            root_owned_dir_message(dir, None).is_none(),
            "неизвестный владелец — не повод пугать человека"
        );
        assert!(
            root_owned_dir_message(dir, Some((998, 998))).is_none(),
            "каталог демона в порядке"
        );
        let complaint = root_owned_dir_message(dir, Some((0, 0)))
            .expect("root-овый каталог обязан быть назван");
        assert!(complaint.contains("/var/lib/hearth"), "{complaint}");
        assert!(
            complaint.contains("fix-permissions.sh"),
            "беда без команды выхода — это просто беда: {complaint}"
        );
    }

    #[test]
    fn adopting_the_dir_owner_never_fails_the_caller() {
        // Функция стоит ПЕРЕД чтением журнала и обязана быть безобидной: отсутствующий
        // файл, неопределимый владелец и отказ chown не должны мешать записи алерта.
        let dir = tempfile::tempdir().expect("tempdir");
        adopt_dir_owner(dir.path().join("нет-такого.jsonl"));
        adopt_dir_owner(dir.path().join("нет-каталога").join("alerts.jsonl"));

        let path = dir.path().join("alerts.jsonl");
        append_line(&path, "строка").expect("append");
        adopt_dir_owner(&path);
        assert_eq!(tail_lines(&path, 10).expect("tail").len(), 1);
    }

    #[test]
    fn the_runbook_names_the_script_that_actually_fixes_the_owners() {
        // Жалобы демона и hearthctl называют deploy/fix-permissions.sh. Скрипт, не
        // названный в runbook, ночью не найдут; runbook, обещающий не то, что скрипт
        // делает, — хуже отсутствующего. Проверяем обе стороны обещания.
        let runbook = include_str!("../../docs/runbook-node-mode.md");
        assert!(
            runbook.contains("fix-permissions.sh"),
            "runbook обязан назвать штатный выход из владельческих тупиков"
        );

        let script = include_str!("../deploy/fix-permissions.sh");
        // Root-овый каталог состояния и журналы внутри него — один и тот же chown -R.
        assert!(
            script.contains("chown -R hearth:hearth"),
            "скрипт обязан чинить владельца рекурсивно"
        );
        for dir in ["/var/lib/hearth", "/var/opt/hearth"] {
            assert!(script.contains(dir), "скрипт обязан назвать {dir}");
        }
        assert!(
            script.contains("alerts.jsonl"),
            "журналы алертов — часть того же тупика, и это должно быть видно в скрипте"
        );
    }

    #[test]
    fn secrets_are_trimmed_and_non_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pass");
        write_secret(&path, "s3cret").expect("write");
        assert_eq!(read_secret(&path).expect("read"), "s3cret");
        write_atomic(&path, b"   \n", MODE_SECRET).expect("write empty");
        assert!(read_secret(&path).is_err());
    }

    #[test]
    fn a_lock_serialises_read_modify_write() {
        // Без блокировки вторая команда загружает файл до записи первой и затирает
        // её изменение — обе при этом отчитываются об успехе.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        write_atomic(&path, b"0", MODE_STATE).unwrap();

        let counter = std::sync::Arc::new(std::sync::Mutex::new(0u32));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let path = path.clone();
                let counter = counter.clone();
                scope.spawn(move || {
                    with_lock(&path, || {
                        // Чтение и запись внутри блокировки: снаружи они разъезжаются.
                        let current: u32 = std::fs::read_to_string(&path)
                            .unwrap()
                            .trim()
                            .parse()
                            .unwrap();
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        write_atomic(&path, (current + 1).to_string().as_bytes(), MODE_STATE)?;
                        *counter.lock().unwrap() += 1;
                        Ok(())
                    })
                    .expect("lock");
                });
            }
        });

        let final_value: u32 = std::fs::read_to_string(&path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(*counter.lock().unwrap(), 8);
        assert_eq!(final_value, 8, "ни одно изменение не должно потеряться");
    }

    #[test]
    fn a_busy_lock_gives_up_instead_of_hanging() {
        // Чужая блокировка не должна вешать команду навсегда: через таймаут человек
        // получает внятный отказ, а не молчащий терминал.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let lock = path.with_extension("lock");
        std::fs::write(&lock, b"").unwrap();

        let started = std::time::Instant::now();
        let outcome = with_lock(&path, || Ok(42));
        assert!(outcome.is_err(), "занятая блокировка обязана быть отказом");
        assert!(
            started.elapsed() >= LOCK_TIMEOUT,
            "отказ не должен приходить раньше таймаута ожидания"
        );
    }

    #[test]
    fn random_hex_has_expected_length_and_varies() {
        let a = random_hex(24);
        let b = random_hex(24);
        assert_eq!(a.len(), 48);
        assert_ne!(a, b);
    }
}
