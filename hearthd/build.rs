//! Паспорт сборки: вшивает в бинарник, из какого дерева исходников он собран.
//!
//! # Зачем
//!
//! Установленный `hearthd` умел сообщить о себе ровно строку `0.1.0` — одинаковую для
//! любой сборки любого коммита за всю историю ветки. Посчитать sha256 файла на узле
//! можно, но сопоставить его с коммитом было не с чем: таблицы «коммит → sha256»
//! никто не ведёт, а строк с коммитом внутри бинарника не было. Аудит упирался в это
//! первым же вопросом «из чего это собрано», и ответить было нечем.
//!
//! # Почему не переменная окружения
//!
//! Очевидный способ — `GIT_COMMIT=$(git rev-parse HEAD) cargo build` — доказывает
//! ровно ничего: значение в паспорт кладёт тот же человек, который собирает, и любая
//! строка подойдёт. Поэтому здесь ни одно поле провенанса не читается из окружения:
//! всё спрашивается у git прямо отсюда. Cargo передаёт результат `cargo::rustc-env`
//! в окружение самого rustc, перекрывая одноимённую внешнюю переменную, — то есть
//! подставить своё значение снаружи нельзя, не подменив этот файл (а он сам входит в
//! `HEARTH_TREE_SHA256`).
//!
//! # Что паспорт доказывает и чего НЕ доказывает
//!
//! Доказывает: «этот бинарник собран из дерева с таким содержимым, и это дерево —
//! коммит X, не изменённый после checkout». Проверяется чужими руками: см.
//! [`tree_sha256`] — команда для независимого пересчёта выписана там же.
//!
//! НЕ доказывает, что в дереве нет закладки. Паспорт связывает бинарник с
//! ИСХОДНИКАМИ; доверие к самим исходникам даёт чтение кода, а не хеш. И не
//! доказывает побайтовую воспроизводимость сборки — это отдельная задача
//! (`deploy/build-reproducible.sh`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Что входит в хеш дерева.
///
/// Ровно то, из чего получается бинарник, и ничего сверх. `docs/` и `android/` в
/// сборку не попадают: включи их — и правка опечатки в руководстве меняла бы паспорт
/// демона, то есть значение перестало бы быть сравнимым между выпусками и его быстро
/// научились бы игнорировать. `build.rs` включён намеренно: он и есть то, что пишет
/// паспорт, и подмена его без следа сделала бы всю затею бессмысленной.
const TREE_PATHS: [&str; 5] = [
    "src",
    "build.rs",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
];

/// Значение поля, которое узнать не удалось.
///
/// Отсутствие git при сборке не валит сборку: демон собирают и на машинах, где
/// разворачивают архив без истории. Но и молчать об этом нельзя — `unknown` в
/// паспорте читается как «сопоставить не с чем», а пустая строка выглядела бы как
/// пропущенное поле.
const UNKNOWN: &str = "unknown";

fn main() {
    let dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from("."),
    };

    let commit = git(&dir, &["rev-parse", "HEAD"])
        .filter(|c| c.len() == 40 && c.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| UNKNOWN.to_string());

    // Fail-closed: «выяснить не удалось» приравнено к «дерево грязное». Обратное
    // умолчание означало бы, что сборка без git утверждает чистоту, которую никто не
    // проверял, — а именно на это утверждение и смотрит аудитор.
    let dirty = match git(&dir, &["status", "--porcelain"]) {
        Some(out) => !out.trim().is_empty(),
        None => true,
    };

    let tree = tree_sha256(&dir).unwrap_or_else(|| UNKNOWN.to_string());

    let target = std::env::var("TARGET").unwrap_or_else(|_| UNKNOWN.to_string());
    let rustc = rustc_version().unwrap_or_else(|| UNKNOWN.to_string());

    // Дата сборки НЕ входит в хеш дерева: иначе два прогона одного коммита давали бы
    // разные значения и сверять стало бы нечего. Отдельным полем, из
    // SOURCE_DATE_EPOCH (его задаёт воспроизводимая сборка), иначе — дата коммита.
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| git(&dir, &["log", "-1", "--format=%ct"]))
        .unwrap_or_else(|| UNKNOWN.to_string());

    println!("cargo:rustc-env=HEARTH_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=HEARTH_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=HEARTH_TREE_SHA256={tree}");
    println!("cargo:rustc-env=HEARTH_BUILD_TARGET={target}");
    println!("cargo:rustc-env=HEARTH_RUSTC={rustc}");
    println!("cargo:rustc-env=HEARTH_SOURCE_DATE_EPOCH={epoch}");

    // Пересобираться надо и при правке файла, и при переезде на другой коммит.
    for path in TREE_PATHS {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(git_dir) = git(&dir, &["rev-parse", "--absolute-git-dir"]) {
        let git_dir = Path::new(&git_dir);
        for marker in ["HEAD", "index"] {
            println!("cargo:rerun-if-changed={}", git_dir.join(marker).display());
        }
    }
}

/// Хеш дерева исходников — то, что аудитор пересчитывает у себя.
///
/// Считается по НОРМАЛИЗОВАННОМУ git'ом содержимому рабочих файлов
/// (`git hash-object`), а не по байтам с диска. Причина прозаична: в этом
/// репозитории `core.autocrlf=true`, и один и тот же коммит на Windows и на Linux
/// лежит в рабочем дереве разными байтами. Хеш по байтам с диска зависел бы от
/// машины сборщика и не сходился бы у проверяющего — то есть не годился бы ровно для
/// того, ради чего заведён. `hash-object` смотрит на рабочий файл (а не на индекс),
/// поэтому несохранённая правка хеш меняет.
///
/// Пути внутри хеша — от корня репозитория (`--full-name`), а не от каталога крейта:
/// `git hash-object --stdin-paths` разрешает их именно от корня, и совпадение двух
/// систем координат здесь важнее краткости.
///
/// Независимая проверка на чистом клоне коммита (из корня репозитория):
///
/// ```sh
/// git ls-files -- hearthd/src hearthd/build.rs hearthd/Cargo.toml \
///                 hearthd/Cargo.lock hearthd/rust-toolchain.toml \
///   | LC_ALL=C sort \
///   | while read -r p; do printf '%s\0%s\0' "$p" "$(git hash-object "$p")"; done \
///   | sha256sum
/// ```
fn tree_sha256(dir: &Path) -> Option<String> {
    let mut args = vec!["ls-files", "--full-name", "--"];
    args.extend(TREE_PATHS);
    let listing = git(dir, &args)?;

    let mut paths: Vec<&str> = listing
        .lines()
        .map(str::trim_end)
        .filter(|p| !p.is_empty())
        .collect();
    if paths.is_empty() {
        return None;
    }
    // Имя с переводом строки развалило бы и передачу списка в git, и сам формат
    // хеширования. Такого имени в дереве нет и быть не должно; если появится —
    // честнее сказать «неизвестно», чем посчитать хеш по обрезанному списку.
    if paths
        .iter()
        .any(|p| p.contains('\n') || p.contains('\r') || p.contains('\0'))
    {
        return None;
    }
    paths.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    paths.dedup();

    let stdin_body = {
        let mut body = paths.join("\n");
        body.push('\n');
        body
    };
    let blobs = git_with_stdin(dir, &["hash-object", "--stdin-paths"], &stdin_body)?;
    let blobs: Vec<&str> = blobs
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if blobs.len() != paths.len() {
        return None;
    }

    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    for (path, blob) in paths.iter().zip(&blobs) {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update(blob.as_bytes());
        hasher.update([0u8]);
    }
    Some(hex::encode(hasher.finalize()))
}

/// Версия компилятора — одной строкой, как её печатает `rustc -V`.
///
/// Берётся у ТОГО rustc, которым идёт сборка (cargo кладёт путь в `RUSTC`), а не у
/// того, что первым нашёлся в PATH: на машине с несколькими тулчейнами это разные
/// программы.
fn rustc_version() -> Option<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let out = Command::new(rustc).arg("-V").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8(out.stdout).ok()?;
    let line = line.lines().next()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// Вызов git. `None` — git недоступен, это не репозиторий или команда не удалась.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.trim_end_matches(['\n', '\r']).to_string())
}

/// То же, но со списком путей на stdin.
///
/// Список весит килобайты и умещается в буфер трубы, поэтому пишется до чтения
/// вывода: отдельный поток тут не нужен, а взаимной блокировки не возникает.
fn git_with_stdin(dir: &Path, args: &[&str], body: &str) -> Option<String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(body.as_bytes()).ok()?;
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}
