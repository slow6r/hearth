//! Pinned upstream versions and hashes — `/etc/hearth/manifest.toml` (ТЗ §6.1, §7.3).
//!
//! One source of truth for what is allowed to run on the node. `latest` does not
//! exist here: every artefact is a tag plus a sha256. The integrity module compares
//! the running binaries against this file at start-up and hourly (A12).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The manifest document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub upstream: Upstream,
    /// Every binary that must match a known hash.
    #[serde(default, rename = "binary")]
    pub binaries: Vec<BinaryEntry>,
}

/// Provenance of the pinned upstream release.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// simplexmq release tag, e.g. `v6.4.2`.
    pub simplexmq_tag: String,
    /// simplex-chat release tag the Android fork rebases onto.
    pub simplex_chat_tag: String,
    /// GPG identity whose signature was verified for the release artefacts.
    pub gpg_identity: String,
    /// When the pin was last reviewed (ISO date).
    pub reviewed: String,
}

/// One pinned binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryEntry {
    /// Logical name, e.g. `smp-server`.
    pub name: String,
    /// Absolute path on the node.
    pub path: PathBuf,
    /// Upstream version/tag this binary came from.
    pub version: String,
    /// Lowercase hex sha256 of the file.
    pub sha256: String,
    /// Where it was obtained from (release URL or `built-from-source`).
    #[serde(default)]
    pub source: Option<String>,
    /// Коммит, из которого собран запиненный файл (для своих бинарников).
    ///
    /// # Почему это НЕ участвует в проверке целостности
    ///
    /// Проверка отвечает на вопрос «файл на диске тот же, что запинен», и ответ на
    /// него даёт только sha256. Начни сверять ещё и коммит — и любой перепин версии
    /// (то есть штатное обновление) ронял бы узел в карантин из-за расхождения
    /// строки, которую никто не измеряет. Здесь это ЗАПИСЬ О ПРОИСХОЖДЕНИИ: она
    /// отвечает на другой вопрос — «а запинен-то файл из какого кода», — и её
    /// ценность в том, что её можно сверить с `hearthd build-info` и с журналом
    /// установки, а не в том, что из-за неё что-то останавливается.
    ///
    /// `None` у upstream-бинарников: у них внешний якорь доверия — GPG-подпись
    /// релиза (см. `[upstream]`), и коммита в нашем смысле у них нет.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Хеш дерева исходников той же сборки (`hearthd build-info`, поле
    /// `tree_sha256`). Тем же полем сборка сверяется с чистым клоном коммита.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_sha256: Option<String>,
}

/// Провенанс сборки, записываемый рядом с хешем.
///
/// Отдельный тип, а не два параметра: коммит без хеша дерева (и наоборот) —
/// наполовину заполненная запись, по которой ничего не проверишь.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryProvenance {
    pub commit: String,
    pub tree_sha256: String,
}

impl EntryProvenance {
    /// Разобрать вывод `<binary> build-info --json`.
    ///
    /// Поля `unknown` — не провенанс: сборка без git не может сказать, из чего она
    /// сделана, и записывать это в манифест значит выдавать незнание за запись.
    pub fn from_build_info_json(raw: &str) -> Result<Self> {
        let doc: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| Error::Parse(e.to_string()))?;
        let field = |name: &str| -> Result<String> {
            doc.get(name)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| Error::invalid(format!("в паспорте сборки нет поля `{name}`")))
        };
        let provenance = Self {
            commit: field("commit")?,
            tree_sha256: field("tree_sha256")?,
        };
        provenance.validate()?;
        Ok(provenance)
    }

    /// Обе величины — шестнадцатеричные и нужной длины.
    pub fn validate(&self) -> Result<()> {
        if self.commit.len() != 40 || !self.commit.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::invalid(format!(
                "`{}` не похоже на коммит (40 hex)",
                self.commit
            )));
        }
        if self.tree_sha256.len() != 64 || !self.tree_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::invalid(format!(
                "`{}` не похоже на sha256 дерева (64 hex)",
                self.tree_sha256
            )));
        }
        Ok(())
    }
}

/// Result of checking one binary against the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityFinding {
    pub name: String,
    pub path: PathBuf,
    pub expected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    pub status: IntegrityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// Hash matches the manifest.
    Ok,
    /// Hash differs — the binary was replaced. Critical (ТЗ §7.3).
    Mismatch,
    /// File is missing or unreadable.
    Missing,
    /// Хеш в манифесте — нулевой плейсхолдер: этот бинарь ещё никто не пинил.
    ///
    /// Отдельный статус, а не `Mismatch`, потому что это разные события. «Хеш не
    /// совпал» означает подмену и стоит карантина. «Хеш не записан» означает
    /// невыполненный шаг установки — поставочный manifest.toml приходит с нулями во
    /// ВСЕХ записях, включая `turnserver`, о котором печатный список шагов раньше не
    /// упоминал. Свежеустановленный узел через час объявлял себе подмену и уходил в
    /// карантин, переживающий перезагрузку, — то есть семья теряла связь из-за
    /// пропущенной строки в инструкции, а не из-за атаки.
    Unpinned,
}

/// Нулевой плейсхолдер: 64 нуля вместо хеша.
pub const UNPINNED_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

impl Manifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let manifest: Manifest = toml::from_str(&raw)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.binaries.is_empty() {
            return Err(Error::config("manifest lists no binaries"));
        }
        for entry in &self.binaries {
            if entry.sha256.len() != 64 || !entry.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Error::config(format!(
                    "manifest entry `{}` has an invalid sha256: {}",
                    entry.name, entry.sha256
                )));
            }
            if entry.sha256.chars().any(|c| c.is_ascii_uppercase()) {
                return Err(Error::config(format!(
                    "manifest entry `{}` sha256 must be lowercase hex",
                    entry.name
                )));
            }
            if entry.version.eq_ignore_ascii_case("latest") {
                return Err(Error::config(format!(
                    "manifest entry `{}` uses `latest`, which ТЗ §2.6 forbids",
                    entry.name
                )));
            }
        }
        Ok(())
    }

    pub fn binary(&self, name: &str) -> Option<&BinaryEntry> {
        self.binaries.iter().find(|b| b.name == name)
    }

    /// Hash every listed binary and compare against the pin.
    pub fn verify_all(&self) -> Vec<IntegrityFinding> {
        self.binaries.iter().map(verify_one).collect()
    }
}

fn verify_one(entry: &BinaryEntry) -> IntegrityFinding {
    // «Ещё не запинено» решается ДО чтения файла: сам файл при этом может быть каким
    // угодно — сказать про него нечего, пока в манифесте стоит плейсхолдер.
    if entry.sha256 == UNPINNED_SHA256 {
        return IntegrityFinding {
            name: entry.name.clone(),
            path: entry.path.clone(),
            expected: entry.sha256.clone(),
            // Измеренный хеш кладём рядом: его же оператор и запинит.
            actual: sha256_file(&entry.path).ok(),
            status: IntegrityStatus::Unpinned,
        };
    }
    match sha256_file(&entry.path) {
        Ok(actual) => {
            let status = if actual == entry.sha256 {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Mismatch
            };
            IntegrityFinding {
                name: entry.name.clone(),
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: Some(actual),
                status,
            }
        }
        Err(_) => IntegrityFinding {
            name: entry.name.clone(),
            path: entry.path.clone(),
            expected: entry.sha256.clone(),
            actual: None,
            status: IntegrityStatus::Missing,
        },
    }
}

/// Rewrite one binary's `sha256` (and optionally `version`) in the raw manifest text.
///
/// Line based on purpose: re-serializing through `toml` would drop every comment, and
/// this file's comments are the operating instructions for verifying a release.
///
/// # Провенанс
///
/// `provenance = Some(..)` записывает рядом `commit` и `tree_sha256`; `None` —
/// УДАЛЯЕТ их, если они там были. Второе важнее первого: перепин меряет новый файл, и
/// оставленная от прежнего файла запись о происхождении превратилась бы в ложное
/// утверждение — причём выглядящее убедительнее, чем его отсутствие. Отсутствие
/// записи честно читается как «происхождение не заявлено».
pub fn pin(
    raw: &str,
    name: &str,
    sha256: &str,
    version: Option<&str>,
    provenance: Option<&EntryProvenance>,
) -> Result<String> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::invalid(format!("`{sha256}` is not a sha256 digest")));
    }
    let sha256 = sha256.to_ascii_lowercase();
    if let Some(provenance) = provenance {
        provenance.validate()?;
    }

    let lines: Vec<&str> = raw.lines().collect();
    let Some(name_line) = lines
        .iter()
        .position(|line| is_name_line(line.trim(), name))
    else {
        return Err(Error::NotFound(format!("manifest entry `{name}`")));
    };
    // Таблица записи: от её заголовка `[[binary]]` до следующего заголовка. Ключи
    // ищутся по всей таблице, а не только ниже строки `name`: порядок ключей в TOML
    // произволен, и запись, где `name` стоит вторым, правилась бы наполовину.
    let start = lines[..name_line]
        .iter()
        .rposition(|line| line.trim_start().starts_with('['))
        .map(|i| i + 1)
        .unwrap_or(0);
    let end = lines[name_line + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map(|i| name_line + 1 + i)
        .unwrap_or(lines.len());

    let mut block: Vec<String> = Vec::new();
    let mut replaced_sha = false;
    let mut replaced_commit = false;
    let mut replaced_tree = false;
    // Куда дописывать ключ, которого в записи ещё нет: сразу после последней строки
    // «ключ = значение». Не в конец блока — там могут быть пустые строки и
    // комментарий, относящийся к СЛЕДУЮЩЕЙ записи.
    let mut last_key: Option<usize> = None;

    for line in &lines[start..end] {
        let trimmed = line.trim();
        if trimmed.starts_with("sha256") {
            block.push(format!("sha256 = \"{sha256}\""));
            replaced_sha = true;
            last_key = Some(block.len() - 1);
            continue;
        }
        if trimmed.starts_with("version") {
            if let Some(version) = version {
                block.push(format!("version = \"{version}\""));
                last_key = Some(block.len() - 1);
                continue;
            }
        }
        // Обе ветки ниже устроены одинаково: строка либо переписывается новым
        // значением, либо ИСЧЕЗАЕТ (`provenance == None`) — см. доктрину в шапке.
        if trimmed.starts_with("commit") {
            if let Some(provenance) = provenance {
                block.push(format!("commit = \"{}\"", provenance.commit));
                replaced_commit = true;
                last_key = Some(block.len() - 1);
            }
            continue;
        }
        if trimmed.starts_with("tree_sha256") {
            if let Some(provenance) = provenance {
                block.push(format!("tree_sha256 = \"{}\"", provenance.tree_sha256));
                replaced_tree = true;
                last_key = Some(block.len() - 1);
            }
            continue;
        }
        block.push((*line).to_string());
        if !trimmed.starts_with('#') && trimmed.contains('=') {
            last_key = Some(block.len() - 1);
        }
    }

    if !replaced_sha {
        return Err(Error::invalid(format!(
            "manifest entry `{name}` has no sha256 line to update"
        )));
    }

    if let Some(provenance) = provenance {
        let mut fresh: Vec<String> = Vec::new();
        if !replaced_commit {
            fresh.push(format!("commit = \"{}\"", provenance.commit));
        }
        if !replaced_tree {
            fresh.push(format!("tree_sha256 = \"{}\"", provenance.tree_sha256));
        }
        if !fresh.is_empty() {
            let at = last_key.map(|i| i + 1).unwrap_or(block.len());
            for (offset, line) in fresh.into_iter().enumerate() {
                block.insert(at + offset, line);
            }
        }
    }

    let mut out: Vec<String> = lines[..start].iter().map(|l| (*l).to_string()).collect();
    out.extend(block);
    out.extend(lines[end..].iter().map(|l| (*l).to_string()));

    let mut text = out.join("\n");
    if raw.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

fn is_name_line(trimmed: &str, name: &str) -> bool {
    let Some(value) = trimmed.strip_prefix("name") else {
        return false;
    };
    let Some(value) = value.trim_start().strip_prefix('=') else {
        return false;
    };
    value.trim().trim_matches('"') == name
}

/// Streaming sha256 of a file (binaries are ~100 MB; never read them whole).
pub fn sha256_file(path: impl AsRef<Path>) -> Result<String> {
    use sha2::{Digest, Sha256};
    let path = path.as_ref();
    let mut file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| Error::io(path, e))?;
    Ok(hex::encode(hasher.finalize()))
}

/// sha256 of a byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reference_manifest_parses() {
        let raw = include_str!("../../manifest.toml");
        let manifest: Manifest = toml::from_str(raw).expect("manifest parses");
        manifest.validate().expect("manifest is valid");
        assert!(manifest.binary("smp-server").is_some());
        assert!(manifest.binary("xftp-server").is_some());
    }

    #[test]
    fn a_zero_placeholder_is_not_a_substitution() {
        // Дефект 19: поставочный manifest.toml приходит с нулевыми плейсхолдерами во
        // ВСЕХ записях, включая turnserver, которого печатный список шагов не называл.
        // Через час integrity объявлял это подменой, и свежеустановленный узел уходил
        // в карантин, переживающий перезагрузку, — из-за невыполненной строки
        // инструкции, а не из-за атаки.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("turnserver");
        std::fs::write(&file, b"turn").expect("write");

        let entry = BinaryEntry {
            name: "turnserver".into(),
            path: file.clone(),
            version: "distro".into(),
            sha256: UNPINNED_SHA256.to_string(),
            source: None,
            commit: None,
            tree_sha256: None,
        };
        let finding = verify_one(&entry);
        assert_eq!(finding.status, IntegrityStatus::Unpinned);
        // Измеренный хеш кладётся рядом: его же оператор и запинит.
        assert_eq!(finding.actual, Some(sha256_file(&file).expect("hash")));

        // Отсутствующий файл при нулевом плейсхолдере — тоже «ещё не запинено»:
        // сказать про него нечего, пока в манифесте стоят нули.
        let absent = BinaryEntry {
            path: dir.path().join("нет-такого"),
            ..entry.clone()
        };
        assert_eq!(verify_one(&absent).status, IntegrityStatus::Unpinned);

        // А настоящее расхождение остаётся расхождением.
        let tampered = BinaryEntry {
            sha256: "a".repeat(64),
            ..entry
        };
        assert_eq!(verify_one(&tampered).status, IntegrityStatus::Mismatch);
    }

    #[test]
    fn the_shipped_manifest_ships_unpinned_not_tampered() {
        // Поставочный манифест обязан читаться как «ещё не запинено» целиком: иначе
        // первый же обход целостности на свежем узле объявит подмену.
        let raw = include_str!("../../manifest.toml");
        let manifest: Manifest = toml::from_str(raw).expect("manifest parses");
        for entry in &manifest.binaries {
            assert_eq!(
                entry.sha256, UNPINNED_SHA256,
                "поставочный `{}` обязан быть плейсхолдером, а не чужим хешем",
                entry.name
            );
        }
        // И turnserver в нём есть — именно о нём забывал печатный список шагов.
        assert!(manifest.binary("turnserver").is_some());
    }

    #[test]
    fn the_installer_names_every_binary_the_operator_has_to_pin() {
        // Замечание 16. Печатный список шагов называл smp-server и xftp-server, а
        // запись turnserver в манифесте есть и проверяется integrity наравне с
        // остальными: оператор, выполнивший ровно напечатанное, через час получал
        // карантин. Проверяется по списку записей, а не по трём именам, — иначе
        // следующая добавленная запись повторит ту же историю.
        let install = include_str!("../../deploy/install.sh");
        let raw = include_str!("../../manifest.toml");
        let manifest: Manifest = toml::from_str(raw).expect("manifest parses");
        for entry in &manifest.binaries {
            // hearthd и hearthctl установщик пинует сам: это не решение человека, а
            // измерение того, что он же только что положил.
            if entry.name == "hearthd" || entry.name == "hearthctl" {
                continue;
            }
            assert!(
                install.contains(&format!("manifest pin --name {}", entry.name)),
                "install.sh обязан назвать `{}` в списке оставшихся шагов",
                entry.name
            );
        }
    }

    #[test]
    fn rejects_latest_pin() {
        let raw = r#"
            [upstream]
            simplexmq_tag = "v6.4.2"
            simplex_chat_tag = "v6.4.2"
            gpg_identity = "chat@simplex.chat"
            reviewed = "2026-09-06"

            [[binary]]
            name = "smp-server"
            path = "/usr/local/bin/smp-server"
            version = "latest"
            sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
        "#;
        let manifest: Manifest = toml::from_str(raw).expect("parses");
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("latest"), "got {err}");
    }

    #[test]
    fn rejects_malformed_hash() {
        let raw = r#"
            [upstream]
            simplexmq_tag = "v6.4.2"
            simplex_chat_tag = "v6.4.2"
            gpg_identity = "chat@simplex.chat"
            reviewed = "2026-09-06"

            [[binary]]
            name = "smp-server"
            path = "/usr/local/bin/smp-server"
            version = "v6.4.2"
            sha256 = "deadbeef"
        "#;
        let manifest: Manifest = toml::from_str(raw).expect("parses");
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn detects_ok_mismatch_and_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good");
        let mut f = std::fs::File::create(&good).expect("create");
        f.write_all(b"hearth").expect("write");
        drop(f);
        let digest = sha256_file(&good).expect("hash");

        let manifest = Manifest {
            upstream: Upstream {
                simplexmq_tag: "v6.4.2".into(),
                simplex_chat_tag: "v6.4.2".into(),
                gpg_identity: "chat@simplex.chat".into(),
                reviewed: "2026-09-06".into(),
            },
            binaries: vec![
                BinaryEntry {
                    name: "good".into(),
                    path: good.clone(),
                    version: "v1".into(),
                    sha256: digest.clone(),
                    source: None,
                    commit: None,
                    tree_sha256: None,
                },
                BinaryEntry {
                    name: "tampered".into(),
                    path: good,
                    version: "v1".into(),
                    sha256: "a".repeat(64),
                    source: None,
                    commit: None,
                    tree_sha256: None,
                },
                BinaryEntry {
                    name: "absent".into(),
                    path: dir.path().join("nope"),
                    version: "v1".into(),
                    sha256: "b".repeat(64),
                    source: None,
                    commit: None,
                    tree_sha256: None,
                },
            ],
        };

        let findings = manifest.verify_all();
        assert_eq!(findings[0].status, IntegrityStatus::Ok);
        assert_eq!(findings[1].status, IntegrityStatus::Mismatch);
        assert_eq!(findings[2].status, IntegrityStatus::Missing);
    }

    #[test]
    fn pins_a_hash_without_losing_comments() {
        let raw = include_str!("../../manifest.toml");
        let digest = "b".repeat(64);
        let updated = pin(raw, "xftp-server", &digest, Some("v6.4.2"), None).expect("pin");

        assert!(
            updated.contains("# hearth — pinned upstream artefacts"),
            "comments kept"
        );
        let manifest: Manifest = toml::from_str(&updated).expect("still parses");
        let entry = manifest.binary("xftp-server").expect("entry");
        assert_eq!(entry.sha256, digest);
        assert_eq!(entry.version, "v6.4.2");
        // Other entries are untouched.
        assert_eq!(
            manifest.binary("smp-server").expect("entry").sha256,
            "0".repeat(64)
        );
    }

    #[test]
    fn pin_rejects_bad_input() {
        let raw = include_str!("../../manifest.toml");
        assert!(pin(raw, "smp-server", "not-a-hash", None, None).is_err());
        assert!(pin(raw, "does-not-exist", &"a".repeat(64), None, None).is_err());
        // Наполовину заполненный провенанс — не провенанс.
        let broken = EntryProvenance {
            commit: "нет".into(),
            tree_sha256: "c".repeat(64),
        };
        assert!(pin(raw, "hearthd", &"a".repeat(64), None, Some(&broken)).is_err());
    }

    /// Главное, ради чего затевался провенанс: запись `hearthd` должна называть
    /// коммит. До правки полей `commit`/`tree_sha256` в схеме не было вовсе — тест
    /// не компилировался бы.
    #[test]
    fn pinning_writes_the_provenance_and_leaves_the_neighbours_alone() {
        let raw = include_str!("../../manifest.toml");
        let digest = "b".repeat(64);
        let provenance = EntryProvenance {
            commit: "a".repeat(40),
            tree_sha256: "c".repeat(64),
        };
        let updated = pin(raw, "hearthd", &digest, Some("0.1.0"), Some(&provenance)).expect("pin");

        let manifest: Manifest = toml::from_str(&updated).expect("всё ещё разбирается");
        let entry = manifest.binary("hearthd").expect("запись hearthd");
        assert_eq!(entry.sha256, digest);
        assert_eq!(entry.commit.as_deref(), Some(provenance.commit.as_str()));
        assert_eq!(
            entry.tree_sha256.as_deref(),
            Some(provenance.tree_sha256.as_str())
        );
        assert_eq!(entry.source.as_deref(), Some("built-from-source"));

        // Соседние записи не тронуты — ни хешем, ни новыми полями.
        let smp = manifest.binary("smp-server").expect("запись smp-server");
        assert_eq!(smp.sha256, "0".repeat(64));
        assert!(smp.commit.is_none());
        assert!(
            updated.contains("# hearth — pinned upstream artefacts"),
            "комментарии сохранены"
        );

        // И повторный пин того же не плодит дубликаты ключа.
        let twice = pin(&updated, "hearthd", &digest, None, Some(&provenance)).expect("pin");
        assert_eq!(twice.matches("commit = ").count(), 1);
    }

    /// Перепин без провенанса обязан УБРАТЬ прежнюю запись о происхождении: коммит
    /// от старого файла рядом со свежим хешем — ложное утверждение, и выглядит оно
    /// убедительнее, чем его отсутствие.
    #[test]
    fn re_pinning_without_provenance_drops_the_stale_one() {
        let raw = include_str!("../../manifest.toml");
        let provenance = EntryProvenance {
            commit: "a".repeat(40),
            tree_sha256: "c".repeat(64),
        };
        let with = pin(raw, "hearthd", &"b".repeat(64), None, Some(&provenance)).expect("pin");
        assert!(with.contains("commit = "));

        let without = pin(&with, "hearthd", &"d".repeat(64), None, None).expect("pin");
        let manifest: Manifest = toml::from_str(&without).expect("разбирается");
        let entry = manifest.binary("hearthd").expect("запись");
        assert_eq!(entry.sha256, "d".repeat(64));
        assert!(
            entry.commit.is_none() && entry.tree_sha256.is_none(),
            "устаревший провенанс обязан исчезнуть, а не пережить перепин"
        );
    }

    /// Ключи в TOML идут в произвольном порядке, и запись, где `name` стоит не
    /// первым, обязана правиться целиком. Прежний построчный проход смотрел только
    /// НИЖЕ строки `name` и такую запись правил наполовину.
    #[test]
    fn a_name_key_below_the_hash_is_still_found() {
        let raw = r#"[upstream]
simplexmq_tag = "v6.4.2"
simplex_chat_tag = "v6.4.2"
gpg_identity = "chat@simplex.chat"
reviewed = "2026-09-06"

[[binary]]
path = "/usr/local/bin/hearthd"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
name = "hearthd"
version = "0.1.0"
"#;
        let updated = pin(raw, "hearthd", &"e".repeat(64), None, None).expect("pin");
        let manifest: Manifest = toml::from_str(&updated).expect("разбирается");
        assert_eq!(
            manifest.binary("hearthd").expect("запись").sha256,
            "e".repeat(64)
        );
    }

    /// Паспорт, у которого поля `unknown`, — не провенанс: незнание не записывается
    /// в манифест как знание.
    #[test]
    fn an_unknown_build_info_is_not_a_provenance() {
        let good = r#"{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                       "tree_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#;
        assert!(EntryProvenance::from_build_info_json(good).is_ok());

        let unknown = r#"{"commit":"unknown","tree_sha256":"unknown"}"#;
        assert!(EntryProvenance::from_build_info_json(unknown).is_err());

        assert!(EntryProvenance::from_build_info_json("не json").is_err());
        assert!(EntryProvenance::from_build_info_json(r#"{"commit":"aaaa"}"#).is_err());
    }

    #[test]
    fn known_sha256_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
