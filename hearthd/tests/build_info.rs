//! Паспорт сборки глазами того, у кого есть только файл (ТЗ §7.3, аудит 2026-09-17).
//!
//! Тесты запускают СОБРАННЫЙ бинарник, а не библиотеку: проверяется ровно то, что
//! сможет сделать аудитор с копией файла — спросить у него, из чего он собран. До
//! появления `build.rs` и команды `build-info` спросить было не у кого: `--version`
//! отвечал `0.1.0` одинаково для любой сборки любого коммита за всю историю ветки.

use std::collections::BTreeMap;
use std::process::Command;

/// Разбор формата `ключ=значение` — того же, что у паспорта Android-сборки.
fn parse_key_values(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Бинарник обязан сам рассказывать о себе всё, чем его можно сопоставить с
/// исходниками, и делать это БЕЗ конфигурации узла: у аудитора её нет, а у
/// свежесобранного файла её ещё нет.
#[test]
fn the_binary_prints_its_own_passport_without_a_config() {
    let out = Command::new(env!("CARGO_BIN_EXE_hearthd"))
        .args(["--config", "/nope/definitely-not-here.toml", "build-info"])
        .output()
        .expect("запуск hearthd build-info");

    assert!(
        out.status.success(),
        "паспорт обязан печататься без конфигурации: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let fields = parse_key_values(&text);

    for key in [
        "version",
        "commit",
        "dirty",
        "tree_sha256",
        "target",
        "rustc",
        "source_date_epoch",
        "exe_sha256",
    ] {
        let value = fields
            .get(key)
            .unwrap_or_else(|| panic!("в паспорте нет поля `{key}`:\n{text}"));
        assert!(!value.is_empty(), "поле `{key}` пусто:\n{text}");
    }

    let commit = &fields["commit"];
    assert!(
        commit == hearthd::UNKNOWN || is_hex(commit, 40),
        "commit: 40 hex либо `unknown`, получено `{commit}`"
    );
    let tree = &fields["tree_sha256"];
    assert!(
        tree == hearthd::UNKNOWN || is_hex(tree, 64),
        "tree_sha256: 64 hex либо `unknown`, получено `{tree}`"
    );
    assert!(
        is_hex(&fields["exe_sha256"], 64),
        "exe_sha256 обязан быть посчитан всегда: `{}`",
        fields["exe_sha256"]
    );
    assert!(
        fields["dirty"] == "true" || fields["dirty"] == "false",
        "dirty: `{}`",
        fields["dirty"]
    );
}

/// Паспорт файла на диске обязан совпасть с паспортом, вшитым в библиотеку: иначе
/// сверять вывод команды с чем-либо бессмысленно.
#[test]
fn the_printed_passport_matches_the_stamped_one() {
    let out = Command::new(env!("CARGO_BIN_EXE_hearthd"))
        .arg("build-info")
        .output()
        .expect("запуск hearthd build-info");
    let fields = parse_key_values(&String::from_utf8_lossy(&out.stdout));
    let stamped = hearthd::build_info();

    assert_eq!(fields["version"], stamped.version);
    assert_eq!(fields["commit"], stamped.commit);
    assert_eq!(fields["tree_sha256"], stamped.tree_sha256);
    assert_eq!(fields["target"], stamped.target);
}

/// `exe_sha256` обязан быть хешем ИМЕННО ЭТОГО файла, а не какого-нибудь ещё:
/// на этом держится вся цепочка «журнал → файл на диске → коммит».
#[test]
fn the_reported_exe_hash_is_the_hash_of_the_file_on_disk() {
    let path = env!("CARGO_BIN_EXE_hearthd");
    let out = Command::new(path)
        .args(["build-info", "--json"])
        .output()
        .expect("запуск hearthd build-info --json");
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("build-info --json — это JSON");

    let reported = doc
        .get("exe_sha256")
        .and_then(|v| v.as_str())
        .expect("поле exe_sha256");
    let on_disk = hearthd::model::manifest::sha256_file(path).expect("sha256 файла");
    assert_eq!(
        reported, on_disk,
        "процесс назвал не свой файл — цепочка доказательства рвётся здесь"
    );
}

/// Шов между паспортом и манифестом: `manifest pin` записывает происхождение,
/// разбирая РОВНО этот вывод. Синтетический JSON в юнит-тестах `manifest.rs` этого
/// не проверяет — он проверяет разбор, а не то, что разбирать есть что.
#[test]
fn the_json_passport_is_what_manifest_pin_records() {
    use hearthd::model::manifest::EntryProvenance;

    let out = Command::new(env!("CARGO_BIN_EXE_hearthd"))
        .args(["build-info", "--json"])
        .output()
        .expect("запуск hearthd build-info --json");
    let raw = String::from_utf8_lossy(&out.stdout).to_string();

    match EntryProvenance::from_build_info_json(&raw) {
        Ok(provenance) => {
            let stamped = hearthd::build_info();
            assert_eq!(provenance.commit, stamped.commit);
            assert_eq!(provenance.tree_sha256, stamped.tree_sha256);
        }
        Err(e) => {
            // Сборка без git — законный случай; тогда происхождения просто нет, и
            // манифест обязан остаться без записи, а не получить `unknown`.
            assert_eq!(
                hearthd::build_info().commit,
                hearthd::UNKNOWN,
                "паспорт есть, а происхождение не разобрано: {e}\n{raw}"
            );
        }
    }
}

/// hearthctl — второй установленный файл, и он тоже обязан уметь назвать себя:
/// иначе в выгрузке для аудита один из двух бинарников остаётся без паспорта.
#[test]
fn hearthctl_prints_its_passport_too() {
    let out = Command::new(env!("CARGO_BIN_EXE_hearthctl"))
        .args(["--config", "/nope/definitely-not-here.toml", "build-info"])
        .output()
        .expect("запуск hearthctl build-info");
    assert!(
        out.status.success(),
        "паспорт hearthctl обязан печататься без конфигурации: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fields = parse_key_values(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(fields["commit"], hearthd::build_info().commit);
    assert!(is_hex(&fields["exe_sha256"], 64));
}
