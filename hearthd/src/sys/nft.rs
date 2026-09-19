//! nftables named counters — the leak detector's primary signal (ТЗ §5.4, §7.3).
//!
//! The ТЗ sketch uses anonymous counters (`counter log prefix ... drop`). Anonymous
//! counters are not addressable by name and never show up in `nft list counters`, so
//! `deploy/nftables/hearth.nft` declares **named** counters instead
//! (`counter name "egress_drop"`). Same packets, same drop, but hearthd can read them
//! every 30 seconds without parsing rule text.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::sys::Sys;

/// One named counter as reported by `nft -j list counters`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

/// Read all named counters of a table.
///
/// `nft -j list counters table inet hearth`
pub async fn list_counters(
    sys: &Sys,
    family: &str,
    table: &str,
) -> Result<BTreeMap<String, Counter>> {
    let out = sys
        .run("nft", &["-j", "list", "counters", "table", family, table])
        .await?;
    parse_counters(&out.stdout)
}

/// Parse the `nft -j` counter listing.
pub fn parse_counters(json: &str) -> Result<BTreeMap<String, Counter>> {
    #[derive(Deserialize)]
    struct Doc {
        nftables: Vec<Node>,
    }
    #[derive(Deserialize)]
    struct Node {
        #[serde(default)]
        counter: Option<CounterNode>,
    }
    #[derive(Deserialize)]
    struct CounterNode {
        name: String,
        #[serde(default)]
        packets: u64,
        #[serde(default)]
        bytes: u64,
    }

    let doc: Doc = serde_json::from_str(json)
        .map_err(|e| Error::Parse(format!("nft -j output is not valid json: {e}")))?;
    let mut counters = BTreeMap::new();
    for node in doc.nftables {
        if let Some(c) = node.counter {
            counters.insert(
                c.name,
                Counter {
                    packets: c.packets,
                    bytes: c.bytes,
                },
            );
        }
    }
    if counters.is_empty() {
        return Err(Error::Parse(
            "nft reported no named counters; is deploy/nftables/hearth.nft loaded?".into(),
        ));
    }
    Ok(counters)
}

/// Взять счётчик по имени, отказав, если его в выводе нет.
///
/// Раньше имя читалось через `unwrap_or_default()`, а `Counter::default()` — это
/// `{0, 0}`. Для `egress_drop` нуль означает «всё чисто», то есть отсутствующее
/// наблюдение подменялось благополучным. Проверка на пустой список счётчиков ловила
/// только ПОЛНОСТЬЮ пустой вывод: устаревший ruleset, ручная правка или частичная
/// загрузка дают непустой список без нужного имени.
pub fn require(
    counters: &BTreeMap<String, Counter>,
    name: &str,
    family: &str,
    table: &str,
) -> Result<Counter> {
    counters.get(name).copied().ok_or_else(|| {
        // Имя в тексте ошибки обязательно: оператору нужно знать, какой счётчик
        // потерялся, а не только то, что «что-то не так».
        Error::Parse(format!(
            "в таблице {family} {table} не объявлен счётчик `{name}`; \
             загруженный ruleset разошёлся с конфигурацией"
        ))
    })
}

/// Growth of a counter between two observations.
///
/// Counters reset to zero when the ruleset is reloaded; a decrease is treated as a
/// reset (delta 0) rather than an underflow.
pub fn delta(previous: Counter, current: Counter) -> Counter {
    Counter {
        packets: current.packets.saturating_sub(previous.packets),
        bytes: current.bytes.saturating_sub(previous.bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "nftables": [
        {"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch", "json_schema_version": 1}},
        {"counter": {"family": "inet", "name": "egress_drop", "table": "hearth", "handle": 1,
                     "packets": 0, "bytes": 0}},
        {"counter": {"family": "inet", "name": "input_drop", "table": "hearth", "handle": 2,
                     "packets": 41, "bytes": 2460}},
        {"counter": {"family": "inet", "name": "smp_in", "table": "hearth", "handle": 3,
                     "packets": 91011, "bytes": 12345678}}
      ]
    }"#;

    #[test]
    fn parses_named_counters() {
        let counters = parse_counters(SAMPLE).expect("parse");
        assert_eq!(
            counters["egress_drop"],
            Counter {
                packets: 0,
                bytes: 0
            }
        );
        assert_eq!(
            counters["input_drop"],
            Counter {
                packets: 41,
                bytes: 2460
            }
        );
        assert_eq!(counters.len(), 3);
    }

    /// Непустой вывод без нужного имени — это не нуль пакетов.
    #[test]
    fn a_listing_without_the_primary_counter_is_not_zero() {
        // Ruleset, где egress_drop переименован или не загрузился, а остальное на месте.
        const WITHOUT: &str = r#"{
          "nftables": [
            {"metainfo": {"version": "1.0.6", "json_schema_version": 1}},
            {"counter": {"family": "inet", "name": "input_drop", "table": "hearth", "handle": 2,
                         "packets": 41, "bytes": 2460}},
            {"counter": {"family": "inet", "name": "smp_in", "table": "hearth", "handle": 3,
                         "packets": 91011, "bytes": 12345678}}
          ]
        }"#;

        let counters = parse_counters(WITHOUT).expect("список не пуст, разбор проходит");
        assert!(!counters.contains_key("egress_drop"));
        assert_eq!(
            counters.get("egress_drop").copied().unwrap_or_default(),
            Counter::default(),
            "именно так отсутствие и выглядело как чистый нуль"
        );

        let err = require(&counters, "egress_drop", "inet", "hearth").unwrap_err();
        assert!(err.to_string().contains("egress_drop"), "got {err}");
        assert!(require(&counters, "input_drop", "inet", "hearth").is_ok());
    }

    #[test]
    fn empty_listing_is_an_error() {
        let err = parse_counters(r#"{"nftables":[{"metainfo":{}}]}"#).unwrap_err();
        assert!(err.to_string().contains("no named counters"), "got {err}");
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(parse_counters("not json").is_err());
    }

    #[test]
    fn delta_handles_ruleset_reload() {
        let before = Counter {
            packets: 100,
            bytes: 1000,
        };
        let after = Counter {
            packets: 105,
            bytes: 1300,
        };
        assert_eq!(
            delta(before, after),
            Counter {
                packets: 5,
                bytes: 300
            }
        );
        // counter reset -> no phantom incident
        assert_eq!(delta(before, Counter::default()), Counter::default());
    }
}
