//! Domain model: everything hearthd persists or hands to a client.
//!
//! Nothing here knows about messages, queues or contacts — hearthd is deliberately
//! ignorant of relay content (ТЗ §7.4).

pub mod alert;
pub mod bundle;
pub mod device;
pub mod health;
pub mod manifest;

use chrono::{DateTime, SecondsFormat, Utc};

/// RFC 3339 with second precision, exactly as ТЗ Приложение B shows it
/// (`2026-09-06T12:00:00Z`). chrono's default would emit sub-second digits.
pub mod rfc3339 {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ts: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ts.to_rfc3339_opts(SecondsFormat::Secs, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|ts| ts.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }

    pub mod option {
        use chrono::{DateTime, SecondsFormat, Utc};
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(
            ts: &Option<DateTime<Utc>>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            match ts {
                Some(ts) => s.serialize_str(&ts.to_rfc3339_opts(SecondsFormat::Secs, true)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<DateTime<Utc>>, D::Error> {
            let raw = Option::<String>::deserialize(d)?;
            match raw {
                None => Ok(None),
                Some(raw) => DateTime::parse_from_rfc3339(&raw)
                    .map(|ts| Some(ts.with_timezone(&Utc)))
                    .map_err(serde::de::Error::custom),
            }
        }
    }
}

/// Format a timestamp the way the whole project writes timestamps.
pub fn fmt_ts(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Turn a human device name into a stable ASCII identifier.
///
/// Device names are Russian in practice ("Мама — Pixel 8"), while the id ends up in
/// URLs, filenames and the bundle payload, so it is transliterated to ASCII.
pub fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending_sep = false;
    for ch in name.chars() {
        let mapped = translit(ch);
        if mapped.is_empty() {
            pending_sep = !out.is_empty();
            continue;
        }
        if pending_sep {
            out.push('-');
            pending_sep = false;
        }
        out.push_str(&mapped);
    }
    out
}

/// Map one character to its slug representation (empty string = separator).
fn translit(ch: char) -> String {
    if ch.is_ascii_alphanumeric() {
        return ch.to_ascii_lowercase().to_string();
    }
    let lower = ch.to_lowercase().next().unwrap_or(ch);
    let s = match lower {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' | 'ё' | 'э' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' | 'й' => "i",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "h",
        'ц' => "c",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "sch",
        'ы' => "y",
        'ю' => "yu",
        'я' => "ya",
        'ъ' | 'ь' => "",
        _ => "",
    };
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn slugifies_russian_device_names() {
        assert_eq!(slugify("Мама — Pixel 8"), "mama-pixel-8");
        assert_eq!(slugify("Папа iPhone 15"), "papa-iphone-15");
        assert_eq!(slugify("Дочь — Samsung A54"), "doch-samsung-a54");
        assert_eq!(slugify("  ..--  "), "");
    }

    #[test]
    fn slug_is_url_safe() {
        let slug = slugify("Тест/../etc/passwd");
        assert!(
            !slug.contains('/'),
            "slug must not contain path separators: {slug}"
        );
        assert_eq!(slug, "test-etc-passwd");
    }

    #[test]
    fn timestamps_have_second_precision() {
        let ts = Utc
            .with_ymd_and_hms(2026, 9, 6, 12, 0, 0)
            .single()
            .expect("valid ts");
        assert_eq!(fmt_ts(ts), "2026-09-06T12:00:00Z");
    }
}
