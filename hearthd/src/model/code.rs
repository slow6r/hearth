//! Код доступа — то, что человек получает лично и вводит руками.
//!
//! # Зачем отдельный формат
//!
//! Токен приглашения раньше был `random_hex(32)` — 64 знака. Он ехал внутри APK, и
//! читать его никому не приходилось. Теперь код называют вслух или пишут в записке,
//! поэтому у формата появились требования, которых у случайных байт нет:
//!
//!  * ни одного знака, который путают на слух и на бумаге. Алфавит Крокфорда как раз
//!    об этом: нет `I`, `L`, `O`, `U` — остальное различимо. `U` выкинут ещё и затем,
//!    чтобы код случайно не сложился в непристойность;
//!  * ввод прощает человека: регистр любой, дефисы и пробелы не важны, а `O`, `I` и
//!    `L`, если их всё-таки напечатали, читаются как `0` и `1`;
//!  * длина такая, чтобы продиктовать по телефону. Двенадцать знаков тремя группами —
//!    это 60 бит: перебрать нельзя даже без ограничителя на `/claim`, а ограничитель
//!    там всё равно есть.
//!
//! # Чего код НЕ делает
//!
//! Он не шифрует и не подписывает — это просто секрет, который узел узнаёт. Всё, что
//! сказано в [`crate::model::invite`] про пределы приглашения, верно и здесь: код
//! впускает в контур, а не в чужую переписку.

/// Алфавит Крокфорда: 32 знака, без `I`, `L`, `O`, `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Знаков в коде. 12 × 5 бит = 60 бит.
const LEN: usize = 12;

/// По сколько знаков в группе при показе человеку.
const GROUP: usize = 4;

/// Выписать новый код. Возвращается канонический вид — без дефисов, в верхнем
/// регистре; для показа человеку есть [`format_groups`].
pub fn generate() -> String {
    use rand::RngCore;
    let mut buf = [0u8; LEN];
    rand::rng().fill_bytes(&mut buf);
    // 256 делится на 32 нацело, поэтому остаток распределён равномерно и отбраковка
    // не нужна — иначе пришлось бы её писать, а не надеяться, что «почти равномерно».
    buf.iter()
        .map(|b| ALPHABET[(b % 32) as usize] as char)
        .collect()
}

/// Привести введённое человеком к каноническому виду.
///
/// Выбрасывает всё, что не из алфавита (дефисы, пробелы, перевод строки из буфера
/// обмена), поднимает регистр и чинит три привычные замены. Не проверяет длину: это
/// дело вызывающего — здесь только нормализация.
pub fn normalize(input: &str) -> String {
    input
        .chars()
        .filter_map(|c| {
            let c = c.to_ascii_uppercase();
            match c {
                // Человек видит «ноль» и печатает «О», видит «единицу» и печатает «I».
                // Крокфорд предписывает именно это отображение.
                'O' => Some('0'),
                'I' | 'L' => Some('1'),
                c if ALPHABET.contains(&(c as u8)) => Some(c),
                _ => None,
            }
        })
        .collect()
}

/// Похоже ли это на код доступа: правильная длина и только знаки алфавита.
///
/// Нужно, чтобы отличать код от старого шестнадцатеричного токена: пока в реестре
/// живут оба, сравнивать их надо по-разному.
pub fn is_code(canonical: &str) -> bool {
    canonical.len() == LEN && canonical.bytes().all(|b| ALPHABET.contains(&b))
}

/// Разбить на группы для показа: `H7K4-P9QX-M3TV`.
pub fn format_groups(canonical: &str) -> String {
    canonical
        .as_bytes()
        .chunks(GROUP)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_code_is_canonical_and_varies() {
        let a = generate();
        let b = generate();
        assert_eq!(a.len(), LEN);
        assert!(is_code(&a), "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn generated_code_avoids_confusable_letters() {
        for _ in 0..200 {
            let code = generate();
            for bad in ['I', 'L', 'O', 'U'] {
                assert!(!code.contains(bad), "в коде {code} оказалась {bad}");
            }
        }
    }

    #[test]
    fn normalize_forgives_how_a_person_types_it() {
        let canonical = "H7K4P9QXM3TV";
        for typed in [
            "H7K4-P9QX-M3TV",
            "h7k4 p9qx m3tv",
            " H7K4P9QXM3TV\n",
            "h7k4-p9qx-m3tv\r\n",
        ] {
            assert_eq!(normalize(typed), canonical, "ввод: {typed:?}");
        }
    }

    #[test]
    fn normalize_maps_the_three_confusable_letters() {
        assert_eq!(normalize("OIL"), "011");
        assert_eq!(normalize("oil"), "011");
    }

    #[test]
    fn is_code_rejects_the_old_hex_token() {
        let hex = crate::store::random_hex(32);
        assert!(!is_code(&hex));
        // И нормализованный шестнадцатеричный тоже не станет кодом: длина не та.
        assert!(!is_code(&normalize(&hex)));
    }

    #[test]
    fn groups_are_shown_as_dictated() {
        assert_eq!(format_groups("H7K4P9QXM3TV"), "H7K4-P9QX-M3TV");
    }

    #[test]
    fn a_formatted_code_normalizes_back_to_itself() {
        for _ in 0..50 {
            let code = generate();
            assert_eq!(normalize(&format_groups(&code)), code);
        }
    }
}
