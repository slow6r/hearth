//! Подпись манифеста обновлений ключом, которого нет на узле.
//!
//! # Зачем
//!
//! До сих пор подлинность манифеста обновления держалась на серверном TLS — то есть
//! на самом узле. Захват узла раздачи означал власть над тем, что видит клиент:
//! какую версию считать свежей и какой файл качать. Android спасал от прямой подмены
//! сборки (чужая подпись не установится), но не от заморозки — узел мог молчать и
//! держать людей на старой версии с известной дырой, и никто бы не заметил.
//!
//! Здесь появляется вторая подпись — над самим манифестом, ключом, который живёт на
//! рабочей станции рядом с ключом подписи APK и на узел не попадает никогда.
//! Скомпрометированный узел может не отдать обновление, но не может выдать своё.
//!
//! # Почему ECDSA P-256, а не Ed25519
//!
//! Проверять придётся на Android, и там `SHA256withECDSA` есть на всех версиях, а
//! Ed25519 появился только в API 33. Новых зависимостей это не требует ни на одной
//! стороне: `ring` уже в дереве (через rustls и rcgen), Java-провайдер штатный.
//!
//! # Чего это НЕ даёт
//!
//! Защиты от утечки самого ключа подписи манифеста. Если рабочую станцию взломали,
//! потеряны оба ключа сразу — и этот, и ключ APK. Поэтому он и лежит там же: разносить
//! их по разным машинам имеет смысл только если машины действительно разные.

use std::path::Path;

use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, UnparsedPublicKey};

use crate::error::{Error, Result};

/// Заголовок SubjectPublicKeyInfo для P-256.
///
/// Ключ хранится и вшивается в приложение сразу в форме SPKI: на стороне Java это
/// ровно то, что принимает `X509EncodedKeySpec`, и клиенту не приходится собирать
/// структуру руками. `ring` отдаёт голую точку кривой, поэтому заголовок дописываем
/// здесь — он постоянный для P-256 и никаких секретов не содержит.
const P256_SPKI_HEADER: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Длина несжатой точки P-256: 0x04 и две координаты по 32 байта.
const P256_POINT_LEN: usize = 65;

/// Выписать новую пару для подписи манифестов.
///
/// Возвращает (PKCS#8 закрытый ключ, SPKI открытый ключ). Закрытый ключ вызывающий
/// обязан положить туда же, где лежит ключ подписи APK, и никогда не копировать на
/// узел.
pub fn generate() -> Result<(Vec<u8>, Vec<u8>)> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| Error::invalid("cannot generate a release signing key"))?;
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .map_err(|_| Error::invalid("generated key does not load back"))?;
    Ok((
        pkcs8.as_ref().to_vec(),
        spki(key_pair.public_key().as_ref())?,
    ))
}

/// Подписать содержимое манифеста.
///
/// Подписываются БАЙТЫ ФАЙЛА как есть, а не разобранный JSON: канонизация — лишний
/// источник расхождений между тем, что подписали, и тем, что проверяют.
pub fn sign(pkcs8: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
            .map_err(|_| Error::invalid("release signing key is not a P-256 PKCS#8 key"))?;
    let signature = key_pair
        .sign(&rng, body)
        .map_err(|_| Error::invalid("cannot sign the manifest"))?;
    Ok(signature.as_ref().to_vec())
}

/// Проверить подпись открытым ключом в форме SPKI.
pub fn verify(spki_public_key: &[u8], body: &[u8], signature_der: &[u8]) -> Result<()> {
    let point = spki_public_key
        .strip_prefix(P256_SPKI_HEADER)
        .ok_or_else(|| Error::invalid("public key is not a P-256 SubjectPublicKeyInfo"))?;
    if point.len() != P256_POINT_LEN {
        return Err(Error::invalid("public key point has a wrong length"));
    }
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
        .verify(body, signature_der)
        .map_err(|_| Error::invalid("signature does not match"))
}

/// Обернуть голую точку кривой в SubjectPublicKeyInfo.
fn spki(point: &[u8]) -> Result<Vec<u8>> {
    if point.len() != P256_POINT_LEN {
        return Err(Error::invalid("unexpected public key length"));
    }
    let mut out = Vec::with_capacity(P256_SPKI_HEADER.len() + point.len());
    out.extend_from_slice(P256_SPKI_HEADER);
    out.extend_from_slice(point);
    Ok(out)
}

/// Прочитать ключ подписи с диска.
pub fn load_key(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    decode_base64(raw.trim()).ok_or_else(|| Error::invalid("release key is not valid base64"))
}

/// Base64 без внешних зависимостей: алфавит фиксирован, данные наши.
pub fn encode_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut have = 0u8;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for c in text.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | v;
        have += 6;
        if have >= 8 {
            have -= 8;
            out.push((bits >> have) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_manifest_verifies() {
        let (key, public) = generate().expect("generate");
        let body = br#"{"v":1,"versionCode":387}"#;
        let sig = sign(&key, body).expect("sign");
        verify(&public, body, &sig).expect("verify");
    }

    #[test]
    fn a_changed_manifest_does_not_verify() {
        // Ровно тот случай, ради которого подпись и появилась: узел захвачен и
        // подменил содержимое манифеста.
        let (key, public) = generate().expect("generate");
        let sig = sign(&key, br#"{"versionCode":387}"#).expect("sign");
        assert!(verify(&public, br#"{"versionCode":999}"#, &sig).is_err());
    }

    #[test]
    fn another_key_does_not_verify() {
        let (key, _) = generate().expect("first");
        let (_, other_public) = generate().expect("second");
        let sig = sign(&key, b"manifest").expect("sign");
        assert!(verify(&other_public, b"manifest", &sig).is_err());
    }

    #[test]
    fn a_public_key_is_spki_and_fixed_length() {
        let (_, public) = generate().expect("generate");
        assert_eq!(public.len(), P256_SPKI_HEADER.len() + P256_POINT_LEN);
        assert!(public.starts_with(P256_SPKI_HEADER));
    }

    #[test]
    fn base64_round_trips() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let text = encode_base64(&data);
            assert_eq!(decode_base64(&text).expect("decode"), data, "длина {len}");
        }
    }

    #[test]
    fn a_truncated_public_key_is_refused() {
        let (key, public) = generate().expect("generate");
        let sig = sign(&key, b"body").expect("sign");
        assert!(verify(&public[..public.len() - 1], b"body", &sig).is_err());
        assert!(verify(b"not a key", b"body", &sig).is_err());
    }
}
