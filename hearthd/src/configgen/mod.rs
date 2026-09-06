//! config-gen (ТЗ §7.3): turn the node's own state into a client bundle.
//!
//! Inputs: the relay CA fingerprints written by `smp-server init` / `xftp-server init`,
//! the queue-creation passwords, and the coturn static secret. Output: the JSON of
//! ТЗ Приложение B, plus a QR rendering and — for stock iOS — a manual checklist.
//!
//! The bundle is minted on demand and never persisted: it carries relay passwords, so
//! the only copies that exist are the HTTP response and whatever the owner scans.

pub mod turn;

use chrono::Utc;

use crate::config::{Config, Relay};
use crate::error::{Error, Result};
use crate::model::bundle::{Bundle, NetPrefs, ServerUri, BUNDLE_VERSION};
use crate::model::device::{Device, Platform};
use crate::store;

/// Build a bundle for a device.
pub fn build_bundle(config: &Config, device: &Device) -> Result<Bundle> {
    if device.revoked.is_some() {
        return Err(Error::Conflict(format!(
            "device `{}` is revoked; refusing to mint a bundle",
            device.id
        )));
    }

    let smp = server_uri(config, &config.smp)?;
    let xftp = if config.xftp.enabled {
        vec![server_uri(config, &config.xftp)?.to_string()]
    } else {
        Vec::new()
    };

    let ice = if config.turn.enabled {
        let secret = store::read_secret(&config.turn.secret_file)?;
        let cred = turn::credential(
            &secret,
            &config.turn.username,
            config.turn.credential_ttl_secs,
            Utc::now(),
        )?;
        turn::ice_servers(&config.turn, &cred)
    } else {
        Vec::new()
    };

    let bundle = Bundle {
        v: BUNDLE_VERSION,
        smp: vec![smp.to_string()],
        xftp,
        ice,
        net: NetPrefs::default(),
        issued: Utc::now(),
        device: device.id.clone(),
    };
    bundle.validate(config.node.address)?;
    Ok(bundle)
}

/// Compose `<scheme>://<fingerprint>:<password>@<node>:<port>` from on-disk state.
fn server_uri(config: &Config, relay: &Relay) -> Result<ServerUri> {
    if !relay.enabled {
        return Err(Error::Config(format!(
            "relay `{}` is disabled",
            relay.scheme
        )));
    }
    let fingerprint = store::read_secret(&relay.fingerprint_file).map_err(|e| {
        Error::Config(format!(
            "cannot read the {} CA fingerprint ({}): {e}. Has `{}-server init` been run?",
            relay.scheme,
            relay.fingerprint_file.display(),
            relay.scheme
        ))
    })?;
    let password = store::read_secret(&relay.password_file)?;
    ServerUri::new(
        &relay.scheme,
        &fingerprint,
        Some(&password),
        config.node.address,
        relay.listen.port(),
    )
}

/// Manual setup checklist for a stock client (ТЗ §9).
///
/// Upstream iOS cannot import a bundle from one QR, so hearthd emits the exact steps
/// instead — generated from the same source of truth as the bundle, so the two can
/// never drift apart.
pub fn manual_checklist(device: &Device, bundle: &Bundle) -> String {
    let platform = match device.platform {
        Platform::Ios => "iOS (стоковое приложение SimpleX Chat)",
        Platform::Desktop => "Desktop (стоковое приложение SimpleX Chat)",
        Platform::Android => "Android (стоковое приложение — форк умеет импорт по QR)",
    };
    let smp = bundle.smp.join("\n     ");
    let xftp = if bundle.xftp.is_empty() {
        "(xftp выключен)".to_string()
    } else {
        bundle.xftp.join("\n     ")
    };
    let ice = bundle
        .ice
        .iter()
        .flat_map(|s| s.urls.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n     ");
    let turn_user = bundle
        .ice
        .iter()
        .find_map(|s| s.username.clone())
        .unwrap_or_else(|| "(нет)".into());
    let turn_cred = bundle
        .ice
        .iter()
        .find_map(|s| s.credential.clone())
        .unwrap_or_else(|| "(нет)".into());

    format!(
        "Ручная настройка устройства: {name} [{id}]\n\
         Платформа: {platform}\n\
         Выпущено: {issued}\n\
         \n\
         ВНИМАНИЕ: строки ниже содержат пароли релеев. Показывать только внутри WG,\n\
         не пересылать через другие мессенджеры, не сохранять в облако.\n\
         \n\
         1. Подключить устройство к семейному WireGuard/AmneziaWG (профиль на UDM Pro).\n\
            Проверка: ping 10.66.10.10 отвечает.\n\
         \n\
         2. Настройки → Network & servers → Operators: выключить всех операторов\n\
            (SimpleX Chat, Flux и любых других). Пресеты публичной сети должны быть\n\
            выключены полностью — иначе клиент уйдёт на чужие релеи.\n\
         \n\
         3. SMP servers: удалить все предустановленные, добавить только:\n\
            {smp}\n\
            Отметить «Use for new connections».\n\
         \n\
         4. XFTP servers: удалить все предустановленные, добавить только:\n\
            {xftp}\n\
         \n\
         5. Settings → Audio & video calls → WebRTC ICE servers: заменить содержимое на\n\
            {ice}\n\
            TURN username:   {turn_user}\n\
            TURN credential: {turn_cred}\n\
            Публичные STUN (stun.l.google.com и подобные) удалить.\n\
         \n\
         6. Private message routing: Always (и «Show message status» по вкусу).\n\
            Notifications: Instant. Push/Periodic не использовать — сервера уведомлений\n\
            в контуре нет.\n\
         \n\
         Проверка: отправить сообщение члену семьи; в hearthctl health узел ok.\n",
        name = device.name,
        id = device.id,
        issued = crate::model::fmt_ts(bundle.issued),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::device::Device;
    use chrono::Utc;
    use std::path::Path;

    fn config_with(dir: &Path) -> Config {
        let raw = include_str!("../../deploy/hearthd.toml");
        let mut config: Config = toml::from_str(raw).expect("reference config");
        config.smp.fingerprint_file = dir.join("smp-fingerprint");
        config.smp.password_file = dir.join("smp-password");
        config.xftp.fingerprint_file = dir.join("xftp-fingerprint");
        config.xftp.password_file = dir.join("xftp-password");
        config.turn.secret_file = dir.join("turn-secret");
        config
    }

    fn seed(dir: &Path) {
        store::write_secret(dir.join("smp-fingerprint"), "smpFingerPrintAbC").expect("w");
        store::write_secret(dir.join("smp-password"), "smpPassword123").expect("w");
        store::write_secret(dir.join("xftp-fingerprint"), "xftpFingerPrintXyZ").expect("w");
        store::write_secret(dir.join("xftp-password"), "xftpPassword456").expect("w");
        store::write_secret(dir.join("turn-secret"), "turnStaticSecret").expect("w");
    }

    fn device() -> Device {
        Device {
            id: "mama-pixel-8".into(),
            name: "Мама — Pixel 8".into(),
            platform: Platform::Android,
            created: Utc::now(),
            revoked: None,
            bundles_issued: 0,
            last_bundle: None,
            note: None,
        }
    }

    #[test]
    fn builds_a_valid_bundle_from_node_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed(dir.path());
        let config = config_with(dir.path());

        let bundle = build_bundle(&config, &device()).expect("bundle");
        assert_eq!(bundle.v, 1);
        assert_eq!(
            bundle.smp,
            vec!["smp://smpFingerPrintAbC:smpPassword123@10.66.10.10:5223".to_string()]
        );
        assert_eq!(
            bundle.xftp,
            vec!["xftp://xftpFingerPrintXyZ:xftpPassword456@10.66.10.10:5443".to_string()]
        );
        assert_eq!(bundle.ice.len(), 2);
        assert_eq!(bundle.device, "mama-pixel-8");
        bundle.validate(config.node.address).expect("valid");
        assert!(bundle.to_json().expect("json").len() <= 1024);
    }

    #[test]
    fn refuses_to_mint_for_a_revoked_device() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed(dir.path());
        let config = config_with(dir.path());
        let mut device = device();
        device.revoked = Some(Utc::now());
        let err = build_bundle(&config, &device).unwrap_err();
        assert!(err.to_string().contains("revoked"), "got {err}");
    }

    #[test]
    fn missing_fingerprint_names_the_init_step() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config_with(dir.path());
        let err = build_bundle(&config, &device()).unwrap_err();
        assert!(err.to_string().contains("init"), "got {err}");
    }

    #[test]
    fn checklist_covers_every_manual_step() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed(dir.path());
        let config = config_with(dir.path());
        let mut device = device();
        device.platform = Platform::Ios;
        let bundle = build_bundle(&config, &device).expect("bundle");

        let text = manual_checklist(&device, &bundle);
        assert!(text.contains("WireGuard"));
        assert!(text.contains("Operators"));
        assert!(text.contains("smp://"));
        assert!(text.contains("xftp://"));
        assert!(text.contains("stun:10.66.10.10:3478"));
        assert!(text.contains("Instant"));
        // Every numbered step 1..6 is present.
        for step in 1..=6 {
            assert!(text.contains(&format!("{step}. ")), "missing step {step}");
        }
    }

    #[test]
    fn bundle_without_xftp_is_still_valid() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed(dir.path());
        let mut config = config_with(dir.path());
        config.xftp.enabled = false;
        let bundle = build_bundle(&config, &device()).expect("bundle");
        assert!(bundle.xftp.is_empty());
        bundle.validate(config.node.address).expect("valid");
    }
}
