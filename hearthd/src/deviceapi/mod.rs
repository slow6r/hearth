//! Device API — единственный сервис узла, с которым говорят сами телефоны.
//!
//! # Зачем он вообще появился
//!
//! [ADR 0007](../../docs/adr/0007-public-relay-no-vpn.md) свёл публичную поверхность
//! узла к релеям и TURN, то есть к стоковому коду upstream. Этот модуль добавляет к
//! ней наш код, и это заметное изменение. Взамен снимаются две вещи, каждая из которых
//! иначе неустранима:
//!
//! 1. **Обновление за ≤ 7 дней (ТЗ §1.4).** Раздача через домашний F-Droid не работает
//!    для того, кто уехал, — а именно он и остаётся с непропатченной дырой.
//! 2. **Звонки, ломающиеся раз в месяц.** TURN-креды в bundle — это HMAC текущего
//!    секрета, и при ротации они умирают у всех сразу. Симптом коварный: сообщения
//!    ходят, звонки молчат. Здесь телефон берёт свежие сам.
//!
//! # Чем он НЕ является
//!
//! Не admin API. Тот — mTLS, только из `admin_networks`, полные права. Этот — токен на
//! устройство, из интернета, и умеет ровно две операции. Разные слушатели и разные
//! модели доверия: ошибка в маршрутизации между ними стоила бы прав администратора.
//!
//! # Доверие
//!
//! TLS с сертификатом, выписанным hearth CA на `node.host`. Приложение пинует этот CA
//! в network security config. Публичный CA не нужен: не будет ни записи в
//! CT-логах, ни certbot'а, который однажды молча не продлится.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;

use crate::configgen::turn;
use crate::error::{Error, Result};
use crate::state::AppState;
use crate::store;

/// Заголовок с секретом устройства. Именно заголовок, не параметр URL: URL оседает в
/// логах прокси, в истории и в отчётах об ошибках.
pub mod throttle;

const TOKEN_HEADER: &str = "x-hearth-device-token";
/// Заголовок приглашения. Отдельный от токена устройства намеренно: у них разный
/// срок жизни и разный смысл, и путать их в одном заголовке — значит однажды
/// принять просроченное приглашение за живое устройство.
const INVITE_HEADER: &str = "x-hearth-invite-token";
/// Больше этого манифест обновления быть не может — он маленький по определению.
const MANIFEST_LIMIT: u64 = 64 * 1024;
/// Адрес того, кто пришёл.
///
/// Соединения device API принимает вручную (TLS поверх своего `accept`), а не через
/// `axum::serve`, поэтому штатный `ConnectInfo` тут пуст — адрес кладётся в расширения
/// запроса при приёме и достаётся обработчиком.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerIp(pub std::net::IpAddr);

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub async fn serve(
    state: Arc<AppState>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listen = state.config.device_api.listen;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| Error::io(listen.to_string(), e))?;
    serve_on(state, listener, shutdown).await
}

pub async fn serve_on(
    state: Arc<AppState>,
    listener: TcpListener,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let tls_config = crate::api::tls::device_server_config(&state.config.api.pki_dir)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    tracing::info!(
        listen = ?listener.local_addr().ok(),
        host = %state.config.node.host,
        "device api listening (TLS, token auth)"
    );

    let app = router(state.clone());

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("device api stopping");
                    return Ok(());
                }
                continue;
            }
        };

        let (tcp, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "device api accept failed");
                continue;
            }
        };

        // Фильтра по адресу здесь нет и быть не может: телефоны приходят из
        // произвольных мобильных сетей. Единственный замок — токен устройства.
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "device api tls handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "device api tls handshake timed out");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(tls);
            let service = hyper::service::service_fn(move |mut req: hyper::Request<_>| {
                req.extensions_mut().insert(PeerIp(peer.ip()));
                let app = app.clone();
                async move { tower::ServiceExt::oneshot(app, req).await }
            });
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            {
                tracing::debug!(%peer, error = %e, "device api connection closed");
            }
        });
    }
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/updates/manifest.json", get(update_manifest))
        // Статический маршрут, поэтому выигрывает у `/updates/{file}` — как и строка выше.
        .route("/updates/manifest.json.sig", get(update_manifest_signature))
        .route("/updates/{file}", get(update_file))
        .route("/stickers/index.json", get(sticker_index))
        .route("/stickers/{pack}/{file}", get(sticker_file))
        .route("/turn-credentials", get(turn_credentials))
        .route("/enroll", axum::routing::post(enroll))
        .route("/claim", axum::routing::post(claim))
        .with_state(state)
}

/// Ошибка device API.
///
/// Отдельный маленький тип, а не `Response` в `Err`: `Response` весит больше сотни
/// байт, и каждый `Result` в модуле раздувался бы до его размера на обеих ветках.
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

/// Кто пришёл. Возвращает id устройства, чтобы его можно было назвать в логах.
async fn authorize(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let token = headers
        .get(TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_string();

    if token.is_empty() {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "device token required"));
    }

    let devices = state.devices.read().await;
    // Сравнение в постоянное время: токен — секрет, а разница во времени ответа
    // на «первый символ не тот» и «все символы кроме последнего те» подбирается.
    let found = devices
        .active()
        .find(|d| {
            d.token
                .as_deref()
                .map(|t| ct_eq(t, &token))
                .unwrap_or(false)
        })
        .map(|d| d.id.clone());

    match found {
        Some(id) => Ok(id),
        None => {
            // Отозванное устройство приходит сюда же и получает то же самое: узнать по
            // ответу, «был ли такой токен когда-то», нельзя.
            tracing::warn!("device api: rejected an unknown or revoked token");
            Err(ApiError(StatusCode::UNAUTHORIZED, "unknown device"))
        }
    }
}

pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Имя файла, и только имя.
///
/// Без этой проверки `..%2f..%2fetc%2fshadow` отдал бы что угодно, до чего дотягивается
/// пользователь `hearth` — включая секреты релеев. axum декодирует percent-encoding ДО
/// того, как значение попадает сюда, так что проверять надо уже раскодированное.
// ------------------------------------------------------------------ стикеры
//
// Наборы кладёт `stickers/import-telegram.py`: `index.json` и `<набор>/{pack.json,NNN.webp}`.
// Замок тот же, что у обновлений, — токен устройства. Имена из пути проверяются по
// белому списку ДО join(): всё, что не «строчные+цифры+_» для набора и не «NNN.webp» /
// `pack.json` для файла, отвергается, и `..` туда не пролезает по построению.
//
// Файлы маленькие (стикер — десятки килобайт), поэтому читаются целиком, но с
// потолком: подменённый или переполненный каталог не должен заставить узел отдавать
// гигабайты одному телефону.
const STICKER_FILE_LIMIT: u64 = 4 * 1024 * 1024;

fn is_safe_sticker_pack(pack: &str) -> bool {
    !pack.is_empty()
        && pack.len() <= 64
        && pack
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_safe_sticker_file(file: &str) -> bool {
    if file == "pack.json" {
        return true;
    }
    // Ровно `NNN.webp` — так нумерует импорт.
    file.len() == 8 && file.ends_with(".webp") && file.as_bytes()[..3].iter().all(u8::is_ascii_digit)
}

fn sticker_content_type(file: &str) -> &'static str {
    if file.ends_with(".json") {
        "application/json"
    } else {
        "image/webp"
    }
}

async fn serve_small_file(path: std::path::PathBuf, content_type: &'static str) -> ApiResult<Response> {
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "no such file"))?;
    if !meta.is_file() || meta.len() > STICKER_FILE_LIMIT {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such file"));
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot read"))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(Body::from(bytes))
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot build response"))
}

async fn sticker_index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    authorize(&state, &headers).await?;
    serve_small_file(
        state.config.device_api.stickers_dir.join("index.json"),
        "application/json",
    )
    .await
}

async fn sticker_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((pack, file)): AxumPath<(String, String)>,
) -> ApiResult<Response> {
    let device = authorize(&state, &headers).await?;
    if !is_safe_sticker_pack(&pack) || !is_safe_sticker_file(&file) {
        tracing::warn!(%device, %pack, %file, "device api: refused a suspicious sticker path");
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad sticker path"));
    }
    serve_small_file(
        state.config.device_api.stickers_dir.join(&pack).join(&file),
        sticker_content_type(&file),
    )
    .await
}

fn is_safe_apk_name(file: &str) -> bool {
    !file.is_empty()
        && !file.contains('/')
        && !file.contains('\\')
        && !file.contains("..")
        && !file.starts_with('.')
        && file.ends_with(".apk")
}

async fn update_manifest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let device = authorize(&state, &headers).await?;
    let path = state.config.device_api.updates_dir.join("manifest.json");

    let meta = tokio::fs::metadata(&path).await.map_err(|_| {
        // Обновлений просто нет — это нормальное состояние, а не ошибка.
        ApiError(StatusCode::NOT_FOUND, "no update published")
    })?;
    if meta.len() > MANIFEST_LIMIT {
        tracing::error!(path = %path.display(), "update manifest is implausibly large");
        return Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, "bad manifest"));
    }

    let body = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "cannot read update manifest");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "bad manifest")
    })?;

    tracing::debug!(%device, "device api: manifest served");
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

/// Подпись манифеста обновления.
///
/// Отдельный маршрут, а не `/updates/{file}`: тот пропускает только `*.apk` и отвечал на
/// подпись 400. Клиент со вшитым ключом (ADR 0014) на всё, кроме 200 и 404, считает
/// проверку обновления неудавшейся, поэтому обновление по воздуху не ставилось ни на
/// одном таком телефоне с того коммита, где появилась подпись (aac8697): подпись
/// выкладывалась, но узел её не отдавал.
///
/// Отсутствие файла — честный 404: клиент со вшитым ключом откажет сам (fail-closed), а
/// сборка без ключа пойдёт дальше, как задумано.
async fn update_manifest_signature(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let device = authorize(&state, &headers).await?;
    let path = state.config.device_api.updates_dir.join("manifest.json.sig");

    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "no manifest signature"))?;
    if meta.len() > MANIFEST_LIMIT {
        tracing::error!(path = %path.display(), "manifest signature is implausibly large");
        return Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, "bad signature"));
    }

    let body = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "cannot read manifest signature");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "bad signature")
    })?;

    tracing::debug!(%device, "device api: manifest signature served");
    Ok(([(header::CONTENT_TYPE, "text/plain")], body).into_response())
}

async fn update_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(file): AxumPath<String>,
) -> ApiResult<Response> {
    let device = authorize(&state, &headers).await?;

    if !is_safe_apk_name(&file) {
        tracing::warn!(%device, %file, "device api: refused a suspicious file name");
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad file name"));
    }

    let path = state.config.device_api.updates_dir.join(&file);
    let mut f = tokio::fs::File::open(&path)
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "no such file"))?;
    let total = f
        .metadata()
        .await
        .map(|m| m.len())
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot stat"))?;

    // Докачка. Обновление весит сотни мегабайт, а телефон в дороге теряет сеть
    // постоянно; без этого каждый обрыв означал бы скачивание заново с нуля.
    //
    // Объявлять `accept-ranges: bytes` и не реализовать разбор — хуже, чем не
    // объявлять вовсе: клиент поверит заголовку, пошлёт Range, получит 200 со всем
    // файлом и молча начнёт сначала.
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_range(v, total));

    let (status, start, len) = match range {
        Some(Some((start, end))) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        // Заголовок был, но разобрать его не удалось или он вне файла: по RFC 9110
        // это 416, а не «отдать всё» — иначе клиент склеит мусор с тем, что уже есть.
        Some(None) => {
            return Err(ApiError(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "range not satisfiable",
            ))
        }
        None => (StatusCode::OK, 0, total),
    };

    if start > 0 {
        use tokio::io::AsyncSeekExt as _;
        f.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot seek"))?;
    }

    // Потоком и с ограничением по длине: APK весит сотни мегабайт, а узел — мини-ПК,
    // читать файл целиком в память нельзя.
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(f.take(len)));

    let mut resp = Response::builder()
        .status(status)
        .header(
            header::CONTENT_TYPE,
            "application/vnd.android.package-archive",
        )
        .header(header::CONTENT_LENGTH, len.to_string())
        .header(header::ACCEPT_RANGES, "bytes");
    if status == StatusCode::PARTIAL_CONTENT {
        resp = resp.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, start + len - 1, total),
        );
    }

    tracing::info!(%device, %file, start, len, total, "device api: update download");
    resp.body(body)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot build response"))
}

/// Разобрать `Range: bytes=START-[END]`.
///
/// * `None` — заголовок не про байты или не наш случай, отдаём файл целиком;
/// * `Some(None)` — заголовок про байты, но диапазон бессмысленный: 416;
/// * `Some(Some((start, end)))` — включительные границы внутри файла.
///
/// Поддерживается только один диапазон. Множественные (`bytes=0-9,20-29`) клиенту
/// обновлений не нужны, а их поддержка требует multipart-ответа — лишний код в месте,
/// которое смотрит в интернет.
fn parse_range(value: &str, total: u64) -> Option<Option<(u64, u64)>> {
    let spec = value.trim().strip_prefix("bytes=")?.trim();
    if spec.contains(',') {
        return Some(None);
    }
    let (start_s, end_s) = spec.split_once('-')?;
    let (start, end) = match (start_s.trim(), end_s.trim()) {
        // `bytes=-N` — последние N байт.
        ("", n) => {
            let n: u64 = n.parse().ok()?;
            if n == 0 || total == 0 {
                return Some(None);
            }
            (total.saturating_sub(n), total - 1)
        }
        (s, "") => (s.parse().ok()?, total.saturating_sub(1)),
        (s, e) => (s.parse().ok()?, e.parse().ok()?),
    };
    if total == 0 || start > end || start >= total {
        return Some(None);
    }
    Some(Some((start, end.min(total - 1))))
}

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    /// Человеческое имя нового устройства, как его вводит член семьи.
    name: String,
    /// `android` | `ios` | `desktop`; без поля — `android`, как у всех сборок до него.
    #[serde(default)]
    platform: Option<String>,
}

/// Платформа из запроса устройства.
///
/// Поле необязательно: Android-сборки, выпущенные до него, его не присылают, и для них
/// всё остаётся как было. Разбор строже, чем `Platform::from_str`: тот понимает `iphone`
/// и `pc`, потому что его вход набирает человек в `hearthctl`. Здесь строку шлёт
/// приложение, и незнакомое значение — ошибка сборки, которую лучше увидеть сразу, чем
/// записать в реестр телефон с неверной платформой.
fn requested_platform(raw: Option<&str>) -> Option<crate::model::device::Platform> {
    use crate::model::device::Platform;
    match raw {
        None | Some("android") => Some(Platform::Android),
        Some("ios") => Some(Platform::Ios),
        Some("desktop") => Some(Platform::Desktop),
        Some(_) => None,
    }
}

/// Завести НОВОЕ устройство по просьбе уже заведённого.
///
/// # Зачем это вообще
///
/// Иначе каждый новый телефон требует администратора у терминала: `hearthctl device
/// add` доступен только по admin API из LAN. Для семьи из двадцати человек это узкое
/// место, а в стоковом SimpleX ничего подобного нет вовсе — там просто ставят
/// приложение, потому что серверы публичные.
///
/// # Почему это не дыра
///
/// Любой уже заведённый телефон ДЕРЖИТ пароль релея у себя: он внутри адреса
/// `smp://<fp>:<pass>@host`. То есть член семьи и так может показать свой QR новому
/// телефону, и никакой код этому не помешает — секрет уже роздан.
///
/// Что этот эндпоинт добавляет — не секретность, а УЧЁТ: новое устройство получает
/// собственную запись в реестре и СВОЙ токен. Без него самодельное «поделись QR»
/// плодило бы телефоны, которых узел не знает и которые нечем отозвать, да ещё и с
/// общим токеном — отзыв одного гасил бы всех.
///
/// Ограничение — `devices.max_devices`, то же, что и у admin API.
async fn enroll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<Response> {
    let inviter = authorize(&state, &headers).await?;

    // Поверхность включается осознанно. Пока она открыта, ЛЮБОЙ действующий токен
    // устройства плодит новые устройства, каждое из которых умеет то же самое, —
    // то есть один потерянный телефон становится бессрочным станком.
    if !state.config.devices.allow_device_enroll {
        tracing::warn!(%inviter, "device api: enroll refused, disabled by configuration");
        return Err(ApiError(StatusCode::FORBIDDEN, "enrolment is disabled"));
    }

    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad device name"));
    }
    let Some(platform) = requested_platform(req.platform.as_deref()) else {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad platform"));
    };

    // Бюджет на сутки: даже включённая поверхность не должна давать одному токену
    // исчерпать max_devices за минуту.
    let since = Utc::now() - chrono::Duration::days(1);
    let recent = state.devices.read().await.children_since(&inviter, since);
    if recent >= state.config.devices.max_enrolls_per_day {
        tracing::warn!(%inviter, recent, "device api: enroll budget exhausted");
        state
            .alerts
            .emit(crate::model::alert::Alert::warning(
                "deviceapi",
                format!(
                    "устройство `{inviter}` завело за сутки {recent} устройств — предел исчерпан"
                ),
            ))
            .await;
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many devices enrolled today",
        ));
    }

    let device = state
        .devices
        .write()
        .await
        .add(
            name,
            platform,
            Some(format!("заведено с устройства {inviter}")),
            state.config.devices.max_devices,
        )
        .map_err(|e| {
            tracing::warn!(%inviter, error = %e, "device api: enroll refused");
            // Лимит устройств и повтор имени — это не ошибка сервера, а ответ ему.
            ApiError(StatusCode::CONFLICT, "cannot add the device")
        })?;

    // Родство записываем сразу: по нему работает транзитивный отзыв.
    if let Err(e) = state
        .devices
        .write()
        .await
        .note_enrolled_by(&device.id, &inviter)
    {
        tracing::error!(%inviter, error = %e, "device api: cannot record the parent");
        let _ = state.devices.write().await.remove(&device.id);
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot record the device",
        ));
    }

    let bundle = crate::configgen::build_bundle(&state.config, &device).map_err(|e| {
        tracing::error!(%inviter, error = %e, "device api: cannot build a bundle");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot build a bundle")
    })?;

    // Помечаем выдачу так же, как это делает admin API: счётчик bundle'ов — часть
    // того, по чему потом разбирают инцидент.
    let _ = state.devices.write().await.note_bundle_issued(&device.id);

    tracing::warn!(
        %inviter,
        new_device = %device.id,
        "device api: a family member enrolled a new device"
    );
    state
        .alerts
        .emit(crate::model::alert::Alert::warning(
            "deviceapi",
            format!(
                "устройство `{}` завело новое устройство `{}` — проверьте, что это ожидаемо",
                inviter, device.id
            ),
        ))
        .await;

    Ok(Json(bundle).into_response())
}

#[derive(Debug, Deserialize)]
struct ClaimRequest {
    /// Ключ установки: один и тот же при повторе после обрыва.
    ///
    /// Необязателен — старые сборки его не присылают, и для них поведение прежнее.
    #[serde(default)]
    install_id: Option<String>,
    /// Как назвать устройство в реестре. Приложение подставляет модель телефона —
    /// человек в этот момент ничего не вводит, в этом и смысл.
    name: String,
    /// `android` | `ios` | `desktop`. Сборки до этого поля его не присылают — для них
    /// `android`, как и было.
    #[serde(default)]
    platform: Option<String>,
}

/// Завести себя по вшитому в сборку приглашению.
///
/// # Зачем
///
/// Это тот самый шаг, которого в SimpleX нет: там серверы публичные и вшиты, поэтому
/// человек ставит приложение и сразу им пользуется. У нас серверы свои, и без этого
/// эндпоинта каждый телефон требовал бы QR — то есть кого-то рядом с настроенным
/// телефоном или у терминала.
///
/// # Чем это отличается от `/enroll`
///
/// `/enroll` предъявляет токен УЖЕ заведённого устройства: человек с работающим
/// телефоном заводит следующий. Здесь предъявляется приглашение — секрет, который
/// живёт в самой сборке и ограничен сроком, числом использований и отзывом.
///
/// # Что здесь можно потерять
///
/// Пока приглашение живо, файл APK ценен: кто его достал, тот войдёт в контур. Это
/// названо в ADR 0010 и ограничивается тремя вещами — коротким сроком, счётчиком
/// использований и тем, что каждое использование поднимает alert. Когда приглашение
/// исчерпано, из сборки достать нечего: паролей релеев в ней нет.
async fn claim(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<PeerIp>>,
    headers: HeaderMap,
    Json(req): Json<ClaimRequest>,
) -> ApiResult<Response> {
    let token = headers
        .get(INVITE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invite token required"));
    }

    // Адреса может не быть: так вызывают из тестов, где соединение не настоящее.
    // Отсутствие адреса не повод отказать — повод не считать.
    let peer_ip = peer.map(|axum::Extension(PeerIp(ip))| ip);
    let at = std::time::Instant::now();
    if let Some(ip) = peer_ip {
        if let throttle::Verdict::Blocked(left) = state.claim_throttle.check(ip, at) {
            tracing::warn!(%ip, left = left.as_secs(), "device api: claim is throttled");
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many attempts, try later",
            ));
        }
    }

    // Всё, что можно проверить по самому запросу, проверяется ДО списания кода. Раньше
    // длинное имя отвергалось уже после `reserve()` и без `release()`: одноразовый код
    // сгорал на ошибке, которой человек даже не видел, — имя подставляет приложение.
    let requested = req.name.trim();
    if requested.chars().count() > 64 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad device name"));
    }
    let Some(platform) = requested_platform(req.platform.as_deref()) else {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad platform"));
    };

    let now = Utc::now();

    // Повтор после потерянного ответа. Телефон в мобильной сети отправил claim, узел
    // его завёл, ответ не доехал — и повтор не должен ни съедать второе
    // использование одноразового кода, ни плодить второе устройство. Проверяем ДО
    // списания: у идемпотентного повтора нет права тратить код.
    let install_id = req
        .install_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(install_id) = install_id {
        let existing = state
            .devices
            .read()
            .await
            .by_install_id(install_id)
            .cloned();
        if let Some(device) = existing {
            let bundle = crate::configgen::build_bundle(&state.config, &device).map_err(|e| {
                tracing::error!(device = %device.id, error = %e, "device api: cannot rebuild a bundle");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot build a bundle")
            })?;
            let _ = state.devices.write().await.note_bundle_issued(&device.id);
            if let Some(ip) = peer_ip {
                state.claim_throttle.note_success(ip, at);
            }
            tracing::info!(device = %device.id, "device api: claim repeated, bundle re-issued");
            return Ok(Json(bundle).into_response());
        }
    }

    // Списание неделимо: проверка и `uses += 1` происходят под одним `&mut`.
    // Раньше между ними было окно, и десять одновременных запросов с одним
    // одноразовым кодом заводили десять устройств.
    let invite = match state.invites.write().await.reserve(&token, now) {
        Ok(invite) => invite,
        Err(_) => {
            // Просроченное, исчерпанное и вовсе несуществующее приглашение
            // отвечают одинаково: по ответу нельзя узнать, было ли оно.
            tracing::warn!("device api: rejected an unusable invite token");
            if let Some(ip) = peer_ip {
                if state.claim_throttle.note_failure(ip, at) {
                    state
                        .alerts
                        .emit(crate::model::alert::Alert::warning(
                            "deviceapi",
                            format!(
                                "с адреса {ip} подбирали код доступа — вход с него закрыт на час"
                            ),
                        ))
                        .await;
                }
            }
            return Err(ApiError(StatusCode::UNAUTHORIZED, "unknown invite"));
        }
    };
    let invite_id = invite.id.clone();

    let requested = if requested.is_empty() {
        "Устройство"
    } else {
        requested
    };

    let device = {
        let mut devices = state.devices.write().await;
        // Имя приходит от приложения — это модель телефона, и два одинаковых телефона
        // в семье не редкость. Совпадение имени не повод отказать человеку в заведении,
        // поэтому подбираем свободное, а не возвращаем 409, как это делает `/enroll`,
        // где имя набирает человек и повтор — почти всегда его опечатка.
        let mut attempt = 0;
        loop {
            let name = if attempt == 0 {
                requested.to_string()
            } else {
                format!("{requested} {}", attempt + 1)
            };
            match devices.add(
                &name,
                platform,
                Some(format!("заведено по приглашению {invite_id}")),
                state.config.devices.max_devices,
            ) {
                Ok(device) => break device,
                Err(crate::error::Error::Conflict(_)) if attempt < 9 => {
                    attempt += 1;
                }
                Err(e) => {
                    tracing::warn!(%invite_id, error = %e, "device api: claim refused");
                    // Заведение не состоялось — использование возвращаем, иначе
                    // честная попытка съедает код.
                    let _ = state.invites.write().await.release(&invite_id);
                    return Err(ApiError(StatusCode::CONFLICT, "cannot add the device"));
                }
            }
        }
    };

    // Дальше любая неудача обязана откатить И запись устройства, И использование:
    // иначе недоступный TURN-секрет превращает каждую попытку в запись-призрак,
    // которая навсегда занимает слот и имя.
    let bundle = match crate::configgen::build_bundle(&state.config, &device) {
        Ok(bundle) => bundle,
        Err(e) => {
            tracing::error!(%invite_id, error = %e, "device api: cannot build a bundle");
            let _ = state.devices.write().await.remove(&device.id);
            let _ = state.invites.write().await.release(&invite_id);
            return Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot build a bundle",
            ));
        }
    };

    // Привязку устройства к приглашению записываем ДО выдачи bundle. Если запись не
    // удалась (диск полон, state_dir перемонтирован в ro), отдавать пароли релеев
    // нельзя: на диске не останется ни счётчика, ни следа, кого этот код впустил, и
    // после перезапуска одноразовый код снова окажется свежим.
    if let Err(e) = state
        .invites
        .write()
        .await
        .note_device(&invite_id, &device.id)
    {
        tracing::error!(%invite_id, error = %e, "device api: cannot record the claim");
        let _ = state.devices.write().await.remove(&device.id);
        let _ = state.invites.write().await.release(&invite_id);
        state
            .alerts
            .emit(crate::model::alert::Alert::critical(
                "deviceapi",
                format!("не удалось записать использование приглашения `{invite_id}`: {e}"),
            ))
            .await;
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot record the claim",
        ));
    }
    if let Some(install_id) = install_id {
        let _ = state
            .devices
            .write()
            .await
            .note_install_id(&device.id, install_id);
    }
    let _ = state.devices.write().await.note_bundle_issued(&device.id);
    // Счётчик неудач сбрасываем только здесь: неудавшийся claim не должен обнулять
    // историю перебора.
    if let Some(ip) = peer_ip {
        state.claim_throttle.note_success(ip, at);
    }

    tracing::warn!(
        %invite_id,
        new_device = %device.id,
        "device api: a device claimed itself with an invite"
    );
    state
        .alerts
        .emit(crate::model::alert::Alert::warning(
            "deviceapi",
            format!(
                "по приглашению `{}` завелось устройство `{}` — проверьте, что это свой",
                invite_id, device.id
            ),
        ))
        .await;

    Ok(Json(bundle).into_response())
}

#[derive(Debug, Serialize)]
struct TurnCredentials {
    username: String,
    credential: String,
    /// Строки ICE в том виде, в каком их принимает клиент — тот же формат, что в bundle.
    ice: Vec<String>,
    #[serde(with = "crate::model::rfc3339")]
    expires: chrono::DateTime<Utc>,
}

/// Свежие TURN-креды.
///
/// Это и есть лечение той асимметрии, которую описывает `rotate_turn_secret`: раньше
/// после ротации секрета у всех устройств умирали звонки, а сообщения продолжали
/// ходить, и симптом читался как «сломался микрофон», а не «протухли креды».
async fn turn_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let device = authorize(&state, &headers).await?;

    if !state.config.turn.enabled {
        return Err(ApiError(StatusCode::NOT_FOUND, "turn is disabled"));
    }

    let secret = store::read_secret(&state.config.turn.secret_file).map_err(|e| {
        tracing::error!(error = %e, "device api: cannot read the turn secret");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "turn secret unavailable")
    })?;
    let cred = turn::credential(&secret, state.config.turn.credential_ttl_secs, Utc::now())
        .map_err(|e| {
            tracing::error!(error = %e, "device api: cannot mint turn credentials");
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot mint credentials")
        })?;
    let ice =
        turn::ice_servers(&state.config.turn, &state.config.node.host, &cred).map_err(|e| {
            tracing::error!(error = %e, "device api: cannot build ice servers");
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, "cannot build ice")
        })?;

    tracing::debug!(%device, "device api: turn credentials issued");
    Ok(Json(TurnCredentials {
        username: cred.username,
        credential: cred.credential,
        ice,
        expires: cred.expires,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_plain_apk_name() {
        assert!(is_safe_apk_name("hearth-7.0.1-arm64-v8a.apk"));
    }

    #[test]
    fn refuses_traversal_and_anything_that_is_not_an_apk() {
        for bad in [
            "",
            "../../etc/shadow",
            "..",
            "../hearth.apk",
            "sub/dir/hearth.apk",
            ".hidden.apk",
            "manifest.json",
            "hearth.apk.exe",
        ] {
            assert!(!is_safe_apk_name(bad), "должно быть отвергнуто: {bad:?}");
        }
    }

    #[test]
    fn refuses_a_windows_style_traversal() {
        assert!(!is_safe_apk_name("..\\hearth.apk"));
    }

    #[test]
    fn token_comparison_is_length_safe() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        // Разная длина не должна ни паниковать, ни совпадать.
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn parses_ordinary_ranges() {
        assert_eq!(parse_range("bytes=0-99", 1000), Some(Some((0, 99))));
        assert_eq!(parse_range("bytes=100-", 1000), Some(Some((100, 999))));
        // Конец за пределами файла подрезается, а не отвергается: так делает
        // большинство клиентов, и RFC 9110 это разрешает.
        assert_eq!(parse_range("bytes=900-5000", 1000), Some(Some((900, 999))));
        assert_eq!(parse_range("bytes=-100", 1000), Some(Some((900, 999))));
    }

    #[test]
    fn refuses_nonsense_ranges() {
        // Начало за концом файла — 416, а не «отдать всё»: иначе клиент склеит
        // полученное с тем, что уже скачал, и получит мусор.
        assert_eq!(parse_range("bytes=1000-", 1000), Some(None));
        assert_eq!(parse_range("bytes=500-100", 1000), Some(None));
        assert_eq!(parse_range("bytes=0-9,20-29", 1000), Some(None));
        assert_eq!(parse_range("bytes=-0", 1000), Some(None));
    }

    #[test]
    fn ignores_units_it_does_not_speak() {
        assert_eq!(parse_range("items=0-99", 1000), None);
        assert_eq!(parse_range("bytes=abc", 1000), None);
    }

    #[test]
    fn the_platform_is_strict_and_defaults_to_android() {
        use crate::model::device::Platform;
        assert_eq!(requested_platform(None), Some(Platform::Android));
        assert_eq!(requested_platform(Some("android")), Some(Platform::Android));
        assert_eq!(requested_platform(Some("ios")), Some(Platform::Ios));
        assert_eq!(requested_platform(Some("desktop")), Some(Platform::Desktop));
        // То, что `hearthctl` прощает человеку, приложению не прощается.
        for bad in ["iphone", "iOS", "pc", "", "symbian"] {
            assert_eq!(requested_platform(Some(bad)), None, "{bad:?}");
        }
    }

    /// Узел с секретами релеев на диске — ровно столько, сколько `/claim` нужно для bundle.
    fn claim_node(dir: &std::path::Path) -> Arc<AppState> {
        let mut config = crate::state::tests::test_config(dir);
        config.smp.fingerprint_file = dir.join("smp-fingerprint");
        config.smp.password_file = Some(dir.join("smp-password"));
        config.xftp.fingerprint_file = dir.join("xftp-fingerprint");
        config.xftp.password_file = Some(dir.join("xftp-password"));
        config.turn.secret_file = dir.join("turn-secret");
        for (file, value) in [
            ("smp-fingerprint", "smpFingerPrintAbC"),
            ("smp-password", "smpPassword123"),
            ("xftp-fingerprint", "xftpFingerPrintXyZ"),
            ("xftp-password", "xftpPassword456"),
            ("turn-secret", "turnStaticSecret"),
        ] {
            store::write_secret(dir.join(file), value).expect("seed");
        }
        AppState::new(config, crate::sys::Sys::new(true)).expect("state")
    }

    async fn post_claim(state: &Arc<AppState>, code: &str, body: serde_json::Value) -> StatusCode {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/claim")
            .header(INVITE_HEADER, code)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        tower::ServiceExt::oneshot(router(state.clone()), request)
            .await
            .expect("response")
            .status()
    }

    #[test]
    fn sticker_paths_are_whitelisted() {
        assert!(is_safe_sticker_pack("animals"));
        assert!(is_safe_sticker_pack("just_zoo_it_2"));
        assert!(!is_safe_sticker_pack(""));
        // Только строчные: так пишет импорт, а лишняя свобода — лишняя поверхность.
        assert!(!is_safe_sticker_pack("Animals"));
        assert!(!is_safe_sticker_pack("../updates"));
        assert!(!is_safe_sticker_pack("a/b"));
        assert!(!is_safe_sticker_pack(&"x".repeat(65)));

        assert!(is_safe_sticker_file("pack.json"));
        assert!(is_safe_sticker_file("001.webp"));
        assert!(!is_safe_sticker_file("1.webp"));
        assert!(!is_safe_sticker_file("001.png"));
        assert!(!is_safe_sticker_file("../pack.json"));
        // Индекс лежит уровнем выше и отдаётся своим маршрутом.
        assert!(!is_safe_sticker_file("index.json"));
    }

    async fn get_signature(state: &Arc<AppState>, token: &str) -> (StatusCode, Vec<u8>) {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/updates/manifest.json.sig")
            .header(TOKEN_HEADER, token)
            .body(Body::empty())
            .expect("request");
        let response = tower::ServiceExt::oneshot(router(state.clone()), request)
            .await
            .expect("response");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, body.to_vec())
    }

    #[tokio::test]
    async fn a_device_gets_the_manifest_signature_and_an_honest_404_without_it() {
        // Ровно тот сбой, из-за которого обновление по воздуху не ставилось: подпись
        // лежала рядом с манифестом, а узел отвечал на неё 400.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        let updates = dir.path().join("updates");
        std::fs::create_dir_all(&updates).expect("updates dir");
        config.device_api.updates_dir = updates.clone();
        let state = AppState::new(config, crate::sys::Sys::new(true)).expect("state");
        let token = state
            .devices
            .write()
            .await
            .add("sig-check", crate::model::device::Platform::Android, None, 10)
            .expect("device")
            .token
            .expect("token");

        // Подписи нет: 404, а не 400 — клиент со вшитым ключом сам откажет (fail-closed).
        let (status, _) = get_signature(&state, &token).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        std::fs::write(updates.join("manifest.json.sig"), b"c2lnbmF0dXJl
").expect("seed sig");
        let (status, body) = get_signature(&state, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"c2lnbmF0dXJl
".to_vec(), "отдаётся ровно файл подписи");
    }

    #[test]
    fn the_signature_is_not_an_apk_name() {
        // Именно поэтому у подписи свой маршрут: общий `/updates/{file}` её отвергает.
        assert!(!is_safe_apk_name("manifest.json.sig"));
        assert!(!is_safe_apk_name("manifest.json"));
    }

    #[tokio::test]
    async fn the_manifest_signature_requires_a_device_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = claim_node(dir.path());
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/updates/manifest.json.sig")
            .body(Body::empty())
            .expect("request");
        let status = tower::ServiceExt::oneshot(router(state), request)
            .await
            .expect("response")
            .status();
        // 401, а не 400: запрос дошёл до своего обработчика, а не до `/updates/{file}`.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stickers_require_a_device_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = claim_node(dir.path());
        for uri in ["/stickers/index.json", "/stickers/animals/001.webp"] {
            let request = axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request");
            let status = tower::ServiceExt::oneshot(router(state.clone()), request)
                .await
                .expect("response")
                .status();
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn a_bad_request_does_not_burn_a_single_use_code() {
        // Раньше длинное имя отвергалось после reserve() и без release(): одноразовый код
        // сгорал, хотя устройство так и не завелось.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = claim_node(dir.path());
        let invite = state
            .invites
            .write()
            .await
            .create(1, 0, None)
            .expect("invite");

        let long_name = "x".repeat(65);
        assert_eq!(
            post_claim(
                &state,
                &invite.token,
                serde_json::json!({ "name": long_name })
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_claim(
                &state,
                &invite.token,
                serde_json::json!({ "name": "iPhone", "platform": "symbian" })
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            state
                .invites
                .read()
                .await
                .get(&invite.id)
                .expect("invite")
                .uses,
            0,
            "ни одна отвергнутая попытка не списала код"
        );

        assert_eq!(
            post_claim(
                &state,
                &invite.token,
                serde_json::json!({ "name": "iPhone" })
            )
            .await,
            StatusCode::OK,
            "the code still lets the device in"
        );
    }

    #[tokio::test]
    async fn a_claim_records_the_platform_it_was_given() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = claim_node(dir.path());
        let ios = state
            .invites
            .write()
            .await
            .create(1, 0, None)
            .expect("invite");
        let legacy = state
            .invites
            .write()
            .await
            .create(1, 0, None)
            .expect("invite");

        assert_eq!(
            post_claim(
                &state,
                &ios.token,
                serde_json::json!({ "name": "iPhone 15", "platform": "ios" })
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            post_claim(
                &state,
                &legacy.token,
                serde_json::json!({ "name": "Pixel 8" })
            )
            .await,
            StatusCode::OK
        );

        let devices = state.devices.read().await;
        let platform_of = |name: &str| {
            devices
                .active()
                .find(|device| device.name == name)
                .map(|device| device.platform)
        };
        assert_eq!(
            platform_of("iPhone 15"),
            Some(crate::model::device::Platform::Ios)
        );
        assert_eq!(
            platform_of("Pixel 8"),
            Some(crate::model::device::Platform::Android),
            "a build without the field stays android"
        );
    }
}
