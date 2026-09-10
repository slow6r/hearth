//! Admin API handlers (ТЗ §7.3).
//!
//! Every handler is a thin projection of state the background modules already computed,
//! or a call into one of them. Handlers never block on `nft`/`systemctl` except where
//! the operator explicitly asked for an action (backup now, rotate, migrate).
//!
//! What the API deliberately does not expose: relay message data, client addresses, or
//! anything that would let an admin session read traffic (ТЗ §7.4).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::backup::BackupJob;
use crate::configgen;
use crate::error::Error;
use crate::model::alert::Severity;
use crate::model::device::Platform;
use crate::state::AppState;

/// Who is on the other end of the mTLS connection.
#[derive(Debug, Clone)]
pub struct Admin {
    pub name: String,
    pub fingerprint: String,
    pub peer: std::net::SocketAddr,
}

/// Build the router. The peer identity is injected per connection by the server loop.
pub fn router(state: Arc<AppState>) -> Router {
    let max_body = state.config.api.max_body_bytes;
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/alerts", get(alerts))
        .route("/egress", get(egress))
        .route("/egress/incidents", get(egress_incidents))
        .route("/devices", get(list_devices).post(add_device))
        .route("/devices/{id}", get(get_device))
        .route("/devices/{id}/revoke", post(revoke_device))
        .route("/devices/{id}/bundle.json", get(bundle_json))
        .route("/devices/{id}/bundle.png", get(bundle_png))
        .route("/devices/{id}/checklist.txt", get(bundle_checklist))
        .route("/invites", get(list_invites).post(create_invite))
        .route("/invites/{id}/revoke", post(revoke_invite))
        .route("/rotate/turn-secret", post(rotate_turn_secret))
        .route("/backup/now", post(backup_now))
        .route("/backup/status", get(backup_status))
        .route("/migrate/export", get(migrate_status).post(migrate_export))
        .layer(axum::extract::DefaultBodyLimit::max(max_body))
        .with_state(state)
}

// --------------------------------------------------------------------------- errors

/// JSON error body.
#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
    kind: &'static str,
}

/// Wrapper so handlers can `?` on [`crate::error::Error`].
#[derive(Debug)]
pub struct ApiFailure(Error);

impl From<Error> for ApiFailure {
    fn from(e: Error) -> Self {
        ApiFailure(e)
    }
}

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        let (status, kind) = match &self.0 {
            Error::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            Error::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Error::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
            Error::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Error::EgressDenied(_) => (StatusCode::FORBIDDEN, "egress_denied"),
            Error::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config"),
            Error::Integrity(_) => (StatusCode::INTERNAL_SERVER_ERROR, "integrity"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self.0, "admin api request failed");
        }
        (
            status,
            Json(ApiError {
                error: self.0.to_string(),
                kind,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiFailure>;

// --------------------------------------------------------------------------- status

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut snapshot = state.health.read().await.clone();
    snapshot.uptime_secs = state.uptime_secs();
    Json(snapshot)
}

async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.status().await)
}

#[derive(Debug, Deserialize)]
struct AlertQuery {
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn alerts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AlertQuery>,
) -> ApiResult<impl IntoResponse> {
    let severity = match query.severity.as_deref() {
        Some(raw) => Some(raw.parse::<Severity>()?),
        None => None,
    };
    let since = match query.since.as_deref() {
        Some(raw) => Some(
            DateTime::parse_from_rfc3339(raw)
                .map_err(|e| Error::invalid(format!("bad `since` timestamp: {e}")))?
                .with_timezone(&Utc),
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(100).min(1000);
    Ok(Json(state.alerts.query(severity, since, limit).await))
}

async fn egress(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.egress.read().await.clone())
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn egress_incidents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LimitQuery>,
) -> ApiResult<impl IntoResponse> {
    let limit = query.limit.unwrap_or(100).min(1000);
    Ok(Json(state.alerts.incident_history(limit)?))
}

// -------------------------------------------------------------------------- devices

async fn list_devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.devices.read().await.devices.clone())
}

#[derive(Debug, Deserialize)]
struct NewInvite {
    /// Сколько устройств можно завести. По умолчанию одно.
    #[serde(default)]
    max_uses: Option<u32>,
    /// Сколько дней приглашение живо. По умолчанию неделя.
    #[serde(default)]
    ttl_days: Option<i64>,
    #[serde(default)]
    note: Option<String>,
}

async fn list_invites(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    let invites = state.invites.read().await;
    Ok(Json(invites.invites.clone()))
}

/// Выписать приглашение.
///
/// Ответ содержит токен — единственный раз, когда он покидает узел в открытом виде.
/// Дальше он живёт в сборке приложения, а здесь остаётся только для сверки.
async fn create_invite(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    Json(body): Json<NewInvite>,
) -> ApiResult<impl IntoResponse> {
    let invite = state.invites.write().await.create(
        body.max_uses
            .unwrap_or(crate::model::invite::DEFAULT_MAX_USES),
        body.ttl_days
            .unwrap_or(crate::model::invite::DEFAULT_TTL_DAYS),
        body.note,
    )?;
    tracing::warn!(
        admin = %admin.name,
        invite = %invite.id,
        max_uses = invite.max_uses,
        "invite issued"
    );
    state
        .alerts
        .emit(crate::model::alert::Alert::warning(
            "api",
            format!(
                "выписано приглашение `{}` на {} устройств до {}",
                invite.id,
                invite.max_uses,
                invite.expires.format("%Y-%m-%d")
            ),
        ))
        .await;
    Ok((StatusCode::CREATED, Json(invite)))
}

async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let invite = state.invites.write().await.revoke(&id)?;
    tracing::warn!(admin = %admin.name, invite = %invite.id, "invite revoked");
    Ok(Json(invite))
}

#[derive(Debug, Deserialize)]
struct NewDevice {
    name: String,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

async fn add_device(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    Json(body): Json<NewDevice>,
) -> ApiResult<impl IntoResponse> {
    let platform: Platform = body.platform.as_deref().unwrap_or("android").parse()?;
    let device = state.devices.write().await.add(
        &body.name,
        platform,
        body.note,
        state.config.devices.max_devices,
    )?;
    tracing::info!(admin = %admin.name, device = %device.id, "device registered");
    Ok((StatusCode::CREATED, Json(device)))
}

async fn get_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let devices = state.devices.read().await;
    let device = devices
        .get(&id)
        .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?;
    Ok(Json(device.clone()))
}

async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let device = state.devices.write().await.revoke(&id)?;
    tracing::warn!(admin = %admin.name, device = %device.id, "device revoked");
    state
        .alerts
        .emit(crate::model::alert::Alert::warning(
            "api",
            format!("device `{}` revoked by {}", device.id, admin.name),
        ))
        .await;
    Ok(Json(device))
}

/// Mint a bundle and record the issue. Shared by the JSON, PNG and checklist routes.
async fn mint(
    state: &Arc<AppState>,
    id: &str,
) -> std::result::Result<(crate::model::device::Device, crate::model::bundle::Bundle), Error> {
    let device = {
        let devices = state.devices.read().await;
        devices
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("device `{id}`")))?
    };
    let bundle = configgen::build_bundle(&state.config, &device)?;
    let device = state.devices.write().await.note_bundle_issued(id)?;
    Ok((device, bundle))
}

/// Headers that keep a bundle out of caches and history.
fn no_store() -> [(header::HeaderName, &'static str); 3] {
    [
        (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
        (header::PRAGMA, "no-cache"),
        (
            header::HeaderName::from_static("x-content-type-options"),
            "nosniff",
        ),
    ]
}

async fn bundle_json(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let (_device, bundle) = mint(&state, &id).await?;
    tracing::info!(admin = %admin.name, device = %id, "bundle issued (json)");
    Ok((no_store(), Json(bundle)))
}

async fn bundle_png(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let (_device, bundle) = mint(&state, &id).await?;
    let png = crate::qr::png(&bundle.to_json()?, crate::qr::DEFAULT_SCALE)?;
    tracing::info!(admin = %admin.name, device = %id, "bundle issued (qr)");
    Ok((no_store(), [(header::CONTENT_TYPE, "image/png")], png))
}

async fn bundle_checklist(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let (device, bundle) = mint(&state, &id).await?;
    tracing::info!(admin = %admin.name, device = %id, "manual checklist issued");
    Ok((
        no_store(),
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        configgen::manual_checklist(&device, &bundle),
    ))
}

// ------------------------------------------------------------------------ operations

#[derive(Debug, Serialize)]
struct RotateReport {
    rotated: bool,
    unit: String,
    note: &'static str,
    /// Devices whose TURN credentials just stopped working. Every active device, in
    /// practice — the point is to hand the operator the list rather than leave them
    /// to remember it.
    reissue_bundles_for: Vec<String>,
}

async fn rotate_turn_secret(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
) -> ApiResult<impl IntoResponse> {
    if !state.config.turn.enabled {
        return Err(Error::Conflict("turn is disabled".into()).into());
    }
    configgen::turn::rotate_secret(&state.sys, &state.config.turn).await?;
    tracing::warn!(admin = %admin.name, "turn static secret rotated");

    // Credentials are HMACs of the old secret, so every bundle issued before this
    // moment is now dead for calls — while messages keep flowing. That asymmetry is
    // exactly what makes the symptom confusing, so name the devices explicitly.
    let stale: Vec<String> = state
        .devices
        .read()
        .await
        .active()
        .filter(|d| d.last_bundle.is_some())
        .map(|d| d.id.clone())
        .collect();

    state
        .alerts
        .emit(
            crate::model::alert::Alert::warning(
                "api",
                format!(
                    "TURN secret rotated by {}; {} device(s) need a new bundle or their \
                     calls will fail while messages keep working",
                    admin.name,
                    stale.len()
                ),
            )
            .with_details(serde_json::json!({ "devices": stale })),
        )
        .await;

    Ok(Json(RotateReport {
        rotated: true,
        unit: state.config.turn.unit.clone(),
        note: "credentials from the old secret are dead; re-issue bundles for the \
               devices listed below — calls break, messages do not, so the symptom \
               is easy to misread",
        reissue_bundles_for: stale,
    }))
}

async fn backup_now(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
) -> ApiResult<impl IntoResponse> {
    tracing::info!(admin = %admin.name, "manual backup requested");
    let info = BackupJob::new(state.clone()).run_once().await?;
    Ok(Json(info))
}

async fn backup_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.backup.read().await.clone())
}

async fn migrate_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.migrate.read().await.clone())
}

/// ТЗ §10.2 п.3. This *stops the relays*, so it is a POST — a GET that halts the
/// messenger would be triggered by any curious link-follower.
async fn migrate_export(
    State(state): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
) -> ApiResult<impl IntoResponse> {
    tracing::warn!(admin = %admin.name, "migration export requested; relays will stop");
    let report = crate::migrate::export(&state).await?;
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_mapping() {
        let cases = [
            (Error::NotFound("x".into()), StatusCode::NOT_FOUND),
            (Error::Conflict("x".into()), StatusCode::CONFLICT),
            (Error::Invalid("x".into()), StatusCode::BAD_REQUEST),
            (Error::Unauthorized("x".into()), StatusCode::UNAUTHORIZED),
            (Error::EgressDenied("x".into()), StatusCode::FORBIDDEN),
            (Error::Crypto("x".into()), StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (error, expected) in cases {
            let response = ApiFailure(error).into_response();
            assert_eq!(response.status(), expected);
        }
    }

    #[test]
    fn bundles_are_marked_no_store() {
        let headers = no_store();
        assert!(headers
            .iter()
            .any(|(name, value)| *name == header::CACHE_CONTROL && value.contains("no-store")));
    }
}
