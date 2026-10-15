//! Encrypted attachment lifecycle inside the authenticated Oak dispatcher.
use std::collections::{HashMap, HashSet};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    api::error::ApiError,
    auth::User,
    config::R2Config,
    storage::{
        attachments::{MAX_ATTACHMENTS_PER_CHAT, link_attachment_records},
        quota::require_pro,
        r2::R2Storage,
    },
};

use crate::storage::ciphertext::{MIN_ENVELOPE_BYTES, WRAPPED_CHAT_KEY_BYTES, decode_envelope};

const MAX_METADATA_CIPHERTEXT_BYTES: usize = 64 * 1024;
const AES_GCM_PART_OVERHEAD_BYTES: i64 = 28;
const MAX_ATTACHMENT_BYTES: i64 = 20 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;

#[derive(Clone)]
struct AttachmentState {
    db: PgPool,
    config: Option<R2Config>,
    storage: Option<R2Storage>,
}

pub fn router(db: PgPool, config: Option<R2Config>) -> Router {
    let storage = config.as_ref().map(R2Storage::new);
    Router::new()
        .route("/v1/attachments", post(create_attachment))
        .route(
            "/v1/attachments/{attachment_id}",
            get(get_attachment).delete(delete_attachment),
        )
        .route(
            "/v1/attachments/{attachment_id}/complete",
            post(complete_attachment),
        )
        .route("/v1/attachments/{attachment_id}/upload", post(sign_upload))
        .route("/v1/attachments/link", put(link_attachments))
        .route("/v1/attachments/{attachment_id}/link", put(link_attachment))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(AttachmentState {
            db,
            config,
            storage,
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateAttachmentRequest {
    attachment_id: Uuid,
    source_size: i64,
    encryption_version: i16,
    encrypted_metadata: String,
    encrypted_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAttachmentResponse {
    attachment_id: Uuid,
    plaintext_part_size: i64,
    part_count: i32,
    ciphertext_size: i64,
    created_at: DateTime<Utc>,
    upload: SignedRequestResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedRequestResponse {
    url: String,
    headers: HashMap<String, String>,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkAttachmentRequest {
    chat_id: Uuid,
    message_id: Uuid,
    encrypted_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkAttachmentsRequest {
    chat_id: Uuid,
    message_id: Uuid,
    attachments: Vec<LinkAttachmentItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkAttachmentItem {
    attachment_id: Uuid,
    encrypted_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentResponse {
    attachment_id: Uuid,
    status: String,
    encryption_version: i16,
    encrypted_metadata: String,
    encrypted_key: String,
    ciphertext_size: i64,
    plaintext_part_size: i64,
    part_count: i32,
    created_at: DateTime<Utc>,
    download: SignedRequestResponse,
}

async fn create_attachment(
    State(state): State<AttachmentState>,
    user: User,
    Json(input): Json<CreateAttachmentRequest>,
) -> Result<(StatusCode, Json<CreateAttachmentResponse>), ApiError> {
    require_pro(&state.db, user.id()).await?;
    let storage = storage(&state)?;
    let config = state.config.as_ref().ok_or(ApiError::Unavailable)?;
    let max_attachment_bytes = config.max_attachment_bytes.min(MAX_ATTACHMENT_BYTES);
    if input.source_size <= 0 || input.source_size > max_attachment_bytes {
        return Err(ApiError::BadRequest(format!(
            "sourceSize must be between 1 and {max_attachment_bytes} bytes"
        )));
    }
    if input.encryption_version != 1 {
        return Err(ApiError::BadRequest(
            "encryptionVersion must currently be 1".into(),
        ));
    }
    let encrypted_metadata = decode_envelope(
        "encryptedMetadata",
        &input.encrypted_metadata,
        MIN_ENVELOPE_BYTES,
        MAX_METADATA_CIPHERTEXT_BYTES,
    )?;
    let encrypted_key = decode_envelope(
        "encryptedKey",
        &input.encrypted_key,
        WRAPPED_CHAT_KEY_BYTES,
        WRAPPED_CHAT_KEY_BYTES,
    )?;
    let ciphertext_size = input
        .source_size
        .checked_add(AES_GCM_PART_OVERHEAD_BYTES)
        .ok_or_else(|| ApiError::BadRequest("attachment size overflow".into()))?;
    let attachment_id = input.attachment_id;
    let object_key = format!("attachments/{attachment_id}");
    let signed = storage
        .presign_upload(&object_key, ciphertext_size)
        .await
        .map_err(|_| {
            tracing::warn!("could not presign R2 attachment upload");
            ApiError::Unavailable
        })?;

    let row = sqlx::query(
        r"INSERT INTO attachments
           (id, user_id, object_key, upload_id, status, encryption_version,
            encrypted_metadata, encrypted_key, ciphertext_size, part_size, part_count)
           VALUES ($1, $2, $3, NULL, 'uploading', $4, $5, $6, $7, $8, 1)
           RETURNING created_at",
    )
    .bind(attachment_id)
    .bind(user.id())
    .bind(&object_key)
    .bind(input.encryption_version)
    .bind(encrypted_metadata)
    .bind(encrypted_key)
    .bind(ciphertext_size)
    .bind(MAX_ATTACHMENT_BYTES)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateAttachmentResponse {
            attachment_id,
            plaintext_part_size: MAX_ATTACHMENT_BYTES,
            part_count: 1,
            ciphertext_size,
            created_at: row.try_get("created_at")?,
            upload: signed_response(&state, signed),
        }),
    ))
}

async fn sign_upload(
    State(state): State<AttachmentState>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<Json<SignedRequestResponse>, ApiError> {
    require_pro(&state.db, user.id()).await?;
    let storage = storage(&state)?;
    let row = sqlx::query(
        r"SELECT object_key, ciphertext_size
           FROM attachments
           WHERE id = $1 AND user_id = $2 AND status = 'uploading'",
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.try_get("object_key")?;
    let ciphertext_size: i64 = row.try_get("ciphertext_size")?;
    let signed = storage
        .presign_upload(&object_key, ciphertext_size)
        .await
        .map_err(|_| {
            tracing::warn!("could not renew R2 attachment upload");
            ApiError::Unavailable
        })?;
    Ok(Json(signed_response(&state, signed)))
}

async fn complete_attachment(
    State(state): State<AttachmentState>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_pro(&state.db, user.id()).await?;
    let storage = storage(&state)?;
    let row = sqlx::query(
        r"SELECT status, object_key, ciphertext_size
           FROM attachments
           WHERE id = $1 AND user_id = $2",
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let status: String = row.try_get("status")?;
    if status == "ready" || status == "attached" {
        return Ok(StatusCode::OK);
    }
    if status != "uploading" {
        return Err(ApiError::Conflict);
    }
    let object_key: String = row.try_get("object_key")?;
    let ciphertext_size: i64 = row.try_get("ciphertext_size")?;
    let stored_size = storage.object_size(&object_key).await.map_err(|_| {
        tracing::warn!("could not verify completed R2 attachment size");
        ApiError::Unavailable
    })?;
    if stored_size != ciphertext_size {
        if storage.delete_object(&object_key).await.is_err() {
            tracing::warn!("could not delete oversized R2 attachment");
        }
        sqlx::query("DELETE FROM attachments WHERE id = $1 AND user_id = $2")
            .bind(attachment_id)
            .bind(user.id())
            .execute(&state.db)
            .await?;
        return Err(ApiError::BadRequest(
            "uploaded attachment size does not match the declared size".into(),
        ));
    }
    let updated = sqlx::query(
        r"UPDATE attachments
           SET status = 'ready', upload_id = NULL, updated_at = now()
           WHERE id = $1 AND user_id = $2 AND status = 'uploading'",
    )
    .bind(attachment_id)
    .bind(user.id())
    .execute(&state.db)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::Conflict);
    }
    Ok(StatusCode::OK)
}

async fn link_attachment(
    State(state): State<AttachmentState>,
    user: User,
    Path(attachment_id): Path<Uuid>,
    Json(input): Json<LinkAttachmentRequest>,
) -> Result<StatusCode, ApiError> {
    require_pro(&state.db, user.id()).await?;
    let encrypted_key = decode_envelope(
        "encryptedKey",
        &input.encrypted_key,
        WRAPPED_CHAT_KEY_BYTES,
        WRAPPED_CHAT_KEY_BYTES,
    )?;
    link_attachment_records(
        &state.db,
        user.id(),
        input.chat_id,
        input.message_id,
        &[(attachment_id, encrypted_key)],
    )
    .await?;
    Ok(StatusCode::OK)
}

async fn link_attachments(
    State(state): State<AttachmentState>,
    user: User,
    Json(input): Json<LinkAttachmentsRequest>,
) -> Result<StatusCode, ApiError> {
    require_pro(&state.db, user.id()).await?;
    if input.attachments.is_empty() || input.attachments.len() > MAX_ATTACHMENTS_PER_CHAT {
        return Err(ApiError::BadRequest(
            "attachments must contain 1..20 entries".into(),
        ));
    }
    let mut ids = HashSet::with_capacity(input.attachments.len());
    let mut attachments = Vec::with_capacity(input.attachments.len());
    for attachment in input.attachments {
        if !ids.insert(attachment.attachment_id) {
            return Err(ApiError::BadRequest(
                "attachments must not contain duplicate IDs".into(),
            ));
        }
        attachments.push((
            attachment.attachment_id,
            decode_envelope(
                "encryptedKey",
                &attachment.encrypted_key,
                WRAPPED_CHAT_KEY_BYTES,
                WRAPPED_CHAT_KEY_BYTES,
            )?,
        ));
    }
    link_attachment_records(
        &state.db,
        user.id(),
        input.chat_id,
        input.message_id,
        &attachments,
    )
    .await?;
    Ok(StatusCode::OK)
}

async fn get_attachment(
    State(state): State<AttachmentState>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<Json<AttachmentResponse>, ApiError> {
    let storage = storage(&state)?;
    let row = sqlx::query(
        r"SELECT status, object_key, encryption_version, encrypted_metadata,
                  encrypted_key, ciphertext_size, part_size, part_count, created_at
           FROM attachments
           WHERE id = $1 AND user_id = $2 AND status IN ('ready', 'attached')",
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.try_get("object_key")?;
    let signed = storage.presign_download(&object_key).await.map_err(|_| {
        tracing::warn!("could not presign R2 attachment download");
        ApiError::Unavailable
    })?;
    Ok(Json(AttachmentResponse {
        attachment_id,
        status: row.try_get("status")?,
        encryption_version: row.try_get("encryption_version")?,
        encrypted_metadata: STANDARD.encode(row.try_get::<Vec<u8>, _>("encrypted_metadata")?),
        encrypted_key: STANDARD.encode(row.try_get::<Vec<u8>, _>("encrypted_key")?),
        ciphertext_size: row.try_get("ciphertext_size")?,
        plaintext_part_size: row.try_get("part_size")?,
        part_count: row.try_get("part_count")?,
        created_at: row.try_get("created_at")?,
        download: signed_response(&state, signed),
    }))
}

async fn delete_attachment(
    State(state): State<AttachmentState>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let storage = storage(&state)?;
    let row = sqlx::query(
        r"SELECT object_key
           FROM attachments WHERE id = $1 AND user_id = $2",
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.try_get("object_key")?;
    storage.delete_object(&object_key).await.map_err(|_| {
        tracing::warn!("could not delete R2 attachment object");
        ApiError::Unavailable
    })?;
    sqlx::query("DELETE FROM attachments WHERE id = $1 AND user_id = $2")
        .bind(attachment_id)
        .bind(user.id())
        .execute(&state.db)
        .await?;
    Ok(StatusCode::OK)
}

fn storage(state: &AttachmentState) -> Result<&R2Storage, ApiError> {
    state.storage.as_ref().ok_or(ApiError::Unavailable)
}

fn signed_response(
    state: &AttachmentState,
    signed: crate::storage::r2::PresignedRequest,
) -> SignedRequestResponse {
    SignedRequestResponse {
        url: signed.url,
        headers: signed.headers,
        expires_in_seconds: state
            .config
            .as_ref()
            .expect("storage config exists")
            .presign_ttl_seconds,
    }
}
