//! Encrypted chat storage, mounted only in the authenticated Oak dispatcher.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    api::error::ApiError,
    auth::User,
    storage::{
        chats::{Chat, ChatStore},
        ciphertext::{MIN_ENVELOPE_BYTES, WRAPPED_CHAT_KEY_BYTES, decode_envelope},
    },
};

const MAX_CHAT_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;

pub fn router(db: PgPool) -> Router {
    Router::new()
        .route(
            "/v1/chats",
            get(list_chats).put(put_chat).delete(delete_all_chats),
        )
        .route(
            "/v1/chats/{chat_id}",
            get(get_chat)
                .put(patch_chat)
                .patch(patch_chat)
                .delete(delete_chat),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(ChatStore::new(db))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutChatRequest {
    ciphertext: String,
    encrypted_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchChatRequest {
    ciphertext: String,
    #[serde(default)]
    expected_revision: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatResponse {
    id: Uuid,
    ciphertext: String,
    encrypted_key: String,
    created_at: DateTime<Utc>,
    last_message_at: DateTime<Utc>,
    revision: i64,
}

impl From<Chat> for ChatResponse {
    fn from(chat: Chat) -> Self {
        Self {
            id: chat.id,
            ciphertext: STANDARD.encode(chat.ciphertext),
            encrypted_key: STANDARD.encode(chat.encrypted_key),
            created_at: chat.created_at,
            last_message_at: chat.last_message_at,
            revision: chat.revision,
        }
    }
}

#[derive(Serialize)]
struct ChatListResponse {
    items: Vec<ChatResponse>,
}

async fn put_chat(
    State(store): State<ChatStore>,
    user: User,
    Json(input): Json<PutChatRequest>,
) -> Result<Json<ChatResponse>, ApiError> {
    let ciphertext = decode_envelope(
        "ciphertext",
        &input.ciphertext,
        MIN_ENVELOPE_BYTES,
        MAX_CHAT_CIPHERTEXT_BYTES,
    )?;
    let encrypted_key = decode_envelope(
        "encryptedKey",
        &input.encrypted_key,
        WRAPPED_CHAT_KEY_BYTES,
        WRAPPED_CHAT_KEY_BYTES,
    )?;
    let chat = store.create(user.id(), &ciphertext, &encrypted_key).await?;
    Ok(Json(chat.into()))
}

async fn list_chats(
    State(store): State<ChatStore>,
    user: User,
) -> Result<Json<ChatListResponse>, ApiError> {
    let items = store
        .list(user.id())
        .await?
        .into_iter()
        .map(ChatResponse::from)
        .collect();
    Ok(Json(ChatListResponse { items }))
}

async fn get_chat(
    State(store): State<ChatStore>,
    user: User,
    Path(chat_id): Path<Uuid>,
) -> Result<Json<ChatResponse>, ApiError> {
    Ok(Json(store.get(user.id(), chat_id).await?.into()))
}

async fn patch_chat(
    State(store): State<ChatStore>,
    user: User,
    Path(chat_id): Path<Uuid>,
    Json(input): Json<PatchChatRequest>,
) -> Result<Json<ChatResponse>, ApiError> {
    let ciphertext = decode_envelope(
        "ciphertext",
        &input.ciphertext,
        MIN_ENVELOPE_BYTES,
        MAX_CHAT_CIPHERTEXT_BYTES,
    )?;
    let chat = store
        .update(user.id(), chat_id, &ciphertext, input.expected_revision)
        .await?;
    Ok(Json(chat.into()))
}

async fn delete_chat(
    State(store): State<ChatStore>,
    user: User,
    Path(chat_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    store.delete(user.id(), chat_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_all_chats(
    State(store): State<ChatStore>,
    user: User,
) -> Result<StatusCode, ApiError> {
    store.delete_all(user.id()).await?;
    Ok(StatusCode::NO_CONTENT)
}
