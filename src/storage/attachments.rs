//! Atomic, user-scoped attachment linking against existing chat/message records.
use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

use crate::api::error::ApiError;

pub(crate) const MAX_ATTACHMENTS_PER_CHAT: usize = 20;
const MAX_CRDB_ATTEMPTS: usize = 4;

pub(crate) async fn link_attachment_records(
    pool: &PgPool,
    user_id: &str,
    chat_id: Uuid,
    message_id: Uuid,
    attachments: &[(Uuid, Vec<u8>)],
) -> Result<(), ApiError> {
    for attempt in 0..MAX_CRDB_ATTEMPTS {
        match link_attachment_records_once(pool, user_id, chat_id, message_id, attachments).await {
            Err(ApiError::Database { retryable: true }) if attempt + 1 < MAX_CRDB_ATTEMPTS => {
                tokio::time::sleep(Duration::from_millis(10 * (1_u64 << attempt))).await;
            }
            result => return result,
        }
    }
    Err(ApiError::Unavailable)
}

async fn link_attachment_records_once(
    pool: &PgPool,
    user_id: &str,
    chat_id: Uuid,
    message_id: Uuid,
    attachments: &[(Uuid, Vec<u8>)],
) -> Result<(), ApiError> {
    let mut tx = pool.begin().await?;
    let owned = sqlx::query_scalar::<_, bool>(
        "SELECT true FROM chats WHERE id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(chat_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !owned {
        return Err(ApiError::NotFound);
    }
    let message_exists = sqlx::query_scalar::<_, bool>(
        "SELECT true FROM messages WHERE message_id = $1 AND chat_id = $2",
    )
    .bind(message_id)
    .bind(chat_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !message_exists {
        return Err(ApiError::NotFound);
    }
    let current_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM attachments WHERE user_id = $1 AND chat_id = $2 AND status = 'attached'",
    )
    .bind(user_id)
    .bind(chat_id)
    .fetch_one(&mut *tx)
    .await?;
    if current_count + i64::try_from(attachments.len()).map_err(|_| ApiError::Internal)?
        > i64::try_from(MAX_ATTACHMENTS_PER_CHAT).map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::BadRequest(
            "a conversation can contain at most 20 attachments".into(),
        ));
    }
    for (attachment_id, encrypted_key) in attachments {
        let updated = sqlx::query(
            r"UPDATE attachments
               SET chat_id = $1, message_id = $2, encrypted_key = $3,
                   status = 'attached', updated_at = now()
               WHERE id = $4 AND user_id = $5 AND status = 'ready'",
        )
        .bind(chat_id)
        .bind(message_id)
        .bind(encrypted_key)
        .bind(attachment_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::NotFound);
        }
    }
    tx.commit().await?;
    Ok(())
}
