//! User-scoped ciphertext storage using the existing chats schema.
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};
use uuid::Uuid;

use crate::api::error::ApiError;

pub(crate) struct Chat {
    pub id: Uuid,
    pub ciphertext: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_message_at: DateTime<Utc>,
    pub revision: i64,
}

#[derive(Clone)]
pub(crate) struct ChatStore {
    db: PgPool,
}

impl ChatStore {
    pub(crate) fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub(crate) async fn create(
        &self,
        user_id: &str,
        ciphertext: &[u8],
        encrypted_key: &[u8],
    ) -> Result<Chat, ApiError> {
        let row = sqlx::query(
            r"INSERT INTO chats (id, user_id, ciphertext, encrypted_key)
              VALUES ($1, $2, $3, $4)
              RETURNING id, ciphertext, encrypted_key, created_at, last_message_at, revision",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(ciphertext)
        .bind(encrypted_key)
        .fetch_one(&self.db)
        .await?;
        row_to_chat(&row)
    }

    pub(crate) async fn list(&self, user_id: &str) -> Result<Vec<Chat>, ApiError> {
        let rows = sqlx::query(
            r"SELECT id, ciphertext, encrypted_key, created_at, last_message_at, revision
              FROM chats WHERE user_id = $1
              ORDER BY last_message_at DESC, id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;
        rows.iter().map(row_to_chat).collect()
    }

    pub(crate) async fn get(&self, user_id: &str, chat_id: Uuid) -> Result<Chat, ApiError> {
        let row = sqlx::query(
            r"SELECT id, ciphertext, encrypted_key, created_at, last_message_at, revision
              FROM chats WHERE id = $1 AND user_id = $2",
        )
        .bind(chat_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(ApiError::NotFound)?;
        row_to_chat(&row)
    }

    pub(crate) async fn update(
        &self,
        user_id: &str,
        chat_id: Uuid,
        ciphertext: &[u8],
        expected_revision: Option<i64>,
    ) -> Result<Chat, ApiError> {
        let row = if let Some(expected_revision) = expected_revision {
            let updated = sqlx::query(
                r"UPDATE chats SET ciphertext = $1, revision = revision + 1
                  WHERE id = $2 AND user_id = $3 AND revision = $4
                  RETURNING id, ciphertext, encrypted_key, created_at, last_message_at, revision",
            )
            .bind(ciphertext)
            .bind(chat_id)
            .bind(user_id)
            .bind(expected_revision)
            .fetch_optional(&self.db)
            .await?;
            if let Some(row) = updated {
                row
            } else {
                let exists = sqlx::query_scalar::<_, bool>(
                    "SELECT true FROM chats WHERE id = $1 AND user_id = $2",
                )
                .bind(chat_id)
                .bind(user_id)
                .fetch_optional(&self.db)
                .await?
                .is_some();
                return Err(if exists {
                    ApiError::Conflict
                } else {
                    ApiError::NotFound
                });
            }
        } else {
            sqlx::query(
                r"UPDATE chats SET ciphertext = $1, revision = revision + 1
                  WHERE id = $2 AND user_id = $3
                  RETURNING id, ciphertext, encrypted_key, created_at, last_message_at, revision",
            )
            .bind(ciphertext)
            .bind(chat_id)
            .bind(user_id)
            .fetch_optional(&self.db)
            .await?
            .ok_or(ApiError::NotFound)?
        };
        row_to_chat(&row)
    }

    pub(crate) async fn delete(&self, user_id: &str, chat_id: Uuid) -> Result<(), ApiError> {
        let result = sqlx::query("DELETE FROM chats WHERE id = $1 AND user_id = $2")
            .bind(chat_id)
            .bind(user_id)
            .execute(&self.db)
            .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::NotFound);
        }
        Ok(())
    }

    pub(crate) async fn delete_all(&self, user_id: &str) -> Result<(), ApiError> {
        // Existing foreign keys cascade to message and attachment metadata.
        sqlx::query("DELETE FROM chats WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }
}

fn row_to_chat(row: &PgRow) -> Result<Chat, ApiError> {
    Ok(Chat {
        id: row.try_get("id")?,
        ciphertext: row.try_get("ciphertext")?,
        encrypted_key: row.try_get("encrypted_key")?,
        created_at: row.try_get("created_at")?,
        last_message_at: row.try_get("last_message_at")?,
        revision: row.try_get("revision")?,
    })
}
