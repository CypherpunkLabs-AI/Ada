//! Encrypted user preferences in the existing application schema.
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};

use crate::api::error::ApiError;

pub(crate) struct EncryptedValue {
    pub ciphertext: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}

pub(crate) struct Preference {
    pub value: EncryptedValue,
    pub updated_at: DateTime<Utc>,
}

pub(crate) struct Preferences {
    pub preferred_name: Option<Preference>,
    pub custom_instructions: Option<Preference>,
}

#[derive(Clone)]
pub(crate) struct PreferenceStore {
    db: PgPool,
}

impl PreferenceStore {
    pub(crate) fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub(crate) async fn get(&self, user_id: &str) -> Result<Preferences, ApiError> {
        let preferred_name = sqlx::query(
            "SELECT ciphertext, encrypted_key, updated_at FROM preferred_names WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?
        .as_ref()
        .map(row_to_preference)
        .transpose()?;
        let custom_instructions = sqlx::query(
            "SELECT ciphertext, encrypted_key, updated_at FROM custom_instructions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?
        .as_ref()
        .map(row_to_preference)
        .transpose()?;
        Ok(Preferences {
            preferred_name,
            custom_instructions,
        })
    }

    pub(crate) async fn put(
        &self,
        user_id: &str,
        preferred_name: EncryptedValue,
        custom_instructions: EncryptedValue,
    ) -> Result<Preferences, ApiError> {
        let mut tx = self.db.begin().await?;
        let preferred_name = sqlx::query(
            r"INSERT INTO preferred_names (user_id, ciphertext, encrypted_key)
              VALUES ($1, $2, $3)
              ON CONFLICT (user_id) DO UPDATE SET
                ciphertext = excluded.ciphertext,
                encrypted_key = excluded.encrypted_key,
                updated_at = now()
              RETURNING ciphertext, encrypted_key, updated_at",
        )
        .bind(user_id)
        .bind(preferred_name.ciphertext)
        .bind(preferred_name.encrypted_key)
        .fetch_one(&mut *tx)
        .await?;
        let custom_instructions = sqlx::query(
            r"INSERT INTO custom_instructions (user_id, ciphertext, encrypted_key)
              VALUES ($1, $2, $3)
              ON CONFLICT (user_id) DO UPDATE SET
                ciphertext = excluded.ciphertext,
                encrypted_key = excluded.encrypted_key,
                updated_at = now()
              RETURNING ciphertext, encrypted_key, updated_at",
        )
        .bind(user_id)
        .bind(custom_instructions.ciphertext)
        .bind(custom_instructions.encrypted_key)
        .fetch_one(&mut *tx)
        .await?;
        let result = Preferences {
            preferred_name: Some(row_to_preference(&preferred_name)?),
            custom_instructions: Some(row_to_preference(&custom_instructions)?),
        };
        tx.commit().await?;
        Ok(result)
    }
}

fn row_to_preference(row: &PgRow) -> Result<Preference, ApiError> {
    Ok(Preference {
        value: EncryptedValue {
            ciphertext: row.try_get("ciphertext")?,
            encrypted_key: row.try_get("encrypted_key")?,
        },
        updated_at: row.try_get("updated_at")?,
    })
}
