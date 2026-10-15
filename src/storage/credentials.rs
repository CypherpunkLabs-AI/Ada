//! User-owned passkey IDs and opaque wrapped master keys.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgRow};

use crate::api::error::ApiError;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CredentialType {
    Passkey,
}

impl CredentialType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "PASSKEY",
        }
    }
}

#[allow(
    clippy::struct_field_names,
    reason = "names match the credential database schema"
)]
pub(crate) struct Credential {
    pub credential_id: String,
    pub credential_type: CredentialType,
    pub encrypted_master_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub(crate) struct CredentialStore {
    db: PgPool,
}

impl CredentialStore {
    pub(crate) fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub(crate) async fn put(
        &self,
        user_id: &str,
        credential_id: &str,
        credential_type: CredentialType,
        encrypted_master_key: &str,
    ) -> Result<Credential, ApiError> {
        // Repeated PUTs may replace the wrapped key, but never transfer ownership.
        let row = sqlx::query(
            r"INSERT INTO credentials
                (credential_id, user_id, credential_type, encrypted_master_key)
              VALUES ($1, $2, $3, $4)
              ON CONFLICT (credential_id) DO UPDATE SET
                credential_type = excluded.credential_type,
                encrypted_master_key = excluded.encrypted_master_key
              WHERE credentials.user_id = excluded.user_id
              RETURNING credential_id, credential_type, encrypted_master_key, created_at",
        )
        .bind(credential_id)
        .bind(user_id)
        .bind(credential_type.as_str())
        .bind(encrypted_master_key)
        .fetch_optional(&self.db)
        .await?
        .ok_or(ApiError::Conflict)?;
        row_to_credential(&row)
    }

    pub(crate) async fn list(&self, user_id: &str) -> Result<Vec<Credential>, ApiError> {
        let rows = sqlx::query(
            r"SELECT credential_id, credential_type, encrypted_master_key, created_at
              FROM credentials WHERE user_id = $1
              ORDER BY created_at ASC, credential_id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;
        rows.iter().map(row_to_credential).collect()
    }
}

fn row_to_credential(row: &PgRow) -> Result<Credential, ApiError> {
    let credential_type = if row.try_get::<String, _>("credential_type")? == "PASSKEY" {
        CredentialType::Passkey
    } else {
        tracing::error!("unsupported stored credential type");
        return Err(ApiError::Internal);
    };
    Ok(Credential {
        credential_id: row.try_get("credential_id")?,
        credential_type,
        encrypted_master_key: row.try_get("encrypted_master_key")?,
        created_at: row.try_get("created_at")?,
    })
}
