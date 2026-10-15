//! Credential synchronization inside the authenticated Oak dispatcher.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{
    api::error::ApiError,
    auth::User,
    services::stripe::StripeClient,
    storage::credentials::{Credential, CredentialStore, CredentialType},
};

const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
const MAX_ENCRYPTED_MASTER_KEY_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct CredentialsState {
    store: CredentialStore,
    stripe: StripeClient,
}

pub fn router(db: PgPool, stripe: StripeClient) -> Router {
    Router::new()
        .route("/v3/credentials", get(list_credentials).put(put_credential))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(CredentialsState {
            store: CredentialStore::new(db),
            stripe,
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutCredentialRequest {
    credential_id: String,
    #[serde(rename = "type")]
    credential_type: CredentialType,
    encrypted_master_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialResponse {
    credential_id: String,
    #[serde(rename = "type")]
    credential_type: CredentialType,
    encrypted_master_key: String,
    created_at: DateTime<Utc>,
}

impl From<Credential> for CredentialResponse {
    fn from(credential: Credential) -> Self {
        Self {
            credential_id: credential.credential_id,
            credential_type: credential.credential_type,
            encrypted_master_key: credential.encrypted_master_key,
            created_at: credential.created_at,
        }
    }
}

async fn put_credential(
    State(state): State<CredentialsState>,
    user: User,
    Json(input): Json<PutCredentialRequest>,
) -> Result<Json<CredentialResponse>, ApiError> {
    validate_credential(&input)?;
    let credential = state
        .store
        .put(
            user.id(),
            &input.credential_id,
            input.credential_type,
            &input.encrypted_master_key,
        )
        .await?;
    Ok(Json(credential.into()))
}

async fn list_credentials(
    State(state): State<CredentialsState>,
    user: User,
) -> Result<Json<Vec<CredentialResponse>>, ApiError> {
    let credentials = state.store.list(user.id()).await?;
    if credentials.is_empty() {
        state.stripe.ensure_customer(user.id()).await?;
    }
    Ok(Json(credentials.into_iter().map(Into::into).collect()))
}

fn validate_credential(input: &PutCredentialRequest) -> Result<(), ApiError> {
    if input.credential_id.is_empty()
        || input.credential_id.len() > MAX_CREDENTIAL_ID_BYTES
        || !input
            .credential_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApiError::BadRequest(
            "credentialId must be a 1..1024 byte base64url value".into(),
        ));
    }
    if input.encrypted_master_key.is_empty()
        || input.encrypted_master_key.len() > MAX_ENCRYPTED_MASTER_KEY_BYTES
        || URL_SAFE_NO_PAD
            .decode(input.encrypted_master_key.as_bytes())
            .is_err()
    {
        return Err(ApiError::BadRequest(
            "encryptedMasterKey must be a 1..16384 byte base64url value".into(),
        ));
    }
    Ok(())
}
