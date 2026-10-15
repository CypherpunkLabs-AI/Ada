//! Encrypted preferences inside the authenticated Oak dispatcher.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{
    api::error::ApiError,
    auth::User,
    storage::{
        ciphertext::{MIN_ENVELOPE_BYTES, WRAPPED_CHAT_KEY_BYTES, decode_envelope},
        preferences::{EncryptedValue, Preference, PreferenceStore, Preferences},
    },
};

const MAX_PREFERRED_NAME_CIPHERTEXT_BYTES: usize = 1024;
const MAX_CUSTOM_INSTRUCTIONS_CIPHERTEXT_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;

pub fn router(db: PgPool) -> Router {
    Router::new()
        .route("/v3/preferences", get(get_preferences).put(put_preferences))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(PreferenceStore::new(db))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedPreferenceInput {
    ciphertext: String,
    encrypted_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutPreferencesRequest {
    preferred_name: EncryptedPreferenceInput,
    custom_instructions: EncryptedPreferenceInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedPreferenceResponse {
    ciphertext: String,
    encrypted_key: String,
    updated_at: DateTime<Utc>,
}

impl From<Preference> for EncryptedPreferenceResponse {
    fn from(preference: Preference) -> Self {
        Self {
            ciphertext: STANDARD.encode(preference.value.ciphertext),
            encrypted_key: STANDARD.encode(preference.value.encrypted_key),
            updated_at: preference.updated_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreferencesResponse {
    preferred_name: Option<EncryptedPreferenceResponse>,
    custom_instructions: Option<EncryptedPreferenceResponse>,
}

impl From<Preferences> for PreferencesResponse {
    fn from(preferences: Preferences) -> Self {
        Self {
            preferred_name: preferences.preferred_name.map(Into::into),
            custom_instructions: preferences.custom_instructions.map(Into::into),
        }
    }
}

async fn get_preferences(
    State(store): State<PreferenceStore>,
    user: User,
) -> Result<Json<PreferencesResponse>, ApiError> {
    Ok(Json(store.get(user.id()).await?.into()))
}

async fn put_preferences(
    State(store): State<PreferenceStore>,
    user: User,
    Json(input): Json<PutPreferencesRequest>,
) -> Result<Json<PreferencesResponse>, ApiError> {
    let preferred_name = decode_input(&input.preferred_name, MAX_PREFERRED_NAME_CIPHERTEXT_BYTES)?;
    let custom_instructions = decode_input(
        &input.custom_instructions,
        MAX_CUSTOM_INSTRUCTIONS_CIPHERTEXT_BYTES,
    )?;
    Ok(Json(
        store
            .put(user.id(), preferred_name, custom_instructions)
            .await?
            .into(),
    ))
}

fn decode_input(
    input: &EncryptedPreferenceInput,
    maximum_bytes: usize,
) -> Result<EncryptedValue, ApiError> {
    Ok(EncryptedValue {
        ciphertext: decode_envelope(
            "ciphertext",
            &input.ciphertext,
            MIN_ENVELOPE_BYTES,
            maximum_bytes,
        )?,
        encrypted_key: decode_envelope(
            "encryptedKey",
            &input.encrypted_key,
            WRAPPED_CHAT_KEY_BYTES,
            WRAPPED_CHAT_KEY_BYTES,
        )?,
    })
}
