use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;

use crate::inference::UsageMetrics;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize)]
pub(super) struct UsageEventV2 {
    version: u8,
    request_id: Uuid,
    user_id: String,
    model: String,
    prompt_tokens: i64,
    cached_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
    web_search_calls: i64,
    document_parse_calls: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct SignedUsageEnvelope {
    version: u8,
    timestamp: i64,
    nonce: String,
    payload: UsageEventV2,
    signature: String,
}

impl SignedUsageEnvelope {
    pub(super) fn new(
        request_id: Uuid,
        user_id: &str,
        model: &str,
        usage: UsageMetrics,
        secret: &SecretString,
    ) -> anyhow::Result<Self> {
        let mut nonce_bytes = [0_u8; 16];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("usage nonce unavailable"))?;
        Self::new_at(
            request_id,
            user_id,
            model,
            usage,
            Utc::now().timestamp(),
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            secret,
        )
    }

    fn new_at(
        request_id: Uuid,
        user_id: &str,
        model: &str,
        usage: UsageMetrics,
        timestamp: i64,
        nonce: String,
        secret: &SecretString,
    ) -> anyhow::Result<Self> {
        let payload = UsageEventV2 {
            version: 2,
            request_id,
            user_id: user_id.to_owned(),
            model: model.to_owned(),
            prompt_tokens: usage.prompt_tokens,
            cached_tokens: usage.cached_tokens,
            completion_tokens: usage.completion_tokens,
            total_tokens: usage.total_tokens,
            web_search_calls: usage.web_search_calls,
            document_parse_calls: usage.document_parse_calls,
        };
        let canonical = serde_json::to_vec(&(
            2_u8,
            timestamp,
            &nonce,
            payload.version,
            payload.request_id,
            &payload.user_id,
            &payload.model,
            payload.prompt_tokens,
            payload.cached_tokens,
            payload.completion_tokens,
            payload.total_tokens,
            payload.web_search_calls,
            payload.document_parse_calls,
        ))?;
        let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid usage HMAC key"))?;
        mac.update(&canonical);
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        Ok(Self {
            version: 2,
            timestamp,
            nonce,
            payload,
            signature,
        })
    }
}
