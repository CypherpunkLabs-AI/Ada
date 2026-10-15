//! Idempotent Stripe customer setup for credential onboarding.
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::{Client, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;

use crate::api::error::ApiError;

const MAX_CUSTOMER_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct StripeClient {
    db: PgPool,
    client: Client,
    base_url: Url,
    secret_key: Option<SecretString>,
}

#[derive(Deserialize)]
struct CreatedCustomer {
    id: String,
    email: Option<String>,
}

impl StripeClient {
    /// Construct customer onboarding using the shared application pool.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be initialized.
    pub fn new(
        db: PgPool,
        base_url: Url,
        secret_key: Option<SecretString>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            db,
            client: Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .build()?,
            base_url,
            secret_key,
        })
    }

    pub(crate) async fn ensure_customer(&self, user_id: &str) -> Result<String, ApiError> {
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT stripe_cus_id FROM stripe_customers WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;
        if let Some(customer_id) = existing {
            return Ok(customer_id);
        }

        let secret_key = self.secret_key.as_ref().ok_or_else(|| {
            tracing::error!("STRIPE_SECRET_KEY is not configured for customer onboarding");
            ApiError::Internal
        })?;
        let url = self.base_url.join("v1/customers").map_err(|_| {
            tracing::error!("invalid Stripe customer endpoint");
            ApiError::Internal
        })?;
        // Keep the original key so retries across the backend migration reuse
        // the same Stripe customer creation operation.
        let response = self
            .client
            .post(url)
            .basic_auth(secret_key.expose_secret(), Some(""))
            .header("Idempotency-Key", format!("stripe-customer-v1:{user_id}"))
            .form(&[("metadata[user_id]", user_id)])
            .send()
            .await
            .map_err(|_| {
                tracing::warn!("Stripe customer creation request failed");
                ApiError::Unavailable
            })?;
        if !response.status().is_success() {
            tracing::warn!(status = %response.status(), "Stripe rejected customer creation");
            return Err(ApiError::Unavailable);
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ApiError::Unavailable)?;
            if body.len().saturating_add(chunk.len()) > MAX_CUSTOMER_RESPONSE_BYTES {
                return Err(ApiError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let customer: CreatedCustomer = serde_json::from_slice(&body).map_err(|_| {
            tracing::warn!("Stripe returned an invalid customer response");
            ApiError::Unavailable
        })?;
        if !customer.id.starts_with("cus_") || customer.id.len() > 255 {
            tracing::warn!("Stripe returned an invalid customer ID");
            return Err(ApiError::Unavailable);
        }

        sqlx::query(
            r"INSERT INTO stripe_customers (stripe_cus_id, email, metadata, user_id)
              VALUES ($1, $2, $3, $4)
              ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(&customer.id)
        .bind(customer.email)
        .bind(json!({"user_id": user_id}))
        .bind(user_id)
        .execute(&self.db)
        .await?;
        Ok(customer.id)
    }
}
