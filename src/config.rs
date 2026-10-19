use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, bail};

#[derive(Debug, Clone)]
pub struct R2Config {
    pub endpoint: reqwest::Url,
    pub bucket: String,
    pub access_key_id: secrecy::SecretString,
    pub secret_access_key: secrecy::SecretString,
    pub presign_ttl_seconds: u64,
    pub max_attachment_bytes: i64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub inference: crate::inference::config::Config,
    pub auth: crate::auth::AuthConfig,
    pub stripe_api_url: reqwest::Url,
    pub stripe_secret_key: Option<secrecy::SecretString>,
    pub r2: Option<R2Config>,
    pub bind_address: SocketAddr,
    pub tls: crate::tls::Config,
    pub tdx_report_dir: PathBuf,
    pub attestation_dir: PathBuf,
    pub nearai_base_url: String,
    pub nearai_api_key: secrecy::SecretString,
    pub inference_timeout: Duration,
    pub keyset_ttl: Duration,
    pub receipt_ttl: Duration,
    pub source_repository: String,
    pub source_commit: String,
    pub image_digest: Option<String>,
    pub subject: Option<String>,
}

impl Config {
    /// Loads immutable trust policy and runtime settings.
    ///
    /// The NEAR SDK supplies provider verification and encryption. Security
    /// requirements are fixed in the measured proxy, not runtime switches.
    /// # Errors
    /// Rejects invalid configuration or unavailable required confidential services.
    pub fn from_env() -> anyhow::Result<Self> {
        let bind_address = value_or("ADA_BIND_ADDRESS", "0.0.0.0:8443")
            .parse()
            .context("ADA_BIND_ADDRESS must be a socket address")?;
        let stripe_api_url =
            reqwest::Url::parse(&value_or("STRIPE_API_URL", "https://api.stripe.com/"))
                .context("invalid STRIPE_API_URL")?;
        if stripe_api_url.scheme() != "https" {
            bail!("STRIPE_API_URL must use https");
        }

        Ok(Self {
            inference: crate::inference::config::Config::from_env()?,
            auth: crate::auth::AuthConfig::from_env()?,
            stripe_api_url,
            stripe_secret_key: optional("STRIPE_SECRET_KEY").map(Into::into),
            r2: r2_config()?,
            bind_address,
            tls: crate::tls::Config::new(
                required("ADA_TLS_DOMAIN")?,
                &value_or("ADA_ACME_ENVIRONMENT", "production"),
            )?,
            tdx_report_dir: value_or("ADA_TDX_REPORT_DIR", "/run/ada/tdx-report").into(),
            attestation_dir: value_or("ADA_ATTESTATION_DIR", "/run/ada/attestation").into(),
            nearai_base_url: value_or(
                "NEARAI_BASE_URL",
                nearai_inference_sdk::DEFAULT_NEAR_AI_CLOUD_BASE_URL,
            ),
            nearai_api_key: required("NEARAI_API_KEY")?.into(),
            inference_timeout: seconds("NEARAI_TIMEOUT_SECONDS", 600, 10, 3_600)?,
            keyset_ttl: seconds("ADA_KEYSET_TTL_SECONDS", 2_592_000, 3_600, 31_536_000)?,
            receipt_ttl: seconds("ADA_RECEIPT_TTL_SECONDS", 3_600, 60, 86_400)?,
            source_repository: required("ADA_SOURCE_REPOSITORY")?,
            source_commit: required("ADA_SOURCE_COMMIT")?,
            image_digest: optional("ADA_IMAGE_DIGEST"),
            subject: optional("ADA_ATTESTED_SUBJECT"),
        })
    }
}

fn r2_config() -> anyhow::Result<Option<R2Config>> {
    let endpoint = optional("R2_ENDPOINT");
    let bucket = optional("R2_BUCKET");
    let access_key_id = optional("R2_ACCESS_KEY_ID");
    let secret_access_key = optional("R2_SECRET_ACCESS_KEY");
    if endpoint.is_none()
        && bucket.is_none()
        && access_key_id.is_none()
        && secret_access_key.is_none()
    {
        return Ok(None);
    }
    let endpoint = reqwest::Url::parse(
        endpoint
            .as_deref()
            .context("R2_ENDPOINT is required when R2 is configured")?,
    )
    .context("invalid R2_ENDPOINT")?;
    if endpoint.scheme() != "https" {
        bail!("R2_ENDPOINT must use https");
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        bail!("R2_ENDPOINT must not contain a query or fragment");
    }
    let bucket = bucket.context("R2_BUCKET is required when R2 is configured")?;
    if bucket.is_empty() || bucket.len() > 255 {
        bail!("R2_BUCKET must contain 1..255 characters");
    }
    let presign_ttl_seconds = value_or("R2_PRESIGN_TTL_SECONDS", "900")
        .parse::<u64>()
        .context("invalid R2_PRESIGN_TTL_SECONDS")?;
    let max_attachment_bytes = value_or("MAX_ATTACHMENT_BYTES", "20971520")
        .parse::<i64>()
        .context("invalid MAX_ATTACHMENT_BYTES")?;
    if !(60..=3600).contains(&presign_ttl_seconds) || max_attachment_bytes <= 0 {
        bail!("R2_PRESIGN_TTL_SECONDS must be 60..3600 and MAX_ATTACHMENT_BYTES must be positive");
    }
    Ok(Some(R2Config {
        endpoint,
        bucket,
        access_key_id: access_key_id
            .context("R2_ACCESS_KEY_ID is required when R2 is configured")?
            .into(),
        secret_access_key: secret_access_key
            .context("R2_SECRET_ACCESS_KEY is required when R2 is configured")?
            .into(),
        presign_ttl_seconds,
        max_attachment_bytes,
    }))
}

fn required(name: &str) -> anyhow::Result<String> {
    optional(name).with_context(|| format!("{name} is required"))
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn value_or(name: &str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.to_owned())
}

fn seconds(name: &str, default: u64, min: u64, max: u64) -> anyhow::Result<Duration> {
    let value = value_or(name, &default.to_string())
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))?;
    if !(min..=max).contains(&value) {
        bail!("{name} must be between {min} and {max}");
    }
    Ok(Duration::from_secs(value))
}
