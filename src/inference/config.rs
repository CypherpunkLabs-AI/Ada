use anyhow::{Context, ensure};
use secrecy::SecretString;
use std::env;

#[derive(Debug, Clone)]
pub struct UsageQueueConfig {
    pub account_id: String,
    pub queue_id: String,
    pub api_token: SecretString,
    pub hmac_secret: SecretString,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: SecretString,
    pub database_max_connections: u32,
    pub cache_namespace_key: SecretString,
    pub system_prompt: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub max_concurrency: usize,
    pub usage_queue: UsageQueueConfig,
}

impl Config {
    /// Load and validate database, inference and usage accounting settings.
    ///
    /// # Errors
    /// Returns an error for missing settings, invalid limits, insecure database URLs or malformed credentials.
    pub fn from_env() -> anyhow::Result<Self> {
        let database = required("DATABASE_URL")?;
        let url = reqwest::Url::parse(&database).context("invalid DATABASE_URL")?;
        ensure!(
            matches!(url.scheme(), "postgres" | "postgresql")
                && url
                    .query_pairs()
                    .filter(|(k, _)| k == "sslmode")
                    .all(|(_, v)| v == "verify-full")
                && url
                    .query_pairs()
                    .any(|(k, v)| k == "sslmode" && v == "verify-full"),
            "DATABASE_URL requires sslmode=verify-full"
        );
        let database_max_connections = number("DATABASE_MAX_CONNECTIONS", 20u32)?;
        let cache_namespace_key = secret("CACHE_NAMESPACE_KEY")?;
        let system_prompt = required("INFERENCE_SYSTEM_PROMPT")?;
        let temperature = number("INFERENCE_TEMPERATURE", 0.7f32)?;
        let max_tokens = number("INFERENCE_MAX_TOKENS", 32000u32)?;
        let max_concurrency = number("INFERENCE_MAX_CONCURRENCY", 1000usize)?;
        ensure!(
            database_max_connections > 0
                && max_tokens > 0
                && (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&max_concurrency),
            "invalid inference limits"
        );
        ensure!(
            temperature.is_finite() && (0.0..=2.0).contains(&temperature),
            "INFERENCE_TEMPERATURE must be 0..2"
        );
        let account_id = required("CLOUDFLARE_ACCOUNT_ID")?;
        let queue_id = required("CLOUDFLARE_USAGE_QUEUE_ID")?;
        for id in [&account_id, &queue_id] {
            ensure!(
                id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid Cloudflare resource ID"
            );
        }
        Ok(Self {
            database_url: database.into(),
            database_max_connections,
            cache_namespace_key,
            system_prompt,
            temperature,
            max_tokens,
            max_concurrency,
            usage_queue: UsageQueueConfig {
                account_id,
                queue_id,
                api_token: required("CLOUDFLARE_QUEUES_API_TOKEN")?.into(),
                hmac_secret: secret("USAGE_HMAC_SECRET")?,
            },
        })
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .with_context(|| format!("{name} is required"))
}
fn secret(name: &str) -> anyhow::Result<SecretString> {
    let value = required(name)?;
    ensure!(value.len() >= 32, "{name} must contain at least 32 bytes");
    Ok(value.into())
}
fn number<T: std::str::FromStr + ToString + Copy>(name: &str, default: T) -> anyhow::Result<T> {
    env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid {name}"))
}
