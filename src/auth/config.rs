//! Existing AUTH_* configuration, independent of database and inference settings.
use anyhow::{Context, ensure};
use reqwest::Url;
use secrecy::SecretString;
use std::env;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub issuer: String,
    pub jwks_url: Url,
    pub jwt_key: Option<SecretString>,
    pub authorized_parties: Vec<String>,
    pub audience: Option<String>,
    pub jwks_cache_seconds: u64,
}
impl AuthConfig {
    /// Load and validate bearer authentication settings.
    ///
    /// # Errors
    /// Returns an error for missing or invalid issuer, parties, key-source or cache settings.
    pub fn from_env() -> anyhow::Result<Self> {
        let issuer = optional("AUTH_ISSUER")
            .context("AUTH_ISSUER is required")?
            .trim_end_matches('/')
            .to_owned();
        let config = Self {
            jwks_url: Url::parse(
                &optional("AUTH_JWKS_URL")
                    .unwrap_or_else(|| format!("{issuer}/.well-known/jwks.json")),
            )
            .context("invalid AUTH_JWKS_URL")?,
            issuer,
            jwt_key: optional("AUTH_JWT_KEY").map(SecretString::from),
            authorized_parties: optional("AUTH_AUTHORIZED_PARTIES")
                .context("AUTH_AUTHORIZED_PARTIES is required")?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            audience: optional("AUTH_AUDIENCE"),
            jwks_cache_seconds: optional("AUTH_JWKS_CACHE_SECONDS")
                .unwrap_or_else(|| "3600".into())
                .parse()
                .context("invalid AUTH_JWKS_CACHE_SECONDS")?,
        };
        config.validate()?;
        Ok(config)
    }
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        let issuer = Url::parse(&self.issuer).context("invalid AUTH_ISSUER")?;
        ensure!(
            secure_url(&issuer) && issuer.query().is_none(),
            "AUTH_ISSUER must be an HTTPS URL without credentials, query or fragment"
        );
        ensure!(
            secure_url(&self.jwks_url),
            "AUTH_JWKS_URL must be an HTTPS URL without credentials or fragment"
        );
        ensure!(
            !self.authorized_parties.is_empty()
                && self.authorized_parties.iter().all(|s| !s.trim().is_empty()),
            "AUTH_AUTHORIZED_PARTIES must not be empty"
        );
        ensure!(
            self.audience.as_ref().is_none_or(|s| !s.trim().is_empty()),
            "AUTH_AUDIENCE must not be empty when set"
        );
        ensure!(
            (1..=86400).contains(&self.jwks_cache_seconds),
            "AUTH_JWKS_CACHE_SECONDS must be 1..86400"
        );
        Ok(())
    }
}
fn secure_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}
fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}
