//! Shared application database pool.
use secrecy::{ExposeSecret, SecretString};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

/// Construct the pool shared by application storage and inference quotas.
///
/// # Errors
/// Returns an error if the database connection configuration is invalid.
pub fn pool(url: &SecretString, max_connections: u32) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(url.expose_secret())
        .map_err(|_| anyhow::anyhow!("invalid application database configuration"))
}
