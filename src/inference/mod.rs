//! Verified inference forwarding and attested TLS enforcement.
pub mod config;
pub(crate) mod error;
pub(crate) mod rate_limit;
pub(crate) mod request;
pub(crate) mod stream;
pub mod upstream;
pub(crate) mod usage;
pub(crate) use stream::UsageMetrics;
pub const GLM_MODEL: &str = "z-ai/glm-5.3-flash";
pub const KIMI_MODEL: &str = "moonshotai/kimi-k3";
