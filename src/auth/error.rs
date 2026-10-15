//! Redacted authentication responses, matching the existing backend error shape.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum AuthError {
    #[error("authentication required")]
    Unauthorized,
    #[error("service temporarily unavailable")]
    Unavailable,
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let mut response = (
            status,
            [("cache-control", "no-store")],
            Json(json!({"error": {
                "code": code, "message": self.to_string(), "retry_after_seconds": null
            }})),
        )
            .into_response();
        // The Oak adapter distinguishes a rejected request from missing inference proofs.
        response.extensions_mut().insert(self);
        response
    }
}
