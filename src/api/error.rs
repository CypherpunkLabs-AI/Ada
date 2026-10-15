//! Errors for durable application APIs.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, Clone)]
pub(crate) enum ApiError {
    BadRequest(String),
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
    Database { retryable: bool },
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        let retryable = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .is_some_and(|code| code == "40001");
        // Database diagnostics can contain stored values; keep them out of logs.
        if retryable {
            tracing::warn!("application database transaction must be retried");
        } else {
            tracing::error!("application database operation failed");
        }
        Self::Database { retryable }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("invalid request: {message}"),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found".into(),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Pro plan required".into(),
            ),
            Self::Conflict => (StatusCode::CONFLICT, "conflict", "conflict".into()),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service temporarily unavailable".into(),
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal error".into(),
            ),
            Self::Database { retryable: true } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "database operation failed".into(),
            ),
            Self::Database { retryable: false } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "database operation failed".into(),
            ),
        };
        let mut response = (
            status,
            [("cache-control", "no-store")],
            Json(json!({"error": {"code": code, "message": message}})),
        )
            .into_response();
        response.extensions_mut().insert(self);
        response
    }
}
