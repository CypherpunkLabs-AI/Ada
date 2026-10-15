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
    Unavailable,
    RateLimited { retry_after_seconds: i64 },
    RequestRateLimited { retry_after_seconds: u64 },
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, retry) = match &self {
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                "bad_request",
                message.as_str(),
                None,
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Pro access required",
                None,
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Inference temporarily unavailable",
                None,
            ),
            Self::RateLimited {
                retry_after_seconds,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Usage limit reached",
                Some((*retry_after_seconds).max(1).cast_unsigned()),
            ),
            Self::RequestRateLimited {
                retry_after_seconds,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                "request_rate_limited",
                "Too many requests",
                Some(*retry_after_seconds),
            ),
        };
        let mut response = (
            status,
            [("cache-control", "no-store")],
            Json(json!({"error": {
                "code": code, "message": message, "retry_after_seconds": retry
            }})),
        )
            .into_response();
        if let Some(seconds) = retry {
            response.headers_mut().insert(
                "retry-after",
                seconds.to_string().parse().expect("numeric header"),
            );
        }
        response.extensions_mut().insert(self);
        response
    }
}
