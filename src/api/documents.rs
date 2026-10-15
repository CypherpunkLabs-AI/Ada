//! Oak-only document route and separately authenticated private vision broker.
use crate::services::documents::{
    DocumentGateway, Upload, VisionGateway, VisionInput, process_upload, vision_inner,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

const MAX_WIRE: usize = 56 * 1024 * 1024;

/// Merge only into the Oak dispatcher, never a public listener.
pub fn document_router(state: DocumentGateway) -> Router {
    Router::new()
        .route("/v1/convert/file", post(convert_oak))
        .with_state(state)
}
/// Serve only on the configured private broker listener.
pub fn vision_router(state: VisionGateway) -> Router {
    Router::new()
        .route("/internal/document-vision", post(vision))
        .with_state(state)
}

fn public_error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"error":{"message":message}})),
    )
        .into_response()
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|h| h.to_str().ok())
}

async fn convert_oak(State(state): State<DocumentGateway>, request: Request) -> Response {
    let Ok(_permit) = state.slots.try_acquire() else {
        return public_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Document processing is busy.",
        );
    };
    let result = async {
        let bytes = to_bytes(request.into_body(), MAX_WIRE).await?;
        let upload: Upload = serde_json::from_slice(&bytes)?;
        process_upload(&state, upload).await
    };
    match tokio::time::timeout(Duration::from_secs(620), result).await {
        Ok(Ok(bytes)) => ([("content-type", "application/json")], bytes).into_response(),
        _ => public_error(
            StatusCode::BAD_REQUEST,
            "The document could not be processed.",
        ),
    }
}

async fn vision(State(state): State<VisionGateway>, request: Request) -> Response {
    let credential = header(request.headers(), "authorization")
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or_default();
    let expected = Sha256::digest(state.token.as_bytes());
    let supplied = Sha256::digest(credential.as_bytes());
    if !bool::from(expected[..].ct_eq(&supplied[..])) {
        return public_error(StatusCode::UNAUTHORIZED, "Unauthorized.");
    }
    let Ok(_permit) = state.slots.try_acquire() else {
        return public_error(StatusCode::TOO_MANY_REQUESTS, "Vision processing is busy.");
    };
    match tokio::time::timeout(Duration::from_mins(2), async {
        let body = to_bytes(request.into_body(), 32 * 1024 * 1024).await?;
        let input: VisionInput = serde_json::from_slice(&body)?;
        vision_inner(&state, input).await
    })
    .await
    {
        Ok(Ok(text)) => {
            ([("cache-control", "no-store")], Json(json!({"text":text}))).into_response()
        }
        _ => public_error(
            StatusCode::BAD_GATEWAY,
            "Secure document vision is unavailable.",
        ),
    }
}
