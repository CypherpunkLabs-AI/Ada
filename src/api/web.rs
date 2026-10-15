//! Authenticated favicon fetching inside the encrypted Oak dispatcher.
use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::header,
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio::{net::lookup_host, sync::Semaphore, time::timeout};

use crate::{api::error::ApiError, auth::User};

mod policy;

const MAX_HOSTS: usize = 64;
const MAX_ICON_BYTES: usize = 64 * 1024;
const FETCH_CONCURRENCY: usize = 8;
const MAX_CONCURRENT_BATCHES: usize = 4;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Mount on the JWT-protected inner router, never the public TLS router.
pub fn router() -> Router {
    Router::new()
        .route("/v3/web/favicons", post(favicons))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .with_state(Arc::new(Semaphore::new(MAX_CONCURRENT_BATCHES)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaviconRequest {
    hosts: Vec<String>,
}

#[derive(Serialize)]
struct FaviconResponse {
    icons: Vec<Favicon>,
}

#[derive(Serialize)]
struct Favicon {
    host: String,
    data_url: String,
}

async fn favicons(
    State(slots): State<Arc<Semaphore>>,
    _user: User,
    Json(input): Json<FaviconRequest>,
) -> Result<
    (
        [(header::HeaderName, &'static str); 1],
        Json<FaviconResponse>,
    ),
    ApiError,
> {
    if input.hosts.len() > MAX_HOSTS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_HOSTS} favicon hosts may be requested"
        )));
    }
    let hosts = input
        .hosts
        .iter()
        .map(|host| {
            policy::normalize_host(host)
                .ok_or_else(|| ApiError::BadRequest("invalid favicon host".into()))
        })
        .collect::<Result<HashSet<_>, _>>()?;
    let _permit = slots.try_acquire().map_err(|_| ApiError::Unavailable)?;
    let icons = stream::iter(hosts.into_iter().map(|host| async move {
        // Includes DNS resolution, TLS and body download in one deadline.
        timeout(FETCH_TIMEOUT, fetch_favicon(&host))
            .await
            .ok()
            .flatten()
            .map(|data_url| Favicon { host, data_url })
    }))
    .buffer_unordered(FETCH_CONCURRENCY)
    .filter_map(async |icon| icon)
    .collect()
    .await;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(FaviconResponse { icons }),
    ))
}

async fn fetch_favicon(host: &str) -> Option<String> {
    let url = reqwest::Url::parse(&format!("https://{host}/favicon.ico")).ok()?;
    // Reject URL-parser reinterpretation of numeric or unusual host spellings.
    if url.host_str() != Some(host) {
        return None;
    }
    let addresses = lookup_host((host, 443)).await.ok()?.collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|a| !policy::is_public_ip(a.ip())) {
        return None;
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(FETCH_TIMEOUT)
        // Pin the checked DNS results while retaining hostname TLS verification.
        .resolve_to_addrs(host, &addresses)
        .build()
        .ok()?;
    let response = client
        .get(url)
        .header(
            header::ACCEPT,
            "image/png,image/jpeg,image/gif,image/webp,image/x-icon",
        )
        .send()
        .await
        .ok()?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .content_length()
            .is_some_and(|size| size > MAX_ICON_BYTES as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.ok()?;
        if chunk.len() > MAX_ICON_BYTES.saturating_sub(body.len()) {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    // Do not trust a remote Content-Type header; SVG and HTML are not accepted.
    let content_type = policy::image_type(&body)?;
    Some(format!(
        "data:{content_type};base64,{}",
        STANDARD.encode(body)
    ))
}
