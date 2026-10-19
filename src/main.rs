use std::sync::Arc;

use aci_protocol::types::SourceProvenance;
use ada_proxy::{
    attestation::evidence::ServiceConfig,
    attestation::tdx::Attester,
    config::Config,
    inference::upstream::InferenceBackend,
    services::documents::{DocumentGateway, VisionGateway},
};
use anyhow::Context;
use axum::{Router, http::StatusCode, routing::get};
use secrecy::ExposeSecret;
use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::PathBuf,
};
use tokio::net::{TcpListener, UnixListener};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
#[allow(
    clippy::too_many_lines,
    reason = "startup assembles the confidential service dependencies before listening"
)]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS provider already initialized"))?;
    init_tracing();
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => {}
        [command] if command == "serve" => {}
        _ => anyhow::bail!("usage: ada-proxy [serve]"),
    }
    let config = Config::from_env().context("invalid configuration")?;
    // Check RAM storage and disabled swap before generating any service keys.
    let tls = ada_proxy::tls::Server::new(config.tls.clone())?;
    let jwt_verifier = ada_proxy::auth::JwtVerifier::new(&config.auth)
        .context("invalid authentication configuration")?;

    let oak_keys = Arc::new(ada_proxy::attestation::keys::OakKeys::new()?);
    let attester = Attester::new(
        config.tdx_report_dir.clone(),
        config.attestation_dir.clone(),
    )?;

    let upstream = Arc::new(
        InferenceBackend::new(
            &config.nearai_base_url,
            config.nearai_api_key.expose_secret().to_owned(),
            config.inference_timeout,
        )
        .context("failed to construct NEAR inference backend")?,
    );

    let service = ada_proxy::services::inference::Service::new(
        oak_keys.clone(),
        attester,
        upstream.clone(),
        ServiceConfig {
            source_provenance: SourceProvenance {
                repo_url: Some(config.source_repository.clone()),
                repo_commit: Some(config.source_commit.clone()),
                image_digest: config.image_digest.clone(),
                image_provenance: None,
            },
            keyset_ttl_seconds: config.keyset_ttl.as_secs(),
            subject: config.subject.clone(),
            receipt_ttl_seconds: config.receipt_ttl.as_secs(),
        },
    )
    .context("failed to seal Ada ACI service identity")?;
    let service = Arc::new(service);
    let db = ada_proxy::storage::database::pool(
        &config.inference.database_url,
        config.inference.database_max_connections,
    )?;
    let chat = Arc::new(ada_proxy::services::chat::ChatService::new(
        service.clone(),
        config.inference.clone(),
        db.clone(),
    )?);
    let stripe = ada_proxy::services::stripe::StripeClient::new(
        db.clone(),
        config.stripe_api_url.clone(),
        config.stripe_secret_key.clone(),
    )?;
    let mut oak_inner = ada_proxy::api::inference::router(chat)
        .merge(ada_proxy::api::web::router())
        .merge(ada_proxy::api::chats::router(db.clone()))
        .merge(ada_proxy::api::messages::router(db.clone()))
        .merge(ada_proxy::api::preferences::router(db.clone()))
        .merge(ada_proxy::api::attachments::router(
            db.clone(),
            config.r2.clone(),
        ))
        .merge(ada_proxy::api::credentials::router(db, stripe));
    let mut broker_task = None;
    if let Ok(document_socket) = std::env::var("DOCUMENT_ROUTER_SOCKET") {
        let token = std::env::var("DOCUMENT_VISION_BROKER_TOKEN")
            .context("DOCUMENT_VISION_BROKER_TOKEN is required")?;
        anyhow::ensure!(
            token.len() >= 32,
            "document vision token must have at least 32 bytes"
        );
        let model = std::env::var("DOCUMENT_VISION_MODEL")
            .context("DOCUMENT_VISION_MODEL must select a TEE vision model")?;
        anyhow::ensure!(
            !model.trim().is_empty(),
            "document vision model cannot be empty"
        );
        let socket = PathBuf::from(
            std::env::var("DOCUMENT_VISION_SOCKET")
                .context("DOCUMENT_VISION_SOCKET is required")?,
        );
        anyhow::ensure!(socket.is_absolute(), "vision socket must be absolute");
        match std::fs::symlink_metadata(&socket) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_socket(),
                    "vision socket path is occupied"
                );
                std::fs::remove_file(&socket)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let broker_listener = UnixListener::bind(&socket).context("bind private vision socket")?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
        let broker = VisionGateway {
            backend: upstream,
            model,
            token,
            slots: Arc::new(tokio::sync::Semaphore::new(2)),
        };
        broker_task = Some(tokio::spawn(async move {
            axum::serve(
                broker_listener,
                ada_proxy::api::documents::vision_router(broker),
            )
            .await
        }));
        let documents = DocumentGateway::new(document_socket.into())?;
        oak_inner = oak_inner.merge(ada_proxy::api::documents::document_router(documents));
    }
    let oak = ada_proxy::transport::oak::Gateway::new(
        service.clone(),
        oak_keys.binding.clone(),
        ada_proxy::auth::protect(oak_inner, jwt_verifier),
    );
    let app = Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route(
            "/v1/verification-policy",
            get(ada_proxy::attestation::policy::get),
        )
        .merge(oak.router());
    let listener = TcpListener::bind(config.bind_address)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_address))?;
    info!(
        address = %config.bind_address,
        upstream = %config.nearai_base_url,
        "Ada HTTPS/WSS gateway listening"
    );
    tokio::select! {
        result = tls.serve(listener, app, service) => {
            if let Some(task) = broker_task { task.abort(); }
            result.context("TLS server failed")
        },
        () = shutdown_signal() => {
            if let Some(task) = broker_task { task.abort(); }
            Ok(())
        },
        result = async {
            match &mut broker_task {
                Some(task) => task.await,
                None => std::future::pending().await,
            }
        } => {
            result.context("private vision task panicked")??;
            anyhow::bail!("private vision listener stopped")
        },
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ada_proxy=info"))
        // ACME dependency debug/error messages can contain complete HTTP bodies.
        // Emit only the redacted lifecycle messages in tls::Server instead.
        .add_directive("rustls_acme=off".parse().expect("static log filter"))
        .add_directive("async_web_client=off".parse().expect("static log filter"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();
}
