//! TLS terminates in the attested proxy. ACME only exports public CSRs.
mod cache;

use crate::services::inference::Service;
use aci_protocol::types::TlsSpki;
use anyhow::{Context, ensure};
use axum::{Extension, Router};
use futures_util::StreamExt;
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rustls::{
    ServerConfig, SignatureScheme,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{AcmeConfig, AcmeState, EventError, EventOk, ResolvesServerCertAcme};
use sha2::{Digest, Sha256};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_rustls::LazyConfigAcceptor;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

#[derive(Debug, Clone)]
pub struct Config {
    domain: String,
    production: bool,
}

impl Config {
    /// Configure the measured public hostname and ACME environment.
    /// # Errors
    /// Rejects non-DNS hostnames and unknown ACME environments.
    pub fn new(domain: String, environment: &str) -> anyhow::Result<Self> {
        ensure!(
            domain.contains('.') && !domain.ends_with('.') && domain == domain.to_ascii_lowercase(),
            "HIRO_TLS_DOMAIN must be a lowercase, fully qualified DNS hostname"
        );
        rustls::pki_types::DnsName::try_from(domain.clone()).context("invalid HIRO_TLS_DOMAIN")?;
        let production = match environment {
            "production" => true,
            "staging" => false,
            _ => anyhow::bail!("HIRO_ACME_ENVIRONMENT must be production or staging"),
        };
        Ok(Self { domain, production })
    }
}

pub struct Server {
    config: Config,
    state: AcmeState<io::Error>,
}

impl Server {
    /// Initialize issuance and renewal, after checking RAM-only storage.
    /// # Errors
    /// Rejects unsafe certificate storage or enabled swap.
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let cache = cache::RamCache::new()?;
        // rustls-acme generates independent ECDSA P-256 account, challenge and
        // certificate keys using ring's secure random generator.
        let state = AcmeConfig::new([&config.domain])
            .directory_lets_encrypt(config.production)
            .cache(cache)
            .state();
        Ok(Self { config, state })
    }

    /// Serve TLS and drive the ACME renewal stream for the lifetime of the process.
    /// # Errors
    /// Returns on listener failure or unusable ACME/cache state. Issuance errors
    /// use the library's bounded exponential backoff without exposing raw errors.
    pub async fn serve(
        mut self,
        listener: TcpListener,
        app: Router,
        identity: Arc<Service>,
    ) -> anyhow::Result<()> {
        let resolver = self.state.resolver();
        let slots = Arc::new(Semaphore::new(256));
        let mut connections = JoinSet::new();
        tracing::info!(domain = %self.config.domain, "TLS 1.3 listener ready; certificate issuance and renewal enabled");
        loop {
            tokio::select! {
                event = self.state.next() => {
                    match event.context("ACME renewal stream stopped")? {
                        Ok(EventOk::DeployedCachedCert | EventOk::DeployedNewCert) => {
                            tracing::info!("TLS certificate installed");
                        }
                        Ok(_) => {},
                        Err(EventError::Order(_)) => {
                            tracing::warn!("ACME issuance failed; retrying with backoff");
                        }
                        Err(_) => anyhow::bail!("ACME certificate or RAM cache unavailable"),
                    }
                }
                accepted = listener.accept() => {
                    let (tcp, _) = accepted.context("TLS listener failed")?;
                    let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                    let resolver = resolver.clone();
                    let domain = self.config.domain.clone();
                    let app = app.clone();
                    let identity = identity.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        if connection(tcp, resolver, &domain, app, identity).await.is_err() {
                            tracing::debug!("TLS connection closed");
                        }
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {},
            }
        }
    }
}

// Hold the exact key chosen from the live resolver, even if renewal replaces
// the resolver's certificate during this connection's handshake.
#[derive(Debug)]
struct SelectedCertificate(Option<Arc<CertifiedKey>>);

impl ResolvesServerCert for SelectedCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.clone()
    }
}

fn server_config(cert: Option<Arc<CertifiedKey>>, challenge: bool) -> anyhow::Result<ServerConfig> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SelectedCertificate(cert)));
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.key_log = Arc::new(rustls::NoKeyLog);
    config.enable_secret_extraction = false;
    // Every connection presents its selected certificate; no resumed session
    // can silently inherit an older TLS identity after a certificate rotation.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.alpn_protocols = vec![if challenge {
        b"acme-tls/1".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Ok(config)
}

fn certificate_identity(cert: &CertifiedKey, domain: &str) -> anyhow::Result<(TlsSpki, u64)> {
    cert.keys_match().context("TLS certificate key mismatch")?;
    ensure!(
        cert.key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .is_some(),
        "TLS certificate must use ECDSA P-256"
    );
    let leaf = cert.cert.first().context("TLS certificate missing")?;
    let (trailing, parsed) = parse_x509_certificate(leaf.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid TLS certificate"))?;
    ensure!(
        trailing.is_empty() && parsed.validity().is_valid(),
        "TLS certificate is not current"
    );
    let san = parsed
        .subject_alternative_name()?
        .context("TLS certificate has no hostname")?;
    ensure!(
        san.value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName(value) if *value == domain)),
        "TLS certificate hostname mismatch"
    );
    Ok((
        TlsSpki {
            spki_sha256_hex: hex::encode(Sha256::digest(parsed.public_key().raw)),
            domain: Some(domain.into()),
        },
        u64::try_from(parsed.validity().not_after.timestamp())?,
    ))
}

async fn connection(
    tcp: TcpStream,
    resolver: Arc<ResolvesServerCertAcme>,
    domain: &str,
    app: Router,
    identity: Arc<Service>,
) -> anyhow::Result<()> {
    let (mut tls, keyset) = tokio::time::timeout(Duration::from_secs(15), async {
        let handshake = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp).await?;
        let hello = handshake.client_hello();
        ensure!(hello.server_name() == Some(domain), "TLS hostname mismatch");
        let challenge = rustls_acme::is_tls_alpn_challenge(&hello);
        let Some(cert) = resolver.resolve(hello) else {
            // Send the protocol's TLS alert while issuance is pending. This
            // never installs a fallback certificate or enables plaintext HTTP.
            let _ = handshake
                .into_stream(Arc::new(server_config(None, challenge)?))
                .await?;
            anyhow::bail!("TLS handshake unexpectedly succeeded without a certificate");
        };
        let keyset = if challenge {
            None
        } else {
            let (tls_key, expiry) = certificate_identity(&cert, domain)?;
            Some(Arc::new(identity.keyset_for_tls(tls_key, expiry)?))
        };
        let tls = handshake
            .into_stream(Arc::new(server_config(Some(cert), challenge)?))
            .await?;
        Ok::<_, anyhow::Error>((tls, keyset))
    })
    .await??;
    let Some(keyset) = keyset else {
        tls.shutdown().await?;
        return Ok(());
    };
    let app = app.layer(Extension(keyset));
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15))
        .max_buf_size(64 * 1024)
        .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
        .with_upgrades()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        ClientConfig, RootCertStore,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn certificate() -> Arc<CertifiedKey> {
        let generated =
            rcgen::generate_simple_self_signed(vec!["api.cypherpunklabs.io".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()).into();
        Arc::new(
            CertifiedKey::from_der(
                vec![generated.cert.der().clone()],
                key,
                &rustls::crypto::ring::default_provider(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn negotiates_tls13_and_rejects_tls12() {
        let cert = certificate();
        let config = server_config(Some(cert.clone()), false).unwrap();
        assert_eq!(config.max_early_data_size, 0);
        assert!(!config.key_log.will_log("CLIENT_TRAFFIC_SECRET_0"));
        assert!(!config.enable_secret_extraction);
        assert_eq!(config.send_tls13_tickets, 0);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        for (version, succeeds) in [
            (&rustls::version::TLS13, true),
            (&rustls::version::TLS12, false),
        ] {
            let mut roots = RootCertStore::empty();
            roots.add(cert.cert[0].clone()).unwrap();
            let client = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client));
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (server, client) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(
                    acceptor.accept(server_io),
                    connector.connect(
                        ServerName::try_from("api.cypherpunklabs.io").unwrap(),
                        client_io
                    )
                )
            })
            .await
            .unwrap();
            assert_eq!(server.is_ok(), succeeds);
            assert_eq!(client.is_ok(), succeeds);
            if let Ok(server) = server {
                assert_eq!(
                    server.get_ref().1.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3)
                );
            }
        }
    }

    #[test]
    fn certificate_binding_matches_spki_and_rejects_wrong_keys_or_hostnames() {
        let first = certificate();
        let second = certificate();
        let (binding, expiry) = certificate_identity(&first, "api.cypherpunklabs.io").unwrap();
        let (_, leaf) = parse_x509_certificate(first.cert[0].as_ref()).unwrap();
        assert_eq!(
            binding.spki_sha256_hex,
            hex::encode(Sha256::digest(leaf.public_key().raw))
        );
        assert!(expiry > crate::attestation::evidence::now_secs());
        assert_ne!(
            binding.spki_sha256_hex,
            certificate_identity(&second, "api.cypherpunklabs.io")
                .unwrap()
                .0
                .spki_sha256_hex
        );
        assert!(certificate_identity(&first, "other.example.com").is_err());
        let mismatched = CertifiedKey::new(first.cert.clone(), second.key.clone());
        assert!(certificate_identity(&mismatched, "api.cypherpunklabs.io").is_err());
    }
}
