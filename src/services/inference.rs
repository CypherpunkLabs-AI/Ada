//! Oak service dispatch with direct inference verification and signed completion.
use crate::attestation::keys::OakKeys;
use crate::storage::completions::CompletionStore;
use crate::{
    attestation::evidence::{
        AttestedSession, Keyset, Receipt, ServiceConfig, SignedReceipt, now_secs,
        validate_source_provenance,
    },
    inference::upstream::{CompletionProof, InferenceBackend},
};
use aci_protocol::{
    identity::{attestation_statement, report_data, report_data_slot},
    types::{AttestationEnvelope, AttestationReport, ServiceCapabilities, TlsSpki, WorkloadKeyset},
};
use anyhow::{Context, ensure};
use axum::{body::Body, response::Response};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const MAX_BODY: usize = 64 * 1024 * 1024;

pub struct Service {
    keys: Arc<OakKeys>,
    attester: crate::attestation::tdx::Attester,
    config: ServiceConfig,
    upstream: Arc<InferenceBackend>,
    completions: CompletionStore,
}

impl Service {
    /// Seal the process-local keyset and attach the direct TDX attester.
    /// # Errors
    /// Rejects invalid source provenance, expired identity or unexpected key roles.
    pub fn new(
        keys: Arc<OakKeys>,
        attester: crate::attestation::tdx::Attester,
        upstream: Arc<InferenceBackend>,
        config: ServiceConfig,
    ) -> anyhow::Result<Self> {
        validate_source_provenance(&config.source_provenance)?;
        ensure!(
            config.keyset_ttl_seconds > 0,
            "empty service identity lifetime"
        );
        let receipts = keys.receipt_keys();
        let bindings = keys.binding_keys();
        ensure!(
            receipts.len() == 1
                && bindings.len() == 1
                && receipts[0].algo == "ed25519"
                && bindings[0].algo == "oak-session-v1-ed25519"
                && receipts[0].key_id != bindings[0].key_id
                && receipts[0].public_key_hex != bindings[0].public_key_hex,
            "invalid key roles"
        );
        Ok(Self {
            keys,
            attester,
            config,
            upstream,
            completions: CompletionStore::default(),
        })
    }

    /// Snapshot the identity of the certificate selected for one TLS connection.
    /// Renewal must not change the keyset of an already established Oak session.
    /// # Errors
    /// Rejects expired certificates or an invalid identity encoding.
    pub fn keyset_for_tls(&self, tls: TlsSpki, certificate_expiry: u64) -> anyhow::Result<Keyset> {
        let now = now_secs();
        ensure!(certificate_expiry > now, "expired TLS certificate");
        Keyset::new(WorkloadKeyset {
            subject: self.config.subject.clone(),
            not_after: now
                .saturating_add(self.config.keyset_ttl_seconds)
                .min(certificate_expiry),
            receipt_signing_keys: self.keys.receipt_keys(),
            e2ee_public_keys: self.keys.binding_keys(),
            tls_public_keys: vec![tls],
        })
    }

    /// Produce challenge-bound evidence using the established ACI encoding.
    /// # Errors
    /// Rejects malformed challenges, expired identity or failed hardware quotes.
    pub async fn attestation_report(
        &self,
        identity: &Keyset,
        nonce: Option<String>,
    ) -> anyhow::Result<AttestationReport> {
        ensure!(
            !identity.keyset().is_expired_at(now_secs()),
            "expired service identity"
        );
        let nonce = nonce.context("challenge required")?;
        ensure!(
            nonce.len() == 64
                && nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid challenge"
        );
        let statement = attestation_statement(identity.digest(), Some(&nonce))?;
        let data = report_data(&statement);
        let evidence = self.attester.evidence(report_data_slot(data)).await?;
        let report = AttestationReport {
            api_version: "aci/1".into(),
            workload_keyset_digest: identity.digest().into(),
            attestation: AttestationEnvelope {
                tee_type: "tdx".into(),
                workload_keyset: identity.to_value(),
                report_data_hex: hex::encode(data),
                source_provenance: self.config.source_provenance.clone(),
                evidence,
            },
            service_capabilities: ServiceCapabilities::default(),
        };
        ensure!(
            serde_json::to_vec(&report)?.len() <= crate::transport::MAX_EVIDENCE,
            "attestation report exceeds transport limit"
        );
        Ok(report)
    }

    /// Consume the receipt and cited session exactly once for Oak completion.
    pub fn take_completion(&self, id: &str) -> Option<(SignedReceipt, AttestedSession)> {
        self.completions.take_completion(id)
    }

    /// Open a transformed application request through the same verified backend.
    pub(crate) async fn open_inference(
        &self,
        identity: &Keyset,
        path: &str,
        requested_model: Option<&str>,
        received: &[u8],
        forwarded: Vec<u8>,
    ) -> anyhow::Result<(crate::inference::upstream::StreamResponse, PendingReceipt)> {
        ensure!(
            !identity.keyset().is_expired_at(now_secs()),
            "expired service identity"
        );
        let id = uuid::Uuid::new_v4().to_string();
        let receipt = Receipt::new(crate::attestation::evidence::ReceiptRequest {
            id: &id,
            model: requested_model,
            keyset: identity.digest(),
            path,
            received,
            forwarded: &forwarded,
        });
        let (response, proof) = self.upstream.stream(&forwarded).await?;
        Ok((
            response,
            PendingReceipt {
                id,
                receipt,
                proof,
                keyset_not_after: identity.keyset().not_after,
            },
        ))
    }

    /// Hash the actual application response, including SSE keepalive bytes.
    /// Publishing only after clean body completion prevents authenticating truncation.
    pub(crate) fn sign_response(
        self: Arc<Self>,
        pending: PendingReceipt,
        response: Response,
    ) -> Response {
        let (mut parts, body) = response.into_parts();
        parts
            .headers
            .insert("x-receipt-id", pending.id.parse().expect("UUID header"));
        parts
            .headers
            .insert("cache-control", "no-store".parse().expect("static header"));
        let mut chunks = body.into_data_stream();
        let body = async_stream::try_stream! {
            let mut hash = Sha256::new();
            let mut length = 0usize;
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(|_| std::io::Error::other("inference response interrupted"))?;
                length = length.checked_add(chunk.len()).ok_or_else(|| std::io::Error::other("response exceeds limit"))?;
                if length > MAX_BODY { Err(std::io::Error::other("response exceeds limit"))?; }
                hash.update(&chunk);
                yield chunk;
            }
            let verified = pending.proof.get().ok_or_else(|| std::io::Error::other("missing verified completion"))?;
            let expires = now_secs().saturating_add(self.config.receipt_ttl_seconds).min(pending.keyset_not_after);
            let session = AttestedSession::new(verified, expires)
                .map_err(|_| std::io::Error::other("invalid completion evidence"))?;
            let signed = pending.receipt.finish(&format!("sha256:{}", hex::encode(hash.finalize())), verified, &session, self.keys.as_ref())
                .map_err(|_| std::io::Error::other("receipt signing failed"))?;
            self.completions.store_completion(signed, session)?;
        };
        let body: std::pin::Pin<
            Box<dyn futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>,
        > = Box::pin(body);
        Response::from_parts(parts, Body::from_stream(body))
    }
}

pub(crate) struct PendingReceipt {
    id: String,
    receipt: Receipt,
    proof: CompletionProof,
    keyset_not_after: u64,
}
