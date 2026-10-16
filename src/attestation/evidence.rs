//! Product evidence assembly. Cryptographic encodings come from aci-protocol.
use crate::{attestation::keys::OakKeys, inference::upstream::VerifiedInference};
use aci_protocol::{
    digest, identity,
    receipt::receipt_signing_input,
    types::{SourceProvenance, WorkloadKeyset},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

#[must_use]
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}

pub struct ServiceConfig {
    pub source_provenance: SourceProvenance,
    pub keyset_ttl_seconds: u64,
    pub subject: Option<String>,
    pub receipt_ttl_seconds: u64,
}

/// Require a source repository and commit, or an image digest.
///
/// # Errors
/// Returns an error when neither provenance identity is present.
pub fn validate_source_provenance(value: &SourceProvenance) -> Result<()> {
    ensure!(
        value.repo_url.as_ref().is_some_and(|s| !s.is_empty())
            && value.repo_commit.as_ref().is_some_and(|s| !s.is_empty())
            || value.image_digest.as_ref().is_some_and(|s| !s.is_empty()),
        "source provenance required"
    );
    Ok(())
}

pub struct Keyset {
    value: WorkloadKeyset,
    json: Value,
    digest: String,
}
impl Keyset {
    /// Serialize the keyset and calculate its canonical digest.
    ///
    /// # Errors
    /// Returns an error if keyset serialization or canonical hashing fails.
    pub fn new(value: WorkloadKeyset) -> Result<Self> {
        let json = serde_json::to_value(&value)?;
        let digest = identity::workload_keyset_digest(&json)?;
        Ok(Self {
            value,
            json,
            digest,
        })
    }
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
    #[must_use]
    pub fn keyset(&self) -> &WorkloadKeyset {
        &self.value
    }
    #[must_use]
    pub fn to_value(&self) -> Value {
        self.json.clone()
    }
}

#[derive(Clone)]
pub struct AttestedSession {
    id: String,
    bytes: Vec<u8>,
    pub expires_at: u64,
}
impl AttestedSession {
    pub(crate) fn new(event: &VerifiedInference, expires_at: u64) -> Result<Self> {
        ensure!(
            event.established_at <= event.completed_at
                && event.completed_at < expires_at
                && now_secs() < expires_at,
            "expired upstream evidence"
        );
        // ACI carries exact evidence bytes and their digest, rather than the
        // provider-specific object directly in the session's evidence field.
        let evidence = digest::jcs_bytes(&event.evidence)?;
        let spki = event
            .evidence
            .pointer("/gateway/tls_binding/spki_sha256")
            .and_then(Value::as_str)
            .context("missing verified upstream TLS binding")?;
        let origin = reqwest::Url::parse(&event.origin)?
            .origin()
            .ascii_serialization();
        let unknown = json!({"status":"unknown"});
        let tcb = if event.tcb_up_to_date {
            json!({"status":"asserted", "source":"verifier_derived",
                "reason":"Every verified gateway and model quote reports UpToDate"})
        } else {
            json!({"status":"unknown", "source":"verifier_derived",
                "reason":"UpToDate is not asserted: a verified quote reports OutOfDate, accepted by the NEAR SDK default policy; actual statuses and advisories are included in evidence"})
        };
        let value = json!({
            "api_version":"aci/1", "upstream_name":"nearai",
            "endpoint":event.origin, "verifier_id":"nearai-inference-sdk",
            "established_at":event.established_at, "expires_at":expires_at,
            "identity":null, "completed_at":event.completed_at,
            "channel_binding":[{
                "type":"tls_spki_sha256", "origin":origin, "spki_sha256":spki
            }],
            "claims":{
                "tee_attested":{"status":"asserted", "source":"verifier_derived",
                    "reason":"NEAR SDK verified gateway/model TDX evidence, nonce, measured deployment and key binding"},
                "gpu_attested":{"status":"asserted", "source":"verifier_derived", "reason":"Required NVIDIA evidence verified by NEAR SDK"},
                "tcb_up_to_date":tcb,
                "measured_image_provenance":{"status":"asserted", "source":"verifier_derived",
                    "reason":"The required measured gateway and model-launcher images matched trusted NEAR publisher/workflow identities and SDK-verified Sigstore build provenance; supporting and later-loaded images are not covered"},
                "os_known_good":unknown, "serving_software_known_good":unknown,
                "model_weights_provenance":unknown
            },
            "evidence":{
                "digest":digest::sha256_hex(&evidence),
                "data":format!("data:application/json;base64,{}", STANDARD.encode(&evidence))
            },
        });
        let bytes = digest::jcs_bytes(&value)?;
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "upstream evidence exceeds limit"
        );
        let id = hex::encode(digest::sha256_raw(&bytes));
        Ok(Self {
            id,
            bytes,
            expires_at,
        })
    }
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct SignedReceipt {
    pub receipt_id: String,
    pub document: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) struct ReceiptRequest<'a> {
    pub id: &'a str,
    pub model: Option<&'a str>,
    pub keyset: &'a str,
    pub path: &'a str,
    pub received: &'a [u8],
    pub forwarded: &'a [u8],
}

/// An unsigned draft holds application hashes. Signing requires the SDK-verified
/// completion and consumes the draft after the response has been fully hashed.
pub(crate) struct Receipt {
    document: Value,
}
impl Receipt {
    pub fn new(request: ReceiptRequest<'_>) -> Self {
        let ReceiptRequest {
            id,
            model,
            keyset,
            path,
            received,
            forwarded,
        } = request;
        let document = json!({
            "api_version":"aci/1", "receipt_id":id, "chat_id":null,
            "model":model, "workload_keyset_digest":keyset, "endpoint":path,
            "method":"POST", "served_at":now_secs(),
            "event_log":[
                {"type":"request.received", "body_hash":digest::sha256_hex(received)},
                {"type":"request.forwarded", "body_hash":digest::sha256_hex(forwarded)}
            ]
        });
        Self { document }
    }
    pub fn finish(
        mut self,
        response_hash: &str,
        event: &VerifiedInference,
        session: &AttestedSession,
        keys: &OakKeys,
    ) -> Result<SignedReceipt> {
        ensure!(
            now_secs() < session.expires_at,
            "completion evidence expired"
        );
        // The draft predates upstream attestation. Serving happened after that
        // session was established, not when the incoming request was queued.
        self.document["served_at"] = json!(event.completed_at);
        self.document["event_log"]
            .as_array_mut()
            .expect("receipt event array")
            .push(
                json!({"type":"upstream.verified", "result":"verified", "required":true,
                "model_id":event.model_id, "session_id":session.session_id()}),
            );
        self.document["event_log"]
            .as_array_mut()
            .expect("receipt event array")
            .push(json!({"type":"response.returned", "body_hash":response_hash}));
        let key = keys.receipt_keys().remove(0);
        self.document["key_id"] = json!(key.key_id);
        let signature = keys.sign_receipt(&key.key_id, &receipt_signing_input(&self.document)?)?;
        self.document["signature"] = json!(hex::encode(signature));
        Ok(SignedReceipt {
            receipt_id: self.document["receipt_id"]
                .as_str()
                .expect("receipt id")
                .to_owned(),
            document: digest::jcs_bytes(&self.document)?,
        })
    }
}
