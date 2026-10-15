use super::{ASSERTION_ID, Error, Result, decode, wire};
use ed25519_dalek::{Signer, SigningKey};
use oak_proto_rust::oak::{
    attestation::v1::Assertion,
    session::v1::{self as oak, session_request::Request},
};
use oak_session::{
    ProtocolEngine, ServerSession, Session,
    attestation::AttestationType,
    config::SessionConfig,
    generator::{BindableAssertion, BindableAssertionGenerator, BindableAssertionGeneratorError},
    handshake::HandshakeType,
};
use prost::Message;
use std::sync::Arc;
use zeroize::Zeroize;

const PROFILE: &str = "oak-session-v1-ed25519";
const DOMAIN: &[u8] = b"cypherpunk.oak-session.v1";

/// Parse the only unencrypted client initialization record.
/// # Errors
/// Rejects unknown versions, payloads or lengths.
pub fn parse_initialize(bytes: &[u8]) -> Result<String> {
    if bytes.len() != 36 || &bytes[..4] != b"CPK1" {
        return Err(Error::Protocol);
    }
    Ok(hex::encode(&bytes[4..]))
}
struct Generated {
    assertion: Assertion,
    key: Arc<SigningKey>,
}
impl BindableAssertionGenerator for Generated {
    fn generate(
        &self,
    ) -> std::result::Result<Box<dyn BindableAssertion>, BindableAssertionGeneratorError> {
        Ok(Box::new(Self {
            assertion: self.assertion.clone(),
            key: self.key.clone(),
        }))
    }
}
impl BindableAssertion for Generated {
    fn assertion(&self) -> &Assertion {
        &self.assertion
    }
    fn bind(
        &self,
        token: &[u8],
    ) -> std::result::Result<oak::SessionBinding, BindableAssertionGeneratorError> {
        if token.len() != 32 {
            return Err(BindableAssertionGeneratorError::BindingGenerationFailure {
                error_msg: "invalid binding token".into(),
            });
        }
        Ok(oak::SessionBinding {
            binding: self.key.sign(&[token, DOMAIN].concat()).to_bytes().to_vec(),
        })
    }
}

fn empty_attestation() -> oak::SessionRequest {
    oak::SessionRequest {
        request: Some(Request::AttestRequest(oak::AttestRequest::default())),
    }
}
fn write(session: &mut impl Session, record: &wire::Record) -> Result<()> {
    let plaintext = record.encode_to_vec();
    if plaintext.len() > super::MAX_FRAME - 1024 {
        return Err(Error::Limit);
    }
    session
        .write(oak::PlaintextMessage { plaintext })
        .map_err(|_| Error::Crypto)
}
fn read(session: &mut impl Session) -> Result<wire::Record> {
    let mut plaintext = session
        .read()
        .map_err(|_| Error::Crypto)?
        .ok_or(Error::State)?;
    let result = decode(&plaintext.plaintext);
    plaintext.plaintext.zeroize();
    result
}

/// Matching server engine. Its binding key is provisioned inside the CVM.
/// Server admission, deadlines and request dispatch belong to the proxy adapter.
pub struct ServerChannel {
    session: ServerSession,
}
impl ServerChannel {
    /// Produce the assertion flight from the exact challenge-bound evidence.
    /// # Errors
    /// Rejects oversized evidence and Oak initialization failures.
    pub fn new(evidence: Vec<u8>, binding_key: Arc<SigningKey>) -> Result<(Self, Vec<u8>)> {
        if evidence.len() > super::MAX_EVIDENCE {
            return Err(Error::Limit);
        }
        let assertion = Assertion {
            content: wire::Assertion {
                version: 1,
                evidence,
                profile: PROFILE.into(),
            }
            .encode_to_vec(),
        };
        let config =
            SessionConfig::builder(AttestationType::SelfUnidirectional, HandshakeType::NoiseNN)
                .add_self_assertion_generator(
                    ASSERTION_ID.into(),
                    Box::new(Generated {
                        assertion,
                        key: binding_key,
                    }),
                )
                .build();
        let mut session = ServerSession::create(config).map_err(|_| Error::Authentication)?;
        session
            .put_incoming_message(empty_attestation())
            .map_err(|_| Error::Authentication)?;
        let outgoing = session
            .get_outgoing_message()
            .map_err(|_| Error::Authentication)?
            .ok_or(Error::State)?
            .encode_to_vec();
        Ok((Self { session }, outgoing))
    }
    /// Whether Oak authentication and the ephemeral handshake are complete.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.session.is_open()
    }
    /// Process one handshake flight; never accepts early application data.
    /// # Errors
    /// Rejects other record types, client assertions and invalid Noise messages.
    pub fn handshake(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.is_open() || bytes.len() > 2048 {
            return Err(Error::State);
        }
        let message: oak::SessionRequest = decode(bytes)?;
        match &message.request {
            Some(Request::HandshakeRequest(h))
                if h.attestation_bindings.is_empty()
                    && h.assertion_bindings.is_empty()
                    && matches!(&h.handshake_type, Some(oak::handshake_request::HandshakeType::NoiseHandshakeMessage(n)) if valid_noise(n)) =>
                {}
            _ => return Err(Error::Protocol),
        }
        self.session
            .put_incoming_message(message)
            .map_err(|_| Error::Authentication)?;
        self.session
            .get_outgoing_message()
            .map_err(|_| Error::Authentication)
            .map(|m| m.map(|m| m.encode_to_vec()))
    }
    /// Encrypt a single response/control record.
    /// # Errors
    /// Rejects unopened sessions, excessive size and encryption failure.
    pub fn send(&mut self, record: &wire::Record) -> Result<Vec<u8>> {
        write(&mut self.session, record)?;
        self.session
            .get_outgoing_message()
            .map_err(|_| Error::Crypto)?
            .map(|v| v.encode_to_vec())
            .ok_or(Error::State)
    }
    /// Decrypt a single request/control record.
    /// # Errors
    /// Rejects early data, malformed and unauthenticated records.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<wire::Record> {
        let message: oak::SessionRequest = decode(bytes)?;
        if !matches!(&message.request, Some(Request::EncryptedMessage(e)) if valid_encrypted(e)) {
            return Err(Error::Protocol);
        }
        self.session
            .put_incoming_message(message)
            .map_err(|_| Error::Crypto)?;
        read(&mut self.session)
    }
}

fn valid_noise(message: &oak::NoiseHandshakeMessage) -> bool {
    message.ephemeral_public_key.len() == 65
        && message.ephemeral_public_key.first() == Some(&4)
        && message.static_public_key.is_empty()
        && message.ciphertext.len() == 16
}
fn valid_encrypted(message: &oak::EncryptedMessage) -> bool {
    message.associated_data.is_none() && message.nonce.is_none() && message.ciphertext.len() >= 17
}
