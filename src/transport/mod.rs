//! Proxy-side Oak Session engine and wire protocol. Socket handling lives in the proxy.
#![forbid(unsafe_code)]

mod channel;
mod flow;
pub mod oak;
pub use channel::{ServerChannel, parse_initialize};
pub use flow::{Flow, Side, inference_route};

/// Generated common client/server wire schema.
#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod wire;

/// Required WebSocket subprotocol; credentials never belong here or in the URL.
pub const SUBPROTOCOL: &str = "cypherpunk-session-v1";
/// Sole accepted Oak assertion identifier.
pub const ASSERTION_ID: &str = "ada.gcp-tdx.v1";
/// Maximum carrier message, enforced before protobuf decoding.
pub const MAX_FRAME: usize = 5 * 1024 * 1024;
/// Maximum serialized attestation report, including all public release proofs.
pub const MAX_EVIDENCE: usize = 4 * 1024 * 1024;
/// Maximum individual request/response body chunk.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Bounded receive credit in either direction.
pub const WINDOW: u32 = 256 * 1024;
/// Maximum body bytes per direction per request.
pub const MAX_BODY: u64 = 64 * 1024 * 1024;
/// Maximum requests in a session before fresh verification and key exchange.
pub const MAX_REQUESTS: usize = 4096;

/// Redacted transport errors. A failed operation closes its owning session.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed, unexpected or noncanonical wire input.
    #[error("invalid session protocol")]
    Protocol,
    /// Attestation or handshake failure.
    #[error("session authentication failed")]
    Authentication,
    /// Encryption/decryption or ordered-channel failure.
    #[error("encrypted channel failed")]
    Crypto,
    /// Resource limit or exhausted receive credit.
    #[error("session resource limit")]
    Limit,
    /// Wrong lifecycle state, including unacknowledged persistence.
    #[error("invalid session state")]
    State,
    /// Secure randomness unavailable.
    #[error("secure randomness unavailable")]
    Entropy,
}
/// Shared result type.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn decode<T: prost::Message + Default>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    let value = T::decode(bytes).map_err(|_| Error::Protocol)?;
    // Reject duplicate fields/maps, unknown fields, nonminimal varints and
    // alternative encodings before any interpretation or transcript processing.
    if value.encode_to_vec() != bytes {
        return Err(Error::Protocol);
    }
    Ok(value)
}
