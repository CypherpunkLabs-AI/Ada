//! Validation of opaque encrypted envelopes; no decryption happens here.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};

use crate::api::error::ApiError;

pub(crate) const MIN_ENVELOPE_BYTES: usize = 12 + 16;
pub(crate) const WRAPPED_CHAT_KEY_BYTES: usize = MIN_ENVELOPE_BYTES + 32;

pub(crate) fn decode_envelope(
    field: &str,
    encoded: &str,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ApiError> {
    let maximum_encoded_bytes = maximum_bytes.div_ceil(3) * 4;
    if encoded.is_empty() || encoded.len() > maximum_encoded_bytes {
        return Err(ApiError::BadRequest(format!(
            "{field} exceeds the encoded size limit"
        )));
    }
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| ApiError::BadRequest(format!("{field} must be standard Base64")))?;
    if decoded.len() < minimum_bytes || decoded.len() > maximum_bytes {
        return Err(ApiError::BadRequest(format!(
            "{field} must decode to {minimum_bytes}..{maximum_bytes} bytes"
        )));
    }
    Ok(decoded)
}
