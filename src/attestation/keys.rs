//! Independent, process-local keys. Private material is never persisted.
use aci_protocol::types::KeyedPublicKey;
use anyhow::ensure;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use zeroize::Zeroizing;

const RECEIPT_ID: &str = "hiro-ephemeral-receipt-ed25519-v1";
const BINDING_ID: &str = "hiro-ephemeral-oak-session-v1";

pub struct OakKeys {
    receipt: SigningKey,
    pub binding: Arc<SigningKey>,
}

impl OakKeys {
    /// Generate fresh receipt and Oak handshake keys using the guest CSPRNG.
    /// # Errors
    /// Fails if the operating system cannot supply secure randomness.
    pub fn new() -> anyhow::Result<Self> {
        let receipt = generate()?;
        let binding = generate()?;
        ensure!(
            receipt.verifying_key() != binding.verifying_key(),
            "key collision"
        );
        Ok(Self {
            receipt,
            binding: Arc::new(binding),
        })
    }

    #[must_use]
    pub fn receipt_keys(&self) -> Vec<KeyedPublicKey> {
        vec![KeyedPublicKey {
            key_id: RECEIPT_ID.into(),
            algo: "ed25519".into(),
            public_key_hex: hex::encode(self.receipt.verifying_key().as_bytes()),
        }]
    }

    #[must_use]
    pub fn binding_keys(&self) -> Vec<KeyedPublicKey> {
        vec![KeyedPublicKey {
            key_id: BINDING_ID.into(),
            algo: "oak-session-v1-ed25519".into(),
            public_key_hex: hex::encode(self.binding.verifying_key().as_bytes()),
        }]
    }

    /// Sign a receipt with the advertised, process-local receipt key.
    /// # Errors
    /// Rejects an unknown key identifier.
    pub fn sign_receipt(&self, id: &str, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        ensure!(id == RECEIPT_ID, "unknown receipt key");
        Ok(self.receipt.sign(payload).to_bytes().to_vec())
    }
}

fn generate() -> anyhow::Result<SigningKey> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(&mut *seed)
        .map_err(|_| anyhow::anyhow!("guest random number generator unavailable"))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn keys_are_independent_and_restart_rotates_them() {
        let first = OakKeys::new().unwrap();
        let second = OakKeys::new().unwrap();
        assert_ne!(first.receipt.verifying_key(), first.binding.verifying_key());
        assert_ne!(
            first.receipt.verifying_key(),
            second.receipt.verifying_key()
        );
        assert_ne!(
            first.binding.verifying_key(),
            second.binding.verifying_key()
        );
        let signature =
            Signature::from_slice(&first.sign_receipt(RECEIPT_ID, b"receipt").unwrap()).unwrap();
        first
            .receipt
            .verifying_key()
            .verify(b"receipt", &signature)
            .unwrap();
        assert!(
            first
                .binding
                .verifying_key()
                .verify(b"receipt", &signature)
                .is_err()
        );
        assert!(first.sign_receipt(BINDING_ID, b"receipt").is_err());
    }
}
