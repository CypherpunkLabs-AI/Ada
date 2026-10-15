//! Single-use completion proofs and expiring upstream sessions.
use crate::attestation::evidence::{AttestedSession, SignedReceipt, now_secs};
use std::{collections::HashMap, sync::Mutex};

const MAX_PROOFS: usize = 32;

#[derive(Default)]
pub(crate) struct CompletionStore {
    proofs: Mutex<HashMap<String, (SignedReceipt, AttestedSession, u64)>>,
}
impl CompletionStore {
    pub fn take_completion(&self, id: &str) -> Option<(SignedReceipt, AttestedSession)> {
        let (receipt, session, expiry) = self.proofs.lock().ok()?.remove(id)?;
        (now_secs() < expiry).then_some((receipt, session))
    }

    pub(crate) fn store_completion(
        &self,
        receipt: SignedReceipt,
        session: AttestedSession,
    ) -> std::io::Result<()> {
        let now = now_secs();
        let mut proofs = self
            .proofs
            .lock()
            .map_err(|_| std::io::Error::other("receipt state unavailable"))?;
        proofs.retain(|_, (_, _, expiry)| *expiry > now);
        if proofs.len() >= MAX_PROOFS {
            return Err(std::io::Error::other("receipt capacity exceeded"));
        }
        proofs.insert(
            receipt.receipt_id.clone(),
            (receipt, session, now.saturating_add(60)),
        );
        Ok(())
    }
}
