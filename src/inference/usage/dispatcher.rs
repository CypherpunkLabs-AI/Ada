use tokio::sync::mpsc;
use uuid::Uuid;

use crate::inference::{UsageMetrics, config::UsageQueueConfig};

use super::worker::UsageWorker;

const BUFFER_CAPACITY: usize = 100_000;

#[derive(Debug)]
pub(super) struct UsageJob {
    pub request_id: Uuid,
    pub user_id: String,
    pub model: String,
    pub usage: UsageMetrics,
}

/// Non-blocking request-path handle for usage reporting.
///
/// The bounded channel prevents an unavailable Queue API from causing
/// unbounded process memory growth. Network delivery belongs exclusively to
/// the single background worker.
#[derive(Clone)]
pub struct UsageDispatcher {
    sender: mpsc::Sender<UsageJob>,
}

impl UsageDispatcher {
    pub fn start(config: &UsageQueueConfig) -> anyhow::Result<Self> {
        let (sender, receiver) = mpsc::channel(BUFFER_CAPACITY);
        let worker = UsageWorker::new(config)?;
        tokio::spawn(worker.run(receiver));
        Ok(Self { sender })
    }

    /// Reserve accounting capacity before accepting work; never drop a completed
    /// request's event because the channel filled during generation.
    pub fn reserve(&self) -> anyhow::Result<UsageReservation> {
        self.sender
            .clone()
            .try_reserve_owned()
            .map(UsageReservation)
            .map_err(|_| anyhow::anyhow!("usage reporting unavailable"))
    }
}

pub(crate) struct UsageReservation(mpsc::OwnedPermit<UsageJob>);
impl UsageReservation {
    pub fn commit(self, request_id: Uuid, user_id: String, model: String, usage: UsageMetrics) {
        self.0.send(UsageJob {
            request_id,
            user_id,
            model,
            usage,
        });
    }
}
