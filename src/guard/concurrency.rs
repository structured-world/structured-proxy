//! The concurrency limit: at most `max_in_flight` requests at once, the rest
//! turned away at once rather than queued, since a queue behind a saturated
//! upstream only adds latency to what will time out anyway.

use std::sync::Arc;

use axum::response::Response;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::reject;
use crate::config::ConcurrencyConfig;

/// The in-flight slots.
#[derive(Debug)]
pub(crate) struct Concurrency {
    slots: Arc<Semaphore>,
}

impl Concurrency {
    /// The limit `config` sets.
    ///
    /// # Errors
    /// A `max_in_flight` of zero, which would turn every request away, or one
    /// past what a semaphore can count.
    pub(crate) fn build(config: &ConcurrencyConfig) -> Result<Arc<Self>, String> {
        if config.max_in_flight == 0 || config.max_in_flight > Semaphore::MAX_PERMITS {
            return Err(format!(
                "concurrency.max_in_flight must be between 1 and {}",
                Semaphore::MAX_PERMITS
            ));
        }
        Ok(Arc::new(Self {
            slots: Arc::new(Semaphore::new(config.max_in_flight)),
        }))
    }
}

impl Concurrency {
    /// A slot for a request, held until its response body ends, so a stream
    /// counts for its whole life; `None` when none is free.
    pub(super) fn take(&self) -> Option<OwnedSemaphorePermit> {
        self.slots.clone().try_acquire_owned().ok()
    }

    /// The answer to a request no slot is free for: `UNAVAILABLE` and a
    /// one-second `Retry-After`.
    pub(super) fn full() -> Response {
        let mut response = reject(tonic::Code::Unavailable, "too many requests in flight");
        response.headers_mut().insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("1"),
        );
        response
    }
}
