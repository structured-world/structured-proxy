//! The concurrency limit: at most `max_in_flight` requests at once, the rest
//! turned away at once rather than queued, since a queue behind a saturated
//! upstream only adds latency to what will time out anyway.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::pin::Pin;
use core::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use pin_project_lite::pin_project;
// no-std: an `AtomicUsize` slot counter with a drop guard (only try-acquire is used).
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

/// Take a slot for the request and hold it until its response body ends, so
/// a stream counts for its whole life; with none free, `UNAVAILABLE` and a
/// one-second `Retry-After`.
pub(super) async fn middleware(
    State(concurrency): State<Arc<Concurrency>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(slot) = concurrency.slots.clone().try_acquire_owned() else {
        let mut response = reject(tonic::Code::Unavailable, "too many requests in flight");
        response.headers_mut().insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("1"),
        );
        return response;
    };
    next.run(request).await.map(|body| {
        Body::new(Holding {
            body,
            slot: Some(slot),
        })
    })
}

pin_project! {
    /// A response body that frees its request's slot when it ends or is
    /// dropped.
    struct Holding {
        #[pin]
        body: Body,
        slot: Option<OwnedSemaphorePermit>,
    }
}

impl http_body::Body for Holding {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.project();
        let frame = this.body.poll_frame(cx);
        if let Poll::Ready(None | Some(Err(_))) = frame {
            // Ended: the slot is free before the connection moves on.
            this.slot.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
