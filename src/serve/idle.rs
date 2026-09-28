//! When a connection has had no request in flight for long enough to close.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use axum::body::Body;
use pin_project_lite::pin_project;
use tokio::sync::Notify;
use tower::Service;

/// The requests in flight on one connection.
#[derive(Debug, Default)]
pub(super) struct Activity {
    active: AtomicUsize,
    /// Woken when the count leaves or reaches zero.
    changed: Notify,
}

impl Activity {
    /// A request starts; it ends when the returned guard drops.
    fn enter(self: &Arc<Self>) -> InFlight {
        if self.active.fetch_add(1, Ordering::AcqRel) == 0 {
            self.changed.notify_one();
        }
        InFlight(Arc::clone(self))
    }

    /// Resolves once no request has been in flight for `timeout`.
    pub(super) async fn idle_for(&self, timeout: Duration) {
        loop {
            if self.active.load(Ordering::Acquire) == 0 {
                tokio::select! {
                    () = tokio::time::sleep(timeout) => {
                        if self.active.load(Ordering::Acquire) == 0 {
                            return;
                        }
                    }
                    // A request started (and maybe ended): measure again.
                    () = self.changed.notified() => {}
                }
            } else {
                // `notify_one` keeps a permit when nobody waits, so an end
                // between the load and this await is not missed.
                self.changed.notified().await;
            }
        }
    }
}

/// One request in flight.
#[derive(Debug)]
struct InFlight(Arc<Activity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.changed.notify_one();
        }
    }
}

/// `inner`, counting each request in flight on `activity` until its response
/// body ends.
#[derive(Clone, Debug)]
pub(super) struct Tracked<S> {
    pub(super) inner: S,
    pub(super) activity: Arc<Activity>,
}

impl<S, R> Service<R> for Tracked<S>
where
    S: Service<R, Response = http::Response<Body>, Error = Infallible>,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = TrackedFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        TrackedFuture {
            in_flight: Some(self.activity.enter()),
            future: self.inner.call(request),
        }
    }
}

pin_project! {
    /// The response future of [`Tracked`].
    pub(super) struct TrackedFuture<F> {
        #[pin]
        future: F,
        in_flight: Option<InFlight>,
    }
}

impl<F> Future for TrackedFuture<F>
where
    F: Future<Output = Result<http::Response<Body>, Infallible>>,
{
    type Output = Result<http::Response<Body>, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let response = ready!(this.future.poll(cx))?;
        Poll::Ready(Ok(match this.in_flight.take() {
            // The request stays in flight until its response body ends.
            Some(in_flight) => response.map(|body| crate::held::until_end(body, in_flight)),
            None => response,
        }))
    }
}

#[cfg(test)]
mod tests;
