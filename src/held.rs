//! A response body that keeps a value alive until it ends.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use pin_project_lite::pin_project;

/// `body`, holding `value` until the body ends or is dropped: a slot, a
/// request counted as in flight.
pub(crate) fn until_end<T: Send + 'static>(body: Body, value: T) -> Body {
    Body::new(Held {
        body,
        value: Some(value),
    })
}

pin_project! {
    struct Held<T> {
        #[pin]
        body: Body,
        value: Option<T>,
    }
}

impl<T> http_body::Body for Held<T> {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.project();
        let frame = this.body.poll_frame(cx);
        if let Poll::Ready(None | Some(Err(_))) = frame {
            // Ended: let go before the connection moves on.
            this.value.take();
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
