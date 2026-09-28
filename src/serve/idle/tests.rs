use super::*;

use std::time::Duration;

/// Whether `future` has resolved, without waiting.
async fn ready<F: Future>(future: Pin<&mut F>) -> bool {
    tokio::select! {
        biased;
        _ = future => true,
        () = std::future::ready(()) => false,
    }
}

#[tokio::test(start_paused = true)]
async fn a_connection_with_nothing_in_flight_is_idle_after_the_timeout() {
    let activity = Arc::new(Activity::default());
    let idle = activity.idle_for(Duration::from_secs(1));
    tokio::pin!(idle);
    assert!(!ready(idle.as_mut()).await);
    tokio::time::advance(Duration::from_millis(1001)).await;
    assert!(ready(idle.as_mut()).await);
}

#[tokio::test(start_paused = true)]
async fn a_request_in_flight_keeps_its_connection() {
    // A long stream must not be cut because it outlasts the idle timeout.
    let activity = Arc::new(Activity::default());
    let in_flight = activity.enter();
    let idle = activity.idle_for(Duration::from_secs(1));
    tokio::pin!(idle);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(!ready(idle.as_mut()).await);

    // The timeout counts from the end of the request.
    drop(in_flight);
    assert!(!ready(idle.as_mut()).await);
    tokio::time::advance(Duration::from_millis(500)).await;
    assert!(!ready(idle.as_mut()).await);
    tokio::time::advance(Duration::from_millis(501)).await;
    assert!(ready(idle.as_mut()).await);
}

#[tokio::test(start_paused = true)]
async fn a_request_that_comes_and_goes_restarts_the_timeout() {
    let activity = Arc::new(Activity::default());
    let idle = activity.idle_for(Duration::from_secs(1));
    tokio::pin!(idle);
    assert!(!ready(idle.as_mut()).await);
    tokio::time::advance(Duration::from_millis(800)).await;
    drop(activity.enter());
    assert!(!ready(idle.as_mut()).await);
    tokio::time::advance(Duration::from_millis(800)).await;
    assert!(!ready(idle.as_mut()).await);
    tokio::time::advance(Duration::from_millis(201)).await;
    assert!(ready(idle.as_mut()).await);
}
