use super::*;
use axum::body::Body;
use axum::http::StatusCode;
use axum::routing::any;
use tower::ServiceExt;

/// A router whose only route answers every method with the method it saw.
fn app() -> Router {
    let router = Router::new().route(
        "/x",
        any(|method: Method| async move { method.as_str().to_owned() }),
    );
    layer(router, CorsLayer::permissive())
}

async fn send(request: Request) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

fn options(headers: &[(&str, &str)]) -> Request {
    let mut builder = Request::builder().method(Method::OPTIONS).uri("/x");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn ordinary_options_reaches_the_route_as_options() {
    let (status, headers, body) = send(options(&[("origin", "https://a.example")])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "OPTIONS");
    // It is still a CORS response, with the headers of an ordinary request.
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert!(!headers.contains_key("access-control-allow-methods"));
}

#[tokio::test]
async fn options_without_origin_reaches_the_route() {
    let (status, _, body) = send(options(&[])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "OPTIONS");
}

#[tokio::test]
async fn options_with_a_request_method_but_no_origin_reaches_the_route() {
    // A preflight is a CORS request, and a CORS request carries `Origin`
    // (Fetch §3.2.2): without it this is an ordinary OPTIONS, which a
    // forward-auth check must see rather than the CORS layer's 200.
    let (status, _, body) = send(options(&[("access-control-request-method", "PUT")])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "OPTIONS");
}

#[tokio::test]
async fn preflight_is_answered_by_the_cors_layer() {
    let (status, headers, body) = send(options(&[
        ("origin", "https://a.example"),
        ("access-control-request-method", "PUT"),
    ]))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "{body}");
    assert!(headers.contains_key("access-control-allow-methods"));
}

#[tokio::test]
async fn other_methods_are_untouched() {
    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/x")
        .header("origin", "https://a.example")
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = send(request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "DELETE");
    assert_eq!(headers["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn stand_in_method_sent_by_a_client_is_not_turned_into_options() {
    let request = Request::builder()
        .method(stand_in())
        .uri("/x")
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "X-SP-OPTIONS");
}
