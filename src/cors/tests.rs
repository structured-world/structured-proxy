use super::*;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::routing::any;
use axum::Router;
use tower::ServiceExt;

/// A router whose only route answers every method with the method it saw, a
/// `Vary` of its own on it, behind `cors`.
fn app_with(cors: CorsLayer) -> Router {
    Router::new()
        .route(
            "/x",
            any(|method: Method| async move {
                ([(VARY, "accept-encoding")], method.as_str().to_owned())
            }),
        )
        .layer(cors)
}

fn app() -> Router {
    app_with(CorsLayer::any(None))
}

async fn send(request: Request) -> (StatusCode, axum::http::HeaderMap, String) {
    send_to(app(), request).await
}

async fn send_to(app: Router, request: Request) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.oneshot(request).await.unwrap();
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
async fn every_origin_gets_wildcards_and_no_credentials() {
    let (_, headers, _) = send(options(&[
        ("origin", "https://a.example"),
        ("access-control-request-method", "PUT"),
    ]))
    .await;
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(headers["access-control-allow-methods"], "*");
    assert_eq!(headers["access-control-allow-headers"], "*");
    assert!(!headers.contains_key("access-control-allow-credentials"));
    assert!(!headers.contains_key("vary"));
    let request = Request::get("/x")
        .header("origin", "https://a.example")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send(request).await;
    assert_eq!(headers["access-control-expose-headers"], "*");
    let vary: Vec<_> = headers.get_all("vary").iter().collect();
    assert_eq!(vary, ["accept-encoding"]);
}

#[tokio::test]
async fn every_origin_may_send_the_headers_it_asks_for_authorization_included() {
    // `*` in Access-Control-Allow-Headers does not cover `Authorization`
    // (Fetch §3.2.3): the headers a preflight asks for are named back, and
    // the answer varies with them.
    let (_, headers, _) = send(options(&[
        ("origin", "https://a.example"),
        ("access-control-request-method", "GET"),
        ("access-control-request-headers", "authorization,x-a"),
    ]))
    .await;
    assert_eq!(headers["access-control-allow-headers"], "authorization,x-a");
    assert_eq!(headers["vary"], "access-control-request-headers");
    assert_eq!(headers["access-control-allow-origin"], "*");
}

/// The configured origins with credentials, exposing two headers, a preflight
/// cached for ten minutes.
fn listed() -> Router {
    app_with(CorsLayer::listed(
        vec![HeaderValue::from_static("https://a.example")],
        &[
            HeaderName::from_static("grpc-status"),
            HeaderName::from_static("x-custom"),
        ],
        Some(600),
    ))
}

#[tokio::test]
async fn a_listed_origin_preflight_gets_back_what_it_asked_for() {
    // With credentials the Fetch standard (§3.2.5) forbids `*`: the method
    // and headers asked for are echoed, for the listed origin only.
    let request = options(&[
        ("origin", "https://a.example"),
        ("access-control-request-method", "PUT"),
        ("access-control-request-headers", "x-a,x-b"),
    ]);
    let (status, headers, body) = send_to(listed(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "{body}");
    assert_eq!(headers["access-control-allow-origin"], "https://a.example");
    assert_eq!(headers["access-control-allow-methods"], "PUT");
    assert_eq!(headers["access-control-allow-headers"], "x-a,x-b");
    assert_eq!(headers["access-control-allow-credentials"], "true");
    assert_eq!(headers["access-control-max-age"], "600");
    assert_eq!(
        headers["vary"],
        "origin, access-control-request-method, access-control-request-headers"
    );
}

#[tokio::test]
async fn a_listed_origin_reads_the_exposed_headers() {
    let request = Request::get("/x")
        .header("origin", "https://a.example")
        .body(Body::empty())
        .unwrap();
    let (_, headers, body) = send_to(listed(), request).await;
    assert_eq!(body, "GET");
    assert_eq!(headers["access-control-allow-origin"], "https://a.example");
    assert_eq!(headers["access-control-allow-credentials"], "true");
    assert_eq!(
        headers["access-control-expose-headers"],
        "grpc-status,x-custom"
    );
    // The response's own `Vary` stays beside the CORS one.
    let vary: Vec<_> = headers.get_all("vary").iter().collect();
    assert_eq!(
        vary,
        [
            "accept-encoding",
            "origin, access-control-request-method, access-control-request-headers"
        ]
    );
    assert!(!headers.contains_key("access-control-max-age"));
}

#[tokio::test]
async fn an_origin_not_listed_is_not_allowed() {
    let request = Request::get("/x")
        .header("origin", "https://b.example")
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = send_to(listed(), request).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "GET"));
    assert!(!headers.contains_key("access-control-allow-origin"));
}
