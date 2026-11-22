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
        None,
    ))
}

/// The origins `admitted` holds at the moment of each call, as an embedder's
/// run-time settings name them.
struct Admitted(std::sync::Mutex<Vec<String>>);

impl crate::hooks::CorsOrigins for Admitted {
    fn admits(&self, origin: &str) -> bool {
        self.0.lock().unwrap().iter().any(|o| o == origin)
    }
}

/// Credentialed CORS for `listed` origins and whatever `admitted` admits.
fn admitting(listed: &[&'static str], admitted: Arc<Admitted>) -> Router {
    app_with(CorsLayer::listed(
        listed.iter().map(|o| HeaderValue::from_static(o)).collect(),
        &[HeaderName::from_static("grpc-status")],
        None,
        Some(admitted),
    ))
}

// An origin the embedder admits at run time gets the credentialed answer a
// listed one gets, preflight included: the preflight never reaches the
// embedder's own routes, so only the CORS layer can answer it.
#[tokio::test]
async fn an_admitted_origin_gets_credentialed_cors() {
    let admitted = Arc::new(Admitted(std::sync::Mutex::new(vec![
        "https://console.example".into(),
    ])));
    let app = admitting(&["https://a.example"], admitted.clone());
    let (_, headers, body) = send_to(
        app.clone(),
        options(&[
            ("origin", "https://console.example"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "x-csrf-token"),
        ]),
    )
    .await;
    assert!(body.is_empty(), "{body}");
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://console.example"
    );
    assert_eq!(headers["access-control-allow-credentials"], "true");
    assert_eq!(headers["access-control-allow-headers"], "x-csrf-token");
    let request = Request::post("/x")
        .header("origin", "https://console.example")
        .body(Body::empty())
        .unwrap();
    let (_, headers, body) = send_to(app.clone(), request).await;
    assert_eq!(body, "POST");
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://console.example"
    );
    assert_eq!(headers["access-control-allow-credentials"], "true");
    assert_eq!(headers["access-control-expose-headers"], "grpc-status");
    // The listed origin keeps its answer beside the admitted one.
    let request = Request::get("/x")
        .header("origin", "https://a.example")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send_to(app, request).await;
    assert_eq!(headers["access-control-allow-origin"], "https://a.example");
}

// What the embedder admits is asked on every request: an origin it stops
// admitting loses CORS on the next call, one it starts admitting gains it.
#[tokio::test]
async fn admission_follows_the_embedder_per_request() {
    let admitted = Arc::new(Admitted(std::sync::Mutex::new(vec![
        "https://old.example".into()
    ])));
    let app = admitting(&[], admitted.clone());
    let get = |origin: &'static str| {
        Request::get("/x")
            .header("origin", origin)
            .body(Body::empty())
            .unwrap()
    };
    let (_, headers, _) = send_to(app.clone(), get("https://old.example")).await;
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://old.example"
    );
    *admitted.0.lock().unwrap() = vec!["https://new.example".into()];
    let (_, headers, _) = send_to(app.clone(), get("https://old.example")).await;
    assert!(!headers.contains_key("access-control-allow-origin"));
    let (_, headers, _) = send_to(app, get("https://new.example")).await;
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://new.example"
    );
}

// An origin neither listed nor admitted gets nothing, preflight included,
// and the policy with a hook and no listed origins is the credentialed one:
// never the `*` of the development default.
#[tokio::test]
async fn an_origin_neither_listed_nor_admitted_is_not_allowed() {
    let admitted = Arc::new(Admitted(std::sync::Mutex::new(Vec::new())));
    let app = admitting(&[], admitted);
    let (_, headers, _) = send_to(
        app.clone(),
        options(&[
            ("origin", "https://b.example"),
            ("access-control-request-method", "POST"),
        ]),
    )
    .await;
    assert!(!headers.contains_key("access-control-allow-origin"));
    assert_ne!(
        headers
            .get("access-control-allow-methods")
            .map(|v| v.as_bytes()),
        Some(&b"*"[..])
    );
    let request = Request::get("/x")
        .header("origin", "https://b.example")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send_to(app, request).await;
    assert!(!headers.contains_key("access-control-allow-origin"));
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

// The CORS layer owns the allow-origin decision: a route that reflects the
// request's `Origin` itself cannot admit an origin the policy refuses, since
// the layer adds credentials to every answer of the credentialed policy.
// Bug prevented: a credentialed response readable by any reflected origin.
#[tokio::test]
async fn a_route_cannot_admit_an_origin_the_policy_refuses() {
    let app = Router::new()
        .route(
            "/x",
            any(|headers: HeaderMap| async move {
                let origin = headers.get(ORIGIN).cloned().unwrap();
                ([(ACCESS_CONTROL_ALLOW_ORIGIN, origin)], "reflected")
            }),
        )
        .layer(CorsLayer::listed(
            vec![HeaderValue::from_static("https://a.example")],
            &[],
            None,
            None,
        ));
    let request = Request::get("/x")
        .header("origin", "https://b.example")
        .body(Body::empty())
        .unwrap();
    let (_, headers, body) = send_to(app, request).await;
    assert_eq!(body, "reflected");
    assert!(!headers.contains_key("access-control-allow-origin"));
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
