use super::*;
use crate::upstream::GrpcProtocol;

/// No route answering a method beyond the standard ones.
const STANDARD: Routed<'static> = Routed {
    methods: &[],
    every: 0,
};

fn maintenance() -> Maintenance {
    Maintenance {
        exempt: vec![
            "/health/**".into(),
            "/.well-known/**".into(),
            "/metrics".into(),
        ],
        message: "Down".into(),
    }
}

#[test]
fn maintenance_exempts_exact_paths_and_subtrees() {
    let maintenance = maintenance();
    assert!(maintenance.exempts("/health"));
    assert!(maintenance.exempts("/health/ready"));
    assert!(maintenance.exempts("/.well-known/openid-configuration"));
    assert!(maintenance.exempts("/metrics"));
    assert!(!maintenance.exempts("/v1/auth/login"));
    assert!(!maintenance.exempts("/oauth2/token"));
    // An exact path covers nothing below it.
    assert!(!maintenance.exempts("/metrics/extra"));
}

#[test]
fn maintenance_subtree_stops_at_a_segment_boundary() {
    // `/health/**` is the `/health` subtree: a sibling path that only shares
    // the prefix (`/healthz`, `/health-admin`) stays behind the 503.
    let maintenance = maintenance();
    assert!(!maintenance.exempts("/healthz"));
    assert!(!maintenance.exempts("/health-admin/drop"));
    assert!(!maintenance.exempts("/.well-knownx"));
}

fn request(method: &str, path: &str) -> http::Request<()> {
    http::Request::builder()
        .method(method)
        .uri(path)
        .body(())
        .unwrap()
}

#[test]
fn a_scope_without_traffic_takes_the_default() {
    let scope = Scope::compile(
        None,
        &[Traffic::Transcoded, Traffic::Grpc],
        "shield",
        STANDARD,
    )
    .unwrap();
    assert!(scope.covers(Class::Transcoded));
    assert!(scope.covers(Class::Grpc));
    assert!(!scope.covers(Class::Endpoints));
    assert!(!scope.covers(Class::Fallback));
    assert!(!scope.narrows());
}

#[test]
fn all_traffic_covers_every_class() {
    let config = ScopeConfig::traffic([Traffic::All]);
    let scope = Scope::compile(Some(&config), &[], "shield", STANDARD).unwrap();
    for class in [
        Class::Transcoded,
        Class::Endpoints,
        Class::Verify,
        Class::Grpc,
        Class::Fallback,
    ] {
        assert!(scope.covers(class), "{class:?}");
    }
}

#[test]
fn a_scope_that_covers_no_traffic_is_an_error() {
    // An empty list would mount the guard nowhere; a typo, not a choice.
    let config = ScopeConfig::traffic([]);
    let err = Scope::compile(Some(&config), &[Traffic::Transcoded], "auth", STANDARD).unwrap_err();
    assert!(err.contains("auth.scope.traffic"), "{err}");
}

#[test]
fn a_relative_or_invalid_path_glob_is_an_error() {
    let relative = ScopeConfig {
        paths: vec!["v1/**".into()],
        ..ScopeConfig::default()
    };
    let err =
        Scope::compile(Some(&relative), &[Traffic::Transcoded], "shield", STANDARD).unwrap_err();
    assert!(err.contains("must start with '/'"), "{err}");

    let invalid = ScopeConfig {
        paths: vec!["/v1/[".into()],
        ..ScopeConfig::default()
    };
    let err =
        Scope::compile(Some(&invalid), &[Traffic::Transcoded], "shield", STANDARD).unwrap_err();
    assert!(err.contains("is invalid"), "{err}");
}

#[test]
fn an_invalid_method_is_an_error() {
    let config = ScopeConfig {
        methods: vec!["GE T".into()],
        ..ScopeConfig::default()
    };
    let err =
        Scope::compile(Some(&config), &[Traffic::Transcoded], "shield", STANDARD).unwrap_err();
    assert!(err.contains("is not a method"), "{err}");
}

fn methods(names: &[&str], traffic: Traffic) -> ScopeConfig {
    ScopeConfig {
        methods: names.iter().map(|&name| name.into()).collect(),
        ..ScopeConfig::traffic([traffic])
    }
}

#[test]
fn a_catch_all_method_is_an_error() {
    // `*` means every method in route policies; here it would match no
    // request and leave the guard covering nothing.
    let config = methods(&["*"], Traffic::Transcoded);
    let err = Scope::compile(Some(&config), &[], "auth", STANDARD).unwrap_err();
    assert!(err.contains("leave methods out"), "{err}");
}

#[test]
fn a_method_no_route_answers_is_an_error() {
    // A typo matches no request, and the guard would silently cover nothing.
    let config = methods(&["PSOT"], Traffic::Transcoded);
    let err = Scope::compile(Some(&config), &[], "shield", STANDARD).unwrap_err();
    assert!(err.contains("\"PSOT\""), "{err}");
}

#[test]
fn an_extension_method_a_route_answers_is_accepted() {
    let config = methods(&["PROPFIND"], Traffic::Transcoded);
    let routed = [Method::from_bytes(b"PROPFIND").unwrap()];
    let scope = Scope::compile(Some(&config), &[], "shield", Routed::new(&routed)).unwrap();
    assert!(scope.matches(&request("PROPFIND", "/dav")));
    // A transcoded route answering every method answers it too, but only
    // for a scope over transcoded traffic.
    let every = STANDARD.every(Class::Transcoded);
    let scope = Scope::compile(Some(&config), &[], "shield", every).unwrap();
    assert!(scope.matches(&request("PROPFIND", "/dav")));
    let endpoints = methods(&["PROPFIND"], Traffic::Endpoints);
    let err = Scope::compile(Some(&endpoints), &[], "shield", every).unwrap_err();
    assert!(err.contains("\"PROPFIND\""), "{err}");
}

#[test]
fn any_method_token_is_accepted_for_the_fallback() {
    // The fallback is the embedder's own service: which methods it answers
    // is not the proxy's to know.
    let config = methods(&["PROPFIND"], Traffic::Fallback);
    assert!(Scope::compile(Some(&config), &[], "shield", STANDARD).is_ok());
}

#[test]
fn paths_and_methods_narrow_the_requests_a_scope_matches() {
    let config = ScopeConfig {
        paths: vec!["/v1/orders/**".into()],
        methods: vec!["post".into()],
        ..ScopeConfig::default()
    };
    let scope = Scope::compile(Some(&config), &[Traffic::Transcoded], "shield", STANDARD).unwrap();
    assert!(scope.narrows());
    assert!(scope.matches(&request("POST", "/v1/orders/42")));
    // Methods compare as tokens, case aside.
    assert!(!scope.matches(&request("GET", "/v1/orders/42")));
    // `*` stays within a segment and `**` needs its own: `/v1/ordersx` is not
    // below `/v1/orders`.
    assert!(!scope.matches(&request("POST", "/v1/ordersx")));
    assert!(!scope.matches(&request("POST", "/v1/users/1")));
}

#[tokio::test]
async fn a_narrowed_guard_readies_the_branch_it_calls() {
    // An embedder's fallback may need `poll_ready` before `call` (a
    // concurrency limit panics without it); a request outside the scope's
    // paths reaches it through the plain branch.
    use tower::ServiceExt;
    let fallback = tower::limit::ConcurrencyLimit::new(
        tower::service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(axum::body::Body::empty()))
        }),
        1,
    );
    let config = ScopeConfig {
        paths: vec!["/guarded".into()],
        ..ScopeConfig::traffic([Traffic::Fallback])
    };
    let scoped = Scoped {
        layer: tower::layer::layer_fn(|inner| inner),
        scope: Scope::compile(Some(&config), &[], "maintenance", STANDARD).unwrap(),
    }
    .layer(fallback);
    for path in ["/other", "/guarded", "/other"] {
        let request = http::Request::get(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = scoped.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
}

#[test]
fn http_statuses_map_back_to_their_grpc_codes() {
    // The inverse of google/rpc/code.proto's HTTP mapping, so a code a guard
    // answers with over REST is the one a gRPC client gets.
    for (status, code) in [
        (400, tonic::Code::InvalidArgument),
        (401, tonic::Code::Unauthenticated),
        (403, tonic::Code::PermissionDenied),
        (404, tonic::Code::NotFound),
        (409, tonic::Code::Aborted),
        (429, tonic::Code::ResourceExhausted),
        (499, tonic::Code::Cancelled),
        (500, tonic::Code::Internal),
        (501, tonic::Code::Unimplemented),
        (502, tonic::Code::Internal),
        (503, tonic::Code::Unavailable),
        (504, tonic::Code::DeadlineExceeded),
        (302, tonic::Code::Unknown),
    ] {
        let status = StatusCode::from_u16(status).unwrap();
        assert_eq!(http_to_grpc_code(status), code, "{status}");
    }
}

#[tokio::test]
async fn a_rejection_carries_the_status_json_body() {
    let response = reject(tonic::Code::ResourceExhausted, "rate limit exceeded");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let rejection = response.extensions().get::<Rejection>().unwrap();
    assert_eq!(rejection.code, tonic::Code::ResourceExhausted);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "error": "RESOURCE_EXHAUSTED",
            "code": 8,
            "message": "rate limit exceeded",
            "details": [],
        })
    );
}

#[tokio::test]
async fn the_concurrency_limit_holds_a_slot_until_the_response_body_ends() {
    use tower::ServiceExt;
    let concurrency = Concurrency::build(&crate::config::ConcurrencyConfig {
        max_in_flight: 1,
        scope: None,
    })
    .unwrap();
    // `/stream` answers with a body that ends when its sender is dropped.
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, Infallible>>(1);
    let receiver = Arc::new(std::sync::Mutex::new(Some(receiver)));
    let app: Router = Router::new()
        .route(
            "/stream",
            axum::routing::get(move || {
                let receiver = receiver.lock().unwrap().take().unwrap();
                async move {
                    axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(
                        receiver,
                    ))
                }
            }),
        )
        .route("/x", axum::routing::get(|| async { "x" }))
        .layer(
            gate::Gate::layer(
                &Guards {
                    concurrency: Some((
                        concurrency,
                        Scope::compile(
                            None,
                            &[Traffic::Transcoded],
                            "concurrency",
                            Routed::new(&[]),
                        )
                        .unwrap(),
                    )),
                    ..Guards::default()
                },
                Class::Transcoded,
            )
            .unwrap(),
        );
    let get = |path: &str| {
        http::Request::get(path)
            .body(axum::body::Body::empty())
            .unwrap()
    };

    let streaming = app.clone().oneshot(get("/stream")).await.unwrap();
    assert_eq!(streaming.status(), StatusCode::OK);

    // The stream's headers are sent, its body is not: the slot is still taken.
    let shed = app.clone().oneshot(get("/x")).await.unwrap();
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(shed.headers()["retry-after"], "1");
    let rejection = shed.extensions().get::<Rejection>().unwrap();
    assert_eq!(rejection.code, tonic::Code::Unavailable);

    // Ending the body frees the slot.
    sender
        .send(Ok(bytes::Bytes::from_static(b"tail")))
        .await
        .unwrap();
    drop(sender);
    let body = axum::body::to_bytes(streaming.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"tail");
    let after = app.oneshot(get("/x")).await.unwrap();
    assert_eq!(after.status(), StatusCode::OK);
}

#[test]
fn a_concurrency_limit_of_zero_is_an_error() {
    let err = Concurrency::build(&crate::config::ConcurrencyConfig {
        max_in_flight: 0,
        scope: None,
    })
    .unwrap_err();
    assert!(err.contains("max_in_flight"), "{err}");
}

/// The gRPC-path service answering every request with `response`.
fn answering(response: fn() -> Response, protocol: GrpcProtocol) -> GrpcRejections {
    GrpcRejections {
        inner: BoxedService::new(tower::service_fn(move |_: Request| async move {
            Ok::<_, Infallible>(response())
        })),
        protocol,
    }
}

async fn call(mut service: GrpcRejections) -> Response {
    use tower::ServiceExt;
    let request = Request::new(axum::body::Body::empty());
    service.ready().await.unwrap().call(request).await.unwrap()
}

#[tokio::test]
async fn a_rejection_reaches_grpc_as_a_trailers_only_status_with_its_headers() {
    let service = answering(
        || {
            let mut response = reject(tonic::Code::ResourceExhausted, "rate limit exceeded");
            response
                .headers_mut()
                .insert("retry-after", http::HeaderValue::from_static("7"));
            response
        },
        GrpcProtocol::Grpc,
    );
    let response = call(service).await;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(headers["content-type"], "application/grpc");
    assert_eq!(headers["grpc-status"], "8");
    assert_eq!(headers["grpc-message"], "rate%20limit%20exceeded");
    assert_eq!(headers["retry-after"], "7");
    // The JSON body's length does not describe the empty gRPC answer.
    assert!(!headers.contains_key("content-length"));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn a_rejection_on_grpc_web_takes_the_grpc_web_content_type() {
    let service = answering(
        || reject(tonic::Code::Unauthenticated, "authentication required"),
        GrpcProtocol::WebText,
    );
    let response = call(service).await;
    let headers = response.headers();
    assert_eq!(headers["content-type"], "application/grpc-web-text+proto");
    assert_eq!(headers["grpc-status"], "16");
}

#[tokio::test]
async fn an_unmarked_http_answer_maps_its_status() {
    // A guard answer the proxy did not write (an embedder's decider body)
    // still reaches a gRPC client as a status.
    let service = answering(
        || (StatusCode::FORBIDDEN, "nope").into_response(),
        GrpcProtocol::Grpc,
    );
    let response = call(service).await;
    assert_eq!(response.headers()["grpc-status"], "7");
}

#[tokio::test]
async fn an_upstream_grpc_answer_passes_unchanged() {
    let service = answering(
        || {
            let mut response = Response::new(axum::body::Body::from("frame"));
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/grpc"),
            );
            response
        },
        GrpcProtocol::Grpc,
    );
    let response = call(service).await;
    assert!(!response.headers().contains_key("grpc-status"));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"frame");
}
