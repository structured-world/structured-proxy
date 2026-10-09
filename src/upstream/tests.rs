use super::*;

fn with_content_type(value: &'static str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(value),
    );
    headers
}

fn protocol(value: &'static str) -> Option<GrpcProtocol> {
    grpc_protocol(&with_content_type(value))
}

#[test]
fn grpc_media_types_are_grpc() {
    // gRPC PROTOCOL-HTTP2: `application/grpc` with an optional `+codec`.
    for value in [
        "application/grpc",
        "application/grpc+proto",
        "application/grpc+json",
        "Application/GRPC",
        "application/grpc; charset=utf-8",
        " application/grpc ",
    ] {
        assert_eq!(protocol(value), Some(GrpcProtocol::Grpc), "{value}");
    }
}

#[test]
fn grpc_web_media_types_are_grpc_web() {
    // gRPC PROTOCOL-WEB: the binary and the base64 text form, each with a
    // codec, told apart so a failure answers in the same one.
    for value in [
        "application/grpc-web",
        "application/grpc-web+proto",
        "APPLICATION/GRPC-WEB",
    ] {
        assert_eq!(protocol(value), Some(GrpcProtocol::Web), "{value}");
    }
    for value in [
        "application/grpc-web-text",
        "application/grpc-web-text+proto",
        "application/GRPC-WEB-TEXT",
    ] {
        assert_eq!(protocol(value), Some(GrpcProtocol::WebText), "{value}");
    }
}

#[test]
fn other_media_types_are_not_grpc() {
    // A type that only shares the prefix is someone else's: it must reach the
    // proxy's routes, never the upstream.
    for value in [
        "application/json",
        "application/grpcx",
        "application/grpc-webx",
        "application/grpc-web-textual",
        "application/grpc-json",
        "application/gr",
        "text/grpc",
        "",
    ] {
        assert_eq!(protocol(value), None, "{value:?}");
    }
}

#[test]
fn a_request_without_a_content_type_is_not_grpc() {
    assert_eq!(grpc_protocol(&http::HeaderMap::new()), None);
}

fn preflight(headers: &[(&'static str, &'static str)]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in headers {
        map.append(*name, http::HeaderValue::from_static(value));
    }
    map
}

#[test]
fn a_preflight_announcing_x_grpc_web_is_a_grpc_web_preflight() {
    for requested in [
        "x-grpc-web",
        "content-type,x-grpc-web,x-user-agent",
        "Content-Type, X-Grpc-Web",
    ] {
        let headers = preflight(&[
            ("origin", "https://app.example"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", requested),
        ]);
        assert!(
            is_grpc_web_preflight(&http::Method::OPTIONS, &headers),
            "{requested}"
        );
    }
    // Split over several header lines, as a list may be.
    let headers = preflight(&[
        ("origin", "https://app.example"),
        ("access-control-request-method", "POST"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-headers", "x-grpc-web"),
    ]);
    assert!(is_grpc_web_preflight(&http::Method::OPTIONS, &headers));
}

#[test]
fn an_options_without_a_request_method_is_no_preflight() {
    // A CORS-preflight request names the method it asks for (Fetch §3.2.2):
    // without it, an OPTIONS announcing `x-grpc-web` is an ordinary request,
    // the routes', never a call for the upstream.
    let headers = preflight(&[
        ("origin", "https://app.example"),
        ("access-control-request-headers", "x-grpc-web"),
    ]);
    assert!(!is_grpc_web_preflight(&http::Method::OPTIONS, &headers));
}

#[test]
fn other_requests_are_not_grpc_web_preflights() {
    let announcing = preflight(&[
        ("origin", "https://app.example"),
        ("access-control-request-method", "POST"),
        ("access-control-request-headers", "x-grpc-web"),
    ]);
    // Not an OPTIONS request.
    assert!(!is_grpc_web_preflight(&http::Method::POST, &announcing));
    // No Origin: not a CORS request at all.
    let no_origin = preflight(&[
        ("access-control-request-method", "POST"),
        ("access-control-request-headers", "x-grpc-web"),
    ]);
    assert!(!is_grpc_web_preflight(&http::Method::OPTIONS, &no_origin));
    // A REST preflight, or a header that only shares the prefix.
    for requested in ["content-type,authorization", "x-grpc-webx", "x-grpc"] {
        let headers = preflight(&[
            ("origin", "https://app.example"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", requested),
        ]);
        assert!(
            !is_grpc_web_preflight(&http::Method::OPTIONS, &headers),
            "{requested}"
        );
    }
}

#[test]
fn an_upstream_failure_is_a_trailers_only_grpc_status() {
    // A remote upstream that cannot be reached answers the gRPC client with a
    // status in the headers, not a broken connection.
    let status = tonic::Status::unavailable("connection refused");
    let response = failure(Box::new(status), GrpcProtocol::Grpc);
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/grpc");
    assert_eq!(response.headers()["grpc-status"], "14");
    assert_eq!(response.headers()["grpc-message"], "connection%20refused");
}

#[test]
fn an_upstream_failure_keeps_the_grpc_web_protocol() {
    for (protocol, content_type) in [
        (GrpcProtocol::Web, "application/grpc-web+proto"),
        (GrpcProtocol::WebText, "application/grpc-web-text+proto"),
    ] {
        let status = tonic::Status::unavailable("down");
        let response = failure(Box::new(status), protocol);
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(response.headers()["grpc-status"], "14");
    }
}
