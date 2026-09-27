use super::*;

fn with_content_type(value: &'static str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(value),
    );
    headers
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
        assert!(is_grpc(&with_content_type(value)), "{value}");
    }
}

#[test]
fn grpc_web_media_types_are_grpc() {
    // gRPC PROTOCOL-WEB: binary and base64 text forms, each with a codec.
    for value in [
        "application/grpc-web",
        "application/grpc-web+proto",
        "application/grpc-web-text",
        "application/grpc-web-text+proto",
        "application/GRPC-WEB-TEXT",
    ] {
        assert!(is_grpc(&with_content_type(value)), "{value}");
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
        assert!(!is_grpc(&with_content_type(value)), "{value:?}");
    }
}

#[test]
fn a_request_without_a_content_type_is_not_grpc() {
    assert!(!is_grpc(&http::HeaderMap::new()));
}

#[test]
fn an_upstream_failure_is_a_trailers_only_grpc_status() {
    // A remote upstream that cannot be reached answers the gRPC client with a
    // status in the headers, not a broken connection.
    let status = tonic::Status::unavailable("connection refused");
    let response = failure(Box::new(status));
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/grpc");
    assert_eq!(response.headers()["grpc-status"], "14");
    assert_eq!(response.headers()["grpc-message"], "connection%20refused");
}
