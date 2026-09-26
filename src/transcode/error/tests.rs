use super::*;

use serde_json::json;
use tonic_types::{BadRequest, DebugInfo, ErrorDetail, ErrorInfo, FieldViolation, StatusExt};

use crate::config::ErrorDetailsRouteConfig;

#[test]
fn test_grpc_to_http_mapping() {
    assert_eq!(grpc_to_http_status(tonic::Code::Ok), StatusCode::OK);
    assert_eq!(
        grpc_to_http_status(tonic::Code::InvalidArgument),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::NotFound),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::AlreadyExists),
        StatusCode::CONFLICT
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::PermissionDenied),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::Unauthenticated),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::ResourceExhausted),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::Unimplemented),
        StatusCode::NOT_IMPLEMENTED
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::Internal),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::Unavailable),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        grpc_to_http_status(tonic::Code::DeadlineExceeded),
        StatusCode::GATEWAY_TIMEOUT
    );
}

#[test]
fn test_grpc_code_name() {
    assert_eq!(grpc_code_name(tonic::Code::Ok), "OK");
    assert_eq!(grpc_code_name(tonic::Code::NotFound), "NOT_FOUND");
    assert_eq!(
        grpc_code_name(tonic::Code::Unauthenticated),
        "UNAUTHENTICATED"
    );
}

#[test]
fn test_status_to_response() {
    let status = tonic::Status::not_found("user not found");
    let response = status_to_response(&status, None);
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- fixtures -------------------------------------------------------------

/// A renderer over an empty product pool: only the canonical google.rpc
/// descriptors resolve.
fn canonical_only() -> StatusDetails {
    StatusDetails::new(&DescriptorPool::new())
}

/// An `INVALID_ARGUMENT` status carrying `ErrorInfo` + `BadRequest`, the shape
/// the issue's acceptance criterion names.
fn rich_status() -> tonic::Status {
    tonic::Status::with_error_details_vec(
        tonic::Code::InvalidArgument,
        "invalid email",
        [
            ErrorDetail::from(ErrorInfo::new(
                "EMAIL_TAKEN",
                "identity.example.com",
                [("email".to_string(), "a@b.c".to_string())]
                    .into_iter()
                    .collect::<std::collections::HashMap<_, _>>(),
            )),
            ErrorDetail::from(BadRequest::new(vec![FieldViolation::new(
                "email",
                "already registered",
            )])),
        ],
    )
}

/// A status whose trailer holds the given raw `(type_url, value)` details,
/// for types tonic-types has no builder for.
fn status_with_raw_details(details: &[(&str, Vec<u8>)]) -> tonic::Status {
    let mut rpc = tonic_types::pb::Status {
        code: tonic::Code::FailedPrecondition as i32,
        message: "raw".into(),
        ..Default::default()
    };
    for (type_url, value) in details {
        rpc.details.push(Default::default());
        let any = rpc.details.last_mut().expect("just pushed");
        any.type_url = (*type_url).to_string();
        any.value = value.clone();
    }
    tonic::Status::with_details(
        tonic::Code::FailedPrecondition,
        "raw",
        bytes::Bytes::from(rpc.encode_to_vec()),
    )
}

/// A product pool compiled from one in-memory `.proto` source.
fn product_pool(name: &str, source: &str) -> DescriptorPool {
    struct OneFile {
        name: String,
        source: String,
    }
    impl protox::file::FileResolver for OneFile {
        fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
            if name == self.name {
                protox::file::File::from_source(name, &self.source)
            } else {
                Err(protox::Error::file_not_found(name))
            }
        }
    }
    protox::Compiler::with_file_resolver(OneFile {
        name: name.to_owned(),
        source: source.to_owned(),
    })
    .open_file(name)
    .expect("test proto compiles")
    .descriptor_pool()
}

// --- body shape -------------------------------------------------------------

#[test]
fn body_without_renderer_keeps_the_details_key_absent() {
    // A route with details switched off must answer with exactly the
    // pre-existing shape: no `details` key at all, not an empty array, so the
    // off switch is observable and nothing about the upstream leaks.
    let body = error_body(&rich_status(), None);
    assert_eq!(
        body,
        json!({"error": "INVALID_ARGUMENT", "message": "invalid email", "code": 3})
    );
}

#[test]
fn body_without_trailer_has_empty_details() {
    // No `grpc-status-details-bin` from the upstream: the enabled shape still
    // carries `details`, as an empty array, so clients never branch on presence.
    let status = tonic::Status::not_found("user not found");
    let body = error_body(&status, Some(&canonical_only()));
    assert_eq!(
        body,
        json!({"error": "NOT_FOUND", "message": "user not found", "code": 5, "details": []})
    );
}

#[test]
fn error_info_and_bad_request_render_as_canonical_json() {
    // The two most common details come out in the ProtoJSON form of `Any`:
    // `@type` plus the message fields in lowerCamelCase, unset fields omitted.
    let body = error_body(&rich_status(), Some(&canonical_only()));
    assert_eq!(
        body,
        json!({
            "error": "INVALID_ARGUMENT",
            "message": "invalid email",
            "code": 3,
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "EMAIL_TAKEN",
                    "domain": "identity.example.com",
                    "metadata": {"email": "a@b.c"}
                },
                {
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": [
                        {"field": "email", "description": "already registered"}
                    ]
                }
            ]
        })
    );
}

#[test]
fn status_to_response_keeps_http_mapping_with_details() {
    // Rendering details must not change the HTTP status chosen by the
    // gRPC → HTTP mapping.
    let resp = status_to_response(&rich_status(), Some(&canonical_only()));
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn debug_info_is_never_rendered() {
    // DebugInfo carries stack traces for operators; it is dropped while the
    // details around it still render, in their original order.
    let status = tonic::Status::with_error_details_vec(
        tonic::Code::Internal,
        "boom",
        [
            ErrorDetail::from(ErrorInfo::new(
                "DB_DOWN",
                "store.example.com",
                std::collections::HashMap::new(),
            )),
            ErrorDetail::from(DebugInfo::new(
                vec!["at store::write (store.rs:42)".to_string()],
                "connection refused to 10.0.0.7:5432",
            )),
        ],
    );
    let details = canonical_only().render(&status);
    assert_eq!(
        details,
        vec![json!({
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "DB_DOWN",
            "domain": "store.example.com"
        })]
    );
    let text = serde_json::to_string(&details).unwrap();
    assert!(!text.contains("store.rs:42") && !text.contains("10.0.0.7"));
}

#[test]
fn debug_info_is_dropped_under_any_type_url_prefix() {
    // The type is identified by the last URL segment, so a non-default prefix
    // cannot smuggle DebugInfo past the filter.
    let debug = tonic_types::pb::DebugInfo {
        stack_entries: vec!["secret frame".into()],
        detail: "secret".into(),
    };
    let status = status_with_raw_details(&[(
        "example.com/types/google.rpc.DebugInfo",
        debug.encode_to_vec(),
    )]);
    assert!(canonical_only().render(&status).is_empty());
}

#[test]
fn unknown_detail_type_keeps_type_and_base64_value() {
    // A type neither pool knows has no ProtoJSON form; it is kept in the
    // opaque-detail extension (original type URL, base64 of the original
    // bytes) instead of being dropped.
    let status = status_with_raw_details(&[(
        "type.googleapis.com/acme.v1.Unknown",
        vec![0x08, 0x96, 0x01],
    )]);
    assert_eq!(
        canonical_only().render(&status),
        vec![json!({"@type": "type.googleapis.com/acme.v1.Unknown", "value": "CJYB"})]
    );
}

#[test]
fn undecodable_known_detail_falls_back_to_base64() {
    // Bytes that do not decode as the named type (here a truncated
    // length-delimited field) go to the opaque-detail extension rather than
    // vanish.
    let status = status_with_raw_details(&[(
        "type.googleapis.com/google.rpc.ErrorInfo",
        vec![0x0a, 0x05, b'a'],
    )]);
    assert_eq!(
        canonical_only().render(&status),
        vec![json!({"@type": "type.googleapis.com/google.rpc.ErrorInfo", "value": "CgVh"})]
    );
}

#[test]
fn well_known_type_detail_goes_under_value() {
    // A well-known type with a special JSON representation (Duration is
    // "1.500s") sits under `value`, which is ProtoJSON for `Any`; unlike the
    // opaque extension, `value` here holds that JSON, not base64 bytes.
    let duration = prost_reflect::prost_types::Duration {
        seconds: 1,
        nanos: 500_000_000,
    };
    let status = status_with_raw_details(&[(
        "type.googleapis.com/google.protobuf.Duration",
        duration.encode_to_vec(),
    )]);
    assert_eq!(
        canonical_only().render(&status),
        vec![json!({"@type": "type.googleapis.com/google.protobuf.Duration", "value": "1.500s"})]
    );
}

#[test]
fn product_defined_detail_type_renders_its_fields() {
    // A service's own detail message resolves through the product descriptors.
    let pool = product_pool(
        "acme.proto",
        "syntax = \"proto3\"; package acme.v1; message QuotaTicket { string ticket = 1; int64 wait_ms = 2; }",
    );
    let ticket = pool.get_message_by_name("acme.v1.QuotaTicket").unwrap();
    let mut msg = DynamicMessage::new(ticket);
    msg.set_field_by_name("ticket", prost_reflect::Value::String("T-1".into()));
    msg.set_field_by_name("wait_ms", prost_reflect::Value::I64(1500));
    let status = status_with_raw_details(&[(
        "type.googleapis.com/acme.v1.QuotaTicket",
        msg.encode_to_vec(),
    )]);
    assert_eq!(
        StatusDetails::new(&pool).render(&status),
        vec![json!({
            "@type": "type.googleapis.com/acme.v1.QuotaTicket",
            "ticket": "T-1",
            "waitMs": "1500"
        })]
    );
}

#[test]
fn product_revision_of_a_canonical_type_wins() {
    // When the product ships its own google.rpc revision, that definition is
    // used: a field it adds (number 9 here) renders by its name instead of
    // being lost as an unknown field of the canonical revision.
    let pool = product_pool(
        "google/rpc/error_details.proto",
        "syntax = \"proto3\"; package google.rpc; message ErrorInfo { string reason = 1; string domain = 2; string tenant = 9; }",
    );
    let desc = pool.get_message_by_name("google.rpc.ErrorInfo").unwrap();
    let mut msg = DynamicMessage::new(desc);
    msg.set_field_by_name("reason", prost_reflect::Value::String("R".into()));
    msg.set_field_by_name("tenant", prost_reflect::Value::String("t-7".into()));
    let status = status_with_raw_details(&[(
        "type.googleapis.com/google.rpc.ErrorInfo",
        msg.encode_to_vec(),
    )]);
    assert_eq!(
        StatusDetails::new(&pool).render(&status),
        vec![json!({
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "R",
            "tenant": "t-7"
        })]
    );
}

#[test]
fn malformed_trailer_renders_no_details() {
    // A trailer that is not a google.rpc.Status cannot be split into
    // details; the body still answers with the status code and message.
    let status = tonic::Status::with_details(
        tonic::Code::Internal,
        "boom",
        bytes::Bytes::from_static(&[0x1a, 0xff]),
    );
    assert_eq!(
        error_body(&status, Some(&canonical_only())),
        json!({"error": "INTERNAL", "message": "boom", "code": 13, "details": []})
    );
}

// --- policy -----------------------------------------------------------------

fn policy(enabled: bool, routes: &[(&str, bool)]) -> Result<ErrorDetailsPolicy, String> {
    let cfg = ErrorDetailsConfig {
        enabled,
        routes: routes
            .iter()
            .map(|(pattern, enabled)| ErrorDetailsRouteConfig {
                pattern: (*pattern).to_string(),
                enabled: *enabled,
            })
            .collect(),
    };
    ErrorDetailsPolicy::from_config(&cfg)
}

#[test]
fn policy_defaults_to_enabled_everywhere() {
    let p = ErrorDetailsPolicy::default();
    assert!(p.enabled_for("/v1/users/{id}"));
    assert!(p.enabled_for("/anything"));
}

#[test]
fn policy_global_off_disables_every_route() {
    let p = policy(false, &[]).unwrap();
    assert!(!p.enabled_for("/v1/users/{id}"));
}

#[test]
fn policy_route_rule_overrides_global_in_both_directions() {
    // Global off with a sub-route switched back on, and a nested route inside
    // that sub-route switched off again by an earlier rule.
    let p = policy(
        false,
        &[("/v1/public/internal/*", false), ("/v1/public/**", true)],
    )
    .unwrap();
    assert!(p.enabled_for("/v1/public/items/{id}"));
    assert!(!p.enabled_for("/v1/public/internal/{id}"));
    assert!(!p.enabled_for("/v1/admin/items"));
}

#[test]
fn policy_first_matching_rule_wins() {
    // Order is the contract: a broad rule listed first shadows a narrower
    // one listed after it.
    let p = policy(true, &[("/v1/**", false), ("/v1/public/**", true)]).unwrap();
    assert!(!p.enabled_for("/v1/public/items"));
}

#[test]
fn policy_star_matches_one_parameter_segment_only() {
    // A path parameter is one segment: `*` matches `{id}` but not a deeper
    // route under it, while `**` also matches an axum catch-all.
    let p = policy(true, &[("/v1/users/*", false), ("/v1/files/**", false)]).unwrap();
    assert!(!p.enabled_for("/v1/users/{id}"));
    assert!(p.enabled_for("/v1/users/{id}/keys"));
    assert!(!p.enabled_for("/v1/files/{*path}"));
}

#[test]
fn policy_rejects_relative_pattern() {
    // `v1/admin/**` can never match a route path; a silent no-op would leave
    // details on where the operator meant to turn them off.
    let err = policy(true, &[("v1/admin/**", false)]).unwrap_err();
    assert!(err.contains("must start with '/'"), "{err}");
}

#[test]
fn policy_rejects_invalid_glob() {
    let err = policy(true, &[("/v1/[admin", false)]).unwrap_err();
    assert!(err.contains("invalid glob pattern"), "{err}");
}
