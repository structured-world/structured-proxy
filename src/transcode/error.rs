//! gRPC → HTTP error mapping.
//!
//! Converts `tonic::Status` to appropriate HTTP status codes and JSON error bodies
//! following the gRPC-HTTP status code mapping from the gRPC specification.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Map a gRPC status code to the corresponding HTTP status code.
///
/// Based on <https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md>
pub fn grpc_to_http_status(code: tonic::Code) -> StatusCode {
    match code {
        tonic::Code::Ok => StatusCode::OK,
        tonic::Code::Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST),
        tonic::Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::OutOfRange => StatusCode::BAD_REQUEST,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
    }
}

/// Convert a `tonic::Status` into an axum HTTP response with JSON error body.
pub fn status_to_response(status: tonic::Status) -> Response {
    let http_status = grpc_to_http_status(status.code());
    let body = serde_json::json!({
        "error": grpc_code_name(status.code()),
        "message": status.message(),
        "code": status.code() as i32,
    });
    (http_status, Json(body)).into_response()
}

/// Human-readable gRPC code name for JSON error responses.
fn grpc_code_name(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "OK",
        tonic::Code::Cancelled => "CANCELLED",
        tonic::Code::Unknown => "UNKNOWN",
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
        tonic::Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        tonic::Code::NotFound => "NOT_FOUND",
        tonic::Code::AlreadyExists => "ALREADY_EXISTS",
        tonic::Code::PermissionDenied => "PERMISSION_DENIED",
        tonic::Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
        tonic::Code::Aborted => "ABORTED",
        tonic::Code::OutOfRange => "OUT_OF_RANGE",
        tonic::Code::Unimplemented => "UNIMPLEMENTED",
        tonic::Code::Internal => "INTERNAL",
        tonic::Code::Unavailable => "UNAVAILABLE",
        tonic::Code::DataLoss => "DATA_LOSS",
        tonic::Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let response = status_to_response(status);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
