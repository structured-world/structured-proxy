//! External authorization via the Envoy ext_authz gRPC contract.
//!
//! Before a transcoded request is forwarded upstream, the proxy calls the
//! configured ext_authz server's `envoy.service.auth.v3.Authorization/Check`
//! with the request's HTTP attributes. An OK status allows the request (and may
//! inject response headers); anything else denies it. This is the same contract
//! OPA's Envoy plugin and any ext_authz server implement.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header::{HeaderName, HeaderValue, HOST};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tonic::transport::Channel;

use envoy_types::pb::envoy::config::core::v3::HeaderValueOption;
use envoy_types::pb::envoy::service::auth::v3::{
    attribute_context::{HttpRequest, Request as AttrRequest},
    authorization_client::AuthorizationClient,
    check_response::HttpResponse as EnvoyHttpResponse,
    AttributeContext, CheckRequest, CheckResponse, DeniedHttpResponse,
};

use crate::config::AuthzConfig;
use crate::guard::{http_to_grpc_code, mark_rejection, reject};

/// A configured ext_authz client.
pub struct Authz {
    channel: Channel,
    timeout: Duration,
    failure_mode_allow: bool,
}

impl Authz {
    /// Build the authz client, or `None` when authz is disabled.
    ///
    /// # Errors
    /// Returns an error when `endpoint` is not a valid gRPC URL.
    pub fn build(config: &AuthzConfig) -> Result<Option<Arc<Self>>, String> {
        if !config.enabled {
            return Ok(None);
        }
        let channel = Channel::from_shared(config.endpoint.clone())
            .map_err(|e| format!("invalid authz endpoint: {e}"))?
            .connect_lazy();
        Ok(Some(Arc::new(Self {
            channel,
            timeout: Duration::from_millis(config.timeout_ms),
            failure_mode_allow: config.failure_mode_allow,
        })))
    }
}

/// Axum middleware gating proxied requests through the ext_authz server.
pub async fn middleware(
    State(authz): State<Arc<Authz>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let check = build_check_request(request.headers(), request.method().as_str(), request.uri());
    let mut client = AuthorizationClient::new(authz.channel.clone());
    let mut grpc_req = tonic::Request::new(check);
    grpc_req.set_timeout(authz.timeout);

    match client.check(grpc_req).await {
        Ok(resp) => match evaluate(resp.into_inner()) {
            Decision::Allow(headers) => {
                apply_headers(request.headers_mut(), headers);
                next.run(request).await
            }
            Decision::Deny(response) => response,
        },
        // The authz call itself failed (unreachable / timeout): fail open or
        // closed per config. Fail-closed is a 503, distinct from a policy 403.
        Err(status) if authz.failure_mode_allow => {
            tracing::warn!(error = %status, "authz check failed; failing open");
            next.run(request).await
        }
        Err(status) => {
            tracing::warn!(error = %status, "authz check failed; failing closed");
            reject(
                tonic::Code::Unavailable,
                "authorization service unavailable",
            )
        }
    }
}

/// The result of an authorization check.
enum Decision {
    /// Allowed; add these headers (from the OK response) to the upstream request.
    Allow(Vec<(HeaderName, HeaderValue)>),
    /// Denied; return this response to the client.
    Deny(Response),
}

/// Build a `CheckRequest` from the incoming request's HTTP attributes.
fn build_check_request(headers: &HeaderMap, method: &str, uri: &Uri) -> CheckRequest {
    let mut header_map = std::collections::HashMap::new();
    for (name, value) in headers {
        if let Ok(v) = value.to_str() {
            header_map.insert(name.as_str().to_string(), v.to_string());
        }
    }
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();

    let http = HttpRequest {
        method: method.to_string(),
        path: uri.path().to_string(),
        query: uri.query().unwrap_or_default().to_string(),
        host,
        scheme,
        headers: header_map,
        ..Default::default()
    };
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(AttrRequest {
                http: Some(http),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

/// Interpret a `CheckResponse`: an OK `rpc.Status` (code 0) allows the request.
fn evaluate(resp: CheckResponse) -> Decision {
    let allowed = resp.status.as_ref().map(|s| s.code == 0).unwrap_or(false);
    if allowed {
        let headers = match resp.http_response {
            Some(EnvoyHttpResponse::OkResponse(ok)) => {
                ok.headers.into_iter().filter_map(header_kv).collect()
            }
            _ => Vec::new(),
        };
        Decision::Allow(headers)
    } else {
        let response = match resp.http_response {
            Some(EnvoyHttpResponse::DeniedResponse(denied))
            | Some(EnvoyHttpResponse::ErrorResponse(denied)) => {
                let response = denied_to_response(denied);
                // A gRPC caller gets the Check's own status, the decision in
                // gRPC terms; a Check that sets no code maps the HTTP one.
                let code = match resp.status.as_ref().map(|s| s.code) {
                    Some(code) if code != 0 => tonic::Code::from_i32(code),
                    _ => http_to_grpc_code(response.status()),
                };
                let message = resp
                    .status
                    .map(|s| s.message)
                    .filter(|m| !m.is_empty())
                    .unwrap_or_else(|| DENIED.to_string());
                mark_rejection(response, code, message)
            }
            _ => reject(tonic::Code::PermissionDenied, DENIED),
        };
        Decision::Deny(response)
    }
}

/// The message of a denial that carries none of its own.
const DENIED: &str = "forbidden by authorization policy";

/// Append the headers an allowed check adds to the upstream request,
/// preserving multiple values for the same name (e.g. several `Set-Cookie`)
/// instead of overwriting all but the last. A client-address header is not
/// applied: the proxy sets those from the resolved address alone.
fn apply_headers(dst: &mut HeaderMap, headers: Vec<(HeaderName, HeaderValue)>) {
    for (name, value) in headers {
        if crate::client_address::owns(name.as_str()) {
            tracing::warn!(header = %name, "ext_authz header ignored: the proxy sets it from the client address");
            continue;
        }
        dst.append(name, value);
    }
}

/// Convert an Envoy `HeaderValueOption` into an axum header pair.
fn header_kv(opt: HeaderValueOption) -> Option<(HeaderName, HeaderValue)> {
    let header = opt.header?;
    let name = HeaderName::try_from(header.key).ok()?;
    let value = HeaderValue::try_from(header.value).ok()?;
    Some((name, value))
}

/// Render a denied ext_authz response as an HTTP response (default 403).
fn denied_to_response(denied: DeniedHttpResponse) -> Response {
    // Envoy's HttpStatus.code carries the numeric HTTP status directly.
    let status = denied
        .status
        .and_then(|s| u16::try_from(s.code).ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::FORBIDDEN);
    // The denial's own headers go to the client as they are.
    let mut headers = HeaderMap::new();
    for (name, value) in denied.headers.into_iter().filter_map(header_kv) {
        headers.append(name, value);
    }
    (status, headers, denied.body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::config::core::v3::HeaderValue as EnvoyHeaderValue;
    use envoy_types::pb::envoy::r#type::v3::HttpStatus;
    use envoy_types::pb::envoy::service::auth::v3::{CheckResponse, OkHttpResponse};
    use envoy_types::pb::google::rpc::Status as RpcStatus;

    fn hvo(key: &str, value: &str) -> HeaderValueOption {
        HeaderValueOption {
            header: Some(EnvoyHeaderValue {
                key: key.to_string(),
                value: value.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn build_check_request_maps_http_attributes() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("api.example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-forwarded-user", HeaderValue::from_static("alice"));
        let uri: Uri = "/v1/things?page=2".parse().unwrap();

        let check = build_check_request(&headers, "POST", &uri);
        let http = check.attributes.unwrap().request.unwrap().http.unwrap();
        assert_eq!(http.method, "POST");
        assert_eq!(http.path, "/v1/things");
        assert_eq!(http.query, "page=2");
        assert_eq!(http.host, "api.example.com");
        assert_eq!(http.scheme, "https");
        // The verified identity header is forwarded for the policy to use.
        assert_eq!(http.headers.get("x-forwarded-user").unwrap(), "alice");
    }

    #[test]
    fn scheme_defaults_to_http() {
        let headers = HeaderMap::new();
        let uri: Uri = "/x".parse().unwrap();
        let check = build_check_request(&headers, "GET", &uri);
        let http = check.attributes.unwrap().request.unwrap().http.unwrap();
        assert_eq!(http.scheme, "http");
    }

    #[test]
    fn ok_status_allows_and_collects_headers() {
        let resp = CheckResponse {
            status: Some(RpcStatus {
                code: 0,
                ..Default::default()
            }),
            http_response: Some(EnvoyHttpResponse::OkResponse(OkHttpResponse {
                headers: vec![hvo("x-authz-decision", "allow")],
                ..Default::default()
            })),
            ..Default::default()
        };
        match evaluate(resp) {
            Decision::Allow(headers) => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].0.as_str(), "x-authz-decision");
                assert_eq!(headers[0].1, "allow");
            }
            Decision::Deny(_) => panic!("expected allow"),
        }
    }

    #[test]
    fn apply_headers_preserves_duplicate_names() {
        // Multiple authz headers with the same name (e.g. Set-Cookie) must all
        // survive, not collapse to the last one.
        let mut dst = HeaderMap::new();
        apply_headers(
            &mut dst,
            vec![
                (
                    HeaderName::from_static("set-cookie"),
                    HeaderValue::from_static("a=1"),
                ),
                (
                    HeaderName::from_static("set-cookie"),
                    HeaderValue::from_static("b=2"),
                ),
            ],
        );
        let values: Vec<_> = dst
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["a=1", "b=2"]);
    }

    #[test]
    fn an_allowed_check_cannot_set_the_client_address_headers() {
        // The proxy writes these from the resolved client address: an
        // ext_authz server's OK headers must not replace it upstream.
        let mut dst = HeaderMap::new();
        dst.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        apply_headers(
            &mut dst,
            [
                ("x-forwarded-for", "198.51.100.1"),
                ("X-Real-IP", "198.51.100.2"),
                ("forwarded", "for=198.51.100.3"),
                ("x-authz-decision", "allow"),
            ]
            .into_iter()
            .map(|(n, v)| {
                (
                    HeaderName::from_bytes(n.as_bytes()).unwrap(),
                    HeaderValue::from_static(v),
                )
            })
            .collect(),
        );
        assert_eq!(
            dst.get_all("x-forwarded-for").iter().collect::<Vec<_>>(),
            ["203.0.113.7"]
        );
        assert!(dst.get("x-real-ip").is_none());
        assert!(dst.get("forwarded").is_none());
        assert_eq!(dst["x-authz-decision"], "allow");
    }

    #[test]
    fn missing_status_denies() {
        // An empty CheckResponse (no OK status) must deny, never leak through.
        let resp = CheckResponse::default();
        match evaluate(resp) {
            Decision::Deny(response) => assert_eq!(response.status(), StatusCode::FORBIDDEN),
            Decision::Allow(_) => panic!("expected deny"),
        }
    }

    #[test]
    fn denied_response_uses_its_status() {
        let resp = CheckResponse {
            status: Some(RpcStatus {
                code: 7, // PermissionDenied
                ..Default::default()
            }),
            http_response: Some(EnvoyHttpResponse::DeniedResponse(DeniedHttpResponse {
                status: Some(HttpStatus { code: 401 }),
                body: "nope".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        match evaluate(resp) {
            Decision::Deny(response) => assert_eq!(response.status(), StatusCode::UNAUTHORIZED),
            Decision::Allow(_) => panic!("expected deny"),
        }
    }

    #[tokio::test]
    async fn fail_closed_returns_503_when_authz_unreachable() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let authz = Authz::build(&AuthzConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:1".into(),
            timeout_ms: 100,
            failure_mode_allow: false,
            scope: None,
        })
        .unwrap()
        .unwrap();
        let app: Router = Router::new()
            .route("/x", get(|| async { "upstream" }))
            .layer(axum::middleware::from_fn_with_state(authz, middleware));
        let resp = app
            .oneshot(
                axum::http::Request::get("/x")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn fail_open_passes_through_when_authz_unreachable() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let authz = Authz::build(&AuthzConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:1".into(),
            timeout_ms: 100,
            failure_mode_allow: true,
            scope: None,
        })
        .unwrap()
        .unwrap();
        let app: Router = Router::new()
            .route("/x", get(|| async { "upstream" }))
            .layer(axum::middleware::from_fn_with_state(authz, middleware));
        let resp = app
            .oneshot(
                axum::http::Request::get("/x")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
