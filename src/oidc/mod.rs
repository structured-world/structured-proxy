//! OpenID Connect discovery surface.
//!
//! When `oidc_discovery.enabled`, the proxy serves the OpenID Provider metadata
//! document at `/.well-known/openid-configuration` and, when a signing key is
//! configured, a JWKS document built from its public key. This lets the proxy
//! front an identity provider so relying parties can discover endpoints + keys.

use std::path::Path;

use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::config::OidcDiscoveryConfig;

/// Length of an Ed25519 public key in bytes (the tail of its SPKI encoding).
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Precomputed OIDC discovery responses.
pub struct Oidc {
    discovery: Value,
    jwks: Option<Value>,
    jwks_path: String,
}

impl Oidc {
    /// Build the discovery responses, or `None` when discovery is disabled.
    ///
    /// # Errors
    /// Returns an error when a configured signing key cannot be read or is not a
    /// supported (Ed25519) public key.
    pub fn build(config: &OidcDiscoveryConfig) -> Result<Option<Self>, String> {
        if !config.enabled {
            return Ok(None);
        }

        let alg = config
            .signing_key
            .as_ref()
            .map(|k| k.algorithm.clone())
            .unwrap_or_else(|| "EdDSA".to_string());
        let jwks_uri = config.jwks_uri.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/jwks.json",
                config.issuer.trim_end_matches('/')
            )
        });

        let discovery = discovery_document(config, &alg, &jwks_uri);

        let jwks = match &config.signing_key {
            Some(sk) => Some(json!({ "keys": [ed25519_jwk(&sk.public_key_pem_file, &alg)?] })),
            None => None,
        };

        Ok(Some(Self {
            discovery,
            jwks,
            jwks_path: jwks_uri_path(&jwks_uri),
        }))
    }

    /// Routes serving the discovery document and (if configured) the JWKS.
    pub fn routes<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let discovery = self.discovery.clone();
        let mut router = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let doc = discovery.clone();
                async move { Json(doc) }
            }),
        );
        if let Some(jwks) = &self.jwks {
            let jwks = jwks.clone();
            router = router.route(
                &self.jwks_path,
                get(move || {
                    let keys = jwks.clone();
                    async move { Json(keys) }
                }),
            );
        }
        router
    }
}

/// Build the OpenID Provider metadata document from config.
fn discovery_document(config: &OidcDiscoveryConfig, alg: &str, jwks_uri: &str) -> Value {
    let mut m = Map::new();
    m.insert("issuer".into(), json!(config.issuer));
    if let Some(v) = &config.authorization_endpoint {
        m.insert("authorization_endpoint".into(), json!(v));
    }
    if let Some(v) = &config.token_endpoint {
        m.insert("token_endpoint".into(), json!(v));
    }
    if let Some(v) = &config.userinfo_endpoint {
        m.insert("userinfo_endpoint".into(), json!(v));
    }
    m.insert("jwks_uri".into(), json!(jwks_uri));
    m.insert(
        "response_types_supported".into(),
        json!(["code", "id_token", "token id_token"]),
    );
    m.insert("subject_types_supported".into(), json!(["public"]));
    m.insert("id_token_signing_alg_values_supported".into(), json!([alg]));
    m.insert(
        "scopes_supported".into(),
        json!(["openid", "profile", "email"]),
    );
    m.insert(
        "token_endpoint_auth_methods_supported".into(),
        json!(["client_secret_basic", "client_secret_post"]),
    );
    Value::Object(m)
}

/// The path component of a (possibly absolute) JWKS URI.
fn jwks_uri_path(uri: &str) -> String {
    // Strip scheme://host if present, keep the path (default to a well-known).
    if let Some(rest) = uri.split_once("://") {
        match rest.1.find('/') {
            Some(idx) => rest.1[idx..].to_string(),
            None => "/.well-known/jwks.json".to_string(),
        }
    } else if uri.starts_with('/') {
        uri.to_string()
    } else {
        "/.well-known/jwks.json".to_string()
    }
}

/// Convert an Ed25519 public-key PEM into an OKP JWK.
fn ed25519_jwk(pem_path: &Path, alg: &str) -> Result<Value, String> {
    if !matches!(alg, "EdDSA" | "Ed25519") {
        return Err(format!(
            "oidc_discovery signing key algorithm {alg:?} is not supported (only EdDSA)"
        ));
    }
    let pem = std::fs::read_to_string(pem_path)
        .map_err(|e| format!("failed to read oidc signing key {pem_path:?}: {e}"))?;
    let der = decode_pem_body(&pem)?;
    if der.len() < ED25519_PUBLIC_KEY_LEN {
        return Err("oidc signing key is not a valid Ed25519 public key".to_string());
    }
    // The Ed25519 public key is the final 32 bytes of the SPKI structure.
    let raw = &der[der.len() - ED25519_PUBLIC_KEY_LEN..];
    Ok(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "kid": key_id(raw),
        "x": URL_SAFE_NO_PAD.encode(raw),
    }))
}

/// Decode the base64 body of a PEM block.
fn decode_pem_body(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    STANDARD
        .decode(body.trim())
        .map_err(|e| format!("invalid PEM base64: {e}"))
}

/// Stable key id: the first 16 hex chars of the SHA-256 of the public key.
fn key_id(raw: &[u8]) -> String {
    let digest = Sha256::digest(raw);
    hex16(&digest)
}

/// Render the first 8 bytes of a digest as lowercase hex.
fn hex16(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(8) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SigningKeyConfig;

    const TEST_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEARCMxEnaM2/dblLuPNgBZpTvSUXO5ir+XQ1nyzJm4CFw=\n\
        -----END PUBLIC KEY-----\n";

    fn write_pub() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "sp_oidc_{}_{}.pem",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, TEST_PUB_PEM).unwrap();
        p
    }

    #[test]
    fn discovery_document_includes_configured_endpoints() {
        let cfg = OidcDiscoveryConfig {
            enabled: true,
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: Some("https://idp.example.com/authorize".into()),
            token_endpoint: Some("https://idp.example.com/token".into()),
            userinfo_endpoint: None,
            jwks_uri: None,
            signing_key: None,
        };
        let doc = discovery_document(
            &cfg,
            "EdDSA",
            "https://idp.example.com/.well-known/jwks.json",
        );
        assert_eq!(doc["issuer"], "https://idp.example.com");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://idp.example.com/authorize"
        );
        assert_eq!(doc["token_endpoint"], "https://idp.example.com/token");
        // Absent endpoints are omitted, not null.
        assert!(doc.get("userinfo_endpoint").is_none());
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            json!(["EdDSA"])
        );
        assert_eq!(
            doc["jwks_uri"],
            "https://idp.example.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn jwks_uri_path_extracts_path() {
        assert_eq!(
            jwks_uri_path("https://idp.example.com/oauth/keys"),
            "/oauth/keys"
        );
        assert_eq!(jwks_uri_path("/keys.json"), "/keys.json");
        assert_eq!(
            jwks_uri_path("https://idp.example.com"),
            "/.well-known/jwks.json"
        );
    }

    #[test]
    fn ed25519_pem_becomes_okp_jwk() {
        let path = write_pub();
        let jwk = ed25519_jwk(&path, "EdDSA").unwrap();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        // x is the 32-byte key, base64url without padding (43 chars).
        assert_eq!(jwk["x"].as_str().unwrap().len(), 43);
        assert_eq!(jwk["kid"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn non_eddsa_signing_key_is_rejected() {
        let path = write_pub();
        assert!(ed25519_jwk(&path, "RS256").is_err());
    }

    #[test]
    fn build_serves_jwks_when_signing_key_present() {
        let cfg = OidcDiscoveryConfig {
            enabled: true,
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: Some("https://idp.example.com/keys.json".into()),
            signing_key: Some(SigningKeyConfig {
                algorithm: "EdDSA".into(),
                public_key_pem_file: write_pub(),
            }),
        };
        let oidc = Oidc::build(&cfg).unwrap().unwrap();
        assert_eq!(oidc.jwks_path, "/keys.json");
        assert!(oidc.jwks.is_some());
        assert_eq!(
            oidc.discovery["jwks_uri"],
            "https://idp.example.com/keys.json"
        );
    }

    #[tokio::test]
    async fn routes_serve_discovery_and_jwks() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let cfg = OidcDiscoveryConfig {
            enabled: true,
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: Some("https://idp.example.com/keys.json".into()),
            signing_key: Some(SigningKeyConfig {
                algorithm: "EdDSA".into(),
                public_key_pem_file: write_pub(),
            }),
        };
        let app: axum::Router = Oidc::build(&cfg).unwrap().unwrap().routes();

        let disc = app
            .clone()
            .oneshot(
                Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disc.status(), 200);

        let jwks = app
            .oneshot(Request::get("/keys.json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(jwks.status(), 200);
        let body = axum::body::to_bytes(jwks.into_body(), 4096).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["keys"][0]["kty"], "OKP");
    }

    #[test]
    fn disabled_yields_none() {
        let cfg = OidcDiscoveryConfig {
            enabled: false,
            issuer: "x".into(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            signing_key: None,
        };
        assert!(Oidc::build(&cfg).unwrap().is_none());
    }
}
