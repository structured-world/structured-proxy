//! OpenID Connect discovery surface.
//!
//! When `oidc_discovery.enabled`, the proxy serves the OpenID Provider metadata
//! document at `/.well-known/openid-configuration` and a JWKS document at the
//! advertised `jwks_uri` path (built from the configured signing key, or an
//! empty set when none is set). This lets the proxy front an identity provider
//! so relying parties can discover endpoints and keys.

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

/// Fixed 12-byte SPKI header that precedes the 32-byte key in an Ed25519
/// `SubjectPublicKeyInfo` (`AlgorithmIdentifier` for `id-Ed25519` + BIT STRING).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Precomputed OIDC discovery responses.
pub struct Oidc {
    discovery: Value,
    jwks: Value,
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

        // Always have a JWKS to serve: an empty set when no signing key is
        // configured, so the advertised `jwks_uri` never 404s.
        let jwks = match &config.signing_key {
            Some(sk) => json!({ "keys": [ed25519_jwk(&sk.public_key_pem_file, &alg)?] }),
            None => json!({ "keys": [] }),
        };

        Ok(Some(Self {
            discovery,
            jwks,
            jwks_path: jwks_uri_path(&jwks_uri),
        }))
    }

    /// Routes serving the discovery document and the JWKS.
    pub fn routes<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let discovery = self.discovery.clone();
        // Serialize the JWKS once; serve it with the RFC 7517 media type.
        let jwks_body =
            serde_json::to_string(&self.jwks).unwrap_or_else(|_| "{\"keys\":[]}".to_string());
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let doc = discovery.clone();
                    async move { Json(doc) }
                }),
            )
            .route(
                &self.jwks_path,
                get(move || {
                    let body = jwks_body.clone();
                    async move {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/jwk-set+json")],
                            body,
                        )
                    }
                }),
            )
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
    // An Ed25519 SPKI is exactly the 12-byte prefix + 32-byte key. Verify both,
    // so an RSA/EC key (which would also be longer than 32 bytes) is rejected
    // loudly instead of having its tail bytes published as a bogus Ed25519 key.
    if der.len() != ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_LEN
        || der[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX
    {
        return Err(
            "oidc signing key is not a valid Ed25519 (EdDSA) public key in SPKI form".to_string(),
        );
    }
    let raw = &der[ED25519_SPKI_PREFIX.len()..];
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

    // An EC P-256 public key (91-byte SPKI) that the loose length check would
    // accept, publishing its last 32 bytes as a bogus Ed25519 key.
    const EC_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgAJ0pjQcIv5a3YQTu2YHKyl9tYB8\n\
        zxWf7gcS1JeuSRRT6RtezpLXHy5SGMxFCWnJukWOqaLR2lgxTFxQ48HsKA==\n\
        -----END PUBLIC KEY-----\n";

    #[test]
    fn non_ed25519_spki_is_rejected_under_eddsa() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(1000);
        let p = std::env::temp_dir().join(format!(
            "sp_oidc_ec_{}_{}.pem",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, EC_PUB_PEM).unwrap();
        // EdDSA configured but the PEM is an EC key: must be a hard error, not a
        // silently-published wrong key.
        assert!(ed25519_jwk(&p, "EdDSA").is_err());
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
        assert_eq!(oidc.jwks["keys"][0]["kty"], "OKP");
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

    #[tokio::test]
    async fn jwks_uri_is_served_even_without_signing_key() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // No signing key, but the discovery doc still advertises a local
        // jwks_uri, so that path must resolve (empty set), not 404.
        let cfg = OidcDiscoveryConfig {
            enabled: true,
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            signing_key: None,
        };
        let oidc = Oidc::build(&cfg).unwrap().unwrap();
        let advertised = oidc.discovery["jwks_uri"].as_str().unwrap().to_string();
        let path = jwks_uri_path(&advertised);
        let app: axum::Router = oidc.routes();
        let resp = app
            .oneshot(Request::get(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-type"], "application/jwk-set+json");
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({ "keys": [] })
        );
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
