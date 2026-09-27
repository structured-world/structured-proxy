//! One authenticated request through the JWT middleware, with the claims cache
//! on (the token was seen before) and off (every request checks the EdDSA
//! signature).

use std::hint::black_box;
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use structured_proxy::auth::{middleware, Auth};
use structured_proxy::config::ProxyConfig;
use tower::ServiceExt;

/// An Ed25519 key, its public key as a PEM file, and a token it signed.
fn key_file_and_token() -> (std::path::PathBuf, String) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.verifying_key().as_bytes());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        STANDARD.encode(&der)
    );
    let path = std::env::temp_dir().join(format!("sp_bench_{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "sub": "user-42", "roles": ["admin"], "exp": 9_999_999_999u64
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
    (path, format!("{input}.{signature}"))
}

/// A router behind the JWT middleware, with the cache as `cache_yaml` says.
fn app(pem: &std::path::Path, cache_yaml: &str) -> axum::Router {
    let yaml = format!(
        "upstream:\n  default: \"http://127.0.0.1:1\"\nauth:\n  mode: jwt\n  jwt:\n    public_key_pem_file: \"{}\"\n    claims_headers:\n      sub: x-user\n    cache:\n      {cache_yaml}\n",
        pem.display()
    );
    let config = ProxyConfig::from_yaml_str(&yaml).unwrap();
    let auth: Arc<Auth> = Auth::build(config.auth.as_ref().unwrap(), None)
        .unwrap()
        .unwrap();
    axum::Router::new()
        .route("/secure", axum::routing::get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(auth, middleware))
}

fn bench(c: &mut Criterion) {
    let (pem, token) = key_file_and_token();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("jwt_verify");
    for (name, cache) in [
        ("cache_hit", "enabled: true"),
        ("no_cache", "enabled: false"),
    ] {
        let app = app(&pem, cache);
        let authorization = format!("Bearer {token}");
        group.bench_function(name, |b| {
            b.to_async(&runtime).iter(|| {
                let app = app.clone();
                let request = Request::get("/secure")
                    .header("authorization", &authorization)
                    .body(Body::empty())
                    .unwrap();
                async move { black_box(app.oneshot(request).await.unwrap().status()) }
            });
        });
    }
    group.finish();
    std::fs::remove_file(pem).ok();
}

criterion_group!(benches, bench);
criterion_main!(benches);
