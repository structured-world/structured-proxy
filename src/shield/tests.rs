//! Middleware-level tests driving the compiled Shield through axum + tower.

use super::*;
use crate::config::{KeySourceConfig, LimitProfileConfig, RateRuleConfig, ShieldConfig};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use std::collections::HashMap;
use tower::ServiceExt;

/// A ShieldConfig with the given profiles + rules, everything else off.
fn config(profiles: Vec<(&str, &str, Option<u64>)>, rules: Vec<RateRuleConfig>) -> ShieldConfig {
    let profiles = profiles
        .into_iter()
        .map(|(name, rate, burst)| {
            (
                name.to_string(),
                LimitProfileConfig {
                    rate: rate.to_string(),
                    burst,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    ShieldConfig {
        enabled: true,
        profiles,
        rules,
        default_profile: None,
        jwt_limits: None,
        limit_service: None,
        sync: None,
        trusted_proxies: Vec::new(),
    }
}

fn rule(pattern: &str, key: KeySourceConfig, profile: Option<&str>) -> RateRuleConfig {
    RateRuleConfig {
        pattern: pattern.to_string(),
        key,
        profile: profile.map(str::to_string),
    }
}

fn app(cfg: ShieldConfig) -> Router {
    let shield = Shield::build(&cfg).unwrap().unwrap();
    Router::new()
        .route("/api/x", get(|| async { "ok" }))
        .route("/open", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            shield,
            pre_auth_middleware,
        ))
}

async fn get_req(app: &Router, path: &str, xff: Option<&str>) -> Response {
    let mut req = Request::builder().uri(path);
    if let Some(xff) = xff {
        req = req.header("x-forwarded-for", xff);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get_keyed(app: &Router, path: &str, header: (&str, &str)) -> Response {
    let req = Request::builder()
        .uri(path)
        .header(header.0, header.1)
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

#[tokio::test]
async fn admits_burst_then_rejects() {
    let app = app(config(
        vec![("t", "60/min", Some(2))], // 1/s, burst 2
        vec![rule("/api/**", KeySourceConfig::Ip, Some("t"))],
    ));
    // Same client (same XFF) → shared budget of 2.
    assert_eq!(
        get_req(&app, "/api/x", Some("9.9.9.9")).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get_req(&app, "/api/x", Some("9.9.9.9")).await.status(),
        StatusCode::OK
    );
    let third = get_req(&app, "/api/x", Some("9.9.9.9")).await;
    assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
    // A rejected response carries Retry-After.
    assert!(third.headers().contains_key("retry-after"));
}

#[tokio::test]
async fn emits_ratelimit_headers_when_allowed() {
    let app = app(config(
        vec![("t", "100/min", Some(10))],
        vec![rule("/api/**", KeySourceConfig::Ip, Some("t"))],
    ));
    let resp = get_req(&app, "/api/x", Some("1.2.3.4")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h.get("ratelimit-limit").unwrap(), "100");
    // After one admitted request, 9 of the burst-10 remain.
    assert_eq!(h.get("ratelimit-remaining").unwrap(), "9");
    assert!(h.contains_key("ratelimit-reset"));
}

#[tokio::test]
async fn unmatched_path_is_not_limited() {
    let app = app(config(
        vec![("t", "1/min", Some(1))],
        vec![rule("/api/**", KeySourceConfig::Ip, Some("t"))],
    ));
    // `/open` matches no rule: never limited even past the /api budget.
    for _ in 0..5 {
        assert_eq!(
            get_req(&app, "/open", Some("5.5.5.5")).await.status(),
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn header_key_isolates_clients() {
    let app = app(config(
        vec![("t", "60/min", Some(1))], // burst 1
        vec![rule(
            "/api/**",
            KeySourceConfig::Header {
                name: "x-api-key".to_string(),
            },
            Some("t"),
        )],
    ));
    // Key "alice": first ok, second rejected.
    assert_eq!(
        get_keyed(&app, "/api/x", ("x-api-key", "alice"))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        get_keyed(&app, "/api/x", ("x-api-key", "alice"))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // A different key has its own budget.
    assert_eq!(
        get_keyed(&app, "/api/x", ("x-api-key", "bob"))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rule_without_resolvable_profile_passes() {
    // Rule pins no profile and there is no default_profile → cannot limit → allow.
    let app = app(config(
        vec![("t", "1/min", Some(1))],
        vec![rule("/api/**", KeySourceConfig::Ip, None)],
    ));
    for _ in 0..3 {
        assert_eq!(
            get_req(&app, "/api/x", Some("7.7.7.7")).await.status(),
            StatusCode::OK
        );
    }
}

#[test]
fn jwt_claim_key_uses_claim_then_falls_back_to_ip() {
    let claims = serde_json::json!({ "sub": "alice", "org": { "id": "acme" } });
    let key = KeySource::JwtClaim("sub".to_string());
    // Present claim: identity is the raw claim value (for service resolution);
    // the store key is de-identified (no raw value) and tagged `jwt`.
    let k = rule_key("fp", &key, "1.1.1.1", &HeaderMap::new(), Some(&claims));
    assert_eq!(k.identity, "alice");
    assert!(k.store.starts_with("fp:jwt:"));
    assert!(
        !k.store.contains("alice"),
        "raw value must not appear in store key"
    );
    // Dotted path into a nested claim.
    let nested = KeySource::JwtClaim("org.id".to_string());
    assert_eq!(
        rule_key("fp", &nested, "1.1.1.1", &HeaderMap::new(), Some(&claims)).identity,
        "acme"
    );
    // No claims (anonymous) → IP fallback, so the limit can't be dodged.
    let anon = rule_key("fp", &key, "1.1.1.1", &HeaderMap::new(), None);
    assert_eq!(anon.identity, "1.1.1.1");
    assert!(anon.store.starts_with("fp:ip:"));
    // Claim present but missing the requested field → IP fallback.
    let missing = rule_key(
        "fp",
        &KeySource::JwtClaim("missing".to_string()),
        "1.1.1.1",
        &HeaderMap::new(),
        Some(&claims),
    );
    assert_eq!(missing.identity, "1.1.1.1");
    assert!(missing.store.starts_with("fp:ip:"));
}

#[test]
fn store_key_namespaced_by_fingerprint_and_value() {
    let key = KeySource::Ip;
    // Same client under two different rules (fingerprints) → independent budgets.
    let a = rule_key("fpA", &key, "1.1.1.1", &HeaderMap::new(), None);
    let b = rule_key("fpB", &key, "1.1.1.1", &HeaderMap::new(), None);
    assert_ne!(a.store, b.store);
    // Same rule + same value → identical store key (stable across instances).
    let a2 = rule_key("fpA", &key, "1.1.1.1", &HeaderMap::new(), None);
    assert_eq!(a.store, a2.store);
    // Different value → different store key.
    let c = rule_key("fpA", &key, "2.2.2.2", &HeaderMap::new(), None);
    assert_ne!(a.store, c.store);
}

#[test]
fn secs_ceil_rounds_sub_second_waits_up() {
    use std::time::Duration;
    // A sub-millisecond wait must report at least 1 second, never 0.
    assert_eq!(secs_ceil(Duration::from_micros(500)), 1);
    assert_eq!(secs_ceil(Duration::from_millis(1)), 1);
    assert_eq!(secs_ceil(Duration::from_millis(1500)), 2);
    assert_eq!(secs_ceil(Duration::from_secs(3)), 3);
    // Genuinely zero stays zero.
    assert_eq!(secs_ceil(Duration::ZERO), 0);
}

#[test]
fn build_rejects_unknown_default_profile() {
    let mut cfg = config(vec![("t", "1/min", None)], Vec::new());
    cfg.rules = vec![rule("/x", KeySourceConfig::Ip, Some("t"))];
    cfg.default_profile = Some("missing".to_string());
    assert!(Shield::build(&cfg).is_err());
}

/// End-to-end two-phase test: a rule keyed by a validated JWT claim, layered in
/// the same order as the server (pre-auth → auth → post-auth), limits per
/// principal using the claims the auth middleware verifies and attaches.
mod two_phase {
    use super::*;
    use crate::auth::Auth;
    use crate::config::{AuthConfig, JwtConfig};
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair_pem() -> (SigningKey, std::path::PathBuf) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let spki_prefix: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let mut der = spki_prefix.to_vec();
        der.extend_from_slice(sk.verifying_key().as_bytes());
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "sp_shield_{}_{}.pem",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, pem).unwrap();
        (sk, path)
    }

    fn token(sk: &SigningKey, sub: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        // Far-future exp so default expiry validation passes.
        let claims = serde_json::json!({ "sub": sub, "exp": 9_999_999_999u64 });
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn auth(pem: std::path::PathBuf) -> std::sync::Arc<Auth> {
        let cfg = AuthConfig {
            mode: "jwt".into(),
            jwt: Some(JwtConfig {
                issuer: None,
                audience: None,
                jwks_uri: None,
                public_key_pem_file: Some(pem),
                claims_headers: HashMap::new(),
                roles_claim: "roles".into(),
            }),
            forward_auth: None,
            authz: None,
        };
        Auth::build(&cfg).unwrap().unwrap()
    }

    fn stack(shield: std::sync::Arc<Shield>, auth: std::sync::Arc<Auth>) -> Router {
        // Same layering order as the server: post-auth is innermost (sees the
        // verified claims), auth in the middle, pre-auth outermost.
        Router::new()
            .route("/api/x", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                shield.clone(),
                post_auth_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                auth,
                crate::auth::middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                shield,
                pre_auth_middleware,
            ))
    }

    async fn get_with(app: &Router, bearer: &str) -> StatusCode {
        let req = Request::builder()
            .uri("/api/x")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn limits_per_principal_via_validated_claim() {
        let (sk, pem) = keypair_pem();
        let cfg = config(
            vec![("t", "60/min", Some(1))], // burst 1 per principal
            vec![rule(
                "/api/**",
                KeySourceConfig::JwtClaim {
                    claim: "sub".to_string(),
                },
                Some("t"),
            )],
        );
        let shield = Shield::build(&cfg).unwrap().unwrap();
        let app = stack(shield, auth(pem));

        let alice = token(&sk, "alice");
        let bob = token(&sk, "bob");
        // Alice: first request ok, second over her burst.
        assert_eq!(get_with(&app, &alice).await, StatusCode::OK);
        assert_eq!(get_with(&app, &alice).await, StatusCode::TOO_MANY_REQUESTS);
        // Bob is a different principal with his own budget.
        assert_eq!(get_with(&app, &bob).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn inner_principal_headers_survive_outer_limiter() {
        // Defense in depth: a generous pre-auth IP rule and a tight post-auth
        // principal rule both match the path. When the principal limit rejects,
        // the 429's RateLimit-* must reflect that tight rule, not be overwritten
        // by the outer pre-auth verdict on the way out.
        let (sk, pem) = keypair_pem();
        let cfg = config(
            vec![("wide", "100/min", Some(100)), ("tight", "60/min", Some(1))],
            vec![
                rule("/api/**", KeySourceConfig::Ip, Some("wide")),
                rule(
                    "/api/**",
                    KeySourceConfig::JwtClaim {
                        claim: "sub".to_string(),
                    },
                    Some("tight"),
                ),
            ],
        );
        let shield = Shield::build(&cfg).unwrap().unwrap();
        let app = stack(shield, auth(pem));
        let alice = token(&sk, "alice");

        let send = |bearer: String| {
            let app = app.clone();
            async move {
                let req = Request::builder()
                    .uri("/api/x")
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap();
                app.oneshot(req).await.unwrap()
            }
        };

        assert_eq!(send(alice.clone()).await.status(), StatusCode::OK);
        let rejected = send(alice).await;
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        // The tight principal rule (limit 100/min → 100? no, "tight" is 60/min)
        // owns the rejection, so its limit shows, not the wide pre-auth rule's.
        assert_eq!(
            rejected.headers().get("ratelimit-limit").unwrap(),
            "60",
            "the rejecting inner rule's RateLimit-Limit must not be overwritten"
        );
    }

    #[tokio::test]
    async fn allowed_response_reports_tighter_outer_budget() {
        // Pre-auth IP rule is tighter (burst 2) than the post-auth principal rule
        // (burst 100). An allowed request must advertise the tighter pre-auth
        // remaining, not the roomy principal one, so the client backs off in time.
        let (sk, pem) = keypair_pem();
        let cfg = config(
            vec![("tight", "60/min", Some(2)), ("wide", "100/min", Some(100))],
            vec![
                rule("/api/**", KeySourceConfig::Ip, Some("tight")),
                rule(
                    "/api/**",
                    KeySourceConfig::JwtClaim {
                        claim: "sub".to_string(),
                    },
                    Some("wide"),
                ),
            ],
        );
        let shield = Shield::build(&cfg).unwrap().unwrap();
        let app = stack(shield, auth(pem));

        let req = Request::builder()
            .uri("/api/x")
            .header("authorization", format!("Bearer {}", token(&sk, "alice")))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // tight burst 2, one admitted → 1 remaining; wide would show 99.
        assert_eq!(resp.headers().get("ratelimit-remaining").unwrap(), "1");
    }

    #[tokio::test]
    async fn allowed_response_reports_longer_reset_on_remaining_tie() {
        // Both phases exhaust their burst on the first admit, leaving the same
        // remaining (0). The pre-auth IP rule (1/hour) binds far longer than the
        // post-auth principal rule (1/min): the client must see the longer reset
        // so it doesn't retry after ~60s and immediately hit the still-blocked
        // hourly IP budget. On a remaining tie the longer-reset header wins.
        let (sk, pem) = keypair_pem();
        let cfg = config(
            vec![
                ("hourly", "1/hour", Some(1)),
                ("minutely", "1/min", Some(1)),
            ],
            vec![
                rule("/api/**", KeySourceConfig::Ip, Some("hourly")),
                rule(
                    "/api/**",
                    KeySourceConfig::JwtClaim {
                        claim: "sub".to_string(),
                    },
                    Some("minutely"),
                ),
            ],
        );
        let shield = Shield::build(&cfg).unwrap().unwrap();
        let app = stack(shield, auth(pem));

        let req = Request::builder()
            .uri("/api/x")
            .header("authorization", format!("Bearer {}", token(&sk, "alice")))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("ratelimit-remaining").unwrap(), "0");
        // Longer reset (hourly IP ≈ 3600s) must win over the minutely 60s, so a
        // paced client waits out the binding budget instead of retrying early.
        let reset: u64 = resp
            .headers()
            .get("ratelimit-reset")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(reset > 120, "expected the hourly reset to win, got {reset}");
    }
}
