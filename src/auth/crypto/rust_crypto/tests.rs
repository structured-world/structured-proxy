use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Header, Validation, decode, encode};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::EncodePrivateKey;
use serde_json::json;

fn claims() -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({"sub": "crypto-contract", "exp": now + 3600})
}

fn install() {
    DEFAULT_PROVIDER.install_default().unwrap();
}

// The public JWT API exercises the signature-2/signature-3 adapter and claims parsing together.
#[test]
fn allowed_signatures_round_trip_through_jsonwebtoken() {
    install();
    let ec256 = p256::SecretKey::from_slice(&[1; 32]).unwrap();
    let ec384 = p384::SecretKey::from_slice(&[2; 48]).unwrap();
    let ed = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let cases = [
        (
            Algorithm::HS256,
            EncodingKey::from_secret(&[4; 64]),
            DecodingKey::from_secret(&[4; 64]),
        ),
        (
            Algorithm::HS384,
            EncodingKey::from_secret(&[4; 64]),
            DecodingKey::from_secret(&[4; 64]),
        ),
        (
            Algorithm::HS512,
            EncodingKey::from_secret(&[4; 64]),
            DecodingKey::from_secret(&[4; 64]),
        ),
        (
            Algorithm::ES256,
            EncodingKey::from_ec_der(ec256.to_pkcs8_der().unwrap().as_bytes()),
            DecodingKey::from_ec_der(&ec256.public_key().to_sec1_bytes()),
        ),
        (
            Algorithm::ES384,
            EncodingKey::from_ec_der(ec384.to_pkcs8_der().unwrap().as_bytes()),
            DecodingKey::from_ec_der(&ec384.public_key().to_sec1_bytes()),
        ),
        (
            Algorithm::EdDSA,
            EncodingKey::from_ed_der(ed.to_pkcs8_der().unwrap().as_bytes()),
            DecodingKey::from_ed_der(ed.verifying_key().as_bytes()),
        ),
    ];
    for (algorithm, private, public) in cases {
        let expected = claims();
        let token = encode(&Header::new(algorithm), &expected, &private).unwrap();
        let actual =
            decode::<serde_json::Value>(&token, &public, &Validation::new(algorithm)).unwrap();
        assert_eq!(actual.claims, expected);
        let (input, signature) = token.rsplit_once('.').unwrap();
        let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        signature[0] ^= 1;
        let corrupt = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert!(
            decode::<serde_json::Value>(&corrupt, &public, &Validation::new(algorithm)).is_err()
        );
    }
}

fn rsa_signature(key: rsa::RsaPrivateKey, algorithm: Algorithm, input: &[u8]) -> Vec<u8> {
    use signature_v3::{RandomizedSigner, Signer};
    // Generated test keys are an oracle only; the product factory never accepts RSA signing.
    match algorithm {
        Algorithm::RS256 => rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
            .try_sign(input)
            .unwrap()
            .to_vec(),
        Algorithm::RS384 => rsa::pkcs1v15::SigningKey::<Sha384>::new(key)
            .try_sign(input)
            .unwrap()
            .to_vec(),
        Algorithm::RS512 => rsa::pkcs1v15::SigningKey::<Sha512>::new(key)
            .try_sign(input)
            .unwrap()
            .to_vec(),
        Algorithm::PS256 => rsa::pss::SigningKey::<Sha256>::new(key)
            .try_sign_with_rng(&mut rand::rng(), input)
            .unwrap()
            .to_vec(),
        Algorithm::PS384 => rsa::pss::SigningKey::<Sha384>::new(key)
            .try_sign_with_rng(&mut rand::rng(), input)
            .unwrap()
            .to_vec(),
        Algorithm::PS512 => rsa::pss::SigningKey::<Sha512>::new(key)
            .try_sign_with_rng(&mut rand::rng(), input)
            .unwrap()
            .to_vec(),
        _ => panic!("test requires an RSA algorithm"),
    }
}

// Every RSA JWT algorithm accepts both PEM-derived DER and JWK components without a private path.
#[test]
fn rsa_public_jwt_verification_and_private_refusal() {
    use rsa::pkcs1::EncodeRsaPublicKey;
    install();
    let private = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let public = private.to_public_key();
    let der = public.to_pkcs1_der().unwrap();
    for algorithm in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ] {
        let jwk = serde_json::from_value(json!({
            "kty": "RSA", "alg": algorithm,
            "n": URL_SAFE_NO_PAD.encode(public.n_bytes()),
            "e": URL_SAFE_NO_PAD.encode(public.e_bytes()),
        }))
        .unwrap();
        let expected = claims();
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Header::new(algorithm)).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&expected).unwrap());
        let input = format!("{header}.{payload}");
        let signature = rsa_signature(private.clone(), algorithm, input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(&signature));
        for key in [
            DecodingKey::from_rsa_der(der.as_bytes()),
            DecodingKey::from_jwk(&jwk).unwrap(),
        ] {
            let actual =
                decode::<serde_json::Value>(&token, &key, &Validation::new(algorithm)).unwrap();
            assert_eq!(actual.claims, expected);
            let verifier = (DEFAULT_PROVIDER.verifier_factory)(&algorithm, &key).unwrap();
            let mut corrupt = signature.clone();
            corrupt[0] ^= 1;
            assert!(verifier.verify(input.as_bytes(), &corrupt).is_err());
            assert!(
                verifier
                    .verify(input.as_bytes(), &vec![0; signature.len() + 1])
                    .is_err()
            );
        }
        assert!(
            (DEFAULT_PROVIDER.signer_factory)(&algorithm, &EncodingKey::from_rsa_der(&[])).is_err()
        );
    }
    assert!(
        (DEFAULT_PROVIDER
            .key_utils
            .rsa_pub_components_from_private_key)(&[])
        .is_err()
    );
}

// Untrusted key material must fail before indexing, integer allocation or algorithm confusion.
#[test]
fn malformed_public_keys_and_family_confusion_are_errors() {
    for length in 0..32 {
        assert!(
            (DEFAULT_PROVIDER.verifier_factory)(
                &Algorithm::EdDSA,
                &DecodingKey::from_ed_der(&vec![0; length])
            )
            .is_err()
        );
    }
    assert!(
        (DEFAULT_PROVIDER.verifier_factory)(&Algorithm::EdDSA, &DecodingKey::from_ed_der(&[0; 33]))
            .is_err()
    );
    assert!(
        (DEFAULT_PROVIDER.verifier_factory)(&Algorithm::ES256, &DecodingKey::from_secret(&[0; 64]))
            .is_err()
    );
    assert!(
        (DEFAULT_PROVIDER.signer_factory)(&Algorithm::ES256, &EncodingKey::from_secret(&[0; 64]))
            .is_err()
    );
    assert!(
        (DEFAULT_PROVIDER.verifier_factory)(
            &Algorithm::RS256,
            &DecodingKey::from_rsa_der(&[0; 32])
        )
        .is_err()
    );
    let oversized = DecodingKey::from_rsa_raw_components(&vec![1; 1025], &[3]);
    assert!((DEFAULT_PROVIDER.verifier_factory)(&Algorithm::RS256, &oversized).is_err());
}

// JWK utility hooks are implemented, including typed refusal of unsupported private keys.
#[test]
fn jwk_utilities_are_real_and_algorithm_bound() {
    let ec = p256::SecretKey::from_slice(&[1; 32]).unwrap();
    let der = ec.to_pkcs8_der().unwrap();
    let (curve, x, y) =
        (DEFAULT_PROVIDER
            .key_utils
            .ec_pub_components_from_private_key)(der.as_bytes(), Algorithm::ES256)
        .unwrap();
    let point = ec.public_key().to_sec1_point(false);
    assert_eq!(curve, jsonwebtoken::jwk::EllipticCurve::P256);
    assert_eq!(x, point.x().unwrap().as_slice());
    assert_eq!(y, point.y().unwrap().as_slice());
    assert!(
        (DEFAULT_PROVIDER
            .key_utils
            .ec_pub_components_from_private_key)(der.as_bytes(), Algorithm::ES384)
        .is_err()
    );
    assert!(
        (DEFAULT_PROVIDER
            .key_utils
            .ed_pub_components_from_private_key)(
            &[], &jsonwebtoken::jwk::EllipticCurve::P256
        )
        .is_err()
    );
    let digest = (DEFAULT_PROVIDER.key_utils.compute_digest)(
        b"abc",
        jsonwebtoken::jwk::ThumbprintHash::SHA256,
    )
    .unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(digest),
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    );
}
