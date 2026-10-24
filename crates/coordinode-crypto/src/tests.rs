#![allow(clippy::unwrap_used, clippy::panic)]

use alloc::vec::Vec;
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::cipher::{AeadKey, Iv, Tls13AeadAlgorithm};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use rustls::{ConnectionTrafficSecrets, Error, PeerMisbehaved};

/// The TLS 1.2 AEAD of `suite` in `provider`.
#[cfg(feature = "tls12")]
fn tls12_aead(
    provider: &rustls::crypto::CryptoProvider,
    suite: rustls::CipherSuite,
) -> &'static dyn rustls::crypto::cipher::Tls12AeadAlgorithm {
    match provider.cipher_suites.iter().find(|s| s.suite() == suite) {
        Some(rustls::SupportedCipherSuite::Tls12(s)) => s.aead_alg,
        _ => panic!("{suite:?} is not a TLS 1.2 suite of the provider"),
    }
}

/// A record of 2^14 plaintext bytes decrypts; one byte more is refused after
/// authentication, as by an independent provider. The sender is that
/// independent provider, so the record is genuinely authenticated.
#[cfg(feature = "tls12")]
fn tls12_record_limit(suite: rustls::CipherSuite) {
    use rustls::crypto::cipher::{InboundOpaqueMessage, OutboundPlainMessage};
    use rustls::{ContentType, ProtocolVersion};

    let oracle = tls12_aead(&rustls::crypto::ring::default_provider(), suite);
    let ours = tls12_aead(&super::provider(), suite);
    let shape = oracle.key_block_shape();
    let key = || AeadKey::from([1; 32]);
    let iv = alloc::vec![0; shape.fixed_iv_len];
    let explicit = alloc::vec![0; shape.explicit_nonce_len];
    for length in [16_384, 16_385] {
        let data = alloc::vec![7; length];
        let record = oracle
            .encrypter(key(), &iv, &explicit)
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: data.as_slice().into(),
                },
                0,
            )
            .unwrap();
        let decrypt = |decrypter: &dyn rustls::crypto::cipher::Tls12AeadAlgorithm| {
            let mut bytes = record.payload.as_ref().to_vec();
            decrypter
                .decrypter(key(), &iv)
                .decrypt(
                    InboundOpaqueMessage::new(record.typ, record.version, &mut bytes),
                    0,
                )
                .map(|plain| plain.payload.to_vec())
        };
        // Lengths, not the buffers, so a failure prints a readable outcome.
        let expected = if length == 16_384 {
            Ok(length)
        } else {
            Err(Error::PeerSentOversizedRecord)
        };
        for (who, aead) in [("oracle", oracle), ("ours", ours)] {
            let outcome = decrypt(aead);
            assert_eq!(
                outcome.as_ref().map(Vec::len),
                expected.as_ref().map(|len| *len),
                "{who}, {length} bytes"
            );
            if let Ok(plain) = outcome {
                assert!(plain == data, "{who}: decrypted bytes differ");
            }
        }
    }
}

// TLS 1.2 plaintext is at most 2^14 bytes (RFC 5246 section 6.2.1), even
// when the record authenticates. AES-128 shares this decrypter through
// `impl_gcm_tls12`; rustls' public `AeadKey` builds only 32-byte keys.
#[cfg(feature = "tls12")]
#[test]
fn tls12_aes_gcm_refuses_an_oversized_authenticated_record() {
    tls12_record_limit(rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_chacha20_refuses_an_oversized_authenticated_record() {
    tls12_record_limit(rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
}

// AES-GCM records under one key are bounded (RFC 8446 section 5.5,
// draft-irtf-cfrg-aead-limits section 5.1): past 2^24 full-size records rustls
// must update the key or close. ChaCha20-Poly1305 has no practical bound.
#[test]
fn aes_gcm_suites_carry_their_confidentiality_limit() {
    use rustls::CipherSuite as S;
    const GCM: u64 = 1 << 24;
    // The exact suites of the compiled profile, in offer order.
    let mut expected = Vec::new();
    #[cfg(feature = "tls12")]
    expected.extend([
        (S::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, GCM),
        (S::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, GCM),
        (S::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, u64::MAX),
        (S::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, GCM),
        (S::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, GCM),
        (S::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, u64::MAX),
    ]);
    expected.extend([
        (S::TLS13_AES_128_GCM_SHA256, GCM),
        (S::TLS13_AES_256_GCM_SHA384, GCM),
        (S::TLS13_CHACHA20_POLY1305_SHA256, u64::MAX),
    ]);
    let actual: Vec<_> = super::provider()
        .cipher_suites
        .iter()
        .map(|suite| {
            let common = match suite {
                rustls::SupportedCipherSuite::Tls12(suite) => &suite.common,
                rustls::SupportedCipherSuite::Tls13(suite) => &suite.common,
            };
            (common.suite, common.confidentiality_limit)
        })
        .collect();
    assert_eq!(actual, expected);
}

// TLS 1.3 must reject non-contributory X25519 shares (RFC 8446 section 7.4.2).
#[test]
fn x25519_rejects_low_order_shares() {
    let mut shares = Vec::new();
    shares.push([0; 32]);
    let mut one = [0; 32];
    one[0] = 1;
    shares.push(one);
    // Order-eight encodings from libsodium's curve25519 ref10 test boundary.
    shares.push([
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ]);
    shares.push([
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ]);
    for first in [0xec, 0xed, 0xee] {
        let mut share = [0xff; 32];
        share[0] = first;
        share[31] = 0x7f;
        shares.push(share);
    }
    for share in shares {
        for high_bit in [0, 0x80] {
            let mut encoded = share;
            encoded[31] |= high_bit;
            let result = super::kx::X25519.start().unwrap().complete(&encoded);
            assert!(matches!(
                result,
                Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
            ));
        }
    }
}

// A valid exchange remains interoperable while low-order shares are refused.
#[test]
fn x25519_valid_exchange_agrees() {
    let alice = super::kx::X25519.start().unwrap();
    let bob = super::kx::X25519.start().unwrap();
    let alice_public = alice.pub_key().to_vec();
    let bob_public = bob.pub_key().to_vec();
    let alice_secret = alice.complete(&bob_public).unwrap();
    let bob_secret = bob.complete(&alice_public).unwrap();
    assert_eq!(alice_secret.secret_bytes(), bob_secret.secret_bytes());
    assert_ne!(alice_secret.secret_bytes(), &[0; 32]);
}

// The provider must refuse RSA private keys independently of their DER wrapper.
#[test]
fn rsa_private_keys_are_refused() {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(
        &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
        2048,
    )
    .unwrap();
    let keys = [
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
            key.to_pkcs1_der().unwrap().as_bytes().to_vec(),
        )),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        )),
    ];
    for key in keys {
        assert!(
            super::provider()
                .key_provider
                .load_private_key(key)
                .is_err()
        );
    }
}

// AES traffic-secret export must preserve the negotiated key size.
#[test]
fn aes128_exports_aes128_traffic_secrets() {
    let secret = super::aead::gcm::Tls13Aes128Gcm
        .extract_keys(AeadKey::from([0u8; 32]), Iv::from([0; 12]))
        .unwrap();
    assert!(matches!(secret, ConnectionTrafficSecrets::Aes128Gcm { .. }));
}

// Truncated TLS 1.2 records are peer errors, including with overflow checks enabled.
#[cfg(feature = "tls12")]
#[test]
fn chacha20_rejects_short_tls12_record() {
    use rustls::crypto::cipher::{InboundOpaqueMessage, Tls12AeadAlgorithm};
    let mut decrypter = Tls12AeadAlgorithm::decrypter(
        &super::aead::chacha20::Chacha20Poly1305,
        AeadKey::from([0u8; 32]),
        &[0; 12],
    );
    let mut bytes = [0u8; 15];
    let message = InboundOpaqueMessage::new(
        rustls::ContentType::ApplicationData,
        rustls::ProtocolVersion::TLSv1_2,
        &mut bytes,
    );
    assert!(matches!(
        decrypter.decrypt(message, 0),
        Err(Error::DecryptError)
    ));
}

// A P-384 SEC1 algorithm identifier must not be ignored for a 32-byte scalar.
#[test]
fn sec1_curve_identifier_is_enforced() {
    use der::Encode;
    use pkcs8::AssociatedOid;
    let key = sec1::EcPrivateKey {
        private_key: &[1; 32],
        parameters: Some(sec1::EcParameters::NamedCurve(p384::NistP384::OID)),
        public_key: None,
    }
    .to_der()
    .unwrap();
    assert!(
        super::provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Sec1(key.into()))
            .is_err()
    );
}

// TLS 1.2 AES export uses its 4-byte fixed IV and 8-byte explicit nonce offset.
#[cfg(feature = "tls12")]
#[test]
fn tls12_aes_export_preserves_nonce_and_algorithm() {
    use rustls::crypto::cipher::Tls12AeadAlgorithm;
    let secret = Tls12AeadAlgorithm::extract_keys(
        &super::aead::gcm::Tls12Aes256Gcm,
        AeadKey::from([0; 32]),
        &[1; 4],
        &[2; 8],
    )
    .unwrap();
    let ConnectionTrafficSecrets::Aes256Gcm { iv, .. } = secret else {
        panic!("AES-256 export changed the negotiated algorithm");
    };
    assert_eq!(iv.as_ref(), &[1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]);
}

// RFC 8446 section 4.2.3 prohibits RSA keys smaller than 2048 bits in TLS 1.3.
#[test]
fn rsa_verification_rejects_small_modulus() {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use signature::{SignatureEncoding, Signer};
    let key = rsa::RsaPrivateKey::new(
        &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
        1024,
    )
    .unwrap();
    let public = key.to_public_key().to_pkcs1_der().unwrap();
    let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key);
    let signature: rsa::pkcs1v15::Signature = signing.try_sign(b"TLS signature").unwrap();
    assert!(
        super::verify::rsa::RSA_PKCS1_SHA256
            .verify_signature(public.as_bytes(), b"TLS signature", &signature.to_vec())
            .is_err()
    );
}

#[cfg(feature = "std")]
mod tls;
