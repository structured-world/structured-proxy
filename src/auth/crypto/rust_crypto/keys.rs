use jsonwebtoken::Algorithm;
use jsonwebtoken::errors::{ErrorKind, Result};
use jsonwebtoken::jwk::{EllipticCurve, ThumbprintHash};
use p256::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub(super) fn rsa_components(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = coordinode_crypto::public_key::rsa_from_pkcs1(bytes)
        .map_err(|_| ErrorKind::InvalidRsaKey("invalid RSA public key".into()))?;
    Ok((key.n_bytes().into_vec(), key.e_bytes().into_vec()))
}

pub(super) fn ec_components(
    bytes: &[u8],
    algorithm: Algorithm,
) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    match algorithm {
        Algorithm::ES256 => {
            let key = p256::ecdsa::SigningKey::from_pkcs8_der(bytes)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
            let point = key.verifying_key().to_sec1_point(false);
            let x = point.x().ok_or(ErrorKind::InvalidEcdsaKey)?.to_vec();
            let y = point.y().ok_or(ErrorKind::InvalidEcdsaKey)?.to_vec();
            Ok((EllipticCurve::P256, x, y))
        }
        Algorithm::ES384 => {
            let key = p384::ecdsa::SigningKey::from_pkcs8_der(bytes)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
            let point = key.verifying_key().to_sec1_point(false);
            let x = point.x().ok_or(ErrorKind::InvalidEcdsaKey)?.to_vec();
            let y = point.y().ok_or(ErrorKind::InvalidEcdsaKey)?.to_vec();
            Ok((EllipticCurve::P384, x, y))
        }
        _ => Err(ErrorKind::InvalidAlgorithm.into()),
    }
}

pub(super) fn ed_components(bytes: &[u8], curve: &EllipticCurve) -> Result<Vec<u8>> {
    if *curve != EllipticCurve::Ed25519 {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    let key =
        ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map_err(|_| ErrorKind::InvalidEddsaKey)?;
    Ok(key.verifying_key().as_bytes().to_vec())
}

pub(super) fn digest(bytes: &[u8], algorithm: ThumbprintHash) -> Result<Vec<u8>> {
    Ok(match algorithm {
        ThumbprintHash::SHA256 => Sha256::digest(bytes).to_vec(),
        ThumbprintHash::SHA384 => Sha384::digest(bytes).to_vec(),
        ThumbprintHash::SHA512 => Sha512::digest(bytes).to_vec(),
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    })
}
