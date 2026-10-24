//! jsonwebtoken adapter over current RustCrypto primitives.
//!
//! JWT parsing, algorithm selection and claims validation remain in jsonwebtoken.
//! This module implements its crypto extension traits; RSA is public-key only.

use core::marker::PhantomData;

use hmac::{KeyInit, Mac};
use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
use jsonwebtoken::errors::{ErrorKind, Result};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey};
use p256::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha384, Sha512};
use signature_v3::SignatureEncoding;

mod keys;

pub(super) static DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: signer,
    verifier_factory: verifier,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        rsa_pub_components_from_public_key: keys::rsa_components,
        ec_pub_components_from_private_key: keys::ec_components,
        ed_pub_components_from_private_key: keys::ed_components,
        compute_digest: keys::digest,
    },
};

struct Signing<K, S> {
    key: K,
    algorithm: Algorithm,
    signature: PhantomData<S>,
}

impl<K, S> signature::Signer<Vec<u8>> for Signing<K, S>
where
    K: signature_v3::Signer<S>,
    S: SignatureEncoding,
{
    fn try_sign(&self, message: &[u8]) -> core::result::Result<Vec<u8>, signature::Error> {
        let signature: S = self
            .key
            .try_sign(message)
            .map_err(|_| signature::Error::new())?;
        Ok(signature.to_vec())
    }
}

impl<K, S> JwtSigner for Signing<K, S>
where
    K: signature_v3::Signer<S>,
    S: SignatureEncoding,
{
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

struct Verification<K, S> {
    key: K,
    algorithm: Algorithm,
    signature_len: usize,
    signature: PhantomData<S>,
}

impl<K, S> signature::Verifier<Vec<u8>> for Verification<K, S>
where
    K: signature_v3::Verifier<S>,
    S: SignatureEncoding,
{
    fn verify(
        &self,
        message: &[u8],
        bytes: &Vec<u8>,
    ) -> core::result::Result<(), signature::Error> {
        // In particular, do not allocate an attacker-sized RSA signature integer.
        if bytes.len() != self.signature_len {
            return Err(signature::Error::new());
        }
        let signature = S::try_from(bytes.as_slice()).map_err(|_| signature::Error::new())?;
        self.key
            .verify(message, &signature)
            .map_err(|_| signature::Error::new())
    }
}

impl<K, S> JwtVerifier for Verification<K, S>
where
    K: signature_v3::Verifier<S>,
    S: SignatureEncoding,
{
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

struct JwtMac<M> {
    initial: M,
    algorithm: Algorithm,
}

impl<M: Mac + Clone> signature::Signer<Vec<u8>> for JwtMac<M> {
    fn try_sign(&self, message: &[u8]) -> core::result::Result<Vec<u8>, signature::Error> {
        // Each operation owns an independent copy of the keyed initial state.
        let mut state = self.initial.clone();
        state.update(message);
        Ok(state.finalize().into_bytes().to_vec())
    }
}

impl<M: Mac + Clone> signature::Verifier<Vec<u8>> for JwtMac<M> {
    fn verify(
        &self,
        message: &[u8],
        bytes: &Vec<u8>,
    ) -> core::result::Result<(), signature::Error> {
        let mut state = self.initial.clone();
        state.update(message);
        state
            .verify_slice(bytes)
            .map_err(|_| signature::Error::new())
    }
}

impl<M: Mac + Clone> JwtSigner for JwtMac<M> {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl<M: Mac + Clone> JwtVerifier for JwtMac<M> {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

fn mac<M: Mac + KeyInit>(bytes: &[u8], algorithm: Algorithm) -> Result<JwtMac<M>> {
    let initial = M::new_from_slice(bytes).map_err(|_| ErrorKind::InvalidKeyFormat)?;
    Ok(JwtMac { initial, algorithm })
}

fn signing<K, S: SignatureEncoding>(key: K, algorithm: Algorithm) -> Signing<K, S> {
    Signing {
        key,
        algorithm,
        signature: PhantomData,
    }
}

fn verification<K, S: SignatureEncoding>(
    key: K,
    algorithm: Algorithm,
    signature_len: usize,
) -> Verification<K, S> {
    Verification {
        key,
        algorithm,
        signature_len,
        signature: PhantomData,
    }
}

fn signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    if algorithm.family() == AlgorithmFamily::Rsa {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    if key.family() != algorithm.family() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let result: Box<dyn JwtSigner> = match *algorithm {
        Algorithm::HS256 => Box::new(mac::<hmac::Hmac<Sha256>>(key.as_bytes(), *algorithm)?),
        Algorithm::HS384 => Box::new(mac::<hmac::Hmac<Sha384>>(key.as_bytes(), *algorithm)?),
        Algorithm::HS512 => Box::new(mac::<hmac::Hmac<Sha512>>(key.as_bytes(), *algorithm)?),
        Algorithm::ES256 => Box::new(signing::<_, p256::ecdsa::Signature>(
            p256::ecdsa::SigningKey::from_pkcs8_der(key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
            *algorithm,
        )),
        Algorithm::ES384 => Box::new(signing::<_, p384::ecdsa::Signature>(
            p384::ecdsa::SigningKey::from_pkcs8_der(key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
            *algorithm,
        )),
        Algorithm::EdDSA => Box::new(signing::<_, ed25519_dalek::Signature>(
            ed25519_dalek::SigningKey::from_pkcs8_der(key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
            *algorithm,
        )),
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    Ok(result)
}

fn verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if key.family() != algorithm.family() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let result: Box<dyn JwtVerifier> = match *algorithm {
        Algorithm::HS256 => Box::new(mac::<hmac::Hmac<Sha256>>(
            key.try_get_as_bytes()?,
            *algorithm,
        )?),
        Algorithm::HS384 => Box::new(mac::<hmac::Hmac<Sha384>>(
            key.try_get_as_bytes()?,
            *algorithm,
        )?),
        Algorithm::HS512 => Box::new(mac::<hmac::Hmac<Sha512>>(
            key.try_get_as_bytes()?,
            *algorithm,
        )?),
        Algorithm::ES256 => Box::new(verification::<_, p256::ecdsa::Signature>(
            p256::ecdsa::VerifyingKey::from_sec1_bytes(key.try_get_as_bytes()?)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
            *algorithm,
            64,
        )),
        Algorithm::ES384 => Box::new(verification::<_, p384::ecdsa::Signature>(
            p384::ecdsa::VerifyingKey::from_sec1_bytes(key.try_get_as_bytes()?)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
            *algorithm,
            96,
        )),
        Algorithm::EdDSA => {
            let bytes = key
                .try_get_as_bytes()?
                .try_into()
                .map_err(|_| ErrorKind::InvalidEddsaKey)?;
            Box::new(verification::<_, ed25519_dalek::Signature>(
                ed25519_dalek::VerifyingKey::from_bytes(bytes)
                    .map_err(|_| ErrorKind::InvalidEddsaKey)?,
                *algorithm,
                64,
            ))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let public = rsa_key(key)?;
            let length = public.size();
            match *algorithm {
                Algorithm::RS256 => Box::new(verification::<_, rsa::pkcs1v15::Signature>(
                    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public),
                    *algorithm,
                    length,
                )),
                Algorithm::RS384 => Box::new(verification::<_, rsa::pkcs1v15::Signature>(
                    rsa::pkcs1v15::VerifyingKey::<Sha384>::new(public),
                    *algorithm,
                    length,
                )),
                Algorithm::RS512 => Box::new(verification::<_, rsa::pkcs1v15::Signature>(
                    rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public),
                    *algorithm,
                    length,
                )),
                Algorithm::PS256 => Box::new(verification::<_, rsa::pss::Signature>(
                    rsa::pss::VerifyingKey::<Sha256>::new(public),
                    *algorithm,
                    length,
                )),
                Algorithm::PS384 => Box::new(verification::<_, rsa::pss::Signature>(
                    rsa::pss::VerifyingKey::<Sha384>::new(public),
                    *algorithm,
                    length,
                )),
                Algorithm::PS512 => Box::new(verification::<_, rsa::pss::Signature>(
                    rsa::pss::VerifyingKey::<Sha512>::new(public),
                    *algorithm,
                    length,
                )),
                _ => return Err(ErrorKind::InvalidAlgorithm.into()),
            }
        }
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    Ok(result)
}

fn rsa_key(key: &DecodingKey) -> Result<rsa::RsaPublicKey> {
    let result = match key.kind() {
        DecodingKeyKind::SecretOrDer(bytes) => coordinode_crypto::public_key::rsa_from_pkcs1(bytes),
        DecodingKeyKind::RsaModulusExponent { n, e } => {
            coordinode_crypto::public_key::rsa_from_components(n, e)
        }
    };
    result.map_err(|_| ErrorKind::InvalidRsaKey("invalid RSA public key".into()).into())
}

#[cfg(test)]
mod tests;
