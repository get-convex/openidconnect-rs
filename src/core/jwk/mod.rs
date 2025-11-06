use crate::core::{crypto, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm};
use crate::helpers::{deserialize_option_or_none, Base64UrlEncodedBytes};
use crate::types::jwks::check_key_compatibility;
use crate::{
    JsonWebKey, JsonWebKeyAlgorithm, JsonWebKeyId, JsonWebKeyType, JsonWebKeyUse,
    JsonWebTokenAlgorithm, PrivateSigningKey, SignatureVerificationError, SigningError,
};

use aws_lc_rs::digest::{digest, SHA256, SHA384, SHA512};
use aws_lc_rs::hmac::{self, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa;
use aws_lc_rs::signature::{
    Ed25519KeyPair, KeyPair, RsaEncoding, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256,
    RSA_PSS_SHA384, RSA_PSS_SHA512,
};
use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[cfg(test)]
mod tests;

// Other than the 'kty' (key type) parameter, which must be present in all JWKs, Section 4 of RFC
// 7517 states that "member names used for representing key parameters for different keys types
// need not be distinct." Therefore, it's possible that future or non-standard key types will supply
// some of the following parameters but with different types, causing deserialization to fail. To
// support such key types, we'll need to define a new impl for JsonWebKey. Deserializing the new
// impl would probably need to involve first deserializing the raw values to access the 'kty'
// parameter, and then deserializing the fields and types appropriate for that key type.
/// Public or symmetric key expressed as a JSON Web Key.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CoreJsonWebKey {
    pub(crate) kty: CoreJsonWebKeyType,
    #[serde(rename = "use")]
    pub(crate) use_: Option<CoreJsonWebKeyUse>,
    pub(crate) kid: Option<JsonWebKeyId>,

    /// The algorithm intended to be used with this key (see
    /// [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517#section-4.4)).
    ///
    /// It can either be an algorithm intended for use with JWS or JWE, or something different.
    pub(crate) alg:
        Option<JsonWebTokenAlgorithm<CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>>,

    // From RFC 7517, Section 4: "Additional members can be present in the JWK; if not understood
    // by implementations encountering them, they MUST be ignored.  Member names used for
    // representing key parameters for different keys types need not be distinct."
    // Hence, we set fields we fail to deserialize (understand) as None.
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) n: Option<Base64UrlEncodedBytes>,
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) e: Option<Base64UrlEncodedBytes>,

    //Elliptic Curve
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) crv: Option<CoreJsonCurveType>,
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) x: Option<Base64UrlEncodedBytes>,
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) y: Option<Base64UrlEncodedBytes>,

    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) d: Option<Base64UrlEncodedBytes>,

    // Used for symmetric keys, which we only generate internally from the client secret; these
    // are never part of the JWK set.
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) k: Option<Base64UrlEncodedBytes>,
}
impl CoreJsonWebKey {
    /// Instantiate a new RSA public key from the raw modulus (`n`) and public exponent (`e`),
    /// along with an optional (but recommended) key ID.
    ///
    /// The key ID is used for matching signed JSON Web Tokens with the keys used for verifying
    /// their signatures.
    pub fn new_rsa(n: Vec<u8>, e: Vec<u8>, kid: Option<JsonWebKeyId>) -> Self {
        Self {
            kty: CoreJsonWebKeyType::RSA,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid,
            n: Some(Base64UrlEncodedBytes::new(n)),
            e: Some(Base64UrlEncodedBytes::new(e)),
            k: None,
            crv: None,
            x: None,
            y: None,
            d: None,
            alg: None,
        }
    }
    /// Instantiate a new EC public key from the raw x (`x`) and y(`y`) part of the curve,
    /// along with an optional (but recommended) key ID.
    ///
    /// The key ID is used for matching signed JSON Web Tokens with the keys used for verifying
    /// their signatures.
    pub fn new_ec(
        x: Vec<u8>,
        y: Vec<u8>,
        crv: CoreJsonCurveType,
        kid: Option<JsonWebKeyId>,
    ) -> Self {
        Self {
            kty: CoreJsonWebKeyType::EllipticCurve,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid,
            n: None,
            e: None,
            k: None,
            crv: Some(crv),
            x: Some(Base64UrlEncodedBytes::new(x)),
            y: Some(Base64UrlEncodedBytes::new(y)),
            d: None,
            alg: None,
        }
    }

    /// Instantiate a new Octet Key-Pair public key from the raw x (`x`) part of the curve,
    /// along with an optional (but recommended) key ID.
    ///
    /// The key ID is used for matching signed JSON Web Tokens with the keys used for verifying
    /// their signatures.
    pub fn new_okp(x: Vec<u8>, crv: CoreJsonCurveType, kid: Option<JsonWebKeyId>) -> Self {
        Self {
            kty: CoreJsonWebKeyType::OctetKeyPair,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid,
            n: None,
            e: None,
            k: None,
            crv: Some(crv),
            x: Some(Base64UrlEncodedBytes::new(x)),
            y: None,
            d: None,
            alg: None,
        }
    }
}
impl JsonWebKey for CoreJsonWebKey {
    type KeyUse = CoreJsonWebKeyUse;
    type SigningAlgorithm = CoreJwsSigningAlgorithm;

    fn key_id(&self) -> Option<&JsonWebKeyId> {
        self.kid.as_ref()
    }
    fn key_type(&self) -> &CoreJsonWebKeyType {
        &self.kty
    }
    fn key_use(&self) -> Option<&CoreJsonWebKeyUse> {
        self.use_.as_ref()
    }

    fn signing_alg(&self) -> JsonWebKeyAlgorithm<&CoreJwsSigningAlgorithm> {
        match self.alg {
            None => JsonWebKeyAlgorithm::Unspecified,
            Some(JsonWebTokenAlgorithm::Signature(ref alg)) => JsonWebKeyAlgorithm::Algorithm(alg),
            Some(_) => JsonWebKeyAlgorithm::Unsupported,
        }
    }

    fn new_symmetric(key: Vec<u8>) -> Self {
        Self {
            kty: CoreJsonWebKeyType::Symmetric,
            use_: None,
            kid: None,
            n: None,
            e: None,
            k: Some(Base64UrlEncodedBytes::new(key)),
            crv: None,
            x: None,
            y: None,
            d: None,
            alg: None,
        }
    }

    fn verify_signature(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        check_key_compatibility(self, signature_alg)
            .map_err(|e| SignatureVerificationError::InvalidKey(e.to_owned()))?;

        match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 => {
                crypto::verify_rsa_signature(self, &RSA_PKCS1_2048_8192_SHA256, message, signature)
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 => {
                crypto::verify_rsa_signature(self, &RSA_PKCS1_2048_8192_SHA384, message, signature)
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 => {
                crypto::verify_rsa_signature(self, &RSA_PKCS1_2048_8192_SHA512, message, signature)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 => {
                crypto::verify_rsa_signature(self, &RSA_PSS_2048_8192_SHA256, message, signature)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 => {
                crypto::verify_rsa_signature(self, &RSA_PSS_2048_8192_SHA384, message, signature)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 => {
                crypto::verify_rsa_signature(self, &RSA_PSS_2048_8192_SHA512, message, signature)
            }
            CoreJwsSigningAlgorithm::HmacSha256 => {
                let key = hmac::Key::new(
                    HMAC_SHA256,
                    self.k.as_ref().ok_or_else(|| {
                        SignatureVerificationError::InvalidKey(
                            "Symmetric key `k` is missing".to_string(),
                        )
                    })?,
                );
                hmac::verify(&key, message, signature)
                    .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
            }
            CoreJwsSigningAlgorithm::HmacSha384 => {
                let key = hmac::Key::new(
                    HMAC_SHA384,
                    self.k.as_ref().ok_or_else(|| {
                        SignatureVerificationError::InvalidKey(
                            "Symmetric key `k` is missing".to_string(),
                        )
                    })?,
                );
                hmac::verify(&key, message, signature)
                    .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
            }
            CoreJwsSigningAlgorithm::HmacSha512 => {
                let key = hmac::Key::new(
                    HMAC_SHA512,
                    self.k.as_ref().ok_or_else(|| {
                        SignatureVerificationError::InvalidKey(
                            "Symmetric key `k` is missing".to_string(),
                        )
                    })?,
                );
                hmac::verify(&key, message, signature)
                    .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
            }
            CoreJwsSigningAlgorithm::EcdsaP256Sha256 => {
                if matches!(self.crv, Some(CoreJsonCurveType::P256)) {
                    crypto::verify_ec_signature(self, message, signature)
                } else {
                    Err(SignatureVerificationError::InvalidKey(
                        "Key uses different CRV than JWT".to_string(),
                    ))
                }
            }
            CoreJwsSigningAlgorithm::EcdsaP384Sha384 => {
                if matches!(self.crv, Some(CoreJsonCurveType::P384)) {
                    crypto::verify_ec_signature(self, message, signature)
                } else {
                    Err(SignatureVerificationError::InvalidKey(
                        "Key uses different CRV than JWT".to_string(),
                    ))
                }
            }
            CoreJwsSigningAlgorithm::EdDsa => match self.crv {
                None => Err(SignatureVerificationError::InvalidKey(
                    "EdDSA key must specify `crv`".to_string(),
                )),
                Some(CoreJsonCurveType::Ed25519) => {
                    crypto::verify_ed_signature(self, message, signature)
                }
                Some(ref crv) => Err(SignatureVerificationError::InvalidKey(format!(
                    "Unsupported EdDSA curve {crv:?}"
                ))),
            },
            ref other => Err(SignatureVerificationError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    fn hash_bytes(&self, bytes: &[u8], alg: &Self::SigningAlgorithm) -> Result<Vec<u8>, String> {
        check_key_compatibility(self, alg).map_err(String::from)?;

        match *alg {
            CoreJwsSigningAlgorithm::HmacSha256
            | CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
            | CoreJwsSigningAlgorithm::RsaSsaPssSha256
            | CoreJwsSigningAlgorithm::EcdsaP256Sha256 => {
                Ok(digest(&SHA256, bytes).as_ref().to_vec())
            }
            CoreJwsSigningAlgorithm::HmacSha384
            | CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384
            | CoreJwsSigningAlgorithm::RsaSsaPssSha384
            | CoreJwsSigningAlgorithm::EcdsaP384Sha384 => {
                Ok(digest(&SHA384, bytes).as_ref().to_vec())
            }
            CoreJwsSigningAlgorithm::HmacSha512
            | CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512
            | CoreJwsSigningAlgorithm::RsaSsaPssSha512
            | CoreJwsSigningAlgorithm::EcdsaP521Sha512 => {
                Ok(digest(&SHA512, bytes).as_ref().to_vec())
            }
            CoreJwsSigningAlgorithm::EdDsa => match self.crv {
                None => Err("EdDSA key must specify `crv`".to_string()),
                Some(CoreJsonCurveType::Ed25519) => Ok(digest(&SHA512, bytes).as_ref().to_vec()),
                Some(ref crv) => Err(format!("Unsupported EdDSA curve {crv:?}")),
            },
            CoreJwsSigningAlgorithm::None => {
                Err("Signature algorithm `none` has no corresponding hash algorithm".to_string())
            }
        }
    }
}

/// HMAC secret key.
///
/// This key can be used for signing messages, or converted to a `CoreJsonWebKey` for verifying
/// them.
#[derive(Clone)]
pub struct CoreHmacKey {
    secret: Vec<u8>,
}
impl CoreHmacKey {
    /// Instantiate a new key from the specified secret bytes.
    pub fn new<T>(secret: T) -> Self
    where
        T: Into<Vec<u8>>,
    {
        Self {
            secret: secret.into(),
        }
    }
}
impl PrivateSigningKey for CoreHmacKey {
    type VerificationKey = CoreJsonWebKey;

    fn sign(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        match *signature_alg {
            CoreJwsSigningAlgorithm::HmacSha256 => {
                let key = hmac::Key::new(HMAC_SHA256, &self.secret);
                Ok(hmac::sign(&key, message).as_ref().to_vec())
            }
            CoreJwsSigningAlgorithm::HmacSha384 => {
                let key = hmac::Key::new(HMAC_SHA384, &self.secret);
                Ok(hmac::sign(&key, message).as_ref().to_vec())
            }
            CoreJwsSigningAlgorithm::HmacSha512 => {
                let key = hmac::Key::new(HMAC_SHA512, &self.secret);
                Ok(hmac::sign(&key, message).as_ref().to_vec())
            }
            ref other => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        CoreJsonWebKey::new_symmetric(self.secret.clone())
    }
}

enum EdDsaSigningKey {
    Ed25519(Ed25519KeyPair),
}

impl EdDsaSigningKey {
    fn from_ed25519_pem(pem: &str) -> Result<Self, String> {
        let [der] = pkcs8_private_keys(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|e: Vec<_>| format!("needed 1 private key, found {}", e.len()))?;
        Ok(Self::Ed25519(
            Ed25519KeyPair::from_pkcs8(der.secret_pkcs8_der())
                .map_err(|e| format!("invalid PKCS#8 Ed25519 private key: {e}"))?,
        ))
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => {
                let signature = key.sign(message);

                signature.as_ref().to_vec()
            }
        }
    }
}

/// EdDSA Private Key.
///
/// This key can be used for signing messages, or converted to a `CoreJsonWebKey` for verifying
/// them.
pub struct CoreEdDsaPrivateSigningKey {
    kid: Option<JsonWebKeyId>,
    key_pair: EdDsaSigningKey,
}
impl CoreEdDsaPrivateSigningKey {
    /// Converts an EdDSA private key (in PEM format) to a JWK representing its public key.
    pub fn from_ed25519_pem(pem: &str, kid: Option<JsonWebKeyId>) -> Result<Self, String> {
        Ok(Self {
            kid,
            key_pair: EdDsaSigningKey::from_ed25519_pem(pem)?,
        })
    }
}
impl PrivateSigningKey for CoreEdDsaPrivateSigningKey {
    type VerificationKey = CoreJsonWebKey;

    fn sign(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        match *signature_alg {
            CoreJwsSigningAlgorithm::EdDsa => Ok(self.key_pair.sign(message)),
            ref other => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        match &self.key_pair {
            EdDsaSigningKey::Ed25519(key) => CoreJsonWebKey {
                kty: CoreJsonWebKeyType::OctetKeyPair,
                use_: Some(CoreJsonWebKeyUse::Signature),
                kid: self.kid.clone(),
                n: None,
                e: None,
                crv: Some(CoreJsonCurveType::Ed25519),
                x: Some(Base64UrlEncodedBytes::new(
                    key.public_key().as_ref().to_vec(),
                )),
                y: None,
                d: None,
                k: None,
                alg: None,
            },
        }
    }
}

/// RSA private key.
///
/// This key can be used for signing messages, or converted to a `CoreJsonWebKey` for verifying
/// them.
pub struct CoreRsaPrivateSigningKey {
    key_pair: rsa::KeyPair,
    kid: Option<JsonWebKeyId>,
}
impl CoreRsaPrivateSigningKey {
    /// Converts an RSA private key (in PEM format) to a JWK representing its public key.
    pub fn from_pem(pem: &str, kid: Option<JsonWebKeyId>) -> Result<Self, String> {
        let [der] = rsa_private_keys(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|e: Vec<_>| format!("needed 1 private key, found {}", e.len()))?;
        let key_pair =
            rsa::KeyPair::from_der(der.secret_pkcs1_der()).map_err(|err| err.to_string())?;
        Ok(Self { key_pair, kid })
    }
}
impl PrivateSigningKey for CoreRsaPrivateSigningKey {
    type VerificationKey = CoreJsonWebKey;

    fn sign(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        msg: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        let rng = SystemRandom::new();
        let alg: &dyn RsaEncoding = match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 => &RSA_PKCS1_SHA256,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 => &RSA_PKCS1_SHA384,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 => &RSA_PKCS1_SHA512,
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 => &RSA_PSS_SHA256,
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 => &RSA_PSS_SHA384,
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 => &RSA_PSS_SHA512,
            ref other => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            ))?,
        };
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(alg, &rng, msg, &mut signature)
            .map_err(|_| SigningError::CryptoError)?;
        Ok(signature)
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        let public_key = self.key_pair.public_key();
        CoreJsonWebKey {
            kty: CoreJsonWebKeyType::RSA,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid: self.kid.clone(),
            n: Some(Base64UrlEncodedBytes::new(
                public_key
                    .modulus()
                    .big_endian_without_leading_zero()
                    .to_vec(),
            )),
            e: Some(Base64UrlEncodedBytes::new(
                public_key
                    .exponent()
                    .big_endian_without_leading_zero()
                    .to_vec(),
            )),
            k: None,
            crv: None,
            x: None,
            y: None,
            d: None,
            alg: None,
        }
    }
}

/// Type of JSON Web Key.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum CoreJsonWebKeyType {
    /// Elliptic Curve Cryptography (ECC) key.
    ///
    /// ECC algorithms such as ECDSA are currently unsupported.
    #[serde(rename = "EC")]
    EllipticCurve,
    /// RSA key.
    #[serde(rename = "RSA")]
    RSA,
    /// EdDSA key.
    #[serde(rename = "OKP")]
    OctetKeyPair,
    /// Symmetric key.
    #[serde(rename = "oct")]
    Symmetric,
}
impl JsonWebKeyType for CoreJsonWebKeyType {}

/// Type of EC-Curve
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum CoreJsonCurveType {
    /// P-256 Curve
    #[serde(rename = "P-256")]
    P256,
    /// P-384 Curve
    #[serde(rename = "P-384")]
    P384,
    /// P-521 Curve (currently not supported)
    #[serde(rename = "P-521")]
    P521,
    /// Ed25519 Curve
    #[serde(rename = "Ed25519")]
    Ed25519,
}

/// Usage restriction for a JSON Web key.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreJsonWebKeyUse {
    /// Key may be used for digital signatures.
    Signature,

    /// Key may be used for encryption.
    Encryption,

    /// Fallback case for other key uses not understood by this library.
    Other(String),
}
impl CoreJsonWebKeyUse {
    fn from_str(s: &str) -> Self {
        match s {
            "sig" => Self::Signature,
            "enc" => Self::Encryption,
            other => Self::Other(other.to_string()),
        }
    }
}
impl AsRef<str> for CoreJsonWebKeyUse {
    fn as_ref(&self) -> &str {
        match self {
            CoreJsonWebKeyUse::Signature => "sig",
            CoreJsonWebKeyUse::Encryption => "enc",
            CoreJsonWebKeyUse::Other(other) => other.as_str(),
        }
    }
}
impl JsonWebKeyUse for CoreJsonWebKeyUse {
    fn allows_signature(&self) -> bool {
        matches!(*self, CoreJsonWebKeyUse::Signature)
    }
    fn allows_encryption(&self) -> bool {
        matches!(*self, CoreJsonWebKeyUse::Encryption)
    }
}
// FIXME: Once https://github.com/serde-rs/serde/issues/912 is resolved, use #[serde(other)] instead
// of custom serializer/deserializers. Right now this isn't possible because serde(other) only
// supports unit variants.
deserialize_from_str!(CoreJsonWebKeyUse);
serialize_as_str!(CoreJsonWebKeyUse);
