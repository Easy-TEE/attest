use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint::BigUint;
use openssl::pkey::PKey;
use serde::Deserialize;
use x509_parser::prelude::*;

use crate::azure::error::MaaError;

/// JSON Web Key used in [HclRuntimeClaims]
#[derive(Debug, Deserialize)]
pub(super) struct Jwk {
    #[allow(unused)]
    pub kty: String,
    pub kid: String,
    #[allow(unused)]
    pub n: Option<String>,
    #[allow(unused)]
    pub e: Option<String>,
    // other fields ignored
}

/// The internal data structure for HCL runtime claims
#[derive(Debug, Deserialize)]
pub(super) struct HclRuntimeClaims {
    pub keys: Vec<Jwk>,
    #[serde(rename = "user-data")]
    pub user_data: Option<String>,
}

/// This is only used as a common type to compare public keys with different
/// formats
#[derive(Debug, PartialEq)]
pub(super) struct RsaPubKey {
    n: BigUint,
    e: BigUint,
}

impl RsaPubKey {
    pub(super) fn from_jwk(jwk: &Jwk) -> Result<Self, MaaError> {
        if jwk.kty != "RSA" {
            return Err(MaaError::NotRsa);
        }

        let n_bytes = URL_SAFE_NO_PAD.decode(jwk.n.clone().ok_or(MaaError::JwkParse)?)?;
        let e_bytes = URL_SAFE_NO_PAD.decode(jwk.e.clone().ok_or(MaaError::JwkParse)?)?;

        Ok(Self { n: BigUint::from_bytes_be(&n_bytes), e: BigUint::from_bytes_be(&e_bytes) })
    }

    pub(super) fn from_certificate(cert: &X509Certificate) -> Result<Self, MaaError> {
        let spki = cert.public_key();
        let Ok(x509_parser::public_key::PublicKey::RSA(rsa_from_cert)) = spki.parsed() else {
            return Err(MaaError::NotRsa);
        };

        Ok(Self {
            n: BigUint::from_bytes_be(rsa_from_cert.modulus),
            e: BigUint::from_bytes_be(rsa_from_cert.exponent),
        })
    }

    pub(super) fn from_openssl_pubkey(key: &PKey<openssl::pkey::Public>) -> Result<Self, MaaError> {
        let rsa_from_pkey = key.rsa()?;

        Ok(Self {
            n: BigUint::from_bytes_be(&rsa_from_pkey.n().to_vec()),
            e: BigUint::from_bytes_be(&rsa_from_pkey.e().to_vec()),
        })
    }
}
