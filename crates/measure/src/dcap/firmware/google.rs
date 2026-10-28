use std::time::Duration;

use prost::Message;
use rsa::{
    RsaPublicKey,
    pkcs8::DecodePublicKey,
    pss::{Signature, VerifyingKey},
    signature::Verifier,
};
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;
use x509_parser::prelude::*;

use super::{DcapFirmware, FirmwareError};

/// Bucket containing Google's signed endorsements and firmware blobs
const ENDORSEMENT_BUCKET: &str = "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm";
/// Google root certificate for verifying endorsements
const ROOT_CERT_URL: &str = "https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt";
/// ureq has no read timeout by default
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

impl DcapFirmware {
    /// Download and verify firmware for a GCP MRTD, then derive events
    /// `root` overrides the endorsement root cert (fetched from pki.goog by
    /// default)
    pub fn from_google(
        mrtd: [u8; 48],
        root: Option<&X509Certificate>,
    ) -> Result<Self, GoogleError> {
        let bytes = http_get(&format!("{ENDORSEMENT_BUCKET}/tdx/{}.binarypb", hex::encode(mrtd)))?;
        let endorsement = Endorsement::decode(&*bytes)?;
        let golden = GoldenMeasurement::decode(&*endorsement.serialized_uefi_golden)?;
        verify_endorsement(&endorsement, &golden, root)?;

        let fw_raw = http_get(&format!("{ENDORSEMENT_BUCKET}/{}.fd", hex::encode(&golden.digest)))?;
        if Sha384::digest(&fw_raw)[..] != golden.digest[..] {
            return Err(GoogleError::Mismatch("firmware digest"));
        }

        let firmware = Self::from_blob(&fw_raw, true)?;
        if firmware.mrtd != mrtd {
            return Err(GoogleError::Mismatch("MRTD"));
        }
        Ok(firmware)
    }
}

#[derive(Message)]
struct Endorsement {
    // Raw bytes are needed verify signature
    #[prost(bytes = "vec", tag = "1")]
    serialized_uefi_golden: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

#[derive(Message)]
struct GoldenMeasurement {
    #[prost(bytes = "vec", tag = "4")]
    cert: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    digest: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum GoogleError {
    #[error("HTTP: {0}")]
    Http(String),
    #[error("malformed launch endorsement: {0}")]
    Endorsement(#[from] prost::DecodeError),
    #[error("endorsement certificate: {0}")]
    Cert(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error("endorsement certificate expired")]
    CertExpired,
    #[error("certificate chain: {0}")]
    CertChain(#[from] x509_parser::error::X509Error),
    #[error("endorsement public key: {0}")]
    Key(#[from] rsa::pkcs8::spki::Error),
    #[error("endorsement signature: {0}")]
    Signature(#[from] rsa::signature::Error),
    #[error("{0} does not match endorsement")]
    Mismatch(&'static str),
    #[error("firmware: {0}")]
    Firmware(#[from] FirmwareError),
}

fn http_get(url: &str) -> Result<Vec<u8>, GoogleError> {
    ureq::get(url)
        .config()
        .timeout_global(Some(HTTP_TIMEOUT))
        .build()
        .call()
        .and_then(|mut r| r.body_mut().read_to_vec())
        .map_err(|e| GoogleError::Http(e.to_string()))
}

// Checks that signature matches protobuf and is signed with Google root key
fn verify_endorsement(
    endorsement: &Endorsement,
    golden: &GoldenMeasurement,
    root: Option<&X509Certificate>,
) -> Result<(), GoogleError> {
    let leaf = X509Certificate::from_der(&golden.cert)?.1;
    if !leaf.validity().is_valid() {
        return Err(GoogleError::CertExpired);
    }
    match root {
        Some(root) => leaf.verify_signature(Some(root.public_key())),
        None => {
            let raw_cert = http_get(ROOT_CERT_URL)?;
            let root = X509Certificate::from_der(&raw_cert)?.1;
            leaf.verify_signature(Some(root.public_key()))
        }
    }?;

    let key = RsaPublicKey::from_public_key_der(leaf.public_key().raw)?;
    let sig = Signature::try_from(&*endorsement.signature)?;
    Ok(VerifyingKey::<Sha256>::new(key).verify(&endorsement.serialized_uefi_golden, &sig)?)
}
