use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let time =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
        Self::from_google_at(mrtd, root, time)
    }

    /// Same as [`Self::from_google`] but checks the endorsement
    /// certificate's validity at an explicit time to support verifying
    /// older quotes
    pub fn from_google_at(
        mrtd: [u8; 48],
        root: Option<&X509Certificate>,
        time: u64,
    ) -> Result<Self, GoogleError> {
        let bytes = http_get(&format!("{ENDORSEMENT_BUCKET}/tdx/{}.binarypb", hex::encode(mrtd)))?;
        let endorsement = Endorsement::decode(&*bytes)?;
        let golden = GoldenMeasurement::decode(&*endorsement.serialized_uefi_golden)?;
        verify_endorsement(&endorsement, &golden, root, time)?;

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
    #[error("endorsement certificate not valid at {time} (valid {not_before} to {not_after})")]
    CertNotValidAt { time: ASN1Time, not_before: ASN1Time, not_after: ASN1Time },
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

// Checks that signature matches protobuf and is signed with Google root
// key, by a certificate valid at `time`
fn verify_endorsement(
    endorsement: &Endorsement,
    golden: &GoldenMeasurement,
    root: Option<&X509Certificate>,
    time: u64,
) -> Result<(), GoogleError> {
    let leaf = X509Certificate::from_der(&golden.cert)?.1;
    let time = ASN1Time::from_timestamp(i64::try_from(time).map_err(|_| X509Error::InvalidDate)?)?;
    let validity = leaf.validity();
    if !validity.is_valid_at(time) {
        return Err(GoogleError::CertNotValidAt {
            time,
            not_before: validity.not_before,
            not_after: validity.not_after,
        });
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
