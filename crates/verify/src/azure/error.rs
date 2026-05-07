use az_tdx_vtpm::{hcl, vtpm};
use openssl::error::ErrorStack;
use thiserror::Error;

/// An error when generating or verifying a Microsoft Azure vTPM attestation
#[derive(Error, Debug)]
pub enum MaaError {
    #[error("HCL: {0}")]
    Hcl(#[from] hcl::HclError),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vTPM quote: {0}")]
    VtpmQuote(#[from] vtpm::QuoteError),
    #[error("AK public key: {0}")]
    AkPub(#[from] vtpm::AKPubError),
    #[error("vTPM quote could not be verified: {0}")]
    TpmQuoteVerify(#[from] vtpm::VerifyError),
    #[error("PEM encode: {0}")]
    Pem(#[from] pem_rfc7468::Error),
    #[error("TD report input does not match hashed HCL var data")]
    TdReportInputMismatch,
    #[error("Base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Attestation Key from HCL runtime claims does not match that from HCL report")]
    AkFromClaimsNotEqualAkFromHcl,
    #[error(
        "Attestation Key from HCL runtime claims does not match that from attestation key certificate"
    )]
    AkFromClaimsNotEqualAkFromCertificate,
    #[error("WebPKI: {0}")]
    WebPki(#[from] webpki::Error),
    #[error("X509 parse: {0}")]
    X509Parse(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error("X509: {0}")]
    X509(#[from] x509_parser::error::X509Error),
    #[error("Cannot encode JSON web key as DER")]
    JwkConversion,
    #[error("OpenSSL: {0}")]
    OpenSSL(#[from] ErrorStack),
    #[error("Expected AK key to be RSA")]
    NotRsa,
    #[error("JSON web key has missing field")]
    JwkParse,
    #[error("HCL runtime claims is missing HCLAkPub field")]
    ClaimsMissingHCLAkPub,
    #[error("HCL runtime claims is missing user-data field")]
    ClaimsMissingUserData,
    #[error("HCL runtime claims user-data must decode to exactly 64 bytes")]
    ClaimsUserDataBadLength,
    #[error("HCL runtime claims user-data does not match expected report input data")]
    ClaimsUserDataInputMismatch,
    #[error("DCAP verification: {0}")]
    DcapVerification(#[from] crate::dcap::DcapVerificationError),
}
