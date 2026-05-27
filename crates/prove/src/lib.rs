//! CVM attestation evidence generation

#[cfg(feature = "azure")]
pub mod azure;
pub mod ccel;
pub mod platform;

use thiserror::Error;
use types::{AttestationEvidence, AttestationType};

/// Generate an attestation for the current CVM and gather platform metadata
pub fn prove(input_data: [u8; 64]) -> Result<AttestationEvidence, ProveError> {
    let platform = platform::metadata()?;
    let quote = match platform.attestation_type {
        AttestationType::GcpTdx | AttestationType::SelfHostedTdx => {
            tdx_attest::get_quote(&input_data)?
        }
        AttestationType::AzureTdx => {
            #[cfg(not(feature = "azure"))]
            return Err(ProveError::AzureFeatureDisabled);
            #[cfg(feature = "azure")]
            azure::create_quote(input_data)?
        }
    };
    Ok(AttestationEvidence { quote, platform })
}

#[derive(Error, Debug)]
pub enum ProveError {
    #[cfg(not(feature = "azure"))]
    #[error("Azure attestation requested but `azure` feature is not enabled")]
    AzureFeatureDisabled,
    #[error("DCAP quote: {0}")]
    DcapQuote(#[from] tdx_attest::TdxAttestError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("CCEL: {0:#}")]
    Ccel(anyhow::Error),
    #[cfg(feature = "azure")]
    #[error("Azure: {0}")]
    Azure(#[from] azure::AzureError),
}
