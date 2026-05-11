//! TEE attestation evidence verification

#[cfg(feature = "azure")]
pub mod azure;
pub mod dcap;

use std::time::{SystemTime, UNIX_EPOCH};

use measure::Measurement;
use pccs::Pccs;
use thiserror::Error;
#[cfg(feature = "azure")]
use types::AzureRegisters;
use types::{AttestationEvidence, AttestationType, DcapRegisters, MeasurementOutput};

/// Verify an attestation against an expected measurement set, returning
/// the report data on success
pub fn verify(
    expected: &MeasurementOutput,
    evidence: &AttestationEvidence,
    pccs: &Pccs,
) -> Result<[u8; 64], VerifyError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    verify_at(expected, evidence, pccs, time)
}

/// Same as [`verify`] but takes an explicit time argument
/// to support verifying older evidence
pub fn verify_at(
    expected: &MeasurementOutput,
    evidence: &AttestationEvidence,
    pccs: &Pccs,
    time: u64,
) -> Result<[u8; 64], VerifyError> {
    match (expected, evidence.platform.attestation_type) {
        (MeasurementOutput::Portable(p), AttestationType::GcpTdx) => {
            let expected_dcap = measure::dcap::gcp::measure(&p.dcap, &[])?.finalize();
            verify_dcap_at(&expected_dcap, &evidence.quote, pccs, time)
        }
        (MeasurementOutput::Portable(_), AttestationType::SelfHostedTdx) => {
            Err(VerifyError::SelfHostedRebuildNotImplemented)
        }
        #[cfg(feature = "azure")]
        (MeasurementOutput::Portable(p), AttestationType::AzureTdx) => {
            let azure = p.azure.as_ref().ok_or(VerifyError::PlatformMismatch)?;
            verify_azure_at(azure, &evidence.quote, pccs, time)
        }
        (MeasurementOutput::Dcap(d), AttestationType::GcpTdx | AttestationType::SelfHostedTdx) => {
            verify_dcap_at(d, &evidence.quote, pccs, time)
        }
        #[cfg(feature = "azure")]
        (MeasurementOutput::Azure(a), AttestationType::AzureTdx) => {
            verify_azure_at(a, &evidence.quote, pccs, time)
        }
        #[cfg(not(feature = "azure"))]
        (MeasurementOutput::Azure(_), _) | (_, AttestationType::AzureTdx) => {
            Err(VerifyError::AzureFeatureDisabled)
        }
        _ => Err(VerifyError::PlatformMismatch),
    }
}

/// Verify DCAP quote and check registers against an expected set of
/// measurements
pub fn verify_dcap(
    expected: &DcapRegisters,
    quote: &[u8],
    pccs: &Pccs,
) -> Result<[u8; 64], VerifyError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    verify_dcap_at(expected, quote, pccs, time)
}

/// Same as [`verify_dcap`] but takes an explicit time argument
/// to support verifying older evidence
pub fn verify_dcap_at(
    expected: &DcapRegisters,
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
) -> Result<[u8; 64], VerifyError> {
    let raw = dcap::validate_quote_at(quote, pccs, time)?;
    if expected.rtmr1 != raw.rtmr1 || expected.rtmr2 != raw.rtmr2 {
        return Err(VerifyError::RegisterMismatch);
    }
    Ok(raw.report_data)
}

/// Verify an Azure attestation document and check its PCRs against an
/// expected set of measurements
#[cfg(feature = "azure")]
pub fn verify_azure(
    expected: &AzureRegisters,
    document: &[u8],
    pccs: &Pccs,
) -> Result<[u8; 64], VerifyError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    verify_azure_at(expected, document, pccs, time)
}

/// Same as [`verify_azure`] but takes an explicit time argument
/// to support verifying older evidence
#[cfg(feature = "azure")]
pub fn verify_azure_at(
    expected: &AzureRegisters,
    document: &[u8],
    pccs: &Pccs,
    time: u64,
) -> Result<[u8; 64], VerifyError> {
    let raw = azure::validate_quote_at(document, pccs, time)?;
    if raw.pcr4 != expected.pcr4 || raw.pcr9 != expected.pcr9 || raw.pcr11 != expected.pcr11 {
        return Err(VerifyError::RegisterMismatch);
    }
    Ok(raw.report_data)
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Platform of evidence does not match expected measurement type")]
    PlatformMismatch,
    #[error("Quote register values do not match any expected entry")]
    RegisterMismatch,
    #[error("Self-hosted register reconstruction is not yet implemented")]
    SelfHostedRebuildNotImplemented,
    #[cfg(not(feature = "azure"))]
    #[error("Azure verification requested but `azure` feature is not enabled")]
    AzureFeatureDisabled,
    #[error("Rebuilding expected registers: {0}")]
    Rebuild(#[from] anyhow::Error),
    #[error("DCAP: {0}")]
    Dcap(#[from] dcap::DcapError),
    #[cfg(feature = "azure")]
    #[error("Azure: {0}")]
    Azure(#[from] azure::error::AzureError),
}
