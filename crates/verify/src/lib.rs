//! TEE attestation evidence verification

#[cfg(feature = "azure")]
pub mod azure;
pub mod dcap;

use std::time::{SystemTime, UNIX_EPOCH};

use measure::dcap::{DcapFirmware, GoogleError, ReconstructError, expected_dcap_registers};
use pccs::Pccs;
use thiserror::Error;
#[cfg(feature = "azure")]
use types::AzureRegisters;
use types::{
    AttestationEvidence,
    AttestationType,
    DcapImageHashes,
    DcapRegisters,
    MeasurementOutput,
    PlatformMetadata,
};

/// Verify an attestation against an expected measurement set, returning
/// the report data on success
pub fn verify(
    expected: &MeasurementOutput,
    evidence: &AttestationEvidence,
    pccs: &Pccs,
    firmware: Option<&[u8]>,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    verify_at(expected, evidence, pccs, firmware, time, debug)
}

/// Same as [`verify`] but takes an explicit time argument
/// to support verifying older evidence
pub fn verify_at(
    expected: &MeasurementOutput,
    evidence: &AttestationEvidence,
    pccs: &Pccs,
    firmware: Option<&[u8]>,
    time: u64,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    match (expected, evidence.platform.attestation_type) {
        #[cfg(feature = "azure")]
        (MeasurementOutput::Portable(p), AttestationType::AzureTdx) => {
            let azure = p.azure.as_ref().ok_or(VerifyError::PlatformMismatch)?;
            verify_azure_at(azure, &evidence.quote, pccs, time, debug)
        }
        #[cfg(not(feature = "azure"))]
        (MeasurementOutput::Azure(_), _) | (_, AttestationType::AzureTdx) => {
            Err(VerifyError::AzureFeatureDisabled)
        }
        (MeasurementOutput::Portable(p), _) => verify_portable_dcap_at(
            &p.dcap,
            &evidence.platform,
            firmware,
            &evidence.quote,
            pccs,
            time,
            debug,
        ),
        (MeasurementOutput::Dcap(d), AttestationType::GcpTdx | AttestationType::SelfHostedTdx) => {
            verify_dcap_at(d, &evidence.quote, pccs, time, debug)
        }
        #[cfg(feature = "azure")]
        (MeasurementOutput::Azure(a), AttestationType::AzureTdx) => {
            verify_azure_at(a, &evidence.quote, pccs, time, debug)
        }
        _ => Err(VerifyError::PlatformMismatch),
    }
}

fn verify_portable_dcap_at(
    image: &DcapImageHashes,
    platform: &PlatformMetadata,
    firmware_blob: Option<&[u8]>,
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let raw = dcap::validate_quote_at(quote, pccs, time)?;
    let firmware = match platform.attestation_type {
        AttestationType::GcpTdx => DcapFirmware::from_google(raw.mrtd, None)?,
        AttestationType::SelfHostedTdx => {
            let blob = firmware_blob.ok_or(VerifyError::MissingFirmware)?;
            DcapFirmware::from_blob(blob, false).map_err(ReconstructError::Firmware)?
        }
        _ => return Err(VerifyError::PlatformMismatch),
    };
    let expected = expected_dcap_registers(image, platform, Some(&firmware))?;

    let expected_mrtd = expected.mrtd.ok_or(VerifyError::IncompleteReconstruction("MRTD"))?;
    let expected_rtmr0 = expected.rtmr0.ok_or(VerifyError::IncompleteReconstruction("RTMR0"))?;

    let mut mismatches = Vec::new();
    if raw.mrtd != expected_mrtd {
        report_mismatch(debug, "MRTD", &raw.mrtd, &expected_mrtd);
        mismatches.push("MRTD");
    }
    if raw.rtmr0 != expected_rtmr0 {
        report_mismatch(debug, "RTMR0", &raw.rtmr0, &expected_rtmr0);
        mismatches.push("RTMR0");
    }
    if raw.rtmr1 != expected.rtmr1 {
        report_mismatch(debug, "RTMR1", &raw.rtmr1, &expected.rtmr1);
        mismatches.push("RTMR1");
    }
    if raw.rtmr2 != expected.rtmr2 {
        report_mismatch(debug, "RTMR2", &raw.rtmr2, &expected.rtmr2);
        mismatches.push("RTMR2");
    }
    if !mismatches.is_empty() {
        return Err(VerifyError::RegisterMismatch(mismatches));
    }
    Ok(raw.report_data)
}

/// Verify DCAP quote and check registers against an expected set of
/// measurements
pub fn verify_dcap(
    expected: &DcapRegisters,
    quote: &[u8],
    pccs: &Pccs,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    verify_dcap_at(expected, quote, pccs, time, debug)
}

/// Same as [`verify_dcap`] but takes an explicit time argument
/// to support verifying older evidence
pub fn verify_dcap_at(
    expected: &DcapRegisters,
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let raw = dcap::validate_quote_at(quote, pccs, time)?;
    let mut mismatches = Vec::new();
    if raw.rtmr1 != expected.rtmr1 {
        report_mismatch(debug, "RTMR1", &raw.rtmr1, &expected.rtmr1);
        mismatches.push("RTMR1");
    }
    if raw.rtmr2 != expected.rtmr2 {
        report_mismatch(debug, "RTMR2", &raw.rtmr2, &expected.rtmr2);
        mismatches.push("RTMR2");
    }
    if !mismatches.is_empty() {
        return Err(VerifyError::RegisterMismatch(mismatches));
    }
    Ok(raw.report_data)
}

/// Log a register mismatch to stderr with actual and expected hex values
pub(crate) fn report_mismatch(debug: bool, name: &str, actual: &[u8], expected: &[u8]) {
    if !debug {
        return;
    }
    eprintln!("{name} mismatch:");
    eprintln!("  actual:   {}", hex::encode(actual));
    eprintln!("  expected: {}", hex::encode(expected));
}

/// Verify an Azure attestation document and check its PCRs against an
/// expected set of measurements
#[cfg(feature = "azure")]
pub fn verify_azure(
    expected: &AzureRegisters,
    document: &[u8],
    pccs: &Pccs,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    verify_azure_at(expected, document, pccs, time, debug)
}

/// Same as [`verify_azure`] but takes an explicit time argument
/// to support verifying older evidence
#[cfg(feature = "azure")]
pub fn verify_azure_at(
    expected: &AzureRegisters,
    document: &[u8],
    pccs: &Pccs,
    time: u64,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let raw = azure::validate_quote_at(document, pccs, time)?;
    let mut mismatches = Vec::new();
    if raw.pcr4 != expected.pcr4 {
        report_mismatch(debug, "PCR4", &raw.pcr4, &expected.pcr4);
        mismatches.push("PCR4");
    }
    if raw.pcr9 != expected.pcr9 {
        report_mismatch(debug, "PCR9", &raw.pcr9, &expected.pcr9);
        mismatches.push("PCR9");
    }
    if raw.pcr11 != expected.pcr11 {
        report_mismatch(debug, "PCR11", &raw.pcr11, &expected.pcr11);
        mismatches.push("PCR11");
    }
    if !mismatches.is_empty() {
        return Err(VerifyError::RegisterMismatch(mismatches));
    }
    Ok(raw.report_data)
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Platform of evidence does not match expected measurement type")]
    PlatformMismatch,
    #[error("Register mismatch: {}", .0.join(", "))]
    RegisterMismatch(Vec<&'static str>),
    #[error("Firmware blob required for self-hosted register verification")]
    MissingFirmware,
    #[error("Expected {0} could not be reconstructed")]
    IncompleteReconstruction(&'static str),
    #[cfg(not(feature = "azure"))]
    #[error("Azure verification requested but `azure` feature is not enabled")]
    AzureFeatureDisabled,
    #[error("Reconstructing expected registers: {0}")]
    Reconstruct(#[from] ReconstructError),
    #[error("DCAP: {0}")]
    Dcap(#[from] dcap::DcapError),
    #[error("Google firmware: {0}")]
    Google(#[from] GoogleError),
    #[cfg(feature = "azure")]
    #[error("Azure: {0}")]
    Azure(#[from] azure::error::AzureError),
}
