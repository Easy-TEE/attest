//! Cryptographic verification of a DCAP TDX quote against PCCS collateral

use std::time::{SystemTime, UNIX_EPOCH};

use dcap_qvl::{
    intel::{quote_ca, quote_fmspc},
    quote::Quote,
};
use pccs::{Pccs, PccsError};
use thiserror::Error;

/// Cryptographically attested register values plus report data extracted
/// from a DCAP TDX quote
pub struct ValidatedDcapQuote {
    pub mrtd: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub report_data: [u8; 64],
}

/// Verify a DCAP TDX quote against PCCS collateral and extract registers
pub fn validate_quote(quote: &[u8], pccs: &Pccs) -> Result<ValidatedDcapQuote, DcapError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    validate_quote_at(quote, pccs, time)
}

/// Same as [`validate_quote`] but takes an explicit time argument
/// to support validating older quotes
pub fn validate_quote_at(
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
) -> Result<ValidatedDcapQuote, DcapError> {
    let parsed = Quote::parse(quote)?;
    let ca = quote_ca(&parsed)?.as_id_str();
    let fmspc = hex::encode_upper(quote_fmspc(&parsed)?);
    let collateral = pccs.get_collateral_sync(fmspc, ca, time)?;
    let verified = dcap_qvl::verify::verify(quote, &collateral, time)?;
    let report = verified.report.as_td10().ok_or(DcapError::SgxNotSupported)?;
    Ok(ValidatedDcapQuote {
        mrtd: report.mr_td,
        rtmr0: report.rt_mr0,
        rtmr1: report.rt_mr1,
        rtmr2: report.rt_mr2,
        report_data: report.report_data,
    })
}

#[derive(Error, Debug)]
pub enum DcapError {
    #[error("SGX quote given when TDX quote expected")]
    SgxNotSupported,
    #[error("DCAP quote verification: {0}")]
    Verify(#[from] anyhow::Error),
    #[error("PCCS: {0}")]
    Pccs(#[from] PccsError),
}
