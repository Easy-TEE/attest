//! Microsoft Azure vTPM attestation evidence verification
mod ak_certificate;
mod ak_pubkey;
pub mod error;

use std::time::{SystemTime, UNIX_EPOCH};

use ak_certificate::verify_ak_cert_with_azure_roots;
use ak_pubkey::{HclRuntimeClaims, RsaPubKey};
use az_tdx_vtpm::{hcl, vtpm};
use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};
use dcap_qvl::intel::{quote_ca, quote_fmspc};
use error::AzureError;
use openssl::pkey::PKey;
use pccs::Pccs;
use serde::Deserialize;
use x509_parser::prelude::*;

use crate::dcap::DcapError;

/// FMSPC with which to override TCB level checks on Azure
const AZURE_BAD_FMSPC: &str = "90C06F000000";

/// Cryptographically attested PCR values plus report data extracted from
/// an Azure vTPM attestation document
pub struct ValidatedAzureQuote {
    pub pcr4: [u8; 32],
    pub pcr9: [u8; 32],
    pub pcr11: [u8; 32],
    pub report_data: [u8; 64],
}

/// Verify an Azure attestation document and extract PCR values
pub fn validate_quote(document: &[u8], pccs: &Pccs) -> Result<ValidatedAzureQuote, AzureError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_secs();
    validate_quote_at(document, pccs, time)
}

/// Same as [`validate_quote`] but takes an explicit time argument
/// to support validating older documents
pub fn validate_quote_at(
    document: &[u8],
    pccs: &Pccs,
    time: u64,
) -> Result<ValidatedAzureQuote, AzureError> {
    let document: AttestationDocument = serde_json::from_slice(document)?;
    let AttestationDocument { tdx_quote_base64, hcl_report_base64, tpm_attestation } = document;

    let hcl_report_bytes = BASE64_URL_SAFE.decode(hcl_report_base64)?;
    let hcl_report = hcl::HclReport::new(hcl_report_bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();

    // The embedded TDX quote's report_data is bound to var_data_hash + 32 zeros
    let mut expected_tdx_input_data = [0u8; 64];
    expected_tdx_input_data[..32].copy_from_slice(&var_data_hash);

    let tdx_quote_bytes = BASE64_URL_SAFE.decode(tdx_quote_base64)?;
    let tdx_report_data = validate_embedded_tdx_quote(&tdx_quote_bytes, pccs, time)?;
    if tdx_report_data != expected_tdx_input_data {
        return Err(AzureError::TdReportInputMismatch);
    }

    let hcl_ak_pub = hcl_report.ak_pub()?;

    // Get attestation key from runtime claims
    let claims: HclRuntimeClaims = serde_json::from_slice(hcl_report.var_data())?;
    let ak_jwk = claims
        .keys
        .iter()
        .find(|k| k.kid == "HCLAkPub")
        .ok_or(AzureError::ClaimsMissingHCLAkPub)?;
    let user_data = claims.user_data.as_deref().ok_or(AzureError::ClaimsMissingUserData)?;
    let report_data: [u8; 64] =
        hex::decode(user_data)?.try_into().map_err(|_| AzureError::ClaimsUserDataBadLength)?;
    let ak_from_claims = RsaPubKey::from_jwk(ak_jwk)?;

    // Check that the TD report input data matches the HCL var data hash
    let td_report: az_tdx_vtpm::tdx::TdReport = hcl_report.try_into()?;
    if var_data_hash != td_report.report_mac.reportdata[..32] {
        return Err(AzureError::TdReportInputMismatch);
    }

    // Verify the vTPM quote
    let hcl_ak_pub_der = hcl_ak_pub.key.try_to_der().map_err(|_| AzureError::JwkConversion)?;
    let pub_key = PKey::public_key_from_der(&hcl_ak_pub_der)?;
    tpm_attestation.quote.verify(&pub_key, &report_data[..32])?;
    let pcrs: Vec<[u8; 32]> = tpm_attestation.quote.pcrs_sha256().copied().collect();

    // Parse AK certificate
    let (_type_label, ak_certificate_der) =
        pem_rfc7468::decode_vec(tpm_attestation.ak_certificate_pem.as_bytes())?;
    let (remaining_bytes, ak_certificate) = X509Certificate::from_der(&ak_certificate_der)?;

    // Check that AK public key matches that from TPM quote and HCL claims
    let ak_from_certificate = RsaPubKey::from_certificate(&ak_certificate)?;
    let ak_from_hcl = RsaPubKey::from_openssl_pubkey(&pub_key)?;
    if ak_from_claims != ak_from_hcl {
        return Err(AzureError::AkFromClaimsNotEqualAkFromHcl);
    }
    if ak_from_claims != ak_from_certificate {
        return Err(AzureError::AkFromClaimsNotEqualAkFromCertificate);
    }

    // Strip trailing data from AK certificate, then verify against Microsoft
    // roots
    let leaf_len = ak_certificate_der.len() - remaining_bytes.len();
    verify_ak_cert_with_azure_roots(&ak_certificate_der[..leaf_len], time)?;

    Ok(ValidatedAzureQuote { pcr4: pcrs[4], pcr9: pcrs[9], pcr11: pcrs[11], report_data })
}

/// The Azure attestation evidence payload received from the prover
#[derive(Debug, Deserialize)]
struct AttestationDocument {
    /// TDX quote from the IMDS
    tdx_quote_base64: String,
    /// Serialized HCL report
    hcl_report_base64: String,
    /// vTPM related evidence
    tpm_attestation: TpmAttest,
}

/// TPM related components of the attestation document
#[derive(Debug, Deserialize)]
struct TpmAttest {
    /// Attestation Key certificate from vTPM
    ak_certificate_pem: String,
    /// vTPM quote
    quote: vtpm::Quote,
}

/// Verify the TDX quote embedded in an Azure attestation document and
/// return its report_data, with a TCB override for [`AZURE_BAD_FMSPC`]
fn validate_embedded_tdx_quote(
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
) -> Result<[u8; 64], DcapError> {
    let parsed = dcap_qvl::quote::Quote::parse(quote)?;
    let collateral = pccs.get_collateral_sync(
        hex::encode_upper(quote_fmspc(&parsed)?),
        quote_ca(&parsed)?.as_id_str(),
        time,
    )?;
    let verified = dcap_qvl::verify::dangerous_verify_with_tcb_override(
        quote,
        &collateral,
        time,
        tcb_override_info,
    )?;
    let report = verified.report.as_td10().ok_or(DcapError::SgxNotSupported)?;
    Ok(report.report_data)
}

fn tcb_override_info(mut tcb_info: dcap_qvl::tcb_info::TcbInfo) -> dcap_qvl::tcb_info::TcbInfo {
    if tcb_info.fmspc == AZURE_BAD_FMSPC {
        for level in &mut tcb_info.tcb_levels {
            level.tcb.sgx_components[7].svn = level.tcb.sgx_components[7].svn.min(3);
        }
    }
    tcb_info
}
