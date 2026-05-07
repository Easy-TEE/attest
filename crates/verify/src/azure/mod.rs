//! Microsoft Azure vTPM attestation evidence verification
mod ak_certificate;
mod ak_pubkey;
pub mod error;

use ak_certificate::verify_ak_cert_with_azure_roots;
use ak_pubkey::{HclRuntimeClaims, RsaPubKey};
use az_tdx_vtpm::{hcl, vtpm};
use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};
use dcap_qvl::QuoteCollateralV3;
use error::MaaError;
use openssl::pkey::PKey;
use pccs::Pccs;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::{dcap::verify_dcap_attestation_with_timestamp_sync, measurements::MultiMeasurements};

/// The attestation evidence payload that gets sent over the channel
#[derive(Debug, Serialize, Deserialize)]
struct AttestationDocument {
    /// TDX quote from the IMDS
    tdx_quote_base64: String,
    /// Serialized HCL report
    hcl_report_base64: String,
    /// vTPM related evidence
    tpm_attestation: TpmAttest,
}

/// TPM related components of the attestation document
#[derive(Debug, Serialize, Deserialize)]
struct TpmAttest {
    /// Attestation Key certificate from vTPM
    ak_certificate_pem: String,
    /// vTPM quote
    quote: vtpm::Quote,
    /// Raw TCG event log bytes (UEFI + IMA) [currently not used]
    ///
    /// `/sys/kernel/security/ima/ascii_runtime_measurements`,
    /// `/sys/kernel/security/tpm0/binary_bios_measurements`,
    event_log: Vec<u8>,
    /// Optional platform / instance metadata used to bind or verify the AK
    /// [currently not used]
    instance_info: Option<Vec<u8>>,
}

/// Carries the parsed-but-not-yet-verified attestation pieces between the
/// initial parse and the final verification step
struct PreparedAzureAttestation {
    tdx_quote_bytes: Vec<u8>,
    hcl_report: hcl::HclReport,
    var_data_hash: [u8; 32],
    expected_tdx_input_data: [u8; 64],
    tpm_attestation: TpmAttest,
}

/// Verify a TDX attestation from Azure
///
/// This relies on having DCAP collateral already present in the cache
pub fn verify_azure_attestation_sync(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
    override_azure_outdated_tcb: bool,
) -> Result<super::measurements::MultiMeasurements, MaaError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    verify_azure_attestation_with_given_timestamp_sync(
        input,
        expected_input_data,
        pccs,
        None,
        now,
        override_azure_outdated_tcb,
    )
}

/// Synchronous version of the verifier
fn verify_azure_attestation_with_given_timestamp_sync(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
    collateral: Option<QuoteCollateralV3>,
    now: u64,
    override_azure_outdated_tcb: bool,
) -> Result<super::measurements::MultiMeasurements, MaaError> {
    let PreparedAzureAttestation {
        tdx_quote_bytes,
        hcl_report,
        var_data_hash,
        expected_tdx_input_data,
        tpm_attestation,
    } = prepare_azure_attestation(input)?;

    let _dcap_measurements = verify_dcap_attestation_with_timestamp_sync(
        tdx_quote_bytes,
        expected_tdx_input_data,
        pccs,
        collateral,
        now,
        override_azure_outdated_tcb,
    )?;

    finish_azure_attestation_verification(
        hcl_report,
        var_data_hash,
        tpm_attestation,
        expected_input_data,
        now,
    )
}

/// Parses the attestation during verification
fn prepare_azure_attestation(input: Vec<u8>) -> Result<PreparedAzureAttestation, MaaError> {
    let attestation_document: AttestationDocument = serde_json::from_slice(&input)?;
    tracing::info!("Attempting to verify azure attestation: {attestation_document:?}");

    let AttestationDocument { tdx_quote_base64, hcl_report_base64, tpm_attestation } =
        attestation_document;

    let hcl_report_bytes = BASE64_URL_SAFE.decode(hcl_report_base64)?;
    let hcl_report = hcl::HclReport::new(hcl_report_bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();

    let mut expected_tdx_input_data = [0u8; 64];
    expected_tdx_input_data[..32].copy_from_slice(&var_data_hash);

    let tdx_quote_bytes = BASE64_URL_SAFE.decode(tdx_quote_base64)?;

    Ok(PreparedAzureAttestation {
        tdx_quote_bytes,
        hcl_report,
        var_data_hash,
        expected_tdx_input_data,
        tpm_attestation,
    })
}

/// The final part of vTPM verification, after verifying DCAP
fn finish_azure_attestation_verification(
    hcl_report: hcl::HclReport,
    var_data_hash: [u8; 32],
    tpm_attestation: TpmAttest,
    expected_input_data: [u8; 64],
    now: u64,
) -> Result<super::measurements::MultiMeasurements, MaaError> {
    let hcl_ak_pub = hcl_report.ak_pub()?;

    // Get attestation key from runtime claims
    let (ak_from_claims, user_data_input) = {
        let runtime_data_raw = hcl_report.var_data();
        let claims: HclRuntimeClaims = serde_json::from_slice(runtime_data_raw)?;

        let ak_jwk = claims
            .keys
            .iter()
            .find(|k| k.kid == "HCLAkPub")
            .ok_or(MaaError::ClaimsMissingHCLAkPub)?;

        let user_data = claims.user_data.as_deref().ok_or(MaaError::ClaimsMissingUserData)?;
        let user_data_bytes = hex::decode(user_data)?;
        let user_data_input: [u8; 64] =
            user_data_bytes.try_into().map_err(|_| MaaError::ClaimsUserDataBadLength)?;

        (RsaPubKey::from_jwk(ak_jwk)?, user_data_input)
    };

    // Check that the TD report input data matches the HCL var data hash
    let td_report: az_tdx_vtpm::tdx::TdReport = hcl_report.try_into()?;
    if var_data_hash != td_report.report_mac.reportdata[..32] {
        return Err(MaaError::TdReportInputMismatch);
    }
    if user_data_input != expected_input_data {
        return Err(MaaError::ClaimsUserDataInputMismatch);
    }

    // Verify the vTPM quote
    let vtpm_quote = tpm_attestation.quote;
    let hcl_ak_pub_der = hcl_ak_pub.key.try_to_der().map_err(|_| MaaError::JwkConversion)?;
    let pub_key = PKey::public_key_from_der(&hcl_ak_pub_der)?;
    vtpm_quote.verify(&pub_key, &expected_input_data[..32])?;

    let pcrs = vtpm_quote.pcrs_sha256();

    // Parse AK certificate
    let (_type_label, ak_certificate_der) =
        pem_rfc7468::decode_vec(tpm_attestation.ak_certificate_pem.as_bytes())?;

    let (remaining_bytes, ak_certificate) = X509Certificate::from_der(&ak_certificate_der)?;

    // Check that AK public key matches that from TPM quote and HCL claims
    let ak_from_certificate = RsaPubKey::from_certificate(&ak_certificate)?;
    let ak_from_hcl = RsaPubKey::from_openssl_pubkey(&pub_key)?;
    if ak_from_claims != ak_from_hcl {
        return Err(MaaError::AkFromClaimsNotEqualAkFromHcl);
    }
    if ak_from_claims != ak_from_certificate {
        return Err(MaaError::AkFromClaimsNotEqualAkFromCertificate);
    }

    // Strip trailing data from AK certificate
    let leaf_len = ak_certificate_der.len() - remaining_bytes.len();
    let ak_certificate_der_without_trailing_data = &ak_certificate_der[..leaf_len];

    // Verify the AK certificate against microsoft root cert
    verify_ak_cert_with_azure_roots(ak_certificate_der_without_trailing_data, now)?;

    Ok(MultiMeasurements::from_pcrs(pcrs))
}
