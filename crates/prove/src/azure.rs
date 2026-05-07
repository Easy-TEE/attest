//! Azure vTPM attestation generation: package a TDX quote together with the
//! HCL report and a vTPM-signed quote of the AK certificate

use az_tdx_vtpm::{hcl, imds, vtpm};
use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};
use serde::Serialize;
use thiserror::Error;
use tss_esapi::{
    Context,
    handles::NvIndexTpmHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

/// NV index where the AK certificate lives in the Azure vTPM
const TPM_AK_CERT_IDX: u32 = 0x1C101D0;

#[derive(Serialize)]
struct AttestationDocument {
    tdx_quote_base64: String,
    hcl_report_base64: String,
    tpm_attestation: TpmAttest,
}

#[derive(Serialize)]
struct TpmAttest {
    ak_certificate_pem: String,
    quote: vtpm::Quote,
    event_log: Vec<u8>,
    instance_info: Option<Vec<u8>>,
}

pub fn create_quote(input_data: [u8; 64]) -> Result<Vec<u8>, AzureError> {
    let hcl_report_bytes = vtpm::get_report_with_report_data(&input_data)?;
    let hcl_report = hcl::HclReport::new(hcl_report_bytes.clone())?;
    let td_report = hcl_report.try_into()?;
    let td_quote_bytes = imds::get_td_quote(&td_report)?;
    let ak_certificate_der = read_ak_certificate_from_tpm()?;

    let document = AttestationDocument {
        tdx_quote_base64: BASE64_URL_SAFE.encode(&td_quote_bytes),
        hcl_report_base64: BASE64_URL_SAFE.encode(&hcl_report_bytes),
        tpm_attestation: TpmAttest {
            ak_certificate_pem: pem_rfc7468::encode_string(
                "CERTIFICATE",
                pem_rfc7468::LineEnding::default(),
                &ak_certificate_der,
            )?,
            quote: vtpm::get_quote(&input_data[..32])?,
            event_log: Vec::new(),
            instance_info: None,
        },
    };
    Ok(serde_json::to_vec(&document)?)
}

fn read_ak_certificate_from_tpm() -> Result<Vec<u8>, tss_esapi::Error> {
    let mut context = Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
    context.set_sessions((Some(AuthSession::Password), None, None));
    let nv_handle = NvIndexTpmHandle::new(TPM_AK_CERT_IDX)?;
    let buf = tss_esapi::abstraction::nv::read_full(&mut context, NvAuth::Owner, nv_handle)?;
    Ok(buf.to_vec())
}

#[derive(Error, Debug)]
pub enum AzureError {
    #[error("HCL report: {0}")]
    Report(#[from] az_tdx_vtpm::report::ReportError),
    #[error("IMDS: {0}")]
    Imds(#[from] imds::ImdsError),
    #[error("vTPM report: {0}")]
    VtpmReport(#[from] az_tdx_vtpm::vtpm::ReportError),
    #[error("HCL: {0}")]
    Hcl(#[from] hcl::HclError),
    #[error("vTPM quote: {0}")]
    VtpmQuote(#[from] vtpm::QuoteError),
    #[error("vTPM read: {0}")]
    TssEsapi(#[from] tss_esapi::Error),
    #[error("PEM encode: {0}")]
    Pem(#[from] pem_rfc7468::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}
