//! GCP TDX expected register rebuild

use measure::dcap::gcp::{KNOWN_CFV, KNOWN_MRTD};
use pccs::Pccs;
use types::{DcapImageHashes, PlatformMetadata};

use crate::{VerifyError, dcap};

pub fn verify_portable(
    image_hashes: &DcapImageHashes,
    platform: &PlatformMetadata,
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
) -> Result<[u8; 64], VerifyError> {
    let raw = dcap::validate_quote_at(quote, pccs, time)?;
    let acpi = platform.acpi.as_ref().ok_or(VerifyError::MissingAcpi)?;
    let PlatformMetadata { num_disks, ram_bytes, .. } = platform;

    let expected_rtmr0 =
        measure::dcap::gcp::build_rtmr0(*ram_bytes, KNOWN_CFV, acpi, *num_disks)?.value();
    let expected_rtmr1 = measure::dcap::gcp::build_rtmr1(image_hashes).value();
    let expected_rtmr2 = measure::dcap::build_rtmr2(image_hashes).value();

    if raw.mrtd != KNOWN_MRTD ||
        raw.rtmr0 != expected_rtmr0 ||
        raw.rtmr1 != expected_rtmr1 ||
        raw.rtmr2 != expected_rtmr2
    {
        return Err(VerifyError::RegisterMismatch);
    }
    Ok(raw.report_data)
}
