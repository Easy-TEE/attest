//! Self-hosted TDX register verification

use measure::dcap::{build_rtmr2, mrtd_sha384, self_hosted};
use pccs::Pccs;
use types::{DcapImageHashes, PlatformMetadata};

use crate::{VerifyError, dcap, report_mismatch};

pub fn verify_portable(
    image_hashes: &DcapImageHashes,
    platform: &PlatformMetadata,
    firmware: &[u8],
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let raw = dcap::validate_quote_at(quote, pccs, time)?;
    let acpi = platform.acpi.as_ref().ok_or(VerifyError::MissingAcpi)?;

    let expected_mrtd = mrtd_sha384(firmware)?;
    let expected_rtmr0 = self_hosted::build_rtmr0(firmware, platform.ram_bytes, acpi)?;
    let expected_rtmr1 = self_hosted::build_rtmr1(image_hashes);
    let expected_rtmr2 = build_rtmr2(image_hashes);

    let mut mismatches = Vec::new();
    if raw.mrtd != expected_mrtd {
        report_mismatch(debug, "MRTD", &raw.mrtd, &expected_mrtd);
        mismatches.push("MRTD");
    }
    for (name, actual, expected) in [
        ("RTMR0", raw.rtmr0, &expected_rtmr0),
        ("RTMR1", raw.rtmr1, &expected_rtmr1),
        ("RTMR2", raw.rtmr2, &expected_rtmr2),
    ] {
        if actual != expected.value() {
            report_mismatch(debug, name, &actual, &expected.value());
            if debug {
                eprintln!("  events:   {:#?}", expected.debug_json());
            }
            mismatches.push(name);
        }
    }
    if !mismatches.is_empty() {
        return Err(VerifyError::RegisterMismatch(mismatches));
    }
    Ok(raw.report_data)
}
