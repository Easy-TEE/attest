//! Self-hosted TDX measurement

use anyhow::Result;
use sha2::Sha384;

use super::{DcapImageHashes, DcapRegisters};
use crate::measure::event::{
    CALLING_EFI_APP, EXIT_BOOT_SERVICES, EXIT_BOOT_SERVICES_SUCCESS, Register, SEPARATOR,
};
use crate::types::PlatformMetadata;

/// Full self-hosted TDX measurement
pub fn measure(
    _hashes: &DcapImageHashes,
    _firmware: &[u8],
    _platform: &PlatformMetadata,
) -> Result<DcapRegisters> {
    // TODO: compute for td-shim?
    todo!()
}

/// RTMR1 on self-hosted TDX
pub fn build_rtmr1(hashes: &DcapImageHashes) -> Register<Sha384> {
    let mut mr = Register::new();
    mr.extend_raw(hashes.kernel_authenticode, "kernel authenticode");
    mr.extend(CALLING_EFI_APP, "calling EFI app");
    mr.extend(SEPARATOR, "separator");
    mr.extend(EXIT_BOOT_SERVICES, "exit boot services");
    mr.extend(EXIT_BOOT_SERVICES_SUCCESS, "exit boot services success");
    mr
}
