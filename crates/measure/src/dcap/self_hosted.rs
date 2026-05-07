//! Self-hosted TDX measurement

use anyhow::Result;
use sha2::Sha384;
use types::PlatformMetadata;

use super::{DcapImageHashes, DcapRegisters};
use crate::event::{
    CALLING_EFI_APP,
    EXIT_BOOT_SERVICES,
    EXIT_BOOT_SERVICES_SUCCESS,
    Register,
    SEPARATOR,
};

/// Full self-hosted TDX measurement
pub fn measure(
    _hashes: &DcapImageHashes,
    _firmware: &[u8],
    _platform: &PlatformMetadata,
) -> Result<DcapRegisters> {
    // TODO: compute for td-shim?
    todo!()
}

/// Generated RTMR1 for self-hosted TDX image
pub fn build_rtmr1(hashes: &DcapImageHashes) -> Register<Sha384> {
    let mut mr = Register::new();
    mr.extend_raw(hashes.kernel_authenticode, "kernel authenticode");
    mr.extend(CALLING_EFI_APP, "calling EFI app");
    mr.extend(SEPARATOR, "separator");
    mr.extend(EXIT_BOOT_SERVICES, "exit boot services");
    mr.extend(EXIT_BOOT_SERVICES_SUCCESS, "exit boot services success");
    mr
}
