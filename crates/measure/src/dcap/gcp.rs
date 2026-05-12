//! GCP TDX measurement

use anyhow::Result;
use hex_literal::hex;
use sha2::Sha384;

use super::{DcapImageHashes, DcapRegisters, build_rtmr2};
use crate::event::{
    CALLING_EFI_APP,
    EXIT_BOOT_SERVICES,
    EXIT_BOOT_SERVICES_SUCCESS,
    Register,
    SEPARATOR,
};

/// EFI Boot variable hashes
pub const BOOT_0001_HASH: [u8; 48] = hex!(
    "A25333C7AEC2E0993034938C7F11893B3C2BCAF67E88C342A3D586F6F7FAE2C6A1247A9ED86988080A6D4BE497D4FBB6"
);
pub const BOOT_0002_HASH: [u8; 48] = hex!(
    "9068065754FF3AE3DD58A5897535EEAF62A19A6757D82DD91349C41BAE2E3F208E268ABBA2A4378BC5C8D1ACF2FD260F"
);
pub const BOOT_0000_HASH: [u8; 48] = hex!(
    "23ADA07F5261F12F34A0BD8E46760962D6B4D576A416F1FEA1C64BC656B1D28EACF7047AE6E967C58FD2A98BFA74C298"
);

/// BootOrder event bytes: 0001, 0002..=(1+num_disks), 0000 (u16 LE)
pub fn boot_order_bytes(num_disks: u32) -> Vec<u8> {
    let mut entries = vec![0x0001u16];
    entries.extend((0..num_disks).map(|i| 0x0002 + i as u16));
    entries.push(0x0000);
    entries.iter().flat_map(|e| e.to_le_bytes()).collect()
}

/// GCP RTMR1 and RTMR2 measurements
pub fn measure(hashes: &DcapImageHashes, _configs: &[String]) -> Result<DcapRegisters> {
    Ok(DcapRegisters { rtmr1: build_rtmr1(hashes), rtmr2: build_rtmr2(hashes) })
}

/// RTMR1: GCP-specific image measurements (depends on image)
pub fn build_rtmr1(hashes: &DcapImageHashes) -> Register<Sha384> {
    let mut mr = Register::new();
    mr.extend(CALLING_EFI_APP, "calling EFI app");
    mr.extend(SEPARATOR, "separator");
    mr.extend_raw(hashes.gpt_disk_guid_hash, "GPT disk GUID");
    mr.extend_raw(hashes.uki_authenticode, "UKI authenticode");
    mr.extend_raw(hashes.kernel_authenticode, "kernel authenticode");
    mr.extend(EXIT_BOOT_SERVICES, "exit boot services");
    mr.extend(EXIT_BOOT_SERVICES_SUCCESS, "exit boot services success");
    mr
}
