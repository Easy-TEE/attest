//! GCP TDX measurement

use anyhow::{Result, ensure};
use hex_literal::hex;
use sha2::Sha384;
use types::AcpiHashes;

use super::{DcapImageHashes, DcapRegisters, build_rtmr2, secure_boot, td_hob};
use crate::event::{
    CALLING_EFI_APP,
    EXIT_BOOT_SERVICES,
    EXIT_BOOT_SERVICES_SUCCESS,
    Register,
    SEPARATOR,
};

/// GCP TDX firmware constants. Today these are pinned values; replace with
/// a verified GCE endorsement lookup when one is available.
pub const KNOWN_MRTD: [u8; 48] = hex!(
    "feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"
);
pub const KNOWN_CFV: [u8; 48] = hex!(
    "9cb6bf09aea7b4acb8549e328d0edd6f15defc0b00d744bb9fb5bab0962bc5c70f69d233e96dbc7c1105ba085781dc88"
);

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
pub fn measure(hashes: &DcapImageHashes) -> DcapRegisters {
    DcapRegisters { rtmr1: build_rtmr1(hashes), rtmr2: build_rtmr2(hashes) }
}

/// RTMR0: GCP-specific platform measurements (independent of image)
pub fn build_rtmr0(
    ram_bytes: u64,
    cfv: [u8; 48],
    acpi: &AcpiHashes,
    num_disks: u32,
) -> Result<Register<Sha384>> {
    ensure!(num_disks <= 1, "num_disks > 1 not yet supported"); // TODO
    let mut mr = Register::new();
    mr.extend_raw(td_hob::digest(ram_bytes)?, "TD HOB");
    mr.extend_raw(cfv, "CFV image");
    mr.extend_raw(secure_boot::secureboot_off(), "secure boot");
    mr.extend_raw(secure_boot::pk(), "PK");
    mr.extend_raw(secure_boot::kek(), "KEK");
    mr.extend_raw(secure_boot::db(), "db");
    mr.extend_raw(secure_boot::dbx(), "dbx");
    mr.extend(SEPARATOR, "separator");
    mr.extend_raw(acpi.loader, "ACPI loader");
    mr.extend_raw(acpi.rsdp, "ACPI RSDP");
    mr.extend_raw(acpi.tables, "ACPI tables");
    mr.extend(&boot_order_bytes(num_disks), "boot order");
    mr.extend_raw(BOOT_0001_HASH, "boot 0001");
    if num_disks >= 1 {
        mr.extend_raw(BOOT_0002_HASH, "boot 0002");
    }
    mr.extend_raw(BOOT_0000_HASH, "boot 0000");
    Ok(mr)
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
