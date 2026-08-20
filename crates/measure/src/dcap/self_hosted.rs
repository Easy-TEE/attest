//! Self-hosted TDX measurement

use hex_literal::hex;
use sha2::Sha384;
use types::AcpiHashes;

use super::{
    DcapFirmware,
    DcapImageHashes,
    DcapRegisters,
    FirmwareError,
    build_rtmr2,
    secure_boot::{EFI_GLOBAL_VARIABLE_GUID, EFI_IMAGE_SECURITY_DATABASE_GUID, secure_boot_hash},
};
use crate::{
    dcap::firmware::BOOT_0000_HASH,
    event::{CALLING_EFI_APP, EXIT_BOOT_SERVICES, EXIT_BOOT_SERVICES_SUCCESS, Register, SEPARATOR},
};

/// Boot path used by QEMU via fw_cfg when booting uki via -kernel
const UKI_BOOT_PATH: &[u8] = b"/rom@genroms/linuxboot_dma.bin\0";
const NEW_BOOT_0000_HASH: [u8; 48] =
    hex!("5068E6A9DED2A1C3A8EBB5D26004410EA8670742D8F444C5C3D161B76C66FA23A7B1D2FB3F9840570B675384B5818F2D");
const EFI_FIRMWARE_BOOT_HASH: [u8; 48] =
    hex!("DD424F2EEB35F3E8A2C2F50F6CC87FF90B7577E92CE63E13A22869D07D104FD5EA9800E6E4F12C5058FC4EAA78374F20");
const OS_DISK_BOOT_HASH: [u8; 48] =
    hex!("1F880024A6BE9E726579B30322F55EDD042DA0FD83CB0A70F76652603DE5B6AB42EC327654382114BA7832778B4D71D6");

/// Self-hosted RTMR1 and RTMR2 measurements
pub fn measure(hashes: &DcapImageHashes) -> DcapRegisters {
    DcapRegisters { rtmr1: build_rtmr1(hashes), rtmr2: build_rtmr2(hashes) }
}

/// RTMR0 rebuilt from firmware blob + platform metadata
pub fn build_rtmr0(
    firmware: &DcapFirmware,
    ram_bytes: u64,
    acpi: &AcpiHashes,
    smbios_handoff: Option<&[u8; 48]>,
    dm_verity_boot: bool,
) -> Result<Register<Sha384>, FirmwareError> {
    let global = &EFI_GLOBAL_VARIABLE_GUID;
    let db = &EFI_IMAGE_SECURITY_DATABASE_GUID;
    let mut mr = Register::new();
    mr.extend_raw(firmware.hob.digest(ram_bytes)?, "TD HOB");
    mr.extend_raw(firmware.cfv, "CFV image");
    // New OVMF versions measure fw_cfg events
    if smbios_handoff.is_some() {
        mr.extend_raw(super::sha384(&[0, 0]), "fw_cfg BootMenu");
        if !dm_verity_boot {
            mr.extend_raw(super::sha384(UKI_BOOT_PATH), "fw_cfg bootorder");
        }
    }
    mr.extend_raw(secure_boot_hash(global, "SecureBoot", &[]), "SecureBoot");
    mr.extend_raw(secure_boot_hash(global, "PK", &[]), "PK");
    mr.extend_raw(secure_boot_hash(global, "KEK", &[]), "KEK");
    mr.extend_raw(secure_boot_hash(db, "db", &[]), "db");
    mr.extend_raw(secure_boot_hash(db, "dbx", &[]), "dbx");
    mr.extend(SEPARATOR, "separator");
    mr.extend_raw(acpi.loader, "ACPI loader");
    mr.extend_raw(acpi.rsdp, "ACPI RSDP");
    mr.extend_raw(acpi.tables, "ACPI tables");
    let Some(smbios) = smbios_handoff else {
        // Older OVMF versions have a single default boot entry
        mr.extend(&[0, 0], "boot order");
        mr.extend_raw(BOOT_0000_HASH, "boot 0000");
        return Ok(mr);
    };
    // Newer OVMF versions have an additional events
    mr.extend_raw(*smbios, "SMBIOS handoff");
    let order: &[u8] = if dm_verity_boot { &[0, 0, 1, 0, 2, 0] } else { &[0, 0, 1, 0] };
    mr.extend(order, "BootOrder");
    mr.extend_raw(NEW_BOOT_0000_HASH, "Boot0000");
    mr.extend_raw(EFI_FIRMWARE_BOOT_HASH, "Boot0001");
    if dm_verity_boot {
        mr.extend_raw(OS_DISK_BOOT_HASH, "Boot0002");
    }
    Ok(mr)
}

/// RTMR1 for self-hosted TDX image
pub fn build_rtmr1(hashes: &DcapImageHashes) -> Register<Sha384> {
    let mut mr = Register::new();
    mr.extend_raw(hashes.uki_authenticode, "UKI authenticode");
    mr.extend(CALLING_EFI_APP, "calling EFI app");
    mr.extend(SEPARATOR, "separator");
    mr.extend_raw(hashes.kernel_authenticode, "kernel authenticode");
    mr.extend(EXIT_BOOT_SERVICES, "exit boot services");
    mr.extend(EXIT_BOOT_SERVICES_SUCCESS, "exit boot services success");
    mr
}
