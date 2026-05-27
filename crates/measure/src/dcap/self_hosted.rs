//! Self-hosted TDX measurement

use anyhow::Result;
use sha2::Sha384;
use types::AcpiHashes;

use super::{
    DcapImageHashes,
    DcapRegisters,
    build_rtmr2,
    gcp::BOOT_0000_HASH,
    secure_boot::{EFI_GLOBAL_VARIABLE_GUID, EFI_IMAGE_SECURITY_DATABASE_GUID, secure_boot_hash},
    td_hob,
    tdvf::cfv_sha384,
};
use crate::event::{
    CALLING_EFI_APP,
    EXIT_BOOT_SERVICES,
    EXIT_BOOT_SERVICES_SUCCESS,
    Register,
    SEPARATOR,
};

/// Self-hosted RTMR1 and RTMR2 measurements
pub fn measure(hashes: &DcapImageHashes) -> DcapRegisters {
    DcapRegisters { rtmr1: build_rtmr1(hashes), rtmr2: build_rtmr2(hashes) }
}

/// RTMR0 rebuilt from firmware blob + platform metadata
pub fn build_rtmr0(fw: &[u8], ram_bytes: u64, acpi: &AcpiHashes) -> Result<Register<Sha384>> {
    let global = &EFI_GLOBAL_VARIABLE_GUID;
    let db = &EFI_IMAGE_SECURITY_DATABASE_GUID;
    let mut mr = Register::new();
    mr.extend_raw(td_hob::digest_from_firmware(fw, ram_bytes)?, "TD HOB");
    mr.extend_raw(cfv_sha384(fw)?, "CFV image");
    mr.extend_raw(secure_boot_hash(global, "SecureBoot", &[]), "SecureBoot");
    mr.extend_raw(secure_boot_hash(global, "PK", &[]), "PK");
    mr.extend_raw(secure_boot_hash(global, "KEK", &[]), "KEK");
    mr.extend_raw(secure_boot_hash(db, "db", &[]), "db");
    mr.extend_raw(secure_boot_hash(db, "dbx", &[]), "dbx");
    mr.extend(SEPARATOR, "separator");
    mr.extend_raw(acpi.loader, "ACPI loader");
    mr.extend_raw(acpi.rsdp, "ACPI RSDP");
    mr.extend_raw(acpi.tables, "ACPI tables");
    mr.extend(&[0x00, 0x00], "boot order");
    mr.extend_raw(BOOT_0000_HASH, "boot 0000");
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
