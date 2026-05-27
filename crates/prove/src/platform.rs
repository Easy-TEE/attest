//! Detect the current CVM platform and gather hardware metadata

use types::{AttestationType, PlatformMetadata};

use crate::{ProveError, ccel};

/// Identify the host platform and read system specs
pub fn metadata() -> Result<PlatformMetadata, ProveError> {
    let attestation_type = detect();
    let acpi = match attestation_type {
        AttestationType::GcpTdx | AttestationType::SelfHostedTdx => {
            Some(ccel::read_acpi_hashes().map_err(ProveError::Ccel)?)
        }
        _ => None,
    };
    let extra_disks = match attestation_type {
        AttestationType::GcpTdx => 2,
        AttestationType::AzureTdx => 1,
        _ => 0,
    };
    let num_disks = num_disks()? - extra_disks;
    let ram_bytes = ram_bytes()?;
    Ok(PlatformMetadata { attestation_type, ram_bytes, num_disks, acpi })
}

/// Identify the host platform from DMI/SMBIOS strings
pub fn detect() -> AttestationType {
    const DMI_FIELDS: &[&str] =
        &["product_name", "sys_vendor", "board_vendor", "bios_vendor", "product_version"];
    for field in DMI_FIELDS {
        let Some(s) = read_dmi(field) else { continue };
        if s.starts_with("Google Compute Engine") {
            return AttestationType::GcpTdx;
        }
        if s.starts_with("Hyper-V") {
            return AttestationType::AzureTdx;
        }
    }
    AttestationType::SelfHostedTdx
}

fn read_dmi(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/dmi/id/{name}")).ok().map(|s| s.trim().to_string())
}

/// Read the total RAM size by parsing memory device entries in DMI/SMBIOS
fn ram_bytes() -> Result<u64, ProveError> {
    const MIB: u64 = 1024 * 1024;
    let mut total = 0u64;
    for entry in std::fs::read_dir("/sys/firmware/dmi/entries")? {
        // Filter to only memory devices (type 17)
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("17-") {
            continue;
        }
        // Read the "raw" file which contains raw SMBIOS bytes
        let raw = std::fs::read(entry.path().join("raw"))?;
        let mb = match u16::from_le_bytes(raw[0x0C..0x0E].try_into().unwrap()) {
            // SMBIOS spec says that 0x7FFF indicates value over 32GB
            // In this case, the actual size is in bytes 0x1C-0x1F
            0x7FFF => u32::from_le_bytes(raw[0x1C..0x20].try_into().unwrap()) as u64,
            // Otherwise, the value is the size in MiB
            s => s as u64,
        };
        total += mb * MIB;
    }
    Ok(total)
}

fn num_disks() -> Result<u32, ProveError> {
    let mut n: u32 = 0;
    for entry in std::fs::read_dir("/sys/block")? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram")) {
            n += 1;
        }
    }
    Ok(n)
}
