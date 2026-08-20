//! Detect the current CVM platform and gather hardware metadata

use thiserror::Error;
use types::{AttestationType, PlatformMetadata};

use crate::ccel::{self, CcelError};

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("CCEL: {0}")]
    Ccel(#[from] CcelError),
    #[error("Detected {detected_disks} disks is less than the {extra_disks} platform disks")]
    TooFewDisks { detected_disks: u32, extra_disks: u32 },
}

/// Identify the host platform and read system specs
pub fn metadata() -> Result<PlatformMetadata, PlatformError> {
    metadata_for(detect())
}

/// Read system specs for a given platform, skipping DMI-based detection
pub fn metadata_for(attestation_type: AttestationType) -> Result<PlatformMetadata, PlatformError> {
    let (acpi, smbios_handoff, dm_verity_boot) = match attestation_type {
        AttestationType::GcpTdx | AttestationType::SelfHostedTdx => {
            let info = ccel::read_ccel()?;
            (Some(info.acpi), info.smbios_handoff, info.dm_verity_boot)
        }
        _ => (None, None, false),
    };
    let extra_disks = match attestation_type {
        AttestationType::GcpTdx => 2,
        AttestationType::AzureTdx => 1,
        _ => 0,
    };
    let detected_disks = num_disks()?;

    let num_disks = detected_disks
        .checked_sub(extra_disks)
        .ok_or(PlatformError::TooFewDisks { detected_disks, extra_disks })?;

    let ram_bytes = ram_bytes()?;
    Ok(PlatformMetadata {
        attestation_type,
        ram_bytes,
        num_disks,
        acpi,
        smbios_handoff,
        dm_verity_boot,
    })
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
fn ram_bytes() -> Result<u64, PlatformError> {
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

fn num_disks() -> Result<u32, PlatformError> {
    let mut n: u32 = 0;
    for entry in std::fs::read_dir("/sys/block")? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if !is_virtual_block_device(&name) {
            n += 1;
        }
    }
    Ok(n)
}

/// Exclude virtual devices when counting the number of disks
fn is_virtual_block_device(name: &str) -> bool {
    ["dm-", "loop", "md", "ram", "zram"].iter().any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_virtual_block_devices() {
        for name in ["dm-0", "loop0", "md0", "ram0", "zram0"] {
            assert!(is_virtual_block_device(name), "{name}");
        }
    }

    #[test]
    fn identifies_physical_block_devices() {
        for name in ["nvme0n1", "sda", "vda"] {
            assert!(!is_virtual_block_device(name), "{name}");
        }
    }
}
