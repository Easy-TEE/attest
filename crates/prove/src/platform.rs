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
    Ok(PlatformMetadata { attestation_type, ram_bytes: ram_bytes()?, num_disks: num_disks()?, acpi })
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

fn ram_bytes() -> Result<u64, ProveError> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")?;
    let kb: u64 = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|n| n.trim().parse().ok())
        .ok_or(ProveError::MemInfoParse)?;
    Ok(kb * 1024)
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
