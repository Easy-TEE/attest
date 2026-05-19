//! Detect the current CVM platform and gather hardware metadata

use std::process::Command;

use thiserror::Error;
use types::{AttestationType, PlatformMetadata};

use crate::ccel;

/// Identify the host platform and read system specs
pub fn metadata() -> Result<PlatformMetadata, PlatformError> {
    metadata_for(detect()?)
}

/// Read system specs for a caller-supplied attestation type. Use this when
/// the platform has already been determined (e.g. by an `attested-tls`
/// generator with an explicit configuration).
pub fn metadata_for(attestation_type: AttestationType) -> Result<PlatformMetadata, PlatformError> {
    let acpi = match attestation_type {
        AttestationType::GcpTdx | AttestationType::SelfHostedTdx => {
            Some(ccel::read_acpi_hashes().map_err(PlatformError::Ccel)?)
        }
        _ => None,
    };
    Ok(PlatformMetadata { attestation_type, ram_bytes: ram_bytes()?, num_disks: num_disks()?, acpi })
}

/// Identify the host platform via `systemd-detect-virt`
pub fn detect() -> Result<AttestationType, PlatformError> {
    let output = Command::new("systemd-detect-virt").output()?;
    let virt = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(match virt.as_str() {
        "google" => AttestationType::GcpTdx,
        "microsoft" => AttestationType::AzureTdx,
        "kvm" | "qemu" => AttestationType::SelfHostedTdx,
        "none" => return Err(PlatformError::NotInTee),
        other => return Err(PlatformError::UnknownPlatform(other.to_string())),
    })
}

fn ram_bytes() -> Result<u64, PlatformError> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")?;
    let kb: u64 = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|n| n.trim().parse().ok())
        .ok_or(PlatformError::MemInfoParse)?;
    Ok(kb * 1024)
}

fn num_disks() -> Result<u32, PlatformError> {
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

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("Not running in a TEE")]
    NotInTee,
    #[error("Unrecognized platform: {0}")]
    UnknownPlatform(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parsing /proc/meminfo")]
    MemInfoParse,
    #[error("CCEL: {0:#}")]
    Ccel(anyhow::Error),
}
