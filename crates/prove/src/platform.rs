//! Detect the current CVM platform and gather hardware metadata

use std::process::Command;

use types::{AttestationType, PlatformMetadata};

use crate::ProveError;

/// Identify the host platform and read system specs
pub fn metadata() -> Result<PlatformMetadata, ProveError> {
    Ok(PlatformMetadata {
        attestation_type: detect()?,
        vcpus: vcpus()?,
        ram_bytes: ram_bytes()?,
        num_disks: num_disks()?,
    })
}

/// Identify the host platform via `systemd-detect-virt`
pub fn detect() -> Result<AttestationType, ProveError> {
    let output = Command::new("systemd-detect-virt").output()?;
    let virt = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(match virt.as_str() {
        "google" => AttestationType::GcpTdx,
        "microsoft" => AttestationType::AzureTdx,
        "kvm" | "qemu" => AttestationType::SelfHostedTdx,
        "none" => return Err(ProveError::NotInTee),
        other => return Err(ProveError::UnknownPlatform(other.to_string())),
    })
}

fn vcpus() -> Result<u32, ProveError> {
    let n = std::thread::available_parallelism()?.get();
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
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
