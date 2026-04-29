//! Platform-dependent measurement constants and machine configurations

use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;

const FIRMWARE_BUCKET: &str = "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm";

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

/// Raw bytes for the BootOrder event ([0001, 0002, 0000] as U16-LE)
pub const BOOT_ORDER_BYTES: [u8; 6] = [0x01, 0x00, 0x02, 0x00, 0x00, 0x00];

#[serde_with::apply([u8; 48] => #[serde_as(as = "Hex")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfig {
    pub name: String,
    pub td_hob_hash: [u8; 48],
    pub acpi_loader_hash: [u8; 48],
    pub acpi_rsdp_hash: [u8; 48],
    pub acpi_tables_hash: [u8; 48],
}

#[serde_with::apply([u8; 48] => #[serde_as(as = "Hex")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareMrtd {
    pub firmware_file_hash: [u8; 48],
    pub mrtd: [u8; 48],
}

// TODO: Get these dynamically from mripper
pub fn machine_configs() -> &'static [MachineConfig] {
    static CONFIGS: OnceLock<Vec<MachineConfig>> = OnceLock::new();
    CONFIGS.get_or_init(|| {
        serde_json::from_str(include_str!("machine_configs.json"))
            .expect("invalid machine_configs.json")
    })
}

pub fn firmware_mrtds() -> &'static [FirmwareMrtd] {
    static MRTDS: OnceLock<Vec<FirmwareMrtd>> = OnceLock::new();
    MRTDS.get_or_init(|| {
        serde_json::from_str(include_str!("mrtds.json")).expect("invalid mrtds.json")
    })
}

/// Download an OVMF firmware blob from `gs://gce_tcb_integrity/ovmf_x64_csm`
pub fn fetch_firmware(file_hash: &[u8; 48]) -> Result<Vec<u8>> {
    let url = format!("{FIRMWARE_BUCKET}/{}.fd", hex::encode(file_hash));
    let resp = reqwest::blocking::get(&url).with_context(|| format!("download firmware {url}"))?;
    if !resp.status().is_success() {
        bail!("firmware download {} returned {}", url, resp.status());
    }
    Ok(resp.bytes()?.to_vec())
}
