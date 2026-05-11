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

/// SHA-384 of the GCP EV_EFI_VARIABLE_DRIVER_CONFIG events
pub const SECURE_BOOT_HASH: [u8; 48] = hex!(
    "CFA4E2C606F572627BF06D5669CC2AB1128358D27B45BC63EE9EA56EC109CFAFB7194006F847A6A74B5EAED6B73332EC"
);
pub const PK_HASH: [u8; 48] = hex!(
    "905F6243BAF0D7C63CD672F89B16E15F99597E8D0392955E685172D447100123F7C490D178543922FADDF896625DABAB"
);
pub const KEK_HASH: [u8; 48] = hex!(
    "BE013B0D9188E72B870F598899C35864D6B25F029A7B5F21A037BACF61CA3646207AF2BC714D471407C9939317763C4A"
);
pub const DB_HASH: [u8; 48] = hex!(
    "723AD4D64F430BF6D325AB9D6C29147993DED5630002E42E13DF696EBC680C4BC14C392D2E113E141154E21723F890F6"
);
pub const DBX_HASH: [u8; 48] = hex!(
    "C61BAE1A3F7B7E6CC3B9B03F630B77292EBD232AE60E0E1916F980955EC38459529574B49F1898C367EAF6D8A62311F5"
);

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
