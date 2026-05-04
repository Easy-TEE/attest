//! GCP TDX measurement

use anyhow::Result;
use hex_literal::hex;
use sha2::Sha384;

use super::tdvf;
use super::{DcapImageHashes, DcapRegisters, build_rtmr2};
use crate::measure::event::{
    CALLING_EFI_APP, EXIT_BOOT_SERVICES, EXIT_BOOT_SERVICES_SUCCESS, Register, SEPARATOR,
};
use crate::platform_events::{
    BOOT_0000_HASH, BOOT_0001_HASH, BOOT_0002_HASH, BOOT_ORDER_BYTES, MachineConfig,
    fetch_firmware, firmware_mrtds, machine_configs,
};

// SHA-384 of the EV_EFI_VARIABLE_DRIVER_CONFIG events for GCP's TDX firmware
// TODO: don't hardcode these
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

/// Full GCP measurement
pub fn measure(hashes: &DcapImageHashes, configs: &[String]) -> Result<DcapRegisters> {
    let machines: Vec<&MachineConfig> = machine_configs()
        .iter()
        .filter(|m| configs.is_empty() || configs.iter().any(|n| n == &m.name))
        .collect();
    if machines.is_empty() {
        anyhow::bail!("no machine configs match {configs:?}");
    }

    let mut mrtd = Vec::new();
    let mut rtmr0 = Vec::new();
    for fw in firmware_mrtds() {
        let bytes = fetch_firmware(&fw.firmware_file_hash)?;
        let cfv_image_hash = tdvf::cfv_sha384(&bytes)?;
        mrtd.push(fw.mrtd);
        for machine in &machines {
            rtmr0.push(build_rtmr0(machine, cfv_image_hash));
        }
    }

    Ok(DcapRegisters {
        mrtd,
        rtmr0,
        rtmr1: vec![build_rtmr1(hashes)],
        rtmr2: vec![build_rtmr2(hashes)],
    })
}

/// RTMR0: platform events (firmware, ACPI, boot order), does not depend on the image
///
/// `cfv_image_hash` is the SHA-384 of the OVMF Configuration Firmware Volume
pub fn build_rtmr0(machine: &MachineConfig, cfv_image_hash: [u8; 48]) -> Register<Sha384> {
    let mut mr = Register::new();
    mr.extend_raw(machine.td_hob_hash, "TD HOB");
    mr.extend_raw(cfv_image_hash, "CFV image");
    mr.extend_raw(SECURE_BOOT_HASH, "secure boot");
    mr.extend_raw(PK_HASH, "PK");
    mr.extend_raw(KEK_HASH, "KEK");
    mr.extend_raw(DB_HASH, "db");
    mr.extend_raw(DBX_HASH, "dbx");
    mr.extend(SEPARATOR, "separator");
    mr.extend_raw(machine.acpi_loader_hash, "ACPI loader");
    mr.extend_raw(machine.acpi_rsdp_hash, "ACPI RSDP");
    mr.extend_raw(machine.acpi_tables_hash, "ACPI tables");
    mr.extend(&BOOT_ORDER_BYTES, "boot order");
    mr.extend_raw(BOOT_0001_HASH, "boot 0001");
    mr.extend_raw(BOOT_0002_HASH, "boot 0002");
    mr.extend_raw(BOOT_0000_HASH, "boot 0000");
    mr
}

/// RTMR1 on GCP
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measure::dcap::build_rtmr2;
    use crate::platform_events::{firmware_mrtds, machine_configs};

    /// Image hashes from a build of flashbox-l1
    fn supplied_image_hashes() -> DcapImageHashes {
        DcapImageHashes {
            cmdline_hash: hex!(
                "e03b89abf354a38976537b7a9138fd312e4cbf73b61eebc44086491701b1d167b9f6cb97a922325866c93e0834723d87"
            ),
            gpt_disk_guid_hash: hex!(
                "a3a41b0f933aec447be266dec5f907c2b0ba89afbc3f4f7378f0dca844969cbfca324ed64f1720da6e9d4484fda4f9da"
            ),
            initrd_hash: hex!(
                "305d9b8e2ce9b62bda924a990eed5234c8441882ba2cd603a427b1ac4180124bf1a49a4b49eae1796983ad608a4da666"
            ),
            kernel_authenticode: hex!(
                "b6c5133268aa8b440509f3d53ee855a5cd3aeb6441eb109a9f27f14c43bce3e2383856df4af876501ceeb4c9a3b15f0c"
            ),
            uki_authenticode: hex!(
                "9b678ccbad7fc2f3935e3e760cf8daedd6e3e3e5a327e72ee9473399b7effac6bb5590002ed73a53f6b3a97d296852e2"
            ),
        }
    }
    /// Register values observed on a GCP deployment with that image
    const OBSERVED_MRTD: [u8; 48] = hex!(
        "feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"
    );
    const OBSERVED_RTMR0: [u8; 48] = hex!(
        "e1d0235496f93f9475bf0b26d33da5c15831cfc94104d6bea7ab82db027c5f1e917d47dda6953eefae7dcb20ab6f75c4"
    );
    const OBSERVED_RTMR1: [u8; 48] = hex!(
        "2bd4946acfa6ccc29f9efa08a78fd5ace02194d0bc38d056003d2937c216e0de08dba010a661c4b344756234f08a4cf2"
    );
    const OBSERVED_RTMR2: [u8; 48] = hex!(
        "4ae34b6b64c2a618c7ee61f488219fcd8383d149ad7e44606616598d73bd3f7a2f20846d780463278715433d9813af2c"
    );
    /// SHA384 hash of GCP OVMF firmware associated with observed MRTD
    const OBSERVED_CFV_IMAGE_HASH: [u8; 48] = hex!(
        "9cb6bf09aea7b4acb8549e328d0edd6f15defc0b00d744bb9fb5bab0962bc5c70f69d233e96dbc7c1105ba085781dc88"
    );

    #[test]
    fn captured_quote_mrtd_is_a_known_gcp_firmware_measurement() {
        assert!(
            firmware_mrtds().iter().any(|fw| fw.mrtd == OBSERVED_MRTD),
            "Observed quote MRTD is not present in mrtds.json"
        );
    }

    #[test]
    fn builds_image_dependent_registers_from_supplied_hashes() {
        let hashes = supplied_image_hashes();

        assert_eq!(build_rtmr1(&hashes).value(), OBSERVED_RTMR1);
        assert_eq!(build_rtmr2(&hashes).value(), OBSERVED_RTMR2);
    }

    #[test]
    fn builds_rtmr0_from_known_gcp_firmware_and_machine_config() {
        let machine = machine_configs()
            .iter()
            .find(|m| m.name == "c3-standard-4")
            .unwrap();

        assert_eq!(
            build_rtmr0(machine, OBSERVED_CFV_IMAGE_HASH).value(),
            OBSERVED_RTMR0
        );
    }
}
