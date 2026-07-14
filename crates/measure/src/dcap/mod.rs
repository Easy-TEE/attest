//! Shared types and helpers for DCAP-based platforms (GCP, self-hosted,
//! etc)

pub mod firmware;
pub mod gcp;
pub mod secure_boot;
pub mod self_hosted;

mod gpt;
mod tdvf;
pub use firmware::{DcapFirmware, FirmwareError, GoogleError, HobTemplate};
use serde::Serialize;
use sha2::{Digest, Sha384};
pub use tdvf::{TdvfError, mrtd_sha384};
use thiserror::Error;
pub use types::DcapImageHashes;
use types::{AttestationType, PlatformMetadata};

use super::{
    Measurement,
    event::Register,
    uki::{Uki, to_utf16le_null_terminated},
};

/// Image-dependent DCAP register values
#[derive(Debug, Serialize)]
pub struct DcapRegisters {
    pub rtmr1: Register<Sha384>,
    pub rtmr2: Register<Sha384>,
}

impl Measurement for DcapRegisters {
    type Wire = types::DcapRegisters;

    fn finalize(&self) -> Self::Wire {
        types::DcapRegisters { rtmr1: self.rtmr1.value(), rtmr2: self.rtmr2.value() }
    }

    fn debug_json(&self) -> serde_json::Value {
        serde_json::json!({
            "rtmr1": self.rtmr1.debug_json(),
            "rtmr2": self.rtmr2.debug_json(),
        })
    }
}

/// Produces portable image hashes from a UKI and optional rootfs disk image
pub fn measure(uki: &Uki, rootfs: Option<&[u8]>) -> DcapImageHashes {
    DcapImageHashes {
        uki_authenticode: uki.authenticode_sha384,
        kernel_authenticode: uki.kernel_authenticode_sha384,
        cmdline_hash: sha384(&to_utf16le_null_terminated(&uki.cmdline)),
        initrd_hash: uki.section(".initrd").expect("UKI missing .initrd section").digest_sha384,
        gpt_disk_guid_hash: match rootfs {
            Some(rootfs) => gpt::disk_guid_hash_from_header(rootfs),
            None => gpt::disk_guid_hash(uki.size),
        },
    }
}

/// RTMR2 from portable image hashes (identical on GCP and self-hosted)
pub fn build_rtmr2(hashes: &DcapImageHashes) -> Register<Sha384> {
    let mut mr = Register::new();
    mr.extend_raw(hashes.cmdline_hash, "cmdline (UTF-16LE)");
    mr.extend_raw(hashes.initrd_hash, "initrd");
    mr
}

pub(crate) fn sha384(data: &[u8]) -> [u8; 48] {
    Sha384::digest(data).into()
}

/// Reconstructed DCAP register values
/// Some fields will be None if reconstruction is incomplete due to missing
/// firmware or platform metadata
#[derive(Debug, Clone, Copy)]
pub struct ExpectedDcapRegisters {
    pub mrtd: Option<[u8; 48]>,
    pub rtmr0: Option<[u8; 48]>,
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
}

#[derive(Error, Debug)]
pub enum ReconstructError {
    #[error("Azure attestations have no DCAP registers")]
    NotDcap,
    #[error("platform metadata missing ACPI hashes")]
    MissingAcpi,
    #[error("GCP reconstruction requires firmware")]
    MissingFirmware,
    #[error("firmware: {0}")]
    Firmware(#[from] FirmwareError),
}

/// Reconstruct expected DCAP registers from image hashes/platform metadata
pub fn expected_dcap_registers(
    image: &DcapImageHashes,
    platform: &PlatformMetadata,
    firmware: Option<&DcapFirmware>,
) -> Result<ExpectedDcapRegisters, ReconstructError> {
    let rtmr2 = build_rtmr2(image).value();
    match platform.attestation_type {
        AttestationType::GcpTdx => {
            let acpi = platform.acpi.as_ref().ok_or(ReconstructError::MissingAcpi)?;
            let firmware = firmware.ok_or(ReconstructError::MissingFirmware)?;
            let rtmr0 =
                gcp::build_rtmr0(firmware, platform.ram_bytes, acpi, platform.num_disks)?.value();
            let rtmr1 = gcp::build_rtmr1(image).value();
            Ok(ExpectedDcapRegisters {
                mrtd: Some(firmware.mrtd),
                rtmr0: Some(rtmr0),
                rtmr1,
                rtmr2,
            })
        }
        AttestationType::SelfHostedTdx => {
            let rtmr1 = self_hosted::build_rtmr1(image).value();
            let (mrtd, rtmr0) = match firmware {
                Some(fw) => {
                    let acpi = platform.acpi.as_ref().ok_or(ReconstructError::MissingAcpi)?;
                    let rtmr0 = self_hosted::build_rtmr0(fw, platform.ram_bytes, acpi)?.value();
                    (Some(fw.mrtd), Some(rtmr0))
                }
                None => (None, None),
            };
            Ok(ExpectedDcapRegisters { mrtd, rtmr0, rtmr1, rtmr2 })
        }
        AttestationType::AzureTdx => Err(ReconstructError::NotDcap),
    }
}
