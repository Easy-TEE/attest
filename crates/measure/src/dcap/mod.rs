//! Shared types and helpers for DCAP-based platforms (GCP, self-hosted,
//! etc)

pub mod gcp;
pub mod secure_boot;
pub mod self_hosted;
pub mod td_hob;

mod gpt;
#[allow(dead_code)]
mod tdvf;

use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha384};
pub use types::DcapImageHashes;
use types::{AttestationType, PlatformMetadata};

use super::{
    Measurement,
    event::Register,
    uki::{Uki, to_utf16le_null_terminated},
};

/// Expected DCAP TDX register values for a given image on a given
/// platform. Registers the platform does not constrain (e.g. RTMR0 on
/// self-hosted, where firmware reconstruction is not yet supported) are
/// returned as `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDcapRegisters {
    pub mrtd: Option<[u8; 48]>,
    pub rtmr0: Option<[u8; 48]>,
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
}

/// Rebuild expected DCAP register values from per-image hashes plus live
/// platform metadata (ACPI, RAM, disk count).
pub fn expected_dcap_registers(
    image: &DcapImageHashes,
    platform: &PlatformMetadata,
) -> Result<ExpectedDcapRegisters> {
    match platform.attestation_type {
        AttestationType::GcpTdx => {
            let acpi = platform.acpi.as_ref().ok_or_else(|| {
                anyhow::anyhow!("GCP RTMR0 reconstruction requires ACPI hashes")
            })?;
            let rtmr0 =
                gcp::build_rtmr0(platform.ram_bytes, gcp::KNOWN_CFV, acpi, platform.num_disks)?
                    .value();
            Ok(ExpectedDcapRegisters {
                mrtd: Some(gcp::KNOWN_MRTD),
                rtmr0: Some(rtmr0),
                rtmr1: gcp::build_rtmr1(image).value(),
                rtmr2: build_rtmr2(image).value(),
            })
        }
        AttestationType::SelfHostedTdx => Ok(ExpectedDcapRegisters {
            mrtd: None,
            rtmr0: None,
            rtmr1: self_hosted::build_rtmr1(image).value(),
            rtmr2: build_rtmr2(image).value(),
        }),
        other => bail!("attestation type {other:?} is not a DCAP TDX platform"),
    }
}

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

/// Produces portable image hashes from a UKI
pub fn measure(uki: &Uki) -> DcapImageHashes {
    DcapImageHashes {
        uki_authenticode: uki.authenticode_sha384,
        kernel_authenticode: uki.kernel_authenticode_sha384,
        cmdline_hash: sha384(&to_utf16le_null_terminated(&uki.cmdline)),
        initrd_hash: uki.section(".initrd").expect("UKI missing .initrd section").digest_sha384,
        gpt_disk_guid_hash: gpt::disk_guid_hash(uki.size),
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
