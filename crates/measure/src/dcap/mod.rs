//! Shared types and helpers for DCAP-based platforms (GCP, self-hosted,
//! etc)

pub mod gcp;
pub mod self_hosted;

mod gpt;
mod tdvf;

use serde::Serialize;
use sha2::{Digest, Sha384};
pub use types::DcapImageHashes;

use super::{
    Measurement,
    event::Register,
    uki::{Uki, to_utf16le_null_terminated},
};

/// Full DCAP register values (GCP or self-hosted)
/// RTMRs are `Vec`s to support multiple valid values (e.g. GCP firmware
/// variants)
#[serde_with::serde_as]
#[derive(Debug, Serialize)]
pub struct DcapRegisters {
    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    pub mrtd: Vec<[u8; 48]>,
    pub rtmr0: Vec<Register<Sha384>>,
    pub rtmr1: Vec<Register<Sha384>>,
    pub rtmr2: Vec<Register<Sha384>>,
}

impl Measurement for DcapRegisters {
    type Wire = types::DcapRegisters;

    fn finalize(&self) -> Self::Wire {
        types::DcapRegisters {
            mrtd: self.mrtd.clone(),
            rtmr0: self.rtmr0.iter().map(Register::value).collect(),
            rtmr1: self.rtmr1.iter().map(Register::value).collect(),
            rtmr2: self.rtmr2.iter().map(Register::value).collect(),
        }
    }

    fn debug_json(&self) -> serde_json::Value {
        let verbose = |rs: &[Register<Sha384>]| -> Vec<serde_json::Value> {
            rs.iter().map(Register::debug_json).collect()
        };
        serde_json::json!({
            "mrtd": self.mrtd.iter().map(hex::encode).collect::<Vec<_>>(),
            "rtmr0": verbose(&self.rtmr0),
            "rtmr1": verbose(&self.rtmr1),
            "rtmr2": verbose(&self.rtmr2),
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
