//! Firmware-based DCAP register reconstruction inputs

use prost::Message;
use rsa::{
    RsaPublicKey,
    pkcs8::DecodePublicKey,
    pss::{Signature, VerifyingKey},
    signature::Verifier,
};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;
use x509_parser::prelude::*;

use super::tdvf::{self, SECTION_TYPE_TD_HOB, SECTION_TYPE_TEMP_MEM};

const LOW_MEM_TOP: u64 = 0x8000_0000;
const LOW_MEM_TOP_GCP: u64 = 0xC000_0000;
const HIGH_MEM_START: u64 = 0x1_0000_0000;
const DEFAULT_TD_HOB_BASE: u64 = 0x80_9000;

/// Bucket containing Google's signed endorsements and firmware blobs
const ENDORSEMENT_BUCKET: &str = "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm";
/// Google root certificate for verifying endorsements
const ROOT_CERT_URL: &str = "https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt";

/// Firmware-based inputs needed to rebuild MRTD and RTMR0
#[serde_with::apply([u8; 48] => #[serde_as(as = "Hex")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcapFirmware {
    pub mrtd: [u8; 48],
    pub cfv: [u8; 48],
    pub hob: HobTemplate,
}

/// Contains HOB bytes with a placeholder for RAM amount
#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HobTemplate {
    #[serde_as(as = "Hex")]
    pub bytes: Vec<u8>,
    pub length_offset: usize,
    pub ram_threshold: u64,
}

#[derive(Error, Debug)]
pub enum FirmwareError {
    #[error("RAM ({ram_bytes:#x}) below firmware threshold ({threshold:#x})")]
    RamBelowThreshold { ram_bytes: u64, threshold: u64 },
    #[error("TDVF parse: {0:#}")]
    Tdvf(anyhow::Error),
    #[error("accepted regions extend allowed maximum: {cursor:#x} > {limit:#x}")]
    AcceptedExceedsLowMem { cursor: u64, limit: u64 },
}

impl HobTemplate {
    /// SHA-384 of the HOB list for the given RAM size
    pub fn digest(&self, ram_bytes: u64) -> Result<[u8; 48], FirmwareError> {
        let value = ram_bytes
            .checked_sub(self.ram_threshold)
            .ok_or(FirmwareError::RamBelowThreshold { ram_bytes, threshold: self.ram_threshold })?;
        let mut buf = self.bytes.clone();
        buf[self.length_offset..self.length_offset + 8].copy_from_slice(&value.to_le_bytes());
        Ok(Sha384::digest(&buf).into())
    }
}

impl DcapFirmware {
    /// Download and verify firmware for a GCP MRTD, then derive events
    pub fn from_google(mrtd: [u8; 48]) -> Result<Self, GoogleError> {
        let bytes = http_get(&format!("{ENDORSEMENT_BUCKET}/tdx/{}.binarypb", hex::encode(mrtd)))?;
        let endorsement = Endorsement::decode(&*bytes).map_err(|_| GoogleError::Endorsement)?;
        let golden = GoldenMeasurement::decode(&*endorsement.serialized_uefi_golden)
            .map_err(|_| GoogleError::Endorsement)?;
        verify_endorsement(&endorsement, &golden)?;

        let fw_raw = http_get(&format!("{ENDORSEMENT_BUCKET}/{}.fd", hex::encode(&golden.digest)))?;
        if Sha384::digest(&fw_raw)[..] != golden.digest[..] {
            return Err(GoogleError::Mismatch("firmware digest"));
        }

        let firmware = Self::from_blob(&fw_raw, true)?;
        if firmware.mrtd != mrtd {
            return Err(GoogleError::Mismatch("MRTD"));
        }
        Ok(firmware)
    }

    /// Derive firmware events by parsing firmware blob
    pub fn from_blob(fw: &[u8], gcp: bool) -> Result<Self, FirmwareError> {
        let mrtd = tdvf::mrtd_sha384(fw).map_err(FirmwareError::Tdvf)?;
        let cfv = tdvf::cfv_sha384(fw).map_err(FirmwareError::Tdvf)?;
        let hob = build_hob_template_from_blob(fw, gcp)?;
        Ok(Self { mrtd, cfv, hob })
    }
}

fn build_hob_template_from_blob(fw: &[u8], gcp: bool) -> Result<HobTemplate, FirmwareError> {
    let low_top = if gcp { LOW_MEM_TOP_GCP } else { LOW_MEM_TOP };

    let mut accepted = Vec::new();
    let mut td_hob_base = DEFAULT_TD_HOB_BASE;
    for s in tdvf::tdx_metadata_sections(fw).map_err(FirmwareError::Tdvf)? {
        // QEMU only accepts TD_HOB/TEMP_MEM sections
        if gcp || matches!(s.kind, SECTION_TYPE_TD_HOB | SECTION_TYPE_TEMP_MEM) {
            accepted.push((s.memory_address, s.memory_address + s.memory_data_size));
        }
        if s.kind == SECTION_TYPE_TD_HOB {
            td_hob_base = s.memory_address;
        }
    }

    let mut hob = vec![0u8; 56];
    hob[0] = 0x01; // HobType = EFI_HOB_TYPE_HANDOFF
    hob[2..4].copy_from_slice(&56u16.to_le_bytes()); // HobLength
    hob[8..12].copy_from_slice(&9u32.to_le_bytes()); // Version

    let mut cursor = 0u64;
    if gcp {
        // HOB order is [accepted, accepted, ..., unaccepted, unaccepted, ...]
        for &(start, end) in &accepted {
            push_memory_range(&mut hob, true, gcp, start, end - start);
        }
        let mut low: Vec<_> = accepted.into_iter().filter(|&(start, _)| start < low_top).collect();
        low.sort_unstable();
        for (start, end) in low {
            if start > cursor {
                push_memory_range(&mut hob, false, gcp, cursor, start - cursor);
            }
            cursor = cursor.max(end);
        }
    } else {
        // HOB order is [unaccepted, accepted, unaccepted, accepted, ...]
        accepted.sort_unstable();
        for (start, end) in accepted {
            if cursor < start {
                push_memory_range(&mut hob, false, gcp, cursor, start - cursor);
            }
            push_memory_range(&mut hob, true, gcp, start, end - start);
            cursor = end;
        }
    }

    if cursor > low_top {
        return Err(FirmwareError::AcceptedExceedsLowMem { cursor, limit: low_top });
    }
    if cursor < low_top {
        push_memory_range(&mut hob, false, gcp, cursor, low_top - cursor);
    }
    push_memory_range(&mut hob, false, gcp, HIGH_MEM_START, 0);

    let length_offset = hob.len() - 8;
    let mut end_of_hob_list = td_hob_base + hob.len() as u64;
    // QEMU ends HOB list with 8 byte EndOfHobList terminator
    if !gcp {
        end_of_hob_list += 8;
    }
    hob[48..56].copy_from_slice(&end_of_hob_list.to_le_bytes());

    Ok(HobTemplate { bytes: hob, length_offset, ram_threshold: low_top })
}

/// Append an EFI_HOB_RESOURCE_DESCRIPTOR for one physical memory range
fn push_memory_range(hob: &mut Vec<u8>, accepted: bool, gcp: bool, start: u64, length: u64) {
    let mut attribute: u32 = 0x07;
    // GCP sets bit 28 on unaccepted memory
    if !accepted && gcp {
        attribute |= 0x1000_0000;
    }
    hob.extend_from_slice(&[0x03, 0x00]); // HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR
    hob.extend_from_slice(&48u16.to_le_bytes()); // HobLength
    hob.extend_from_slice(&[0u8; 4]); // Reserved
    hob.extend_from_slice(&[0u8; 16]); // Owner
    hob.push(if accepted { 0x00 } else { 0x07 }); // ResourceType
    hob.extend_from_slice(&[0u8; 3]); // padding
    hob.extend_from_slice(&attribute.to_le_bytes()); // ResourceAttribute
    hob.extend_from_slice(&start.to_le_bytes());
    hob.extend_from_slice(&length.to_le_bytes());
}

#[derive(Message)]
struct Endorsement {
    // Raw bytes are needed verify signature
    #[prost(bytes = "vec", tag = "1")]
    serialized_uefi_golden: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

#[derive(Message)]
struct GoldenMeasurement {
    #[prost(bytes = "vec", tag = "4")]
    cert: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    digest: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum GoogleError {
    #[error("HTTP: {0}")]
    Http(String),
    #[error("malformed launch endorsement")]
    Endorsement,
    #[error("endorsement verification failed: {0}")]
    Verify(&'static str),
    #[error("{0} does not match endorsement")]
    Mismatch(&'static str),
    #[error("firmware: {0}")]
    Firmware(#[from] FirmwareError),
}

fn http_get(url: &str) -> Result<Vec<u8>, GoogleError> {
    ureq::get(url)
        .call()
        .and_then(|mut r| r.body_mut().read_to_vec())
        .map_err(|e| GoogleError::Http(e.to_string()))
}

// Checks that signature matches protobuf and is signed with Google root key
fn verify_endorsement(
    endorsement: &Endorsement,
    golden: &GoldenMeasurement,
) -> Result<(), GoogleError> {
    let leaf =
        X509Certificate::from_der(&golden.cert).map_err(|_| GoogleError::Verify("bad cert"))?.1;
    let root = http_get(ROOT_CERT_URL)?;
    let root = X509Certificate::from_der(&root).map_err(|_| GoogleError::Verify("root key"))?.1;
    leaf.verify_signature(Some(root.public_key()))
        .map_err(|_| GoogleError::Verify("cert chain"))?;

    let key = RsaPublicKey::from_public_key_der(leaf.public_key().raw)
        .map_err(|_| GoogleError::Verify("bad key"))?;
    let sig = Signature::try_from(&*endorsement.signature)
        .map_err(|_| GoogleError::Verify("signature"))?;
    VerifyingKey::<Sha256>::new(key)
        .verify(&endorsement.serialized_uefi_golden, &sig)
        .map_err(|_| GoogleError::Verify("signature"))
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    const GIB: u64 = 1 << 30;

    /// (RAM GiB, expected HOB digest) for recent GCP firmware
    const EXPECTED_HOB: [(u64, [u8; 48]); 4] = [
        (16, hex!("458994daa60deac8dea19dba79748f6ff93fd0aebb8e3e0be5a65eb12309d342c3ce31cc67af7bbd22af1a44e7d9fe21")),
        (32, hex!("aa9e81feeb58a9eb3a9f4110cc7b5696240437ea4c1a9c30518cfc44fa305183e6473e6bc02ddc4de09d0c49c49fadb5")),
        (88, hex!("a5be8ecd74020972e328fbbe94d2886817ef0d2e8a4e94e9572e8e1b221f3f608cddc868cf8b08e8e645e4aaeba68279")),
        (176, hex!("21092eadb73948aebb405b826354c23c3025635c89a8d91f85905afb120b7d98025a6c3083e8e82b5320695b253ce341")),
    ];

    #[test]
    fn check_gcp_firmware() {
        // MRTD+CFV for two GCP firmware releases
        let releases = [
            (
                // MRTD from March 2026 firmware
                hex!("8370d8f6d02f2d13e211e91c93fde923049522b241425a29a7bf0071ef49b250af4ef49d852fa3e10065d1b51dfce8fb"),
                // CFV from March 2026 firmware
                hex!("16a03d3d47d197945e85080880f6af2d87355f3d1eae2e27295d286e2ce7da3df4128d5d20a31d4c2cb3b20e91aecbca"),
            ),
            (
                // MRTD from April 2026 firmware
                hex!("feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"),
                // CFV from April 2026 firmware
                hex!("9cb6bf09aea7b4acb8549e328d0edd6f15defc0b00d744bb9fb5bab0962bc5c70f69d233e96dbc7c1105ba085781dc88"),
            ),
        ];
        for (mrtd, cfv) in releases {
            let firmware = DcapFirmware::from_google(mrtd).unwrap();
            assert_eq!(firmware.cfv, cfv, "cfv mrtd={}", hex::encode(mrtd));
            for (gib, expected) in EXPECTED_HOB {
                assert_eq!(
                    firmware.hob.digest(gib * GIB).unwrap(),
                    expected,
                    "mrtd={} ram={gib} GiB",
                    hex::encode(mrtd),
                );
            }
        }
    }
}
