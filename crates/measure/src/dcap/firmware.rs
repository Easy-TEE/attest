//! Firmware-based DCAP register reconstruction inputs

use hex_literal::hex;
use sha2::{Digest, Sha384};
use thiserror::Error;

use super::tdvf::{self, SECTION_TYPE_TD_HOB, SECTION_TYPE_TEMP_MEM};

const LOW_MEM_TOP: u64 = 0x8000_0000;
const LOW_MEM_TOP_GCP: u64 = 0xC000_0000;
const HIGH_MEM_START: u64 = 0x1_0000_0000;
const DEFAULT_TD_HOB_BASE: u64 = 0x80_9000;

const GCP_HOB_TEMPLATE: &[u8] = include_bytes!("../../assets/td_hob_template.bin");
const GCP_HOB_LENGTH_OFFSET: usize = 0x240;

/// Firmware-based inputs needed to rebuild MRTD and RTMR0
#[derive(Debug, Clone)]
pub struct DcapFirmware {
    pub mrtd: [u8; 48],
    pub cfv: [u8; 48],
    pub hob: HobTemplate,
}

/// Contains HOB bytes with a placeholder for RAM amount
#[derive(Debug, Clone)]
pub struct HobTemplate {
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
    /// Pinned snapshot of the current Google Cloud TDX firmware
    // TODO: replace with verified Google Cloud endorsement lookup
    pub fn gcp_hardcoded() -> Self {
        Self {
            mrtd: hex!("feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"),
            // TODO: derive these from the firmware blob
            cfv: hex!("9cb6bf09aea7b4acb8549e328d0edd6f15defc0b00d744bb9fb5bab0962bc5c70f69d233e96dbc7c1105ba085781dc88"),
            hob: HobTemplate {
                bytes: GCP_HOB_TEMPLATE.to_vec(),
                length_offset: GCP_HOB_LENGTH_OFFSET,
                ram_threshold: LOW_MEM_TOP_GCP,
            },
        }
    }

    // TODO: pub fn from_google(mrtd: [u8; 48]) -> Self
    // 1. get endorsement from public bucket
    // 2. verify endorsement signature
    // 3. get firmware file path from endorsement
    // 4. download firmware file
    // 5. parse firmware file to get HOB template and CFV

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

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn gcp_hob_digests_match_known_machine_values() {
        const GIB: u64 = 1 << 30;
        let firmware = DcapFirmware::gcp_hardcoded();
        let cases = [
            (16, hex!("458994daa60deac8dea19dba79748f6ff93fd0aebb8e3e0be5a65eb12309d342c3ce31cc67af7bbd22af1a44e7d9fe21")),
            (32, hex!("aa9e81feeb58a9eb3a9f4110cc7b5696240437ea4c1a9c30518cfc44fa305183e6473e6bc02ddc4de09d0c49c49fadb5")),
            (88, hex!("a5be8ecd74020972e328fbbe94d2886817ef0d2e8a4e94e9572e8e1b221f3f608cddc868cf8b08e8e645e4aaeba68279")),
            (176, hex!("21092eadb73948aebb405b826354c23c3025635c89a8d91f85905afb120b7d98025a6c3083e8e82b5320695b253ce341")),
        ];
        for (gib, expected) in cases {
            assert_eq!(firmware.hob.digest(gib * GIB).unwrap(), expected, "ram={gib} GiB");
        }
    }
}
