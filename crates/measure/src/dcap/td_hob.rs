//! TD HOB digest computation

use anyhow::{Result, ensure};
use sha2::{Digest, Sha384};

use super::tdvf::{SECTION_TYPE_TD_HOB, SECTION_TYPE_TEMP_MEM, tdx_metadata_sections};

const TEMPLATE: &[u8; HASH_LEN] = include_bytes!("../../assets/td_hob_template.bin");
const HASH_LEN: usize = 0x248;
const RESOURCE_LENGTH_OFFSET: usize = 0x240;
const GIB: u64 = 1 << 30;

const LOW_MEM_TOP: u64 = 0x8000_0000;
const HIGH_MEM_START: u64 = 0x1_0000_0000;
/// RAM threshold where qemu splits memory
const HIGH_MEM_THRESHOLD: u64 = 0xB000_0000;

/// TD HOB digest for GCP c3-standard TDX VMs
pub fn digest(ram_bytes: u64) -> Result<[u8; 48]> {
    ensure!(ram_bytes > 3 * GIB, "RAM must be > 3 GiB, got {ram_bytes} B");
    let above_4g = ram_bytes - 3 * GIB;
    let mut buf = *TEMPLATE;
    buf[RESOURCE_LENGTH_OFFSET..HASH_LEN].copy_from_slice(&above_4g.to_le_bytes());
    Ok(Sha384::digest(buf).into())
}

/// TD HOB digest reconstructed from TDVF metadata for self-hosted TDX
pub fn digest_from_firmware(fw: &[u8], ram_bytes: u64) -> Result<[u8; 48]> {
    let mut accepted = Vec::new();
    let mut td_hob_base = 0x80_9000u64;
    for s in tdx_metadata_sections(fw)? {
        if matches!(s.kind, SECTION_TYPE_TD_HOB | SECTION_TYPE_TEMP_MEM) {
            accepted.push((s.memory_address, s.memory_address + s.memory_data_size));
        }
        if s.kind == SECTION_TYPE_TD_HOB {
            td_hob_base = s.memory_address;
        }
    }
    accepted.sort();

    let mut hob = vec![0u8; 56];
    hob[0] = 0x01; // HobType = EFI_HOB_TYPE_HANDOFF
    hob[2..4].copy_from_slice(&56u16.to_le_bytes()); // HobLength
    hob[8..12].copy_from_slice(&9u32.to_le_bytes()); // Version

    let mut cursor = 0u64;
    for (start, end) in accepted {
        if cursor < start {
            push_memory_range(&mut hob, false, cursor, start - cursor);
        }
        push_memory_range(&mut hob, true, start, end - start);
        cursor = end;
    }
    ensure!(cursor <= ram_bytes, "accepted regions exceed RAM ({cursor:#x} > {ram_bytes:#x})");

    let low_end = if ram_bytes >= HIGH_MEM_THRESHOLD { LOW_MEM_TOP } else { ram_bytes };
    if cursor < low_end {
        push_memory_range(&mut hob, false, cursor, low_end - cursor);
    }
    if ram_bytes >= HIGH_MEM_THRESHOLD {
        push_memory_range(&mut hob, false, HIGH_MEM_START, ram_bytes - LOW_MEM_TOP);
    }

    let end_of_hob_list = td_hob_base + hob.len() as u64 + 8;
    hob[48..56].copy_from_slice(&end_of_hob_list.to_le_bytes());
    Ok(Sha384::digest(&hob).into())
}

/// Append an EFI_HOB_RESOURCE_DESCRIPTOR for one physical memory range
fn push_memory_range(hob: &mut Vec<u8>, accepted: bool, start: u64, length: u64) {
    hob.extend_from_slice(&[0x03, 0x00]); // HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR
    hob.extend_from_slice(&48u16.to_le_bytes()); // HobLength
    hob.extend_from_slice(&[0u8; 4]); // Reserved
    hob.extend_from_slice(&[0u8; 16]); // Owner
    hob.push(if accepted { 0x00 } else { 0x07 }); // ResourceType
    hob.extend_from_slice(&[0u8; 3]); // padding
    hob.extend_from_slice(&7u32.to_le_bytes()); // ResourceAttribute
    hob.extend_from_slice(&start.to_le_bytes());
    hob.extend_from_slice(&length.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn matches_known_gcp_machine_digests() {
        let cases = [
            (16, hex!("458994daa60deac8dea19dba79748f6ff93fd0aebb8e3e0be5a65eb12309d342c3ce31cc67af7bbd22af1a44e7d9fe21")),
            (32, hex!("aa9e81feeb58a9eb3a9f4110cc7b5696240437ea4c1a9c30518cfc44fa305183e6473e6bc02ddc4de09d0c49c49fadb5")),
            (88, hex!("a5be8ecd74020972e328fbbe94d2886817ef0d2e8a4e94e9572e8e1b221f3f608cddc868cf8b08e8e645e4aaeba68279")),
            (176, hex!("21092eadb73948aebb405b826354c23c3025635c89a8d91f85905afb120b7d98025a6c3083e8e82b5320695b253ce341")),
        ];
        for (gib, expected) in cases {
            assert_eq!(digest(gib * GIB).unwrap(), expected, "ram={gib} GiB");
        }
    }
}
