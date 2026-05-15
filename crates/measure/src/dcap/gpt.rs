//! GPT disk-GUID hash construction for the EV_EFI_GPT_EVENT measurement
//!
//! Sizes are derived from the UKI byte length (same as mkosi.postoutput)

use sha2::{Digest, Sha384};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

const GPT_HEADER_LBA: u64 = 1;
const PARTITION_ENTRY_LBA: u64 = 2;
const ESP_STARTING_LBA: u64 = 2048;

const DISK_GUID: &str = "12345678-1234-5678-1234-567812345678";
const ESP_PARTITION_GUID: &str = "87654321-4321-8765-4321-876543218765";
const EFI_SYSTEM_PARTITION_GUID: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

/// FAT32 minimum size
const MIN_VFAT_BYTES: u64 = 260 * MIB;

/// Deterministic UEFI disk GUID hash for a UKI of `uki_size` bytes
pub(super) fn disk_guid_hash(uki_size: u64) -> [u8; 48] {
    // ESP size is rounded up to multiple of 4096 by systemd-repart
    let size_max = (uki_size + 32 * MIB).div_ceil(4096) * 4096;
    let esp_bytes = size_max.max(MIN_VFAT_BYTES);
    // Disk size rounded up to multiple of 1 GiB
    let disk_bytes = (size_max + MIB).div_ceil(GIB) * GIB;
    let disk_size_sectors = disk_bytes / 512;
    let esp_ending_lba = ESP_STARTING_LBA + esp_bytes / 512 - 1;

    let partition = build_partition(esp_ending_lba);

    // Partition array: 128 entries of 128 bytes each, only the first slot
    // populated
    let mut partition_array = vec![0u8; 128 * 128];
    partition_array[..128].copy_from_slice(&partition);
    let partition_array_crc = crc32fast::hash(&partition_array);

    // Hash header with CRC zeroed out, then write it into the header
    let mut header = build_header(disk_size_sectors, partition_array_crc);
    let header_crc = crc32fast::hash(&header);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());

    // UEFI_GPT_DATA: header || u64(num_partitions=1) || partition entry
    let mut blob = Vec::with_capacity(92 + 8 + 128);
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&1u64.to_le_bytes());
    blob.extend_from_slice(&partition);

    Sha384::digest(&blob).into()
}

/// 92-byte GPT primary header with empty HeaderCRC32
fn build_header(disk_size_sectors: u64, partition_array_crc: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(92);
    h.extend_from_slice(b"EFI PART"); // Signature
    h.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // Revision 1.0
    h.extend_from_slice(&92u32.to_le_bytes()); // HeaderSize
    h.extend_from_slice(&0u32.to_le_bytes()); // HeaderCRC32 (placeholder)
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    h.extend_from_slice(&GPT_HEADER_LBA.to_le_bytes()); // MyLBA
    h.extend_from_slice(&(disk_size_sectors - 1).to_le_bytes()); // AlternateLBA
    h.extend_from_slice(&2048u64.to_le_bytes()); // FirstUsableLBA
    h.extend_from_slice(&(disk_size_sectors - 34).to_le_bytes()); // LastUsableLBA
    h.extend_from_slice(&encode_guid(DISK_GUID));
    h.extend_from_slice(&PARTITION_ENTRY_LBA.to_le_bytes());
    h.extend_from_slice(&128u32.to_le_bytes()); // NumberOfPartitionEntries
    h.extend_from_slice(&128u32.to_le_bytes()); // SizeOfPartitionEntry
    h.extend_from_slice(&partition_array_crc.to_le_bytes());
    debug_assert_eq!(h.len(), 92);
    h
}

/// 128-byte ESP partition entry
fn build_partition(esp_ending_lba: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(128);
    p.extend_from_slice(&encode_guid(EFI_SYSTEM_PARTITION_GUID));
    p.extend_from_slice(&encode_guid(ESP_PARTITION_GUID));
    p.extend_from_slice(&ESP_STARTING_LBA.to_le_bytes());
    p.extend_from_slice(&esp_ending_lba.to_le_bytes());
    p.extend_from_slice(&0u64.to_le_bytes()); // Attributes

    // PartitionName: "esp" in UTF-16LE, padded to 72 bytes
    let mut name = [0u8; 72];
    for (i, c) in "esp".chars().enumerate() {
        let b = (c as u16).to_le_bytes();
        name[i * 2] = b[0];
        name[i * 2 + 1] = b[1];
    }
    p.extend_from_slice(&name);
    debug_assert_eq!(p.len(), 128);
    p
}

/// Encode a UEFI mixed-endian GUID
/// First three groups are little-endian
/// Last two big-endian
fn encode_guid(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut idx = 0;
    for (group_idx, atom) in s.split('-').enumerate() {
        let raw = hex::decode(atom).expect("invalid GUID hex");
        if group_idx <= 2 {
            for b in raw.iter().rev() {
                out[idx] = *b;
                idx += 1;
            }
        } else {
            for b in &raw {
                out[idx] = *b;
                idx += 1;
            }
        }
    }
    debug_assert_eq!(idx, 16);
    out
}
