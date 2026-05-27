//! TDX Virtual Firmware (TDVF) metadata parsing
//!
//! Scans GUID table at the end of an OVMF blob to find the
//! TDX metadata descriptor, which is used to
//! get offsets of Configuration Firmware Volume (CFV)

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha384};

const FW_GUID_TABLE_OFFSET_FROM_END: usize = 0x20;
const FW_GUID_ENTRY_SIZE: usize = 18; // u16 size + 16-byte GUID

/// GUID identifying TDX metadata offset entry in firmware footer table
const TDX_METADATA_OFFSET_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";

const SECTION_TYPE_CFV: u32 = 1;
pub(super) const SECTION_TYPE_TD_HOB: u32 = 2;
pub(super) const SECTION_TYPE_TEMP_MEM: u32 = 3;

const PAGE_SIZE: u64 = 0x1000;
const MR_EXTEND_GRANULARITY: usize = 0x100;
const ATTRIBUTE_MR_EXTEND: u32 = 0x01;
const ATTRIBUTE_PAGE_AUG: u32 = 0x02;

/// MRTD value for a TD built from this firmware (single-pass page ordering, QEMU >= 9.0)
pub fn mrtd_sha384(fw: &[u8]) -> Result<[u8; 48]> {
    let mut h = Sha384::new();
    for s in tdx_metadata_sections(fw)? {
        let num_pages = s.memory_data_size / PAGE_SIZE;
        for page in 0..num_pages {
            let page_gpa = s.memory_address + page * PAGE_SIZE;
            if s.attributes & ATTRIBUTE_PAGE_AUG == 0 {
                extend_tdx_op(&mut h, b"MEM.PAGE.ADD", page_gpa);
            }
            if s.attributes & ATTRIBUTE_MR_EXTEND != 0 {
                for chunk in 0..(PAGE_SIZE as usize / MR_EXTEND_GRANULARITY) {
                    let gpa = page_gpa + (chunk * MR_EXTEND_GRANULARITY) as u64;
                    extend_tdx_op(&mut h, b"MR.EXTEND", gpa);
                    let start = s.image_offset as usize
                        + (page * PAGE_SIZE) as usize
                        + chunk * MR_EXTEND_GRANULARITY;
                    let end = start + MR_EXTEND_GRANULARITY;
                    if end > fw.len() {
                        bail!("section data out of bounds: {start}..{end} of {}", fw.len());
                    }
                    h.update(&fw[start..end]);
                }
            }
        }
    }
    Ok(h.finalize().into())
}

fn extend_tdx_op(h: &mut Sha384, op: &[u8], gpa: u64) {
    let mut buf = [0u8; 128];
    buf[..op.len()].copy_from_slice(op);
    buf[16..24].copy_from_slice(&gpa.to_le_bytes());
    h.update(buf);
}

/// SHA-384 of the Configuration Firmware Volume section of an OVMF blob
/// This is the value measured into RTMR0 as EV_EFI_PLATFORM_FIRMWARE_BLOB2
pub(super) fn cfv_sha384(fw: &[u8]) -> Result<[u8; 48]> {
    let cfv = configuration_firmware_volume(fw)?;
    Ok(Sha384::digest(cfv).into())
}

fn configuration_firmware_volume(fw: &[u8]) -> Result<&[u8]> {
    let sections = tdx_metadata_sections(fw)?;
    let cfv = sections
        .iter()
        .find(|s| s.kind == SECTION_TYPE_CFV)
        .context("no CFV section (type 1) in TDX metadata")?;
    let base = cfv.image_offset as usize;
    let end = base.checked_add(cfv.raw_data_size as usize).context("CFV section size overflow")?;
    if end > fw.len() {
        bail!("CFV section out of bounds: {}..{} of {}", base, end, fw.len());
    }
    Ok(&fw[base..end])
}

#[derive(Debug)]
pub(super) struct Section {
    pub(super) image_offset: u32,
    pub(super) raw_data_size: u32,
    pub(super) memory_address: u64,
    pub(super) memory_data_size: u64,
    pub(super) kind: u32,
    pub(super) attributes: u32,
}

pub(super) fn tdx_metadata_sections(fw: &[u8]) -> Result<Vec<Section>> {
    let offset = tdx_metadata_offset(fw)?;
    if offset > fw.len() {
        bail!("TDX metadata offset {} > firmware size {}", offset, fw.len());
    }
    let mut cursor = &fw[fw.len() - offset..];

    // descriptor: signature(4) + length(4) + version(4) + num_sections(4) = 16
    // bytes
    if cursor.len() < 16 {
        bail!("firmware too small for TDX metadata descriptor");
    }
    let num_sections = u32::from_le_bytes(cursor[12..16].try_into().unwrap());
    cursor = &cursor[16..];

    // section: image_offset(4) + raw_data_size(4) + memory_address(8) +
    // memory_size(8) + type(4) + attributes(4) = 32 bytes
    let mut sections = Vec::with_capacity(num_sections as usize);
    for _ in 0..num_sections {
        if cursor.len() < 32 {
            bail!("firmware truncated mid-section");
        }
        sections.push(Section {
            image_offset: u32::from_le_bytes(cursor[0..4].try_into().unwrap()),
            raw_data_size: u32::from_le_bytes(cursor[4..8].try_into().unwrap()),
            memory_address: u64::from_le_bytes(cursor[8..16].try_into().unwrap()),
            memory_data_size: u64::from_le_bytes(cursor[16..24].try_into().unwrap()),
            kind: u32::from_le_bytes(cursor[24..28].try_into().unwrap()),
            attributes: u32::from_le_bytes(cursor[28..32].try_into().unwrap()),
        });
        cursor = &cursor[32..];
    }
    Ok(sections)
}

fn tdx_metadata_offset(fw: &[u8]) -> Result<usize> {
    let guid_map = parse_guid_map(fw)?;
    let entry = guid_map
        .get(TDX_METADATA_OFFSET_GUID)
        .context("TDX metadata offset GUID not found in firmware footer")?;
    if entry.len() < 4 {
        bail!("TDX metadata offset entry too small: {} bytes", entry.len());
    }
    Ok(u32::from_le_bytes(entry[..4].try_into().unwrap()) as usize)
}

/// Scans the firmware footer GUID table backward to build GUID -> data map
fn parse_guid_map(fw: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    let table = parse_guid_table(fw)?;
    let mut map = HashMap::new();
    let mut remaining = table;
    while !remaining.is_empty() {
        let entry = last_entry(remaining)?;
        let entry_size = entry.size as usize;
        if remaining.len() < entry_size {
            bail!("table entry size {} > remaining table {}", entry_size, remaining.len());
        }
        let entry_start = remaining.len() - entry_size;
        let data_end = remaining.len() - FW_GUID_ENTRY_SIZE;
        map.insert(entry.guid_string(), remaining[entry_start..data_end].to_vec());
        remaining = &remaining[..entry_start];
    }
    Ok(map)
}

fn parse_guid_table(fw: &[u8]) -> Result<&[u8]> {
    if fw.len() < FW_GUID_TABLE_OFFSET_FROM_END {
        bail!("firmware too small for GUID table footer");
    }
    let trimmed = &fw[..fw.len() - FW_GUID_TABLE_OFFSET_FROM_END];
    let anchor = last_entry(trimmed)?;
    let table_size = anchor.size as usize;
    if trimmed.len() < table_size {
        bail!("GUID table size {} > firmware {}", table_size, trimmed.len());
    }
    let start = trimmed.len() - table_size;
    let end = trimmed.len() - FW_GUID_ENTRY_SIZE;
    Ok(&trimmed[start..end])
}

#[derive(Debug)]
struct Entry {
    size: u16,
    guid: [u8; 16],
}

impl Entry {
    /// Standard mixed-endian GUID string
    fn guid_string(&self) -> String {
        let g = &self.guid;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
            u16::from_le_bytes([g[4], g[5]]),
            u16::from_le_bytes([g[6], g[7]]),
            g[8],
            g[9],
            g[10],
            g[11],
            g[12],
            g[13],
            g[14],
            g[15],
        )
    }
}

fn last_entry(table: &[u8]) -> Result<Entry> {
    if table.len() < FW_GUID_ENTRY_SIZE {
        bail!("table too small for entry: {} < {}", table.len(), FW_GUID_ENTRY_SIZE);
    }
    let entry_start = table.len() - FW_GUID_ENTRY_SIZE;
    let data = &table[entry_start..];
    Ok(Entry {
        size: u16::from_le_bytes([data[0], data[1]]),
        guid: data[2..18].try_into().unwrap(),
    })
}
