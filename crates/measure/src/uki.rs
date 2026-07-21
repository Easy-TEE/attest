use std::io::{Cursor, Read};

use authenticode::{PeOffsetError, authenticode_digest};
use object::{Object, ObjectSection, read::pe::PeFile64};
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UkiError {
    #[error("PE parse: {0}")]
    Pe(#[from] object::read::Error),
    #[error("authenticode digest: {0}")]
    Authenticode(#[from] PeOffsetError),
    #[error("disk image: {0}")]
    Disk(&'static str),
}

/// Parsed UKI with pre-computed digests
pub struct Uki {
    pub size: u64,
    pub sections: Vec<UkiSection>,
    pub authenticode_sha384: [u8; 48],
    pub authenticode_sha256: [u8; 32],
    pub kernel_authenticode_sha384: [u8; 48],
    pub kernel_authenticode_sha256: [u8; 32],
    pub cmdline: Vec<u8>,
    /// Only needed when the UKI is embedded in a disk image with a rootfs
    pub disk_guid_hash: Option<[u8; 48]>,
}

pub struct UkiSection {
    pub name: String,
    pub size: u32,
    pub digest_sha256: [u8; 32],
    pub digest_sha384: [u8; 48],
    pub measured: bool,
    pub measure_order: i32,
}

/// Sections measured by systemd-stub, in order
const UKI_MEASURED_SECTIONS: &[&str] =
    &[".linux", ".osrel", ".cmdline", ".initrd", ".splash", ".dtb", ".uname", ".sbat", ".pcrkey"];

impl Uki {
    /// Parse a UKI file (`.efi`) or a disk image (`.raw` / `.tar.gz`)
    /// Disk images are only needed when there's a separate rootfs
    pub fn parse(data: &[u8]) -> Result<Self, UkiError> {
        if data.starts_with(&[0x1f, 0x8b]) {
            // GCP .tar.gz containing .raw disk image containing UKI
            Self::parse(&untar_disk_raw(data)?)
        } else if data.get(512..520) == Some(b"EFI PART".as_slice()) {
            // .raw disk image containing UKI
            let disk_guid_hash = crate::dcap::gpt::disk_guid_hash_from_header(data);
            Self::parse_pe(&extract_uki(data)?, Some(disk_guid_hash))
        } else {
            // Only UKI with no rootfs
            Self::parse_pe(data, None)
        }
    }

    fn parse_pe(data: &[u8], disk_guid_hash: Option<[u8; 48]>) -> Result<Self, UkiError> {
        let pe = PeFile64::parse(data)?;

        let mut sections = Vec::new();
        let mut cmdline = Vec::new();
        let mut kernel_authenticode_sha384 = [0u8; 48];
        let mut kernel_authenticode_sha256 = [0u8; 32];

        for section in pe.sections() {
            let name = section.name().unwrap_or("").to_string();
            let section_data = section.data().unwrap_or(&[]);
            let digest_sha256: [u8; 32] = Sha256::digest(section_data).into();
            let digest_sha384: [u8; 48] = Sha384::digest(section_data).into();

            match name.as_str() {
                ".cmdline" => cmdline = section_data.to_vec(),
                ".linux" => {
                    kernel_authenticode_sha384 = pe_authenticode_sha384(section_data)?;
                    kernel_authenticode_sha256 = pe_authenticode_sha256(section_data)?;
                }
                _ => {}
            }

            let measured = should_measure(&name);
            let measure_order = section_measure_order(&name).map_or(-1, |i| i as i32);
            sections.push(UkiSection {
                size: section_data.len() as u32,
                digest_sha256,
                digest_sha384,
                measured,
                measure_order,
                name,
            });
        }

        sections.sort_by_key(|s| if s.measured { s.measure_order } else { i32::MAX });

        Ok(Uki {
            size: data.len() as u64,
            authenticode_sha384: pe_authenticode_sha384(data)?,
            authenticode_sha256: pe_authenticode_sha256(data)?,
            kernel_authenticode_sha384,
            kernel_authenticode_sha256,
            sections,
            cmdline,
            disk_guid_hash,
        })
    }

    pub fn section(&self, name: &str) -> Option<&UkiSection> {
        self.sections.iter().find(|s| s.name == name)
    }
}

impl UkiSection {
    /// Section name as null-terminated bytes (for PCR11 measurement)
    pub fn null_terminated_name(&self) -> Vec<u8> {
        let mut v = self.name.as_bytes().to_vec();
        if v.last() != Some(&0) {
            v.push(0);
        }
        v
    }
}

pub fn to_utf16le_null_terminated(input: &[u8]) -> Vec<u8> {
    let s = if input.last() == Some(&0) { &input[..input.len() - 1] } else { input };
    let text = String::from_utf8_lossy(s);
    let mut out: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    // null terminator
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

fn pe_authenticode_sha384(data: &[u8]) -> Result<[u8; 48], UkiError> {
    let pe = PeFile64::parse(data)?;
    let mut h = Sha384::new();
    authenticode_digest(&pe, &mut h)?;
    Ok(h.finalize().into())
}

fn pe_authenticode_sha256(data: &[u8]) -> Result<[u8; 32], UkiError> {
    let pe = PeFile64::parse(data)?;
    let mut h = Sha256::new();
    authenticode_digest(&pe, &mut h)?;
    Ok(h.finalize().into())
}

fn section_measure_order(name: &str) -> Option<usize> {
    UKI_MEASURED_SECTIONS.iter().position(|&s| s == name)
}

fn should_measure(name: &str) -> bool {
    UKI_MEASURED_SECTIONS.contains(&name) && name != ".pcrsig"
}

/// Extract `disk.raw` from a GCP .tar.gz
fn untar_disk_raw(targz: &[u8]) -> Result<Vec<u8>, UkiError> {
    let err = |_| UkiError::Disk("invalid tar.gz");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(targz));
    let mut entry = archive
        .entries()
        .map_err(err)?
        .next()
        .ok_or(UkiError::Disk("empty tar.gz"))?
        .map_err(err)?;
    let mut raw = Vec::new();
    entry.read_to_end(&mut raw).map_err(err)?;
    Ok(raw)
}

// Extract UKI from a disk image
fn extract_uki(disk: &[u8]) -> Result<Vec<u8>, UkiError> {
    let entry = disk.get(1024..1152).ok_or(UkiError::Disk("no partition table"))?; // LBA 2
    let start = u64::from_le_bytes(entry[32..40].try_into().unwrap()) as usize;
    let end = u64::from_le_bytes(entry[40..48].try_into().unwrap()) as usize;
    let esp = disk.get(start * 512..(end + 1) * 512).ok_or(UkiError::Disk("bad ESP bounds"))?;
    let fs = fatfs::FileSystem::new(Cursor::new(esp.to_vec()), fatfs::FsOptions::new())
        .map_err(|_| UkiError::Disk("invalid ESP filesystem"))?;
    let mut uki = Vec::new();
    fs.root_dir()
        .open_file("EFI/BOOT/BOOTX64.EFI")
        .and_then(|mut f| f.read_to_end(&mut uki))
        .map_err(|_| UkiError::Disk("could not read UKI from ESP"))?;
    Ok(uki)
}
