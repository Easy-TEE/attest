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
    pub fn parse(data: &[u8]) -> Result<Self, UkiError> {
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
