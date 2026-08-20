//! CCEL parser: extracts ACPI hashes from RTMR0 events

use thiserror::Error;
use types::AcpiHashes;

const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000a;
const EV_EFI_HANDOFF_TABLES: u32 = 0x8000_0009; // SMBIOS
const RTMR0_PCR_INDEX: u32 = 1;

const ACPI_DATA: &[u8] = b"ACPI DATA";
const FW_CFG_BOOTORDER: &[u8] = b"QEMU FW CFG\0bootorder";

const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;

#[derive(Error, Debug)]
pub enum CcelError {
    #[error("CCEL read: {0}")]
    Io(#[from] std::io::Error),
    #[error("unexpected EOF")]
    UnexpectedEof,
    #[error("unknown hash algorithm {0:#06x}")]
    UnknownHashAlgorithm(u16),
    #[error("EV_PLATFORM_CONFIG_FLAGS missing SHA-384")]
    MissingSha384,
    #[error("expected 3 EV_PLATFORM_CONFIG_FLAGS in RTMR0, found {0}")]
    BadEventCount(usize),
}

/// RTMR0 data parsed from the CCEL
pub struct CcelInfo {
    pub acpi: AcpiHashes,
    /// Only used on VMs booted with recent OVMF versions
    pub smbios_handoff: Option<[u8; 48]>,
    /// True when booting from a .raw image with disk rather than UKI
    pub dm_verity_boot: bool,
}

pub fn read_ccel() -> Result<CcelInfo, CcelError> {
    let raw = std::fs::read(CCEL_PATH)?;
    parse_ccel(&raw)
}

pub fn parse_ccel(raw: &[u8]) -> Result<CcelInfo, CcelError> {
    let end = raw.iter().rposition(|&b| b != 0xff).map_or(0, |i| i + 1);
    let mut cur = Cursor::new(&raw[..end]);

    skip_spec_id_event(&mut cur)?;

    let mut acpi = Vec::with_capacity(3);
    let mut smbios_handoff = None;
    let mut dm_verity_boot = true;
    while cur.has_remaining() {
        let event = read_event(&mut cur)?;
        if event.pcr_index != RTMR0_PCR_INDEX {
            continue;
        }
        match event.event_type {
            EV_PLATFORM_CONFIG_FLAGS if event.data == ACPI_DATA => {
                acpi.push(event.sha384.ok_or(CcelError::MissingSha384)?);
            }
            EV_PLATFORM_CONFIG_FLAGS if event.data.starts_with(FW_CFG_BOOTORDER) => {
                dm_verity_boot = false;
            }
            EV_EFI_HANDOFF_TABLES => smbios_handoff = event.sha384,
            _ => {}
        }
    }
    if acpi.len() != 3 {
        return Err(CcelError::BadEventCount(acpi.len()));
    }
    Ok(CcelInfo {
        acpi: AcpiHashes { loader: acpi[0], rsdp: acpi[1], tables: acpi[2] },
        smbios_handoff,
        dm_verity_boot,
    })
}

struct Event {
    pcr_index: u32,
    event_type: u32,
    sha384: Option<[u8; 48]>,
    data: Vec<u8>,
}

fn read_event(c: &mut Cursor) -> Result<Event, CcelError> {
    let pcr_index = c.read_u32()?;
    let event_type = c.read_u32()?;
    let count = c.read_u32()?;
    let mut sha384 = None;
    for _ in 0..count {
        let alg = c.read_u16()?;
        let digest = c.read_bytes(digest_size(alg)?)?;
        if alg == TPM_ALG_SHA384 {
            sha384 = Some(digest.try_into().unwrap());
        }
    }
    let event_size = c.read_u32()? as usize;
    let data = c.read_bytes(event_size)?.to_vec();
    Ok(Event { pcr_index, event_type, sha384, data })
}

// Skips legacy SpecID event
fn skip_spec_id_event(c: &mut Cursor) -> Result<(), CcelError> {
    c.read_u32()?; // pcr_index
    c.read_u32()?; // event_type
    c.read_bytes(20)?; // SHA-1 digest
    let size = c.read_u32()? as usize;
    c.read_bytes(size)?;
    Ok(())
}

fn digest_size(alg: u16) -> Result<usize, CcelError> {
    match alg {
        TPM_ALG_SHA1 => Ok(20),
        TPM_ALG_SHA256 => Ok(32),
        TPM_ALG_SHA384 => Ok(48),
        TPM_ALG_SHA512 => Ok(64),
        _ => Err(CcelError::UnknownHashAlgorithm(alg)),
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn has_remaining(&self) -> bool {
        self.pos < self.data.len()
    }
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CcelError> {
        if self.pos + n > self.data.len() {
            return Err(CcelError::UnexpectedEof);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u16(&mut self) -> Result<u16, CcelError> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }
    fn read_u32(&mut self) -> Result<u32, CcelError> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }
}
