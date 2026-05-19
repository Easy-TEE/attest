//! CCEL parser — extracts ACPI hashes from RTMR0 events

use anyhow::{Context, Result, bail, ensure};
use types::AcpiHashes;

const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000a;
const RTMR0_PCR_INDEX: u32 = 1;

const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;

pub fn read_acpi_hashes() -> Result<AcpiHashes> {
    let raw = std::fs::read(CCEL_PATH).with_context(|| format!("read {CCEL_PATH}"))?;
    parse_acpi_hashes(&raw)
}

pub fn parse_acpi_hashes(raw: &[u8]) -> Result<AcpiHashes> {
    let end = raw.iter().rposition(|&b| b != 0xff).map_or(0, |i| i + 1);
    let mut cur = Cursor::new(&raw[..end]);

    skip_spec_id_event(&mut cur).context("spec ID event")?;

    let mut acpi = Vec::with_capacity(3);
    while cur.has_remaining() {
        let event = read_event(&mut cur)?;
        if event.pcr_index == RTMR0_PCR_INDEX && event.event_type == EV_PLATFORM_CONFIG_FLAGS {
            acpi.push(event.sha384.context("EV_PLATFORM_CONFIG_FLAGS missing SHA-384")?);
        }
    }
    ensure!(acpi.len() == 3, "expected 3 EV_PLATFORM_CONFIG_FLAGS in RTMR0, found {}", acpi.len());
    Ok(AcpiHashes { loader: acpi[0], rsdp: acpi[1], tables: acpi[2] })
}

struct Event {
    pcr_index: u32,
    event_type: u32,
    sha384: Option<[u8; 48]>,
}

fn read_event(c: &mut Cursor) -> Result<Event> {
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
    c.read_bytes(event_size)?;
    Ok(Event { pcr_index, event_type, sha384 })
}

// Skips legacy SpecID event
fn skip_spec_id_event(c: &mut Cursor) -> Result<()> {
    c.read_u32()?; // pcr_index
    c.read_u32()?; // event_type
    c.read_bytes(20)?; // SHA-1 digest
    let size = c.read_u32()? as usize;
    c.read_bytes(size)?;
    Ok(())
}

fn digest_size(alg: u16) -> Result<usize> {
    match alg {
        TPM_ALG_SHA1 => Ok(20),
        TPM_ALG_SHA256 => Ok(32),
        TPM_ALG_SHA384 => Ok(48),
        TPM_ALG_SHA512 => Ok(64),
        _ => bail!("unknown hash algorithm {alg:#06x}"),
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
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.pos + n <= self.data.len(), "unexpected EOF");
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }
    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }
}

