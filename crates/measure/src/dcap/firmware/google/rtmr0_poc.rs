//! Test-only experiment. No production evidence or verification changes.
//!
//! Run offline: `cargo test -p attest-measure rtmr0_poc -- --nocapture`.
//! The quote is unverified. This
//! demonstrates replay mechanics and independent firmware authentication,
//! not full attestation verification or the premise that MRTD-covered SEC
//! always measures CFV second before executing it.
use prost::Message;
use sha2::{Digest, Sha384};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use super::{Endorsement, GoldenMeasurement, verify_endorsement};
use crate::{dcap::DcapFirmware, event::Register};

const CCEL: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gcp-rtmr0/ccel.bin"));
const QUOTE: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gcp-rtmr0/quote.bin"));
const REPORT_DATA: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gcp-rtmr0/reportdata.bin"));
const FIRMWARE: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gcp-rtmr0/firmware.fd"));
const ENDORSEMENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/gcp-rtmr0/endorsement.binarypb"
));
const ROOT: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gcp-rtmr0/root.der"));
const NO_ACTION: u32 = 3;
type Result<T> = std::result::Result<T, &'static str>;

// Parser for CCEL
struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        if size > self.0.len() {
            return Err("truncated record");
        }
        let (value, rest) = self.0.split_at(size);
        self.0 = rest;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

// A parsed CCEL record
#[derive(Debug)]
struct Event<'a> {
    index: u32,
    kind: u32,
    sha384: Option<[u8; 48]>,
    data: &'a [u8],
}

// Parse the raw CCEL into records
fn records(raw: &[u8]) -> Result<Vec<Event<'_>>> {
    let mut c = Input(raw);
    if c.u32()? != 1 || c.u32()? != NO_ACTION || c.take(20)? != [0; 20] {
        return Err("invalid legacy SpecID header");
    }
    let size = c.u32()? as usize;
    let mut spec = Input(c.take(size)?);
    if spec.take(16)? != b"Spec ID Event03\0" {
        return Err("invalid SpecID signature");
    }
    spec.take(8)?; // platform class, minor, major, errata, uintn size
    let count = spec.u32()?;
    if count == 0 || count > 16 {
        return Err("invalid algorithm count");
    }
    let mut algorithms = Vec::new();
    for _ in 0..count {
        let alg = spec.u16()?;
        let size = spec.u16()? as usize;
        let expected = match alg {
            4 => 20,
            11 => 32,
            12 => 48,
            13 => 64,
            _ => return Err("unsupported algorithm"),
        };
        if size != expected || algorithms.iter().any(|&(a, _)| a == alg) {
            return Err("invalid algorithm table");
        }
        algorithms.push((alg, size));
    }
    let vendor_size = spec.take(1)?[0] as usize;
    spec.take(vendor_size)?;
    if !spec.0.is_empty() {
        return Err("extra SpecID bytes");
    }

    let mut events = Vec::new();
    while !c.0.is_empty() {
        // The supplied CCEL's unused tail is 0xff. Also accept zero-filled
        // tails.
        if c.0.iter().all(|&b| b == 0xff) || c.0.iter().all(|&b| b == 0) {
            break;
        }
        let index = c.u32()?;
        let kind = c.u32()?;
        if index > 4 || (index == 0 && kind != NO_ACTION) {
            return Err("invalid TDX register index");
        }
        let count = c.u32()? as usize;
        if count == 0 || count > algorithms.len() {
            return Err("invalid event digest count");
        }
        let mut seen = Vec::new();
        let mut sha384 = None;
        for _ in 0..count {
            let alg = c.u16()?;
            if seen.contains(&alg) {
                return Err("duplicate event digest algorithm");
            }
            seen.push(alg);
            let size =
                algorithms.iter().find(|&&(a, _)| a == alg).ok_or("undeclared event algorithm")?.1;
            let digest = c.take(size)?;
            if alg == 12 {
                sha384 = Some(digest.try_into().unwrap());
            }
        }
        let size = c.u32()? as usize;
        let data = c.take(size)?;
        events.push(Event { index, kind, sha384, data });
    }
    Ok(events)
}

// Parse the CCEL into RTMR0 digests.  This is what would be sent over as
// attestation metadata.
// In the case of the test fixture, there are 16 of them.
fn rtmr0_digests(raw: &[u8]) -> Result<Vec<[u8; 48]>> {
    records(raw)?
        .into_iter()
        // CCEL's TDX mapping is one-based: MR index 1 is RTMR0. The
        // real-capture test independently confirms this against the quote.
        .filter(|e| e.index == 1 && e.kind != NO_ACTION)
        .map(|e| e.sha384.ok_or("RTMR0 extension missing SHA-384"))
        .collect()
}

// On the verifier side, replay the RTMR0 digests to compute expected RTMR0
fn replay(digests: &[[u8; 48]]) -> [u8; 48] {
    let mut register = Register::<Sha384>::new();
    for digest in digests {
        register.extend_raw(*digest, "");
    }
    register.value()
}

// Proposed verifier input: no descriptions, ACPI, RAM or disk metadata.
fn check(digests: &[[u8; 48]], quoted_rtmr0: [u8; 48], cfv: [u8; 48]) -> Result<()> {
    if replay(digests) != quoted_rtmr0 {
        return Err("RTMR0 replay mismatch");
    }

    if digests.get(1) != Some(&cfv) {
        return Err("second extension is not endorsed CFV");
    }

    Ok(())
}

// This fixture is specifically an Intel TDX quote v4 / TD report 1.0.
// Decode fields only: this does NOT validate signature, collateral or
// freshness.
fn quoted_registers() -> ([u8; 48], [u8; 48]) {
    assert_eq!(&QUOTE[..8], &[4, 0, 2, 0, 0x81, 0, 0, 0]);
    let signature_size = u32::from_le_bytes(QUOTE[632..636].try_into().unwrap()) as usize;
    let quote_end = 636 + signature_size;
    assert!(quote_end <= QUOTE.len());
    // The capture saved an 8000-byte output buffer. Its quote occupies 4935
    // bytes; require that the unused tail is entirely zero.
    assert!(QUOTE[quote_end..].iter().all(|&b| b == 0));
    assert_eq!(&QUOTE[568..632], REPORT_DATA);
    (QUOTE[184..232].try_into().unwrap(), QUOTE[376..424].try_into().unwrap())
}

fn authenticated_firmware() -> DcapFirmware {
    let endorsement = Endorsement::decode(ENDORSEMENT).unwrap();
    let golden = GoldenMeasurement::decode(&*endorsement.serialized_uefi_golden).unwrap();
    let root = X509Certificate::from_der(ROOT).unwrap().1;
    // Existing Google endorsement authentication, entirely offline with
    // pinned root.
    verify_endorsement(&endorsement, &golden, Some(&root)).unwrap();
    assert_eq!(Sha384::digest(FIRMWARE)[..], golden.digest);
    let firmware = DcapFirmware::from_blob(FIRMWARE, true).unwrap();
    assert_eq!(firmware.mrtd, quoted_registers().0);
    firmware
}

#[test]
#[ignore = "explicit network check of the pinned fixture against Google's current sources"]
fn check_google_fixture_sources() {
    let firmware = DcapFirmware::from_google(quoted_registers().0, None).unwrap();
    assert_eq!(firmware.cfv, authenticated_firmware().cfv);
}

#[test]
fn real_capture_replay_and_cfv() {
    let firmware = authenticated_firmware();
    let digests = rtmr0_digests(CCEL).unwrap();
    assert_eq!(digests.len(), 16);
    check(&digests, quoted_registers().1, firmware.cfv).unwrap();
    println!(
        "RTMR0: {} digests, {} raw bytes; CFV at index 1: {}",
        digests.len(),
        digests.len() * 48,
        hex::encode(firmware.cfv)
    );
    println!(
        "quoted MRTD: {}; RTMR0: {}",
        hex::encode(firmware.mrtd),
        hex::encode(quoted_registers().1)
    );
    let events = records(CCEL).unwrap();
    assert!(events.iter().any(|e| e.index == 0 && e.kind == NO_ACTION));
    assert!(events.iter().any(|e| e.index == 2 && e.kind != NO_ACTION));
    // Concrete reason full builder reconstruction cannot match: it models
    // 15 events and lacks Ubuntu shim's EV_EFI_VARIABLE_AUTHORITY
    // SbatLevel event.
    let rtmr0: Vec<_> = events.iter().filter(|e| e.index == 1 && e.kind != NO_ACTION).collect();
    assert_eq!(rtmr0[15].kind, 0x8000_00e0);
    assert!(rtmr0[15].data.windows(18).any(|w| w == b"S\0b\0a\0t\0L\0e\0v\0e\0l\0"));
    // BootOrder is 0002,0001,0000 rather than the builder's 0001,0002,0000.
    assert_eq!(rtmr0[11].sha384.unwrap(), <[u8; 48]>::from(Sha384::digest([2, 0, 1, 0, 0, 0])));
    assert_ne!(
        rtmr0[11].sha384.unwrap(),
        <[u8; 48]>::from(Sha384::digest(crate::dcap::gcp::boot_order_bytes(1)))
    );
}

#[test]
fn rejects_changed_missing_and_reordered_extensions() {
    let digests = rtmr0_digests(CCEL).unwrap();
    let target = quoted_registers().1;
    let cfv = digests[1]; // reference independence is tested above
    let mut changed = digests.clone();
    changed[0][0] ^= 1;
    assert_eq!(check(&changed, target, cfv), Err("RTMR0 replay mismatch"));
    let mut dropped = digests.clone();
    dropped.remove(2);
    assert_eq!(check(&dropped, target, cfv), Err("RTMR0 replay mismatch"));
    let mut reordered = digests.clone();
    assert_ne!(reordered[2], reordered[3]);
    reordered.swap(2, 3);
    assert_eq!(check(&reordered, target, cfv), Err("RTMR0 replay mismatch"));
    let mut wrong_cfv = cfv;
    wrong_cfv[0] ^= 1;
    assert_eq!(check(&digests, target, wrong_cfv), Err("second extension is not endorsed CFV"));
}

#[test]
fn synthetic_requires_cfv_at_second_position_and_two_entries() {
    let cfv = [7; 48];
    let digests = [[1; 48], [2; 48], cfv];
    assert_eq!(check(&digests, replay(&digests), cfv), Err("second extension is not endorsed CFV"));
    for short in [&digests[..0], &digests[..1]] {
        assert_eq!(check(short, replay(short), cfv), Err("second extension is not endorsed CFV"));
    }
}

fn spec_id() -> Vec<u8> {
    // A valid, minimal SpecID copied from the fixture; no event
    // descriptions.
    CCEL[..65].to_vec()
}

fn append_event(log: &mut Vec<u8>, index: u32, kind: u32, digest: [u8; 48], data: &[u8]) {
    log.extend(index.to_le_bytes());
    log.extend(kind.to_le_bytes());
    log.extend(1u32.to_le_bytes());
    log.extend(12u16.to_le_bytes());
    log.extend(digest);
    log.extend((data.len() as u32).to_le_bytes());
    log.extend(data);
}

#[test]
fn synthetic_parser_preserves_bytes_and_filters_by_register_and_type() {
    let mut log = spec_id();
    append_event(&mut log, 2, 10, [2; 48], b"ACPI DATA");
    append_event(&mut log, 1, NO_ACTION, [3; 48], b"CFV");
    append_event(&mut log, 1, 10, [0xff; 48], &[0xff; 8]);
    let end = log.len();
    assert_eq!(rtmr0_digests(&log).unwrap(), [[0xff; 48]]);
    log.extend([0xff; 256]);
    assert_eq!(records(&log).unwrap()[2].data, [0xff; 8]);
    assert_eq!(rtmr0_digests(&log).unwrap(), [[0xff; 48]]);
    log.truncate(end);
    log.extend([0; 256]);
    assert_eq!(rtmr0_digests(&log).unwrap(), [[0xff; 48]]);
    for truncated in 65 + 1..end {
        // Complete earlier records are valid; every other prefix is
        // truncated.
        if truncated != 65 + 75 && truncated != 65 + 75 + 69 {
            assert!(records(&log[..truncated]).is_err(), "prefix {truncated}");
        }
    }
}

#[test]
fn synthetic_parser_rejects_malformed_records() {
    let mut log = spec_id();
    append_event(&mut log, 1, 10, [0; 48], b"");
    let mut bad = log.clone();
    bad[65 + 12..65 + 14].copy_from_slice(&11u16.to_le_bytes());
    assert!(records(&bad).is_err(), "algorithm not in SpecID");
    let mut bad = log.clone();
    bad[65 + 8..65 + 12].copy_from_slice(&2u32.to_le_bytes());
    assert!(records(&bad).is_err(), "digest count exceeds banks");
    let mut bad = log.clone();
    bad[65 + 62..65 + 66].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(records(&bad).is_err(), "event size exceeds input");
    log[32] ^= 1;
    assert!(records(&log).is_err(), "invalid SpecID");
}
