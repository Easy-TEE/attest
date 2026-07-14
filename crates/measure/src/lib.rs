//! Computes expected values from a CVM running the specified image

pub mod azure;
pub mod ccel;
pub mod dcap;
pub mod event;
pub mod platform;
pub mod uki;

use std::{fs::File, io::Read, path::Path};

use serde::Serialize;
use types::PortableMeasurements;

use self::uki::{Uki, UkiError};

const GPT_REGION_SECTORS: usize = 34;

/// A computed measurement with both an annotated form
/// and a form with only the final digest values
pub trait Measurement {
    type Wire: Serialize;
    fn finalize(&self) -> Self::Wire;
    fn debug_json(&self) -> serde_json::Value;
}

/// Produces a portable measurement from a UKI file
pub fn measure(uki_data: &[u8], rootfs: Option<&[u8]>) -> Result<PortableMeasurements, UkiError> {
    let uki = Uki::parse(uki_data)?;
    Ok(PortableMeasurements {
        azure: Some(azure::measure(&uki).finalize()),
        dcap: dcap::measure(&uki, rootfs),
    })
}

pub fn get_rootfs_header(path: &Path) -> Result<[u8; 48], std::io::Error> {
    let mut buf = vec![0u8; GPT_REGION_SECTORS * 512];
    File::open(path)?.read_exact(&mut buf)?;
    let mut header = [0u8; 48];
    header.copy_from_slice(&buf[..48]);
    Ok(header)
}
