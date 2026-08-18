//! Computes expected values from a CVM running the specified image

pub mod azure;
pub mod ccel;
pub mod dcap;
pub mod event;
pub mod platform;
pub mod uki;

use serde::Serialize;
use types::PortableMeasurements;

use self::uki::{Uki, UkiError};

/// A computed measurement with both an annotated form
/// and a form with only the final digest values
pub trait Measurement {
    type Wire: Serialize;
    fn finalize(&self) -> Self::Wire;
    fn debug_json(&self) -> serde_json::Value;
}

/// Produces portable measurement from `.efi`, `.raw`, or `.tar.gz` image
pub fn measure(uki_data: &[u8]) -> Result<PortableMeasurements, UkiError> {
    let uki = Uki::parse(uki_data)?;
    Ok(PortableMeasurements {
        azure: Some(azure::measure(&uki).finalize()),
        dcap: dcap::measure(&uki),
    })
}
