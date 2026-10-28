//! Computes expected values from a CVM running the specified image

#[cfg(feature = "image")]
pub mod azure;
#[cfg(feature = "platform")]
pub mod ccel;
pub mod dcap;
pub mod event;
#[cfg(feature = "platform")]
pub mod platform;
#[cfg(feature = "image")]
pub mod uki;

use serde::Serialize;
#[cfg(feature = "image")]
use types::PortableMeasurements;

#[cfg(feature = "image")]
use self::uki::{Uki, UkiError};

/// A computed measurement with both an annotated form
/// and a form with only the final digest values
pub trait Measurement {
    type Wire: Serialize;
    fn finalize(&self) -> Self::Wire;
    #[cfg(feature = "image")]
    fn debug_json(&self) -> serde_json::Value;
}

/// Produces portable measurement from `.efi`, `.raw`, or `.tar.gz` image
#[cfg(feature = "image")]
pub fn measure(uki_data: &[u8]) -> Result<PortableMeasurements, UkiError> {
    let uki = Uki::parse(uki_data)?;
    Ok(PortableMeasurements {
        azure: Some(azure::measure(&uki).finalize()),
        dcap: dcap::measure(&uki),
    })
}
