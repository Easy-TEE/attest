pub mod azure;
pub mod dcap;
pub mod event;
pub mod uki;

use serde::{Deserialize, Serialize};

use self::azure::AzureRegisters;
use self::dcap::DcapImageHashes;
use self::uki::Uki;

/// Default output of the `measure` command
/// Contains the image-dependent DCAP event hashes and the final Azure PCRs
#[derive(Debug, Serialize, Deserialize)]
pub struct PortableMeasurements {
    pub azure: AzureRegisters,
    pub dcap: DcapImageHashes,
}

/// Produces a portable measurement from a UKI file
pub fn measure(uki_data: &[u8]) -> anyhow::Result<PortableMeasurements> {
    let uki = Uki::parse(uki_data)?;
    Ok(PortableMeasurements {
        azure: azure::measure(&uki),
        dcap: dcap::measure(&uki),
    })
}
