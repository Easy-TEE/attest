//! Types shared between the prove, verify, and measure crates

use std::fmt;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::hex::Hex;
use serde_with::serde_as;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    GcpTdx,
    AzureTdx,
    SelfHostedTdx,
}

impl AttestationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GcpTdx => "gcp-tdx",
            Self::AzureTdx => "azure-tdx",
            Self::SelfHostedTdx => "self-hosted-tdx",
        }
    }
}

impl fmt::Display for AttestationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Encode for AttestationType {
    fn encode(&self) -> Vec<u8> {
        self.as_str().encode()
    }
}

impl Decode for AttestationType {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let s = String::decode(input)?;
        serde_json::from_str(&format!("\"{s}\"")).map_err(|_| "unknown attestation type".into())
    }
}

/// Hashes of ACPI tables. These tables are sandboxed on Easy-TEE images
#[serde_with::apply([u8; 48] => #[serde_as(as = "Hex")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AcpiHashes {
    pub loader: [u8; 48],
    pub rsdp: [u8; 48],
    pub tables: [u8; 48],
}

/// Additional platform information used to reconstruct registers
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PlatformMetadata {
    pub attestation_type: AttestationType,
    pub ram_bytes: u64,
    pub num_disks: u32,
    pub acpi: Option<AcpiHashes>,
}

/// Output of `prove` function
/// Raw quote bytes plus info needed to reconstruct registers
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationEvidence {
    #[serde_as(as = "Base64")]
    pub quote: Vec<u8>,
    pub platform: PlatformMetadata,
}

/// Final Azure vTPM PCR values
#[serde_with::apply([u8; 32] => #[serde_as(as = "Hex")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureRegisters {
    pub pcr4: [u8; 32],
    pub pcr9: [u8; 32],
    pub pcr11: [u8; 32],
}

/// Image-specific intermediate hashes for DCAP platforms
/// Combined with platform events at verify time to reconstruct RTMRs
#[serde_with::apply([u8; 48] => #[serde_as(as = "Hex")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapImageHashes {
    pub uki_authenticode: [u8; 48],
    pub kernel_authenticode: [u8; 48],
    pub cmdline_hash: [u8; 48],
    pub initrd_hash: [u8; 48],
    pub gpt_disk_guid_hash: [u8; 48],
}

/// Image-dependent DCAP register values
/// MRTD and RTMR0 must be reconstructed or verified separately
#[serde_with::apply([u8; 48] => #[serde_as(as = "Hex")])]
#[serde_with::serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapRegisters {
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
}

/// Contains only measurement values that depend on the image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableMeasurements {
    pub azure: Option<AzureRegisters>,
    pub dcap: DcapImageHashes,
}

/// Output of `attest measure` command
/// Contains expected measurements for use by verify function
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[allow(clippy::large_enum_variant)]
pub enum MeasurementOutput {
    Portable(PortableMeasurements),
    Dcap(DcapRegisters),
    Azure(AzureRegisters),
}
