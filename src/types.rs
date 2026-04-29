use std::collections::HashMap;
use std::fmt;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    #[default]
    None,
    GcpTdx,
    AzureTdx,
    SelfHostedTdx,
    DcapTdx,
}

impl AttestationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::GcpTdx => "gcp-tdx",
            Self::AzureTdx => "azure-tdx",
            Self::SelfHostedTdx => "self-hosted-tdx",
            Self::DcapTdx => "dcap-tdx",
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DcapRegister {
    MRTD,
    RTMR0,
    RTMR1,
    RTMR2,
    RTMR3,
}

/// Actual register values extracted from a verified quote
#[derive(Clone, Debug, PartialEq)]
pub enum Measurements {
    Dcap(HashMap<DcapRegister, [u8; 48]>),
    Azure(HashMap<u32, [u8; 32]>),
    NoAttestation,
}

/// Hardware params reported by the TEE. The verifier uses these
/// to find the matching platform events (e.g. 4 vcpus + 16Gb RAM -> c3-standard-4)
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PlatformMetadata {
    pub vcpus: u32,
    pub ram_bytes: u64,
    pub num_disks: u32,
}

/// Wire format for attestation exchange
#[derive(Clone, Debug, Default, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationPayload {
    pub attestation_type: AttestationType,
    pub attestation: Vec<u8>,
    pub platform_metadata: Option<PlatformMetadata>,
}
