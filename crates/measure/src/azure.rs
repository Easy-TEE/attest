//! Azure vTPM PCR measurement

use serde::Serialize;
use sha2::Sha256;

use super::{
    Measurement,
    event::{CALLING_EFI_APP, Register, SEPARATOR},
    uki::{Uki, to_utf16le_null_terminated},
};

#[derive(Debug, Serialize)]
pub struct AzureRegisters {
    pub pcr4: Register<Sha256>,
    pub pcr9: Register<Sha256>,
    pub pcr11: Register<Sha256>,
}

impl Measurement for AzureRegisters {
    type Wire = types::AzureRegisters;

    fn finalize(&self) -> Self::Wire {
        types::AzureRegisters {
            pcr4: self.pcr4.value(),
            pcr9: self.pcr9.value(),
            pcr11: self.pcr11.value(),
        }
    }

    fn debug_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pcr4": self.pcr4.debug_json(),
            "pcr9": self.pcr9.debug_json(),
            "pcr11": self.pcr11.debug_json(),
        })
    }
}

pub fn measure(uki: &Uki) -> AzureRegisters {
    AzureRegisters { pcr4: measure_pcr4(uki), pcr9: measure_pcr9(uki), pcr11: measure_pcr11(uki) }
}

/// PCR4: EV_EFI_ACTION + separator + UKI authenticode + kernel authenticode
fn measure_pcr4(uki: &Uki) -> Register<Sha256> {
    let mut pcr = Register::new();
    pcr.extend(CALLING_EFI_APP, "calling EFI app");
    pcr.extend(SEPARATOR, "separator");
    pcr.extend_raw(uki.authenticode_sha256, "UKI authenticode");
    pcr.extend_raw(uki.kernel_authenticode_sha256, "kernel authenticode");
    pcr
}

/// PCR9: cmdline (UTF-16LE) + initrd
fn measure_pcr9(uki: &Uki) -> Register<Sha256> {
    let mut pcr = Register::new();
    pcr.extend(&to_utf16le_null_terminated(&uki.cmdline), "cmdline (UTF-16LE)");
    if let Some(initrd) = uki.section(".initrd") {
        pcr.extend_raw(initrd.digest_sha256, "initrd");
    }
    pcr
}

/// PCR11: for each measured UKI section, extend(name) then extend(content)
fn measure_pcr11(uki: &Uki) -> Register<Sha256> {
    let mut pcr = Register::new();
    for section in &uki.sections {
        if !section.measured {
            continue;
        }
        pcr.extend(&section.null_terminated_name(), format!("{} (name)", section.name));
        pcr.extend_raw(section.digest_sha256, format!("{} (content)", section.name));
    }
    pcr
}
