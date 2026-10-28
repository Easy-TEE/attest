//! Register accumulator for PCR/RTMR measurement construction.
//!
//! [`Register<H>`] applies sequential extend operations (value = H(value ||
//! hash)) and, with the `image` feature, records each step for debug
//! inspection

use std::{fmt, marker::PhantomData};

#[cfg(feature = "image")]
use serde::Deserialize;
use serde::Serialize;
#[cfg(feature = "image")]
use serde_with::{hex::Hex, serde_as};
use sha2::{Digest, Sha256, Sha384};

// Well-known EFI event strings
pub const CALLING_EFI_APP: &[u8] = b"Calling EFI Application from Boot Option";
pub const EXIT_BOOT_SERVICES: &[u8] = b"Exit Boot Services Invocation";
pub const EXIT_BOOT_SERVICES_SUCCESS: &[u8] = b"Exit Boot Services Returned with Success";
pub const SEPARATOR: &[u8] = &[0x00, 0x00, 0x00, 0x00];

pub trait HashAlg: Digest + Default {
    type Array: Copy + AsRef<[u8]> + AsMut<[u8]>;
    fn zero() -> Self::Array;
    fn into_array(h: Self) -> Self::Array;
}

impl HashAlg for Sha256 {
    type Array = [u8; 32];
    fn zero() -> [u8; 32] {
        [0; 32]
    }
    fn into_array(h: Self) -> [u8; 32] {
        h.finalize().into()
    }
}

impl HashAlg for Sha384 {
    type Array = [u8; 48];
    fn zero() -> [u8; 48] {
        [0; 48]
    }
    fn into_array(h: Self) -> [u8; 48] {
        h.finalize().into()
    }
}

#[cfg(feature = "image")]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEvent {
    #[serde_as(as = "Hex")]
    pub digest: Vec<u8>,
    pub description: String,
}

/// Accumulates sequential extend operations on a zero-initialized value
///
/// Extends with `value = H(value || hash)`
///
/// Use [`Register::<Sha256>::new()`] for TPM PCRs and
/// [`Register::<Sha384>::new()`] for TDX RTMRs
pub struct Register<H: HashAlg> {
    value: H::Array,
    #[cfg(feature = "image")]
    events: Vec<RegisterEvent>,
    _h: PhantomData<H>,
}

impl<H: HashAlg> Default for Register<H> {
    fn default() -> Self {
        Self {
            value: H::zero(),
            #[cfg(feature = "image")]
            events: Vec::new(),
            _h: PhantomData,
        }
    }
}

impl<H: HashAlg> Clone for Register<H> {
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            #[cfg(feature = "image")]
            events: self.events.clone(),
            _h: PhantomData,
        }
    }
}

impl<H: HashAlg> fmt::Debug for Register<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Register({})", hex::encode(self.value.as_ref()))
    }
}

impl<H: HashAlg> Register<H> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from a pre-computed value instead of zero
    pub fn from_value(value: H::Array) -> Self {
        Self { value, ..Self::default() }
    }

    /// Extend with a pre-computed hash (e.g. a
    /// [`UkiSection`](super::uki::UkiSection) digest)
    pub fn extend_raw(&mut self, hash: H::Array, description: impl Into<String>) -> &mut Self {
        let mut h = H::default();
        h.update(self.value.as_ref());
        h.update(hash.as_ref());
        self.value = H::into_array(h);
        #[cfg(not(feature = "image"))]
        let _ = description;
        #[cfg(feature = "image")]
        self.events.push(RegisterEvent {
            digest: hash.as_ref().to_vec(),
            description: description.into(),
        });
        self
    }

    /// Hash `data` with `H`, then extend. Use for byte strings and inline
    /// data (e.g. [`CALLING_EFI_APP`], [`SEPARATOR`], section names,
    /// cmdline bytes)
    pub fn extend(&mut self, data: &[u8], description: impl Into<String>) -> &mut Self {
        let hash = H::into_array(H::default().chain_update(data));
        self.extend_raw(hash, description)
    }

    pub fn value(&self) -> H::Array {
        self.value
    }

    #[cfg(feature = "image")]
    pub fn events(&self) -> &[RegisterEvent] {
        &self.events
    }

    #[cfg(feature = "image")]
    pub fn into_events(self) -> Vec<RegisterEvent> {
        self.events
    }

    /// Returns `{"value": "<hex>", "events": [...]}` for `--debug` output
    #[cfg(feature = "image")]
    pub fn debug_json(&self) -> serde_json::Value {
        serde_json::json!({
            "value": hex::encode(self.value.as_ref()),
            "events": self.events,
        })
    }
}

/// Serializes as a hex string (same wire format as `[u8; N]` with
/// `serde_as(Hex)`)
impl<H: HashAlg> Serialize for Register<H> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        hex::encode(self.value.as_ref()).serialize(ser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "image"))]
    #[test]
    fn descriptions_are_not_converted_without_logging() {
        struct Description;
        impl From<Description> for String {
            fn from(_: Description) -> Self {
                panic!("description conversion must be skipped")
            }
        }
        let mut register = Register::<Sha384>::new();
        register.extend(b"event", Description);
        assert_ne!(register.value(), [0; 48]);
    }

    #[cfg(feature = "image")]
    #[test]
    fn records_events_and_debug_output() {
        let mut register = Register::<Sha384>::new();
        register.extend_raw([7; 48], "example");
        assert_eq!(register.events()[0].digest, [7; 48]);
        assert_eq!(register.events()[0].description, "example");
        assert_eq!(
            register.debug_json(),
            serde_json::json!({
                "value": hex::encode(register.value()),
                "events": [{"digest": hex::encode([7; 48]), "description": "example"}]
            })
        );
        assert_eq!(register.clone().into_events().len(), 1);
    }
}
