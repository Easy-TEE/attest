//! UEFI variable hashes for EV_EFI_VARIABLE_DRIVER_CONFIG events

use hex_literal::hex;
use sha2::{Digest, Sha384};

pub const EFI_GLOBAL_VARIABLE_GUID: [u8; 16] = hex!("61dfe48bca93d211aa0d00e098032b8c");
pub const EFI_IMAGE_SECURITY_DATABASE_GUID: [u8; 16] = hex!("cbb219d73a3d9645a3bcdad00e67656f");

/// EFI_SIGNATURE_LIST containing empty DER cert
pub const EMPTY_DER_SIG_LIST: [u8; 52] = hex!(
    "a159c0a5e494a74a87b5ab155c2bf072" // SignatureType = EFI_CERT_X509_GUID
    "34000000"                         // SignatureListSize = 52
    "00000000"                         // SignatureHeaderSize = 0
    "18000000"                         // SignatureSize = 24
    "d2fa81d2888da44797925baa47bb1b89" // SignatureOwner
    "3082010a02820101"                 // minimum-length valid DER cert
);

pub fn secureboot_off() -> [u8; 48] {
    secure_boot_hash(&EFI_GLOBAL_VARIABLE_GUID, "SecureBoot", &[0x00])
}

pub fn pk() -> [u8; 48] {
    secure_boot_hash(&EFI_GLOBAL_VARIABLE_GUID, "PK", &EMPTY_DER_SIG_LIST)
}

pub fn kek() -> [u8; 48] {
    secure_boot_hash(&EFI_GLOBAL_VARIABLE_GUID, "KEK", &EMPTY_DER_SIG_LIST)
}

pub fn db() -> [u8; 48] {
    secure_boot_hash(&EFI_IMAGE_SECURITY_DATABASE_GUID, "db", &EMPTY_DER_SIG_LIST)
}

pub fn dbx() -> [u8; 48] {
    secure_boot_hash(&EFI_IMAGE_SECURITY_DATABASE_GUID, "dbx", &EMPTY_DER_SIG_LIST)
}

/// SHA-384 of TCG UEFI_VARIABLE_DATA
pub fn secure_boot_hash(guid: &[u8; 16], name: &str, data: &[u8]) -> [u8; 48] {
    let name_u16: Vec<u16> = name.encode_utf16().collect();
    let mut h = Sha384::new();
    h.update(guid); // VariableName (GUID)
    h.update((name_u16.len() as u64).to_le_bytes()); // UnicodeNameLength (chars)
    h.update((data.len() as u64).to_le_bytes()); // VariableDataLength (bytes)
    for c in &name_u16 {
        h.update(c.to_le_bytes()); // UnicodeName (UCS-2 char)
    }
    h.update(data); // VariableData
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_config_event_digests() {
        assert_eq!(
            secureboot_off(), hex!("cfa4e2c606f572627bf06d5669cc2ab1128358d27b45bc63ee9ea56ec109cfafb7194006f847a6a74b5eaed6b73332ec"),
        );
        assert_eq!(
            pk(), hex!("905f6243baf0d7c63cd672f89b16e15f99597e8d0392955e685172d447100123f7c490d178543922faddf896625dabab"),
        );
        assert_eq!(
            kek(), hex!("be013b0d9188e72b870f598899c35864d6b25f029a7b5f21a037bacf61ca3646207af2bc714d471407c9939317763c4a"),
        );
        assert_eq!(
            db(), hex!("723ad4d64f430bf6d325ab9d6c29147993ded5630002e42e13df696ebc680c4bc14c392d2e113e141154e21723f890f6"),
        );
        assert_eq!(
            dbx(), hex!("c61bae1a3f7b7e6cc3b9b03f630b77292ebd232ae60e0e1916f980955ec38459529574b49f1898c367eaf6d8a62311f5"),
        );
    }
}
