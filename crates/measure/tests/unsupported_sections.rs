#![cfg(feature = "image")]

use attest_measure::{
    dcap,
    uki::{Uki, UkiError, UkiSection},
};

#[test]
fn rejects_sections_that_change_the_delivered_initrd() {
    for name in [".ucode", ".pcrpkey"] {
        for stub_version in [None, Some(255), Some(256)] {
            // These sections must be rejected even when section measurement
            // is disabled: they also affect the initrd measured by Linux.
            let uki = Uki {
                size: 4096,
                sections: vec![
                    UkiSection {
                        name: ".initrd".into(),
                        size: 4,
                        digest_sha256: [1; 32],
                        digest_sha384: [2; 48],
                        measured: true,
                        measure_order: 3,
                    },
                    UkiSection {
                        name: name.into(),
                        size: 4,
                        digest_sha256: [1; 32],
                        digest_sha384: [2; 48],
                        measured: false,
                        measure_order: -1,
                    },
                ],
                authenticode_sha384: [3; 48],
                authenticode_sha256: [4; 32],
                kernel_authenticode_sha384: [5; 48],
                kernel_authenticode_sha256: [6; 32],
                cmdline: b"quiet".to_vec(),
                stub_version,
                has_rootfs: false,
                disk_guid_hash: None,
            };
            let error = dcap::measure(&uki).unwrap_err();
            assert!(matches!(error, UkiError::UnsupportedTdxSection(section) if section == name));
            assert!(error.to_string().contains(name));
            assert!(error.to_string().contains("initrd passed to Linux"));
        }
    }
}
