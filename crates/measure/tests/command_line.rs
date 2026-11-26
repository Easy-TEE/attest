#![cfg(feature = "image")]

use attest_measure::{
    dcap,
    uki::{Uki, UkiSection},
};
use sha2::{Digest, Sha384};

#[test]
fn measures_the_normalized_command_line() {
    let uki = Uki {
        size: 4096,
        sections: vec![UkiSection {
            name: ".initrd".into(),
            size: 0,
            digest_sha256: [0; 32],
            digest_sha384: [0; 48],
            measured: false,
            measure_order: -1,
        }],
        authenticode_sha256: [0; 32],
        authenticode_sha384: [0; 48],
        kernel_authenticode_sha256: [0; 32],
        kernel_authenticode_sha384: [0; 48],
        cmdline: b"quiet\tloglevel=4".to_vec(),
        stub_version: None,
        has_rootfs: false,
        disk_guid_hash: None,
    };

    let load_options: Vec<u8> =
        "quiet loglevel=4\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let expected: [u8; 48] = Sha384::digest(&load_options).into();

    assert_eq!(dcap::measure(&uki).unwrap().cmdline_hash, expected);
}
