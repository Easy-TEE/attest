#![cfg(feature = "image")]

use attest_measure::{azure, dcap, uki::Uki};
use sha2::{Digest, Sha256, Sha384};

// Minimal PE fixture with the sections used by command-line measurement.
fn image(cmdline: &[u8]) -> Vec<u8> {
    let sections: [(&[u8], &[u8]); 3] = [
        (b".cmdline", cmdline),
        (b".initrd", b"initrd"),
        (b".sdmagic", b"#### LoaderInfo: systemd-stub 257 ####"),
    ];
    let mut data = vec![0; 2048];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
    data[128..132].copy_from_slice(b"PE\0\0");
    data[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    data[134..136].copy_from_slice(&3u16.to_le_bytes());
    data[148..150].copy_from_slice(&240u16.to_le_bytes());
    data[150..152].copy_from_slice(&0x22u16.to_le_bytes());
    let optional = &mut data[152..392];
    optional[..2].copy_from_slice(&0x20bu16.to_le_bytes());
    optional[32..36].copy_from_slice(&4096u32.to_le_bytes());
    optional[36..40].copy_from_slice(&512u32.to_le_bytes());
    optional[56..60].copy_from_slice(&16384u32.to_le_bytes());
    optional[60..64].copy_from_slice(&512u32.to_le_bytes());
    optional[68..70].copy_from_slice(&10u16.to_le_bytes());
    optional[108..112].copy_from_slice(&16u32.to_le_bytes());
    for (i, (name, payload)) in sections.into_iter().enumerate() {
        let offset = 512 * (i + 1);
        let header = &mut data[392 + i * 40..392 + (i + 1) * 40];
        header[..name.len()].copy_from_slice(name);
        header[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[12..16].copy_from_slice(&(4096u32 * (i as u32 + 1)).to_le_bytes());
        header[16..20].copy_from_slice(&512u32.to_le_bytes());
        header[20..24].copy_from_slice(&(offset as u32).to_le_bytes());
        header[36..40].copy_from_slice(&0x40000040u32.to_le_bytes());
        data[offset..offset + payload.len()].copy_from_slice(payload);
    }
    data
}

#[test]
fn normalizes_linux_measurements_but_preserves_raw_section_measurements() {
    let raw_cmdline = b" \tquiet\tconsole=ttyS0\r\n\0ignored";
    let uki = Uki::parse(&image(raw_cmdline)).unwrap();
    let clean = Uki::parse(&image(b"quiet console=ttyS0\0")).unwrap();

    // The section digest must still cover all original bytes, including
    // whitespace and bytes after the first NUL.
    assert_eq!(uki.cmdline, raw_cmdline);
    let section = uki.section(".cmdline").unwrap();
    let raw_sha384: [u8; 48] = Sha384::digest(raw_cmdline).into();
    let raw_sha256: [u8; 32] = Sha256::digest(raw_cmdline).into();
    assert_eq!(section.digest_sha384, raw_sha384);
    assert_eq!(section.digest_sha256, raw_sha256);

    let linux_cmdline: Vec<u8> =
        "quiet console=ttyS0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let hashes = dcap::measure(&uki);
    let clean_hashes = dcap::measure(&clean);
    let cmdline_sha384: [u8; 48] = Sha384::digest(&linux_cmdline).into();
    assert_eq!(hashes.cmdline_hash, cmdline_sha384);
    assert_eq!(hashes.cmdline_hash, clean_hashes.cmdline_hash);
    assert_ne!(hashes.pe_sections, clean_hashes.pe_sections);
    let registers = dcap::gcp::measure(&hashes);
    assert_eq!(registers.rtmr2.events()[0].digest, hashes.cmdline_hash);

    let azure = azure::measure(&uki);
    let clean_azure = azure::measure(&clean);
    assert_eq!(azure.pcr9.value(), clean_azure.pcr9.value());
    assert_ne!(azure.pcr11.value(), clean_azure.pcr11.value());
}
