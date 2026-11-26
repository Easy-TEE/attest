#![cfg(feature = "image")]

use std::io::{Cursor, Write};

use attest_measure::{
    dcap,
    uki::{Uki, UkiError},
};
use sha2::{Digest, Sha384};

const SECTOR: usize = 512;
const ESP_START: usize = 128 * SECTOR;
const ESP_SIZE: usize = 2 * 1024 * 1024;
const ESP_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

// Small PE fixture containing an initrd, sufficient for parsing and
// measurement without carrying a full kernel or application image.
fn uki_image() -> Vec<u8> {
    let mut data = vec![0; 1024];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
    data[128..132].copy_from_slice(b"PE\0\0");
    data[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    data[134..136].copy_from_slice(&1u16.to_le_bytes());
    data[148..150].copy_from_slice(&240u16.to_le_bytes());
    data[150..152].copy_from_slice(&0x22u16.to_le_bytes());
    let optional = &mut data[152..392];
    optional[..2].copy_from_slice(&0x20bu16.to_le_bytes());
    optional[32..36].copy_from_slice(&4096u32.to_le_bytes());
    optional[36..40].copy_from_slice(&512u32.to_le_bytes());
    optional[56..60].copy_from_slice(&8192u32.to_le_bytes());
    optional[60..64].copy_from_slice(&512u32.to_le_bytes());
    optional[68..70].copy_from_slice(&10u16.to_le_bytes());
    optional[108..112].copy_from_slice(&16u32.to_le_bytes());
    let section = &mut data[392..432];
    section[..7].copy_from_slice(b".initrd");
    section[8..12].copy_from_slice(&6u32.to_le_bytes());
    section[12..16].copy_from_slice(&4096u32.to_le_bytes());
    section[16..20].copy_from_slice(&512u32.to_le_bytes());
    section[20..24].copy_from_slice(&512u32.to_le_bytes());
    data[512..518].copy_from_slice(b"initrd");
    data
}

fn disk_image(array_lba: usize, esp_slot: usize, entry_size: usize) -> (Vec<u8>, [u8; 48]) {
    let mut disk = vec![0; ESP_START + ESP_SIZE + 33 * SECTOR];
    let mut root = vec![0; entry_size];
    root[..16].fill(0x11); // Non-ESP partition type.
    root[16..32].fill(0x22);
    root[32..40].copy_from_slice(&96u64.to_le_bytes());
    root[40..48].copy_from_slice(&127u64.to_le_bytes());
    root[128..].fill(0x5a);
    let mut esp = vec![0; entry_size];
    esp[..16].copy_from_slice(&ESP_GUID);
    esp[16..32].fill(0x33);
    esp[32..40].copy_from_slice(&(ESP_START as u64 / SECTOR as u64).to_le_bytes());
    esp[40..48].copy_from_slice(&((ESP_START + ESP_SIZE) as u64 / SECTOR as u64 - 1).to_le_bytes());
    esp[128..].fill(0xa5);

    let array = &mut disk[array_lba * SECTOR..array_lba * SECTOR + 128 * entry_size];
    let root_slot = if esp_slot == 0 { 1 } else { 0 };
    array[root_slot * entry_size..(root_slot + 1) * entry_size].copy_from_slice(&root);
    array[esp_slot * entry_size..(esp_slot + 1) * entry_size].copy_from_slice(&esp);
    // Data in an unused entry must not become a measured partition.
    array[3 * entry_size + 16..4 * entry_size].fill(0x77);
    let array_crc = crc32fast::hash(array);
    let last_lba = disk.len() as u64 / SECTOR as u64 - 1;
    let header = &mut disk[512..604];
    header[..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[24..32].copy_from_slice(&1u64.to_le_bytes());
    header[32..40].copy_from_slice(&last_lba.to_le_bytes());
    header[40..48].copy_from_slice(&96u64.to_le_bytes());
    header[48..56].copy_from_slice(&(last_lba - 33).to_le_bytes());
    header[72..80].copy_from_slice(&(array_lba as u64).to_le_bytes());
    header[80..84].copy_from_slice(&128u32.to_le_bytes());
    header[84..88].copy_from_slice(&(entry_size as u32).to_le_bytes());
    header[88..92].copy_from_slice(&array_crc.to_le_bytes());
    let header_crc = crc32fast::hash(header);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());

    // Independent expected event payload: the header and two occupied
    // entries, in slot order, without any unused entries.
    let mut event = header.to_vec();
    event.extend_from_slice(&2u64.to_le_bytes());
    for entry in if esp_slot == 0 { [&esp, &root] } else { [&root, &esp] } {
        event.extend_from_slice(entry);
    }

    let mut volume = Cursor::new(&mut disk[ESP_START..ESP_START + ESP_SIZE]);
    fatfs::format_volume(&mut volume, fatfs::FormatVolumeOptions::new()).unwrap();
    volume.set_position(0);
    let fs = fatfs::FileSystem::new(volume, fatfs::FsOptions::new()).unwrap();
    {
        let efi = fs.root_dir().create_dir("EFI").unwrap();
        let boot = efi.create_dir("BOOT").unwrap();
        boot.create_file("BOOTX64.EFI").unwrap().write_all(&uki_image()).unwrap();
    }
    fs.unmount().unwrap();
    (disk, Sha384::digest(event).into())
}

#[test]
fn reads_uki_and_measures_the_declared_partition_array() {
    let bare = Uki::parse(&uki_image()).unwrap();
    for (array_lba, esp_slot, entry_size) in [(2, 0, 128), (8, 2, 128), (8, 2, 256)] {
        let (disk, expected_hash) = disk_image(array_lba, esp_slot, entry_size);
        let uki = Uki::parse(&disk).unwrap();
        assert!(uki.has_rootfs);
        assert_eq!(uki.authenticode_sha384, bare.authenticode_sha384);
        assert_eq!(uki.disk_guid_hash, Some(expected_hash));
        let hashes = dcap::measure(&uki).unwrap();
        assert_eq!(hashes.gpt_disk_guid_hash, expected_hash);
        let registers = dcap::gcp::measure(&hashes);
        assert_eq!(registers.rtmr1.events()[2].digest, expected_hash);
    }
}

#[test]
fn reads_nonstandard_layout_from_gcp_archive() {
    let (disk, expected_hash) = disk_image(8, 2, 256);
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_size(disk.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, "disk.raw", disk.as_slice()).unwrap();
    let data = archive.into_inner().unwrap().finish().unwrap();
    let uki = Uki::parse(&data).unwrap();
    assert_eq!(uki.disk_guid_hash, Some(expected_hash));
}

#[test]
fn rejects_missing_or_ambiguous_esp() {
    let (mut disk, _) = disk_image(8, 2, 256);
    let esp_type = 8 * SECTOR + 2 * 256;
    disk[esp_type..esp_type + 16].fill(0x11);
    assert!(matches!(Uki::parse(&disk), Err(UkiError::Disk("GPT has no EFI system partition"))));
    disk[esp_type..esp_type + 16].copy_from_slice(&ESP_GUID);
    disk[8 * SECTOR..8 * SECTOR + 16].copy_from_slice(&ESP_GUID);
    assert!(matches!(
        Uki::parse(&disk),
        Err(UkiError::Disk("GPT has multiple EFI system partitions"))
    ));
}

#[test]
fn malformed_offsets_and_sizes_return_errors() {
    let (disk, _) = disk_image(8, 2, 256);
    let entry = 8 * SECTOR + 2 * 256;
    for (offset, value) in [
        (512 + 72, u64::MAX),       // Partition array offset multiplication overflow.
        (512 + 72, u64::MAX / 512), // Partition array end overflow or out of bounds.
        (512 + 72, disk.len() as u64 / 512), // Truncated partition array.
        (entry + 32, 129),          // First LBA after the last LBA (set below).
        (entry + 40, u64::MAX),     // Inclusive last-LBA conversion overflow.
        (entry + 40, u64::MAX / 512), // Partition end offset overflow.
        (entry + 40, disk.len() as u64 / 512), // Partition past the end of the disk.
    ] {
        let mut invalid = disk.clone();
        invalid[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        if offset == entry + 32 {
            invalid[entry + 40..entry + 48].copy_from_slice(&128u64.to_le_bytes());
        }
        assert!(
            matches!(Uki::parse(&invalid), Err(UkiError::Disk(_))),
            "offset {offset}, value {value}"
        );
    }
    for size in [0u32, 16, 127, u32::MAX] {
        let mut invalid = disk.clone();
        invalid[512 + 84..512 + 88].copy_from_slice(&size.to_le_bytes());
        assert!(matches!(Uki::parse(&invalid), Err(UkiError::Disk(_))));
    }
}
