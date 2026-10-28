use attest_measure::dcap::{DcapFirmware, HobTemplate, expected_dcap_registers};
use types::{AcpiHashes, AttestationType, DcapImageHashes, PlatformMetadata};

#[test]
fn reconstruction_vectors() {
    let fw = DcapFirmware {
        mrtd: [8; 48],
        cfv: [9; 48],
        hob: HobTemplate { bytes: vec![0; 16], length_offset: 8, ram_threshold: 1 << 30 },
    };
    let expected = [
        (
            "91106bcc159e7b49b532f299c48ee6f4875d3fe9c15478e7ab7686b5af568526d11c15483abc6f64d7b5f662794f6d57",
            "1b5000425429cf1e463f4c19971df1cb19490945e66c3b4fecfec3f8603ab0b951ed1c4c7fa32eb85003ccaa0cbf1feb",
            "073b5bc904ee0899b6103f1415cc8ff148265c75f4a81e0b0b2f2f12961f02694beec42e5b385947636e4a5ac8f37531",
        ),
        (
            "e11cc7b8dffc62101d2fb864a7dad60adf5f73bc34f8e64d128bcc143fb0bcab757aac3254ef91dd00a6d9e7ce757af5",
            "14f0c02930eaf63ceda1f319a9ae71d7834f603f045af12f294d2f8d13766643f7ed91d340689885427aae640aad245b",
            "073b5bc904ee0899b6103f1415cc8ff148265c75f4a81e0b0b2f2f12961f02694beec42e5b385947636e4a5ac8f37531",
        ),
        (
            "a618b3a4ca9600f01a4d37aeb803bb9292a6d06c290c30ebb52bf86a8f3d82c375370b03899fb2d3781fe791140c7709",
            "1b5000425429cf1e463f4c19971df1cb19490945e66c3b4fecfec3f8603ab0b951ed1c4c7fa32eb85003ccaa0cbf1feb",
            "f590da9d8aff71be51349ecfed58dc2b7ad4d4a4f650b0263d507a47ac8c64d71ae386d904f3b7c36fbb1fa78055ae78",
        ),
    ];
    for ((kind, disk, sections), (rtmr0, rtmr1, rtmr2)) in [
        (AttestationType::GcpTdx, true, None),
        (AttestationType::SelfHostedTdx, false, None),
        (AttestationType::SelfHostedTdx, true, Some([6; 48])),
    ]
    .into_iter()
    .zip(expected)
    {
        let image = DcapImageHashes {
            uki_authenticode: [1; 48],
            kernel_authenticode: [2; 48],
            cmdline_hash: [3; 48],
            initrd_hash: [4; 48],
            gpt_disk_guid_hash: [5; 48],
            pe_sections: sections,
        };
        let platform = PlatformMetadata {
            attestation_type: kind,
            ram_bytes: 4 << 30,
            num_disks: 1,
            acpi: Some(AcpiHashes { loader: [10; 48], rsdp: [11; 48], tables: [12; 48] }),
            smbios_handoff: None,
            dm_verity_boot: disk,
        };
        let r = expected_dcap_registers(&image, &platform, Some(&fw)).unwrap();
        assert_eq!(r.mrtd, Some(fw.mrtd));
        assert_eq!(hex::encode(r.rtmr0.unwrap()), rtmr0);
        assert_eq!(hex::encode(r.rtmr1), rtmr1);
        assert_eq!(hex::encode(r.rtmr2), rtmr2);
    }
}
