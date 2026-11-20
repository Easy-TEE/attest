# attest

Attestation generation, verification, and measurement for confidential VMs

A library and CLI to:

- **Measure** a TEE VM image file and predict its expected register values (RTMRs / PCRs)
- **Generate** an attestation quote from inside a confidential VM
- **Verify** a quote against expected measurements

Works out of the box with official Flashbots confidential images and with any image built using [Easy-TEE](https://github.com/flashbots/easy-tee)

Supports Azure, GCP, and self-hosted deployments

TDX image measurement does not support UKIs containing `.ucode` (a separate
microcode archive) or `.pcrpkey` (a PCR signature public key). These sections
change the initrd buffer that systemd-stub passes to Linux, which this predictor
does not reconstruct. The GCP, self-hosted, and portable measurement commands
return an error naming the unsupported section instead of predicting RTMR2.
Microcode already bundled inside `.initrd` does not require a separate `.ucode`
section and is covered by the existing initrd hash.

For a client/server library and standalone proxy built on top of `attest`, see [attested-tls](https://github.com/flashbots/attested-tls)

## Measurement library features

`attest-measure` has three features all of which are enabled by default:

| Feature | Enables |
| --- | --- |
| `image` | UKI/PE, disk, archive, and GPT processing; image measurements and Azure PCR calculation; register event recording, event accessors, and debug JSON |
| `platform` | Host metadata collection and CCEL parsing |
| `google-firmware` | Downloading Google firmware and verifying its signed endorsements |
