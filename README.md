# attest

Attestation generation, verification, and measurement for confidential VMs

A library and CLI to:

- **Measure** a TEE VM image file and predict its expected register values (RTMRs / PCRs)
- **Generate** an attestation quote from inside a confidential VM
- **Verify** a quote against expected measurements

Works out of the box with official Flashbots confidential images and with any image built using [Easy-TEE](https://github.com/flashbots/easy-tee)

Supports Azure, GCP, and self-hosted deployments

For a client/server library and standalone proxy built on top of `attest`, see [attested-tls](https://github.com/flashbots/attested-tls)

## Measurement library features

`attest-measure` has three features all of which are enabled by default:

| Feature | Enables |
| --- | --- |
| `image` | UKI/PE, disk, archive, and GPT processing; image measurements and Azure PCR calculation; register event recording, event accessors, and debug JSON |
| `platform` | Host metadata collection and CCEL parsing |
| `google-firmware` | Downloading Google firmware and verifying its signed endorsements |
