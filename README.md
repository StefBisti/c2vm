# c2vm

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## What it is

Convertor from a Debian-family OCI image into a bootable VM disk (QCOW2, OVA), while preserving and verifying the conversion supply-chain.

## The scenario

Someone sends you an `appliance.ova` and even though it runs, you question:

- What exactly is inside it?
- Who built it, and from what?
- Has anything changed inside it since they built it? Is it still safe?
- How much did the conversion add (packages and cves)?

c2vm produces a disk where you can figure out everything above from the artifact itself without even downloading it.

## How it works

```
OCI image
  |  build        pull by digest, partition, format, chroot, install
  |               kernel + GRUB + systemd + cloud-init, record build.json
disk.qcow2 / disk.ova
  |  boot-test    boot headless, assert the guest matches build.json
  |  scan         SBOM both sides, then grype over each
  |  sbom-diff    what the conversion added, grouped by why
  |  cve-diff     what it cost in cves
  |  push         registry as content-addressed storage
  |  sign         keyless, via Sigstore
  |  attest       SBOM + a conversion statement, both signed
  |
  |  verify       six checks from a reference alone — the disk is never downloaded
```

## Quickstart

### For local-usage (only the conversion)

```bash
make tools # installs syft, grype, cosign, oras
make

sudo ./c2vm build ubuntu:24.04 --format qcow2,ova --ssh-key /path/to/ssh/key.pub
# Key must not be pass-phrase protected. The public key will be ingrained in the disk
./c2vm boot-test build/disk.qcow2 --ssh-key /path/to/ssh/key
# Start the vm, then ssh into it
```

### For distributing the vm (supply-chain attestation)

```bash
make tools # installs syft, grype, cosign, oras
make

sudo ./c2vm build ubuntu:24.04 --format qcow2,ova

# a throwaway login for boot-test only
mkdir -p seed
printf '#cloud-config\nusers:\n  - name: c2vm\n    groups: [adm, sudo]\n    shell: /bin/bash\n    sudo: "ALL=(ALL) NOPASSWD:ALL"\n    ssh_authorized_keys:\n      - "%s"\n' \
  "$(cat /path/to/ssh/key.pub)" > seed/user-data
echo "instance-id: iid-boot-test" > seed/meta-data
genisoimage -quiet -output seed.iso -V cidata -r -J seed

# key must not be pass-phrase protected
./c2vm boot-test build/disk.qcow2 --ssh-key /path/to/ssh/key --seed seed.iso

sudo ./c2vm scan build/disk.qcow2
./c2vm sbom-diff results/sbom-source.spdx.json results/sbom-disk.spdx.json
./c2vm cve-diff  results/cve-source.json      results/cve-disk.json

./c2vm push build/disk.qcow2 ghcr.io/<user>/c2vm-demo:latest
./c2vm sign   ghcr.io/<user>/c2vm-demo:latest
./c2vm attest ghcr.io/<user>/c2vm-demo:latest

./c2vm verify ghcr.io/<user>/c2vm-demo:latest
```

Important: The disk is pushed as an OCI artifact with its own media types (nothing will try to docker run it). The registry is being used as a simple content-addressed storage.

## Commands

| | |
|---|---|
| `build <image-ref>` | container image to bootable disk, recording every decision in `build.json` |
| `boot-test <artifact>` | boot it headless, assert the guest is the one `build.json` describes |
| `scan <artifact>` | SBOMs of both sides (SPDX + CycloneDX), then grype over each |
| `sbom-diff <a> <b>` | package delta: added, removed, version-changed |
| `cve-diff <a> <b>` | vulnerability delta by severity, attributed to packages |
| `push` / `sign` / `attest` | publish as an OCI artifact, sign keylessly, attach attestations |
| `verify <oci-ref>` | check signature, identity, both attestations and CVE policy |

## Documentation

| | |
|---|---|
| [requirements.md](docs/requirements.md) | what you need installed |
| [tutorial.md](docs/tutorial.md) | full overview of how c2vm works |
| [cli.md](docs/cli.md) | every command, every flag |
| [internals.md](docs/internals.md) | how each command works |
| [limitations.md](docs/limitations.md) | what it cannot do, why, and workarounds |
| [alternatives.md](docs/alternatives.md) | other converters, and when to use them instead |
| [troubleshooting.md](docs/troubleshooting.md) | when something fails |

## Layout

```
src/core/       process, cleanup and JSON plumbing
src/convert/    build, OVA packaging, boot testing
src/custody/    SBOMs, deltas, signing, attestation
policy/         who may have signed, and the CVE limits
scripts/        rootfs extraction, charting
docs/           everything above
```

## Acknowledgements

Written by Stefan Bisti as a university project, with [Claude Code](https://claude.com/claude-code) used for:
- Architectural planning
- Implementation and code-review
- Clarifying some concepts
- Writing the docs and README

## License

MIT - see [LICENSE](LICENSE).
