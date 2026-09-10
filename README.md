# c2vm

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## What it is

Convertor from a Debian-family OCI image to a bootable VM disk (QCOW2, OVA), while preserving and verifying the conversion supply-chain.

## The scenario

Someone sends you a 600MB `appliance.ova`. Even though it runs, you question:

- What exactly is inside it?
- Who built it, and from what?
- Has anything changed since they built it?
- How much did the conversion add?

c2vm produces a disk where you can answer everything from the artifact itself without even downloading it.

## The numbers

Converting `ubuntu@sha256:2260313b…` (`ubuntu:latest` on 2026-09-09) to a bootable QCOW2, measured with syft 1.51.1 and grype 0.118.0 (vulnerability database built 2026-09-09). Debian packages and CVEs are counted over `pkg:deb` only — see [why there are two columns](docs/examples/cve-diff.md):

| | container | VM disk |
|---|---|---|
| Debian packages | 87 | 215 (**+128**) |
| Critical CVEs | 0 | **4** |
| High CVEs | 0 | **87** |

Sample reports: [docs/examples](docs/examples/)

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
  | verify        six checks from a reference alone — the disk is never downloaded
```

## Quickstart

```bash
make tools # installs syft, grype, cosign, oras
make

sudo ./c2vm build ubuntu:24.04 --format qcow2,ova --ssh-key ~/.ssh/id_ed25519.pub
./c2vm boot-test build/disk.qcow2 --ssh-key ~/.ssh/id_ed25519

sudo ./c2vm scan build/disk.qcow2
./c2vm sbom-diff results/sbom-source.spdx.json results/sbom-disk.spdx.json
./c2vm cve-diff  results/cve-source.json      results/cve-disk.json
```

Publishing, then verifying from anywhere:

```bash
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

## Status and limits

Working and used end to end. Not production-hardened.

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
- Writing the docs

## License

MIT - see [LICENSE](LICENSE).
