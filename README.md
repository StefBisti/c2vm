# c2vm

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## What it is

Convertor from a Debian-family OCI image to a bootable VM disk (QCOW2, OVA), while preserving the conversion supply-chain

## Explanation

A container image has a digest, an SBOM and a signature. Turning it into a bootable disk adds a kernel, an initramfs, GRUB and systemd that weren't initially in the image, so the result is an opaque multi-gigabyte blob whose recipient can prove neither what is in it nor where it came from.

c2vm measures what the conversion added and signs a statement binding the output disk back to the source image digest.

## The numbers

Converting `ubuntu:24.04` to a bootable QCOW2, measured with syft 1.51.1 and grype 0.118.0 (vulnerability database built 2026-09-01):

| | container | VM disk |
|---|---|---|
| Debian packages | 92 | 209 (**+117**) |
| Critical CVEs | 0 | **5** |
| High CVEs | 0 | **152** |

## Quickstart

```sh
make tools          # syft, grype, cosign, oras
make

sudo ./c2vm build ubuntu:24.04 --format qcow2,ova --ssh-key ~/.ssh/id_ed25519.pub
./c2vm boot-test build/disk.qcow2 --ssh-key ~/.ssh/id_ed25519

sudo ./c2vm scan build/disk.qcow2
./c2vm diff results/sbom-source.spdx.json results/sbom-disk.spdx.json
./c2vm cve  results/cve-source.json      results/cve-disk.json
```

Publishing:

```sh
./c2vm push build/disk.qcow2 ghcr.io/<user>/c2vm-demo:latest
./c2vm sign   ghcr.io/<user>/c2vm-demo:latest
./c2vm attest ghcr.io/<user>/c2vm-demo:latest
./c2vm verify ghcr.io/<user>/c2vm-demo:latest
```

Requires a Linux host with KVM, `qemu`, `parted`, `rsync`, `skopeo`, `umoci` and `libguestfs-tools`. `build` and `scan` need root.

## Commands

| | |
|---|---|
| `build <image-ref>` | container image → bootable disk, recording every decision in `build.json` |
| `boot-test <artifact>` | boot it headless, assert the guest is the one `build.json` describes |
| `scan <artifact>` | SBOMs of both sides (SPDX + CycloneDX), then grype over each |
| `diff <sbom-a> <sbom-b>` | package delta: added, removed, version-changed |
| `cve <report-a> <report-b>` | vulnerability delta by severity, attributed to packages |
| `push` / `sign` / `attest` | publish as an OCI artifact, sign keylessly, attach attestations |
| `verify <oci-ref>` | check signature, identity, both attestations and CVE policy |

Full reference in [docs/cli.md](docs/cli.md).

## How the chain holds together

```
ubuntu@sha256:33ceb7…            source, pinned by digest
      │
    build          -> build.json: source digest, kernel, bootloader, flags,
      │                          and the sha256 of every artifact produced
    scan           -> SBOMs of the container and the disk, one syft version
      │
  diff / cve       -> +117 packages, +152 High
      │
push/sign/attest   -> signed in-toto statement, logged in Rekor
      │
    verify         -> identity, both attestations, disk-statement binding,
                     source digest, CVE policy
```

Each step consumes what the previous one recorded. `scan` refuses to run if the disk's hash no longer matches what `build` wrote

## Layout

```
src/core/       process, cleanup and JSON plumbing
src/convert/    build, OVA packaging, boot testing
src/custody/    SBOMs, deltas, signing, attestation
policy/         who may have signed, and the CVE limits
scripts/        rootfs extraction, charting
results/        SBOMs, deltas, the predicate — committed as evidence
```

## Acknowledgements

Written by Stefan Bisti as a university project, with [Claude Code](https://claude.com/claude-code) used for:
- Architectural planning
- Implementation and code-review
- Clarifying some concepts

## License

MIT — see [LICENSE](LICENSE).
