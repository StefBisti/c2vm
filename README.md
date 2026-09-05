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

## Test demo with nginx

``` bash
make
sudo modprobe kvm_intel # enable kvm

# 1. build (Debian kernel)
sudo ./c2vm build nginx:stable \
  --kernel linux-image-amd64 \
  --hostname nginx-vm \
  --format qcow2 \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --out build-nginx
sudo chown -R $USER:$USER build-nginx

# 2. check if it actually boots and matches its own build.json
./c2vm boot-test build-nginx/disk.qcow2 --ssh-key ~/.ssh/id_ed25519 --out build-nginx

# 3. custody, into its own directory
sudo ./c2vm scan build-nginx/disk.qcow2 --out build-nginx --results results-nginx
sudo chown -R $USER:$USER results-nginx
./c2vm diff results-nginx/sbom-source.spdx.json results-nginx/sbom-disk.spdx.json --results results-nginx
./c2vm cve results-nginx/cve-source.json results-nginx/cve-disk.json --results results-nginx

# 4. test nginx serving

cp /usr/share/OVMF/OVMF_VARS_4M.fd /tmp/nginx-vars.fd

qemu-system-x86_64 -machine q35 -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=/tmp/nginx-vars.fd \
  -drive file=build-nginx/disk.qcow2,format=qcow2,if=virtio \
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:80 \
  -device virtio-net-pci,netdev=net0 \
  -display none -serial file:/tmp/nginx-console.log -no-reboot -snapshot

# leave it running for a bit (40s), then, in another terminal:
curl -i http://localhost:8080 # expect HTTP/1.1 200 OK, Server: nginx/1.28.x and the Welcome page

# 5. publish
./c2vm push build-nginx/disk.qcow2 ghcr.io/stefbisti/c2vm-nginx:latest --out build-nginx
./c2vm sign   ghcr.io/stefbisti/c2vm-nginx:latest
./c2vm attest ghcr.io/stefbisti/c2vm-nginx:latest --out build-nginx --results results-nginx
./c2vm verify ghcr.io/stefbisti/c2vm-nginx:latest




```

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
