# c2vm

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Turns a Debian-family container image into a VM disk (qcow2 / ova) that anyone can verify when distributed and also writes down everything the conversion added on the way.

For ubuntu:24.04 that is 117 Debian packages: a kernel, GRUB, systemd, cloud-init, netplan, and whatever those drag in. Every one is recorded, signed, and checkable by whoever you hand the disk to.

## How to use this

If you build the VM for yourself, you get that list of added packages and their cves. `sbom-diff` prints all 117 packages grouped by what pulled each one in, and `cve-diff` says which of them have vulnerabilities.

If someone hands you a VM that c2vm built, you can prove it is theirs before you boot it: this exact disk, built by this named identity, from this exact source image, with those exact 117 packages added. Six checks, run against a registry reference, without you even downloading the disk. That record is written on every build and cannot be by-passed.

## The pipeline

```
OCI image                    ubuntu:24.04, pulled by digest
  |
  |  build         partition, format, chroot, install kernel + GRUB +
  |                systemd + cloud-init, write build.json
  v
disk.qcow2 / disk.ova
  |
  |  boot-test     boot it headless, check the guest against build.json
  |  scan          inventory the source image and the disk with syft,
  |                then scan both with grype
  |  sbom-diff     which packages the conversion added, and what pulled them
  |  cve-diff      which vulnerabilities arrived with them
  |  push          upload to a registry, which indexes it by its sha256
  |  sign          Sigstore. No key to store: you get a 10-minute
  |                certificate tied to whoever you log in as
  |  attest        attach the SBOM and a signed record of the conversion
  v
ghcr.io/you/appliance:1
  |
  |  verify        six checks, from that reference alone.
  |                The disk is never downloaded. You download it after.
```

## Quickstart

```bash
sudo apt install build-essential libcrypt-dev
make
make tools # syft, grype, cosign and oras, into ~/.local/bin
```

Put `~/.local/bin` on your `PATH` if it isn't already. Full list of what else you need is in [requirements.md](docs/requirements.md).

### A VM for yourself

```bash
sudo ./c2vm build ubuntu:24.04 --format qcow2 --ssh-key ~/.ssh/id_ed25519.pub
./c2vm boot-test build/disk.qcow2 --ssh-key ~/.ssh/id_ed25519
```

Your public key gets written into the disk, so only do this for a VM you keep.

The private key can't have a passphrase, because `boot-test` runs `ssh` with no terminal to answer the prompt.

`boot-test` boots the disk headless, checks that the guest matches `build/metadata/build.json`, then shuts it down. It does not leave a VM running for you.

To actually use the disk, point QEMU or VirtualBox at `build/disk.qcow2`.

### A VM to distribute

Build with no credentials at all. Whoever receives the disk supplies their own account at boot time with a cloud-init seed, which is a tiny ISO labelled `cidata` that cloud-init looks for and reads on first boot.

```bash
sudo ./c2vm build ubuntu:24.04 --format qcow2,ova

# a throwaway login, so boot-test can ssh in. It lives on the ISO, never on the disk
mkdir -p seed
printf '#cloud-config\nusers:\n  - name: c2vm\n    groups: [adm, sudo]\n    shell: /bin/bash\n    sudo: "ALL=(ALL) NOPASSWD:ALL"\n    ssh_authorized_keys:\n      - "%s"\n' \
  "$(cat ~/.ssh/id_ed25519.pub)" > seed/user-data
echo "instance-id: iid-boot-test" > seed/meta-data
genisoimage -quiet -output seed.iso -V cidata -r -J seed

./c2vm boot-test build/disk.qcow2 --ssh-key ~/.ssh/id_ed25519 --seed seed.iso

sudo ./c2vm scan build/disk.qcow2
./c2vm sbom-diff results/sbom-source.spdx.json results/sbom-disk.spdx.json
./c2vm cve-diff  results/cve-source.json      results/cve-disk.json

./c2vm push   build/disk.qcow2 ghcr.io/<you>/c2vm-demo:latest
./c2vm sign   ghcr.io/<you>/c2vm-demo:latest
./c2vm attest ghcr.io/<you>/c2vm-demo:latest
```

`push` uploads the disk as an OCI artifact with its own media types rather than as an image, so no runtime will ever try to `docker run` it. The registry is a simple storage here, the manifest is what carries the claims.

## What the other end sees

On a second machine, with only `cosign`, `oras`, `grype` and c2vm installed:

```
$ ./c2vm verify ghcr.io/you/c2vm-demo:latest

==> verifying ghcr.io/you/c2vm-demo:latest
  identity you@example.com (https://github.com/login/oauth)

  ok   signature                    sha256:3f14b536...
  ok   sbom attestation             https://spdx.dev/Document
  ok   conversion attestation       https://c2vm.dev/conversion/v1
  ok   disk digest binding          sha256:d0f38150...
  ok   source image                 sha256:224a1869...

  ubuntu:24.04 -> kernel 6.8.0-139.139, built 2026-09-11T05:55:57Z

  severity            all        deb
  Critical            112          5
  High               1928        164
  Medium             5696       2350
  Low                 228        206
  Negligible           14         14

  ok   cve policy: critical         5 deb finding(s), limit 8
  ok   cve policy: high             164 deb finding(s), limit 220

all checks passed
```

## Commands

| | |
|---|---|
| `build <image-ref>` | container image to bootable disk, recording every decision in `build.json` |
| `boot-test <artifact>` | boot it headless, assert the guest is the one `build.json` describes |
| `scan <artifact>` | SBOMs of the source image and the disk (SPDX + CycloneDX), then grype over each |
| `sbom-diff <a> <b>` | package delta: added, removed, version-changed |
| `cve-diff <a> <b>` | vulnerability delta by severity, attributed to packages |
| `push` / `sign` / `attest` | publish as an OCI artifact, sign it through Sigstore, attach the attestations |
| `verify <oci-ref>` | check signature, identity, both attestations and the CVE policy |

## Documentation

| | |
|---|---|
| [requirements.md](docs/requirements.md) | what you need installed |
| [cli.md](docs/cli.md) | every command, every flag |
| [internals.md](docs/internals.md) | how each command works |
| [limitations.md](docs/limitations.md) | what it cannot do, why, and workarounds |
| [alternatives.md](docs/alternatives.md) | other converters, and when to use them instead |
| [troubleshooting.md](docs/troubleshooting.md) | when something fails |
| [tutorial.md](docs/tutorial.md) | build a real service appliance, publish it, verify it elsewhere, then tamper with it |


## Layout

```
src/core/       process, cleanup and JSON plumbing
src/convert/    build, OVA packaging, boot testing
src/custody/    SBOMs, deltas, signing, attestation
policy/         who may have signed, and the CVE limits
scripts/        rootfs extraction, CVE charts
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
