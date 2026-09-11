# Requirements

## Host

c2vm builds disks by attaching loop devices, mounting them and running `chroot`. Meaning, it is Linux-only and root-only.

| | |
|---|---|
| OS | Linux. Tested on Ubuntu 24.04 (kernel 6.14) |
| Architecture | x86_64 only |
| Privileges | `build` and `scan` need root |
| Virtualisation | `/dev/kvm` for `boot-test`. Without it the timeout triples |
| Disk | ~4 GB per build: extracted rootfs, raw disk, each output format |

## Install (complete)

```bash
sudo apt install build-essential libcrypt-dev skopeo umoci rsync qemu-utils parted dosfstools libguestfs-tools ovmf qemu-system-x86 openssh-client genisoimage

make
mkdir -p ~/.local/bin
make tools          # syft, grype, cosign and oras into ~/.local/bin
grype db update     # as your own user, NOT under sudo
```

Put `~/.local/bin` on your `PATH`. The rest of what `build` uses (`mount`, `losetup`, `blkid`, `chroot`, `tar`, `sha256sum` and friends) ships with any Linux install.

`grype db update` is a one-off per machine. Auto-update is deliberately off, so `verify` can never silently measure against a different database than you meant.

Elsewhere: Fedora `dnf install edk2-ovmf libguestfs-tools-c`, Arch `pacman -S edk2-ovmf libguestfs`. Only Debian and Ubuntu are tested.

## What each command needs

Every tool is looked up on `PATH` when it is used, so you only need the row you actually run.

| command | needs |
|---|---|
| `build` | `skopeo` `umoci` `rsync` `qemu-img` `parted` `mkfs.vfat` `mkfs.ext4` |
| `boot-test` | `qemu-system-x86_64`, OVMF firmware, `ssh` |
| `scan` | `syft` `grype` `guestmount` |
| `sbom-diff` `cve-diff` | nothing |
| `push` `sign` `attest` | `oras` `cosign`, and a browser for the Sigstore login |
| `verify` | `oras` `cosign` `grype` |

`genisoimage` is not used by c2vm itself. You need it to build the cloud-init seed that gives a published disk its credentials.

## Guest images

Debian-family only. `build` runs `apt-get` and `dpkg-query` inside the extracted rootfs and installs `grub-efi-amd64` and `netplan.io` by name.

- works: `ubuntu:*`, `debian:*`, and anything derived from them
- fails: Alpine, Fedora, RHEL/UBI, Arch, distroless, `scratch`

The image has to be in a registry, since `skopeo` pulls it over `docker://`. Push a locally built image first.

## Publishing

`push`, `sign` and `attest` need a registry you can write to and an account Sigstore recognises:

- `docker login ghcr.io` with a token carrying `write:packages`
- a browser, for the OIDC login `cosign sign` opens
- a registry that accepts OCI artifacts with a custom `artifactType` (ghcr does)

`verify` needs none of that. It is read-only and anonymous against a public registry.

## Check your setup

```bash
for t in skopeo umoci rsync qemu-img parted mkfs.vfat guestmount syft grype cosign oras qemu-system-x86_64 ssh; do
  printf '%-20s %s\n' "$t" "$(command -v $t || echo MISSING)"
done
ls /usr/share/OVMF/OVMF_CODE*.fd 2>/dev/null || echo "OVMF MISSING"
[ -e /dev/kvm ] && echo "kvm ok" || echo "no kvm, boot-test will be slow"
```
