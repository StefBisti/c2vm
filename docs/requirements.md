# Requirements

## Host

c2vm builds disks by attaching loop devices, mounting them and running `chroot`. Meaning, it is Linux-only and root-only.

| | |
|---|---|
| OS | Linux. Tested on Ubuntu 24.04 (kernel 6.14) |
| Architecture | x86_64 only |
| Privileges | `build` and `scan` need root |
| Virtualisation | `/dev/kvm` for `boot-test`, without it, 3x slower |
| Disk | ~4 GB per build: extracted rootfs, raw disk, each output format |

## Guest images

c2vm support **debian-family** images only The build runs `apt-get` and `dpkg-query` inside the extracted rootfs, and installs `grub-efi-amd64` and `netplan.io` by name.
- works: `ubuntu:*`, `debian:*`, and images derived from them
- does not work: Alpine, Fedora, RHEL/UBI, Arch, distroless, `scratch`

The image must be reachable by `skopeo` over `docker://`, so it lives in a registry. A locally built image has to be pushed first.

## Build dependencies

```bash
sudo apt install build-essential libcrypt-dev
make
```

- C11 compiler and `make`
- `libcrypt` is linked for `crypt(3)`, used to hash `--root-password`.

## Runtime dependencies

Grouped by the command that needs them. Nothing is bundled; every one is looked up on PATH at the moment it is used, so you only need the set for the commands you actually run.

| command | needs |
|---|---|
| `build` | `skopeo` `umoci` `rsync` `qemu-img` `parted` `losetup` `mount` `findmnt` `udevadm` `blkid` `chroot` `mkfs.vfat` `mkfs.ext4` `tar` `truncate` `sha256sum` |
| `boot-test` | `qemu-system-x86_64`, OVMF firmware, `ssh`, `tar` (for `.ova` input) |
| `scan` | `syft` `grype` `guestmount` `guestunmount` `sha256sum` |
| `push` `sign` `attest` `verify` | `oras` `cosign`, and a browser for the Sigstore login |

Most of the `build` list is `coreutils`, `util-linux` and `e2fsprogs`, already present on any Linux install. On Debian/Ubuntu the rest is:

```bash
sudo apt install skopeo umoci rsync qemu-utils parted dosfstools libguestfs-tools ovmf qemu-system-x86 openssh-client genisoimage
```

`syft`, `grype`, `cosign` and `oras` are single binaries not carried by distributions. Install the pinned versions with:

```bash
make tools # installs into ~/.local/bin
```

Package names differ elsewhere — on Fedora `dnf install edk2-ovmf libguestfs-tools-c`, on Arch `pacman -S edk2-ovmf libguestfs`. Only Debian/Ubuntu is tested. `genisoimage` is not used by c2vm itself; you need it to build the cloud-init seed that gives a published disk its credentials. See [tutorial.md](tutorial.md).

## Checking

```bash
for t in skopeo umoci rsync qemu-img parted mkfs.vfat guestmount syft grype cosign oras qemu-system-x86_64 ssh; do
  printf '%-20s %s\n' "$t" "$(command -v $t || echo MISSING)"
done
ls /usr/share/OVMF/OVMF_CODE*.fd 2>/dev/null || echo "OVMF MISSING"
[ -e /dev/kvm ] && echo "kvm ok" || echo "no kvm — boot-test will be slow"
```

## Publishing

`push`, `sign` and `attest` need a registry you can write to and an account Sigstore recognises:

- `docker login ghcr.io` with a personal access token carrying `write:packages`
- a browser, for the OIDC login `cosign sign` opens
- a registry that accepts OCI artifacts with a custom `artifactType` (ghcr does)

`verify` needs neither, it is read-only and anonymous against a public registry.
