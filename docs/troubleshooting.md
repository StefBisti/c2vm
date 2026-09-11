# Troubleshooting

Symptom, cause, fix. Most of these are a `die` message from c2vm itself.

## build

### `build must run as root`

`losetup`, `mount` and `chroot` need it. Use `sudo`, or `--dry-run` to check a command line without privileges.

### `<dir> exists but is not a c2vm output directory (no metadata/)`

`build` refuses to `rm -rf` a directory it did not create. Either you pointed `--out` at the wrong place, or a previous build died before writing `metadata/`. Delete it by hand once you have checked what is in it.

### `extract-rootfs.sh did not return a digest`

`skopeo` failed. Usually: the image reference is wrong, the registry needs `docker login`, or there is no network. Run the script by hand to see skopeo's own error:

```bash
scripts/extract-rootfs.sh ubuntu:24.04 /tmp/rootfs-test
```

### `apt-get` fails inside the chroot

Almost always DNS. `mount_all` copies the host's `/etc/resolv.conf` into the guest; if the host uses `systemd-resolved`, that file may be a symlink to a stub that means nothing inside a chroot.

```bash
readlink -f /etc/resolv.conf     # if it points into /run, that's the cause
```

Fix by pointing the host's resolv.conf at a real nameserver for the build, or copying `/run/systemd/resolve/resolv.conf` instead.

### `grub-install` fails

The ESP is not mounted, or the image is not Debian-family so `grub-efi-amd64` was never installed. Check that `--format` produced a partitioned disk and that the base image is Debian or Ubuntu.

### `too many packages (limit is 127)`

`--packages` overflowed the argv array in `apt_install`. Split into a smaller set, or install the rest inside the guest at first boot with cloud-init.

### Leaked loop devices after a crash

```bash
make loop-check                   # lists any still attached to this directory
sudo losetup -d /dev/loopN
```

`cleanup.c` runs on `atexit` and on `SIGINT`/`SIGTERM`, so this should only happen after a `SIGKILL` or a host crash. c2vm warns if it could not detach one.

### `<path> is still mounted` after a failure

Same cause. `sudo umount -R <path>`, then remove the output directory.

## boot-test

### `no OVMF firmware found`

```bash
sudo apt install ovmf          # Debian/Ubuntu
sudo dnf install edk2-ovmf     # Fedora
sudo pacman -S edk2-ovmf       # Arch
```

`find_ovmf` checks four known paths. If yours is elsewhere, add it there.

### Times out with no serial output

The disk never reached GRUB. Check that the build actually finished, and read the log c2vm prints on timeout. A missing initramfs virtio module shows up as a kernel panic mentioning no root device.

### Times out after a login prompt

The guest booted but SSH never accepted the key. Check that `--ssh-key` is the **private** key matching the public key passed to `build`, and that `--user` matches the account (`build.json` `flags.user`).

### Very slow, or `/dev/kvm unavailable`

```bash
ls -l /dev/kvm
sudo modprobe kvm_intel        # or kvm_amd
sudo usermod -aG kvm $USER     # log out and back in
```

Without KVM the timeout triples automatically and a boot can take minutes.

### `<file> has no disk.vmdk member`

`boot-test` reads OVAs that c2vm built. A foreign OVA names its disk something else - extract it by hand and pass the `.vmdk` directly.

## scan

### `<artifact> does not match build.json`

The disk changed after it was built. Most often: you booted it without `-snapshot`, or edited it with `guestfish`. Rebuild. `--no-verify` skips the check, but then nothing downstream means anything.

### `cannot scan an OVA directly`

By design, syft would walk the tar and report zero packages. Scan the qcow2 from the same build, or `tar -xf disk.ova disk.vmdk` first.

### `grype has no vulnerability database` / `failed to load vulnerability db: database does not exist`

```bash
grype db update    # as your own user, NOT under sudo
```

Root has no grype cache. `grype_env()` points at `$SUDO_USER`'s cache when running under `sudo`, so update it as yourself first, then scan with `sudo`.

The second wording is grype's own, and usually comes from `verify` on a fresh machine: check 6 scans the signed SBOM locally, and `grype_env()` sets `GRYPE_DB_AUTO_UPDATE=false` so a verification can never silently pull a different database than the one you meant to measure against. The database has to be there first.

### `guestmount` fails or hangs

```bash
sudo libguestfs-test-tool      # the standard diagnostic
```

Usually a missing `libguestfs` appliance or an unreadable host kernel image (`/boot/vmlinuz-*` must be world-readable on some distributions).

## push / sign / attest

### `cannot resolve <ref>; is it pushed, and are you logged in?`

```bash
docker login ghcr.io           # a token with write:packages
```

`oras` reads the same credential store as docker. For GHCR the token needs `write:packages`, and `read:packages` for anyone verifying a private repo.

### `cosign sign` opens no browser / hangs

On a headless host cosign cannot open one. Copy the URL it prints to a browser elsewhere, or use `--identity-token` with a token you obtained separately.

### `attest` says `sbom-diff.json has no "added" array`

Run `sbom-diff` before `attest` — the predicate embeds its output verbatim. Check `--results` points at the directory that actually holds it.

## verify

### `FAIL signature`

Either the identity in `policy/default.yaml` is not the one that signed, or nothing signed it. Confirm with:

```bash
cosign verify <ref>@<digest> \
  --certificate-identity <you> --certificate-oidc-issuer <issuer>
```

### `FAIL disk digest binding`

The disk in the registry is not the one the signed statement describes. Either the artifact was replaced, or `attest` ran against a different build directory than `push` did. **If you did not expect this, do not use the artifact.**

### `FAIL source image`

The predicate's source digest does not match the manifest annotation — `push` and `attest` used different `--out` directories, or the artifact was re-pushed from a different build.

### `FAIL cve policy` on an artifact that passed last week

Your grype database moved. Nothing about the artifact changed; new advisories were published. Either triage them or raise the limits in the policy file, with a comment saying when and why.

### `<policy> must set both 'identity' and 'issuer'`

The parser reads four keys and splits on the first colon. Check indentation and that the values are not commented out.

## Still stuck

Run with `--dry-run` where it exists to see the exact commands, and re-run the failing one by hand — c2vm's output prefixes every command it spawns with `  +`, so it can be copied straight out of the log.
