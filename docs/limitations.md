# Limitations

What c2vm cannot do, why, and what are the work-arounds.

## Input

### Debian-family images only

`build` runs `apt-get` and `dpkg-query` inside the extracted rootfs and installs `grub-efi-amd64` and `netplan.io` by name. Alpine, Fedora, RHEL/UBI, Arch, distroless and `scratch` all fail.

Why: measuring the conversion delta means knowing the package manager. Without `apt`, `sbom-diff` could not attribute added packages to a build.

Workaround: none within c2vm. For RPM-based images, `osbuild/image-builder` converts bootc containers and can emit an SBOM.

### The image must live in a registry

`scripts/extract-rootfs.sh` pulls with `skopeo copy docker://…`. A locally built image that was never pushed cannot be converted.

Why: pulling by digest from a registry is what makes the source pinning meaningful. A local image has no digest anyone else can resolve.

Workaround: `docker push` first. If you genuinely need a local image, `skopeo` supports `docker-daemon:image:tag`. Change the one `docker://` in `extract-rootfs.sh`. You lose the digest guarantee, so `verify`'s source check becomes decorative.

### The container's `CMD` / `ENTRYPOINT` is ignored

The VM boots systemd. Your entrypoint never runs.

Why: a container runtime starts one process, while a VM starts an init system.

Workaround: ship a systemd unit in the image and enable it by symlink, since `systemctl enable` needs a running systemd:

```dockerfile
COPY app.service /etc/systemd/system/app.service
RUN mkdir -p /etc/systemd/system/multi-user.target.wants \
 && ln -s /etc/systemd/system/app.service \
          /etc/systemd/system/multi-user.target.wants/app.service
```

### x86_64 only

Why: four separate places assume it — the rootfs is pulled with `--override-arch amd64`, GRUB installs as `x86_64-efi`, the guest boots `BOOTX64.EFI`, and the OVF declares `ovf:id="102"` (Linux 64-bit).

Workaround: none. arm64 support means changing all four and finding equivalent firmware.

### Multi-arch image indexes

An image index resolves to its amd64 member because of `--override-arch`. The digest recorded is the **index** digest, not the platform manifest's.

Why: `skopeo inspect` reports the digest of what you asked for.

Workaround: pass a platform-specific digest explicitly: `c2vm build ubuntu@sha256:<amd64 manifest digest>`.

## Host

### Linux and root, for `build` and `scan`

Loop devices, `mount`, `chroot`, and `guestmount`. macOS and WSL1 cannot run either command. WSL2 should work except for KVM (not tested).

Why: there is no unprivileged path to writing a partitioned, formatted, bootable disk image.

Workaround: a Linux VM or CI runner. `sbom-diff`, `cve-diff` and `verify` need neither root nor Linux-specific features and run anywhere.

### Builds are not reproducible

Two builds a week apart produce different disks. `apt-get update` runs first, so the kernel and every package float to whatever the archive currently has, and timestamps and UUIDs differ regardless.

Why: `verify` proves what the builder claimed, bound to these bytes, by this identity.

Workaround: none.

## Commands

### `scan` refuses an OVA

```
c2vm scan: cannot scan an OVA directly; scan the qcow2 the same build produced, or extract disk.vmdk first
```

Why: an OVA is a tar. syft would walk it as an archive and report zero packages.

Workaround: build with `--format qcow2,ova` and scan the qcow2. Both formats come from the same `disk.raw`, so the SBOM describes both. Or `tar -xf disk.ova disk.vmdk` and scan that.

### `boot-test` forwards only port 22

Why: it exists to assert the guest booted and matches `build.json`, not to do anything else.

Workaround: run QEMU by hand with extra `hostfwd` rules. See [tutorial.md](tutorial.md) step 3.

### `--format raw` is a no-op

`disk.raw` is always produced as the intermediate. The flag exists so the format validation accepts it.

### The registry must support OCI artifacts

`push` sets a custom artifactType and a custom layer mediaType. Registries that only accept image manifests reject it.

Why: it is the mechanism that stops anything trying to run the disk, and it is what carries the annotations `verify` reads.

Workaround: use a current registry - GHCR, ECR, GAR, Harbor, Zot and recent Docker Hub all handle artifacts. Older or minimal registries may not.

## Verification

### CVE results depend on your grype database

`verify` scans the signed SBOM with your local grype and database, so the same artifact can pass today and fail next month with nothing about it changed.

Why: you want current vulnerability data, not the publisher's stale opinion. But it means "verified" is not a stable property.

**Workaround:** treat checks 1-5 (integrity, deterministic) and check 6 (quality, time-varying) as different questions. Pin the database with `GRYPE_DB_*` if you need a fixed answer.

### Only `layers[0]` is checked

The disk binding compares the signed hash against the first layer digest in the manifest. c2vm pushes exactly one layer, so it is correct today, but a manifest with several layers would have the others unchecked.

### The inner statement's `predicateType` is not validated

`verify` reads `predicate.Data` and trusts it is a c2vm conversion statement. A different `--type custom` attestation from the same pinned identity would be read as one.

Why: identity pinning already limits who can produce one.

### No Secure Boot

The disk boots via `--removable` GRUB with no signed shim. It will not boot a machine with Secure Boot enforcing.

Why: signing a boot chain needs enrolled keys, a different problem from signing an artifact.

Workaround: disable Secure Boot on the target, or use `systemd/mkosi`, which does UKIs and signed variants.

### `\uXXXX` escapes are passed through literally

The JSON reader decodes `\n`, `\t`, `\"` and friends but leaves `\uXXXX` as written.

Why: nothing downstream reads non-ASCII fields. Package names, versions and digests are ASCII.
