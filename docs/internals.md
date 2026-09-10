# Internals

How each command works. Read [cli.md](cli.md) for flags. These are the internals of the code.

## Layers

```
src/core/      # plumbing that knows nothing about what c2vm is for
    run.c      # spawn processes
    util.c     # die/warn/step, P(), read/write files, x-allocators
    json.c     # a JSON reader; no library in this project
    cleanup.c  # the equivalent of `trap … EXIT INT TERM`
src/convert/   # making the disk
src/custody/   # measuring and proving it
```


## build

- inputs: an OCI reference, `--format`, `--size`, `--ssh-key`, and the rest
- preconditions: root, a Debian-family image, `--out` must be either absent or be a c2vm previous output directory (it checks for `metadata/` before `rm -rf` to avoid accidentally removing data on the host)

```
cmd_build:
  parse_opts
  require root            # unless --dry-run

  unshare(CLONE_NEWNS)    # mount --make-rprivate /

  cleanup_init()          # trap for every mount below

  prepare_outdir      # rm -rf, recreate out/{metadata,mnt}

  extract_rootfs      # scripts/extract-rootfs.sh into out/rootfs
                      # writes metadata/source.json

  create_disk         # qemu-img create; parted: ESP, root

  attach_and_format   # losetup --partscan -> /dev/loopN
                      # mkfs.vfat on p1, mkfs.<fstype> on p2

  mount_all           # mount p2 -> out/mnt; rsync rootfs into it
                      # mount p1 -> mnt/boot/efi
                      # bind dev, dev/pts, proc, sys, run; --make-rslave
                      # copy /etc/resolv.conf for apt's DNS

  write_guest_config  # blkid -> fstab by UUID; hostname; hosts

  install_system      # apt-get update; record packages-before
                      # apt_install: kernel + BASE_PACKAGES + --packages
                      # write initramfs virtio modules; update-initramfs
                      # write /etc/default/grub; grub-install; update-grub
                      # systemctl enable serial-getty@ttyS0
                      # record packages-after, kernel and grub versions

  configure_cloud_init  # enable units; write meta-data, network-config,
                        # user-data (ssh keys, hashed password);
                        # reset_identity

  cleanup_run()       # unmount and detach BEFORE converting

  convert_formats     # qemu-img → qcow2; ova_write → ova

  write_metadata      # metadata/build.json
```

**outputs:**
- `disk.raw` plus each requested format
- `metadata/build.json`
- `metadata/source.json`
- `metadata/packages-before.txt`
- `metadata/packages-after.txt`

### A few explanations:

**`unshare(CLONE_NEWNS)` + `--make-rprivate`.** The build makes a dozen mounts. In a private namespace they cannot leak into the host's mount table, even if the process is killed uncleanly.

**Two partitions.** UEFI firmware reads only FAT32, so the ESP is separate. The root filesystem is whatever `--fstype` says.

**fstab by UUID.** `/dev/sda2` on the build host may be `/dev/vda2` in the guest, and enumeration order is not stable. UUIDs travel with the filesystem.

**virtio modules in the initramfs.** The initramfs must mount the root disk before the real root exists. Without `virtio_blk` and friends compiled in, the guest boots and cannot find its own disk.

**`policy-rc.d` returning 101.** Stops `apt` starting daemons inside the chroot, then removed afterwards.

**`reset_identity`.** Truncates `machine-id` and deletes host SSH keys, so every VM cloned from the disk generates its own on first boot.

**`write_metadata` last.** It records the sha256 of every artifact, so the artifacts must exist. This is the first weld.

**`cleanup_run()` before conversion.** qcow2 must be made from a quiesced disk; converting a mounted filesystem captures a dirty one.

**failure modes** anything fatal calls `die`, which exits — and `cleanup_run` is registered with `atexit`, so mounts unwind and loop devices detach in reverse order.


## boot-test

- inputs: an artifact (`.qcow2`, `.raw`, `.img`, `.vmdk`, `.ova`), a private key to use for logging into the vm
- preconditions `metadata/build.json` from the same build; OVMF firmware

```
cmd_boot_test:
  find_ovmf                     # four known paths, else die with install hints

  read build.json; resolve --user

  unpack_ova                    # if .ova: tar out disk.vmdk, qemu-img create a
                                # qcow2 overlay backed by it

  spawn qemu                    # q35, OVMF pflash, virtio disk,
                                # hostfwd tcp::PORT-:22, -serial file:…,
                                # -no-reboot, -snapshot
                                # cleanup_push_kill(pid)

  wait loop                     # tail the serial log for a login prompt,
                                # try ssh true, until timeout

  assert_guest                  # systemctl is-system-running
                                # findmnt -no UUID /     == disk.root_uuid
                                # ip -4 -o addr          non-empty
                                # dpkg-query kernel      == kernel.version

  cleanup_drop_kill; report
```

### A few explanations:

**`-snapshot` is load-bearing.** Booting writes to the disk, so it logs, machine-id, SSH host keys. Without it the artifact's hash changes and `scan` refuses it afterwards.

**failure modes** timeout -> prints the last 50 serial lines, exits 3. A failed assertion -> exits non-zero. The QEMU process is on the cleanup stack, so it dies with the tool.


## scan

- inputs: an artifact, `--out`, `--results`
- preconditions:
    - root (guestmount)
    - `syft`
    - `grype` unless `--skip-cve`
    - the artifact's hash must match `build.json`

```
cmd_scan:
  read build.json -> source.image, source.digest
  
  verify_artifact       # sha256sum == build.json artifacts[].sha256
                        # -> die if not

  record syft/grype/database versions

  syft registry:<repo>@<digest>   # sbom-source.{spdx,cdx}.json
  grype sbom:…                    # cve-source.json
  guestmount --ro out/scanmnt     # cleanup_push_guestunmount
  syft dir:out/scanmnt            # sbom-disk.{spdx,cdx}.json
  cleanup_run()                   # unmount before writing metadata
  grype sbom:…                    # cve-disk.json
  write_tooling                   # results/tooling.json
```

### A few explanations:

**Two SBOMs, not one.** The delta is the important thing.

**The source is scanned by digest, from the registry**, not from `out/rootfs`, so the SBOM describes the image as published, not as extracted.

**The disk is guestmounted** because syft cannot see inside a QCOW2.

**`grype_env()`** pins grype to the database already on disk and, under `sudo`, points it at `$SUDO_USER`'s cache.


## sbom-diff

- inputs: two SPDX JSON documents; `<a>` is the baseline

```
sbom_load  x2       # brace-depth walk of .packages[]
                    # struct pkg {name, version, eco}
                    # eco from the purl's type field
                    # dedupe_sorted - syft reports the kernel twice

qsort by (eco,name,version)

pass 1  cmp_full         # identical triples -> unchanged
                         # leftovers -> only_a, only_b

pass 2  cmp_name         # same (eco,name) in both leftovers -> changed
                         # else added / removed

classify()               # group deb additions: kernel, bootloader, init,
                         # networking, cloud-init, dependency

write_json, write_markdown
```

### A few explanations:

**Why two passes.** In order to detect packages that have been upgraded instead of counting them as a difference.


## cve-diff

- inputs: two grype JSON reports

```
vuln_load ×2            # same walk, over .matches[]
                        # struct vuln {id, severity, package, version, eco}

qsort by cmp_key = (id, package)          # deliberately NOT version

one-pass merge           # new, gone, shared

tally                    # [severity][0] all ecosystems, [severity][1] deb only

attribute                # which package introduced which findings

write_json, write_markdown
```

### A few explanations:

**Keyed on `(id, package)`, not version,** so a CVE that survives a version
bump reads as still present rather than one gone, one new.

**The two columns.** syft records the kernel twice (as a deb package and as a generic binary). Grype matches the deb against the distribution's tracker, which knows what was backported, and the generic one by CPE against NVD. Same kernel, an order of magnitude apart. Report both, gate on deb.


## push

```
# Basically runs this command:
oras push <ref>
  --artifact-type application/vnd.c2vm.disk.v1+json
  --annotation dev.c2vm.source-digest=…
  --annotation org.opencontainers.image.created=…
  disk.qcow2:application/vnd.c2vm.disk.qcow2

oci_digest(ref)   # the manifest digest
```

### A few explanations:

**An artifact, not an image.** A custom artifact-type and layer mediaType make a manifest that is valid OCI but that no runtime will try to run.

**Annotations live in the manifest,** so `verify` reads them in a ~700-byte fetch without touching the blob.

**The registry addresses the blob by its own sha256,** which is why `layers[0].digest` is the disk's hash.


## sign

```
cosign sign --yes <ref>@<digest>
```

1. ephemeral keypair, in memory
2. browser -> OIDC login -> an ID token proving your identity
3. token + public key -> **Fulcio** -> an X.509 certificate valid for 10 minutes
4. sign the **digest**
5. signature + certificate -> **Rekor**, append-only, returns a timestamp
6. the private key is discarded
7. the signature is stored back in the registry

**A ten-minute certificate is fine** because the Rekor entry proves the signature was made while it was valid.

**No revocation.** Rekor is append-only and public.

**`oci_digest` runs first** so the signature covers bytes, not a mutable tag.


## attest

```
predicate_write     # read build.json (never recompute)
                    # embed sbom-diff.json's added_deb[] verbatim
                    # results/predicate.json, an in-toto statement
                    # whose subject is the DISK's sha256

cosign attest --type spdxjson --predicate sbom-disk.spdx.json <subject>

cosign attest --type custom --predicate predicate.json <subject>
```

### A few explanations:

**Read, never recompute.** If `predicate_write` re-hashed the disk at attest time, a tampered disk could be re-attested with fresh, self-consistent values. Reading `build.json` means the claim can only describe the original build.

**The double wrapping.** `predicate.json` is *already* an in-toto Statement. `--type custom` wraps it again and stores your whole document as an escaped string:

```
cosign's statement
  subject: <manifest digest>          # what cosign thinks it is about
  predicate.Data: "{ …your statement… }"
        └─ your statement
             subject: <disk sha256>   # what it is actually about
```


## verify

- inputs: an OCI reference and a policy file. Nothing else.

```
policy_load            # identity, issuer, max_critical, max_high

oci_digest(ref)        # subject = ref@digest

oras manifest fetch    # manifest
1  cosign verify              # --certificate-identity/-oidc-issuer
2  cosign verify-attestation  --type spdxjson  # DSSE → base64 → statement
3  cosign verify-attestation  --type custom    # .Data → inner statement
4  inner.subject.sha256 == manifest.layers[0].digest
5  inner.source.digest  == manifest annotation
6  cve_check: grype over the SIGNED SBOM, gate the deb column
exit 3 if any failed
```

| # | proves | does not prove |
|---|---|---|
| 1 | that identity signed this manifest digest | anything about the bytes inside |
| 2 | an SPDX document was signed by them | that it describes *this* disk |
| 3 | a conversion statement was signed by them | that it is about *this* disk |
| **4** | **the signed subject IS the layer served** | that the disk boots |
| **5** | the source digest matches what push recorded | that the source is trustworthy |
| 6 | the signed SBOM scans within limits *today* | that it will tomorrow |

**What the checks refuse.** The manifest is fetched by the resolved digest, not
by the tag, so a tag that moves mid-run cannot have the signature checked against
one manifest and the bindings against another. The disk binding requires exactly
one layer. A `--type custom` attestation only counts if its inner
`predicateType` really is `https://c2vm.dev/conversion/v1`. And `cve_check`
writes the signed SBOM into a private `mkdtemp` directory, since that file is
what the CVE verdict is computed from.
