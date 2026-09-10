# Alternatives

Other ways to turn a container image into a virtual machine, and when to reach for them instead.

## You probably don't need c2vm if…

- **You want a VM image and nothing else.** `linka-cloud/d2vm` converts arbitrary OCI images to six disk formats and is smaller and simpler.
- **You are on RPM and bootc.** `osbuild/image-builder` is the mature, supported path, and `--with-sbom` already gives you an SPDX document.
- **You are building images from scratch, not converting them.** `systemd/mkosi` is more capable, and does Secure Boot, UKIs and dm-verity, none of which c2vm attempts.
- **You just need a cloud VM.** Start from a distribution cloud image and configure it with Packer or cloud-init. Converting a container buys you nothing there.

c2vm is worth it when you will hand the VM to someone who will ask what is inside it and expect an answer they can check themselves.

## Comparison

| | output | bootloader | supply-chain metadata |
|---|---|---|---|
| c2vm | qcow2, raw, **ova** | GRUB2 + UEFI, serial console | source digest - disk digest, SBOM of both sides, package and CVE delta, in-toto attestation |
| `linka-cloud/d2vm` | qcow2, raw, vmdk, vdi, vhd, qed | kernel + GRUB per detected distro | none |
| `osbuild/image-builder` | qcow2, raw, vmdk, vhd, ami, gce, iso | osbuild stages, UEFI + GRUB2 | SPDX SBOM of the output (`--with-sbom`), build manifest; unsigned, RPM only |
| `bootc-dev/bootc` | none — installs in place | own flow, Discoverable Partitions Spec | `.bootc-aleph.json` records the source image at install; unsigned, on-disk |
| `systemd/mkosi` | GPT, ESP, UKI, tar, cpio | systemd-boot / UKI / GRUB, signed | reproducible builds, GPG-signed `SHA256SUMS`, integrity of the *boot chain*, not provenance of the *source* |

## The gap

No surveyed tool binds the source image digest to the output disk digest and to the conversion decisions in one signed statement a third party can verify, or either measures how many packages and CVEs the conversion adds.

Two of them record something (image-builder an SBOM, bootc a source reference). Neither signs it, neither compares output against source, and both are limited to their own ecosystem. That gap is the scope of c2vm.
