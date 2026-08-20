# Prior art and architecture decision

Made with Claude Opus 5, adjusted by me \
Objective: Decide whether `c2vm` keeps its own builder, wraps existing tools, or does both.

## Results

| Project | Output formats | Bootloader handling | Maintenance (Aug 2026) | **Supply-chain metadata preserved** |
|---|---|---|---|---|
| `linka-cloud/d2vm` | qcow2, raw, vmdk, vdi, vhd, qed | Installs kernel + GRUB per detected distro; optional split boot partition | Active but low-volume; single maintainer | **None.** No SBOM, no source digest recorded, no signature |
| `osbuild/image-builder` (absorbed `bootc-image-builder`, archived 2026-06-18) | qcow2, raw, vmdk, vhd, ami, gce, iso | osbuild stages; UEFI + GRUB2, serial console via blueprint | Active | **`--with-sbom` emits an SPDX SBOM of the built image**, `--with-manifest` the build manifest. dnf/RPM only, unsigned, no source-vs-output comparison |
| `bootc-dev/bootc` | None — installs to disk in place | Own install flow, Discoverable Partitions Spec | Active | **`.bootc-aleph.json`** written at install with the source image reference. Unsigned, on-disk, bootc images only |
| `systemd/mkosi` | GPT disk, esp, uki, tar, cpio | systemd-boot / UKI / GRUB, signed variants; Secure Boot and dm-verity | Very active | No SBOM. Reproducible builds, GPG-signed `SHA256SUMS`; integrity of the *boot chain*, not provenance of the *source* |


## Findings

- The conversion mechanics are already done by many other projects
- None of those tools produce OVA. Three of them emit VMDK, which is one of the four components needed for OVA.
- image-builder produces an SBOM of the built disk, and bootc records install-time provenance. Neither is signed, neither compares the output against the source image, and both are restricted to their own ecosystem (RPM-based distributions, bootc-model images).
- No surveyed tool binds the source image digest to the output disk digest and to the conversion decisions in one signed statement a third party can verify, or measure how many packages and CVEs the conversion adds. That gap is the scope of c2vm.
- For the surveyed tools, input classes differ: d2vm and a native builder accept arbitrary OCI images, while image-builder accepts only bootc containers, so ubuntu:24.04 is not a valid input for it.




## Decision

**`c2vm` keeps its own builder as the only required build path.**

1. The differentiator is the supply-chain layer, not the conversion. Wrapping a tool does not advance it, and ties the project to that tool's input model and release cycle.
2. No candidate produces OVA, so that half of the required output is built by hand either way.
3. No single tool covers arbitrary OCI input, both required outputs, and current maintenance. Wrapping would mean wrapping two tools with incompatible input contracts.
4. Owning the build makes the delta precise: every added package comes from a line of c2vm's own code, so each added CVE traces to a named build decision.
