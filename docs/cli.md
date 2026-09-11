## c2vm usage

```
c2vm <command> [options]
```

Nine commands in pipeline order. `build` and `scan` need root; `scan`, `push`,
`sign`, `attest` and `verify` need the network.

---

### build `<image-ref>`

container image → bootable disk, recording every decision in `build.json`

| flag | |
|---|---|
| `--format <list>` | comma-separated: `qcow2`, `raw`, `ova` (default: `qcow2`) |
| `--size <size>` | disk size (default: `10G`) |
| `--hostname <name>` | guest hostname (default: `c2vm`) |
| `--user <name>` | default account (default: `c2vm`) |
| `--ssh-key <path>` | public key authorised for that account |
| `--root-password <file>` | file holding a root password, hashed and expired on first login |
| `--packages <list>` | extra packages, comma-separated |
| `--kernel <pkg>` | kernel package (default: `linux-image-virtual`) |
| `--fstype <fs>` | root filesystem (default: `ext4`) |
| `--compress` | compress the qcow2, changes its hash |
| `--backend <name>` | build backend (only: `native`) |
| `--out <dir>` | output directory (default: `build`) |
| `--dry-run` | print every command instead of running it |

Writes `disk.raw` plus each requested format, and
`metadata/{build.json,source.json,packages-before.txt,packages-after.txt}`.
`build.json` is written last: it records the sha256 of every artefact, so they
must already exist.

Without `--ssh-key` or `--root-password` the guest boots with no way to log in.
(Used for distributing the image)

---

### boot-test `<artifact>`

boot it headless in QEMU, assert the guest is the one `build.json` describes

| flag | |
|---|---|
| `--ssh-key <path>` | **private** key matching the one built in (required) |
| `--user <name>` | guest account (default: the one `build.json` records) |
| `--port <n>` | host port forwarded to guest 22 (default: `2222`) |
| `--seed <iso>` | cidata ISO supplying the guest account |
| `--timeout <sec>` | hard limit, tripled without KVM (default: `180`) |
| `--out <dir>` | directory holding `metadata/build.json` (default: `build`) |

Checks systemd state, root fs UUID, network address and kernel version against
`build.json`. Runs with `-snapshot`, so the disk's hash survives the boot.
Accepts `.qcow2`, `.raw` and `.ova`. Exits 3 on timeout.

---

### scan `<artifact>`

SBOMs of both sides (SPDX + CycloneDX), then grype over each

| flag | |
|---|---|
| `--source <ref>` | source image to scan (default: the digest in `build.json`) |
| `--skip-source` | scan only the disk |
| `--skip-cve` | write SBOMs but do not scan for vulnerabilities |
| `--no-verify` | do not check the artifact against `build.json`'s hash |
| `--syft <path>` / `--grype <path>` | tool binaries (default: found on PATH) |
| `--out <dir>` | directory holding `metadata/build.json` (default: `build`) |
| `--results <dir>` | where the SBOMs land (default: `results`) |

Refuses to run if the artifact no longer matches `build.json`. The source is
scanned by digest straight from the registry; the disk is guestmounted, because
syft cannot see inside a QCOW2.

Writes `sbom-{source,disk}.{spdx,cdx}.json`, `cve-{source,disk}.json` and
`tooling.json`, which pins the syft, grype and database versions the numbers
came from.

---

### sbom-diff `<sbom-a> <sbom-b>`

package delta: added, removed, version-changed

`--results <dir>` — where the report is written (default: `results`)

Both inputs SPDX JSON. `<sbom-a>` is the baseline: packages only in `<sbom-b>`
are added. Additions are grouped by function (kernel, bootloader, init,
networking, cloud-init) and counted per ecosystem.

Writes `sbom-diff.json` and `sbom-diff.md`. `attest` embeds the `added_deb`
array verbatim, so run this before publishing.

---

### cve-diff `<report-a> <report-b>`

vulnerability delta by severity, attributed to packages

`--results <dir>` — where the report is written (default: `results`)

Both inputs grype JSON. Findings are keyed on `(id, package)`, not version.
Counts are reported in two columns: every ecosystem, and deb only. The kernel is
matched a second time by CPE against NVD, which reports every CVE ever filed
against that version rather than the ones Ubuntu has not backported — an order
of magnitude more. Gate on the deb column.

Writes `cve-diff.json` and `cve-diff.md`.

---

### push `<artifact> <oci-ref>`

publish as an OCI artifact, not an image — nothing will ever run it

| flag | |
|---|---|
| `--out <dir>` | directory holding `metadata/build.json` (default: `build`) |
| `--oras <path>` | oras binary (default: found on PATH) |

Annotates the manifest with `dev.c2vm.source-digest`, which `verify` checks
against the signed conversion statement.

---

### sign `<oci-ref>`

sign the published artefact keylessly

`--cosign <path>` — cosign binary (default: found on PATH)

Opens a browser: Fulcio issues a ten-minute certificate binding your identity to
a throwaway key, cosign signs, the key is discarded, the event is logged in
Rekor. Signs the digest the tag currently points at, never the tag.

---

### attest `<oci-ref>`

attach the SBOM and conversion attestations

| flag | |
|---|---|
| `--artifact <name>` | which artifact the predicate is about (default: `disk.qcow2`) |
| `--out <dir>` | directory holding `metadata/build.json` (default: `build`) |
| `--results <dir>` | directory holding the SBOM and diff (default: `results`) |
| `--cosign <path>` | cosign binary (default: found on PATH) |

Writes `results/predicate.json` — an in-toto statement of type
`https://c2vm.dev/conversion/v1` whose subject is the disk's sha256 — then
attaches it alongside the SPDX SBOM. Needs `sbom-diff.json` to exist.

---

### verify `<oci-ref>`

check signature, signer identity, both attestations and CVE policy

| flag | |
|---|---|
| `--policy <file>` | identity and CVE limits (default: `policy/default.yaml`) |
| `--cosign <path>` / `--oras <path>` / `--grype <path>` | tool binaries (default: found on PATH) |

Six checks from the reference alone — the disk is never downloaded. Beyond
"cosign said ok", two bindings: the disk hash in the signed statement must be
the layer the registry serves, and the statement's source digest must be the
manifest annotation. CVE counts come from the SBOM that was signed, not one
built locally. Exits 3 on any failure.

The policy's `identity` and `issuer` are the point: without them cosign confirms
only that *somebody* signed it.

#### The policy file

Four keys, YAML-ish - the parser splits on the first colon and ignores
everything after a `#`.

```yaml
identity: you@example.com                  # who is allowed to have signed it
issuer: https://github.com/login/oauth     # the OIDC provider that vouched
max_critical: 5                            # deb-only limits; -1 or absent = unlimited
max_high: 200
```

`identity` and `issuer` are required — `verify` dies without both, because a
signature check with no identity confirms only that *somebody* signed it.

The limits count **deb packages only**. The all-ecosystem numbers are printed
beside them but never gated, because the kernel is matched a second time by
CPE against NVD and inflates them by an order of magnitude
([why](../docs/examples/cve-diff.md)).

Leave headroom between the measured count and the limit, or a single newly
published advisory fails every verification until you edit the policy.

### Global flags

- `-h`, `--help` — show usage
- `--version` — show the c2vm version

### Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | runtime failure |
| 2 | usage error |
| 3 | verification, policy or boot-test timeout |

