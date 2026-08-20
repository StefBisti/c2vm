## c2vm usage

```
c2vm <command> [options]
```

- `c2vm build <image-ref> --format qcow2,ova [--size] [--ssh-key] [--packages]` — build a bootable disk from a container image (Stage 2.1); `--ssh-key` replaces password login (Stage 2.2)
- `c2vm scan <artifact>` — SBOM + CVE scan of a built disk (Stage 3.1)
- `c2vm diff <sbom-a> <sbom-b>` — package delta between two SBOMs (Stage 3.2)
- `c2vm push <artifact> <oci-ref>` — publish as an OCI artifact (Stage 3.4)
- `c2vm sign <oci-ref>` / `c2vm attest <oci-ref>` — keyless signing and attestations (Stage 3.4)
- `c2vm verify <oci-ref> [--policy policy/default.yaml]` — the headline command (Stage 3.5)

### Global flags

- `-h`, `--help` — show usage
- `--version` — show the c2vm version

### Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | runtime failure |
| 2 | usage error |
| 3 | verification or policy failure |
| 64 | not implemented |

