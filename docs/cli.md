## c2vm usage

```
c2vm <command> [options]
```

- `c2vm build <image-ref> --format qcow2,ova [--size] [--ssh-key] [--user] [--packages] [--root-password <file>]`
- `c2vm boot-test <artifact> --ssh-key <private-key> [--user] [--out] [--port] [--timeout]` — boot the artifact headless and assert the guest came up
- `c2vm scan <artifact>` — SBOM + CVE scan of a built disk
- `c2vm diff <sbom-a> <sbom-b>` — package delta between two SBOMs
- `c2vm push <artifact> <oci-ref>` — publish as an OCI artifact
- `c2vm sign <oci-ref>` / `c2vm attest <oci-ref>` — keyless signing and attestations
- `c2vm verify <oci-ref> [--policy policy/default.yaml]` — the headline command 

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
| 64 | not implemented |

