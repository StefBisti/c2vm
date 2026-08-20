## c2vm usage

- c2vm build <image-ref> --format qcow2,ova [--size] [--ssh-key] [--packages]
- c2vm scan <artifact> — SBOM + CVE scan of a built disk
- c2vm diff <sbom-a> <sbom-b> — package delta
- c2vm push <artifact> <oci-ref> — publish as an OCI artifact
- c2vm sign <oci-ref> / c2vm attest <oci-ref>
- c2vm verify <oci-ref> [--policy policy/default.yaml] — the headline command