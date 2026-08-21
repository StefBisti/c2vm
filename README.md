# c2vm

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**c2vm converts an OCI container image into a bootable VM disk (QCOW2, OVA)
while preserving and re-establishing the supply-chain chain of custody the
conversion normally destroys** — a signed, SBOM-backed attestation binds the
output disk back to the source image digest and to every decision c2vm made
along the way, verifiable with a single `c2vm verify`.


## Quickstart

```sh
make c2vm
./c2vm --help
./c2vm build ubuntu:24.04 --format qcow2,ova
./c2vm scan build/disk.qcow2
./c2vm verify ghcr.io/<user>/c2vm-demo:latest
```

## Architecture

TODO

## Documentation

See docs/ — architecture, format internals, threat model, and the
prior-art survey are written incrementally as the project proceeds.

## License

MIT — see LICENSE.