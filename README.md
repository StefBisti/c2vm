# c2vm

[![CI](https://img.shields.io/badge/CI-not_yet_wired-lightgrey)](.)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**c2vm converts an OCI container image into a bootable VM disk (QCOW2, OVA)
while preserving and re-establishing the supply-chain chain of custody the
conversion normally destroys** — a signed, SBOM-backed attestation binds the
output disk back to the source image digest and to every decision c2vm made
along the way, verifiable with a single `c2vm verify`.

## Status

Early development. See [c2vm-work-plan.md](c2vm-work-plan.md) for the full
build plan and [docs/cli.md](docs/cli.md) for the command reference. Most
subcommands are stubs right now — check the plan's phase checklists for
what's actually implemented.

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