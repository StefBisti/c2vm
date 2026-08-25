#!/usr/bin/env bash

# Turns a container image reference into a plain directory of files.

set -euo pipefail

IMAGE="${1:?usage: extract-rootfs.sh <image-ref> <output-dir>}"
OUTDIR="${2:?usage: extract-rootfs.sh <image-ref> <output-dir>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "resolving $IMAGE" >&2
DIGEST="$(skopeo inspect --format '{{.Digest}}' "docker://${IMAGE}")"
echo "digest: $DIGEST" >&2

echo "copying to OCI layout" >&2
skopeo copy --override-arch amd64 --override-os linux "docker://${IMAGE}" "oci:${WORK}/img:latest" >&2

echo "unpacking" >&2
umoci unpack --image "${WORK}/img:latest" "${WORK}/bundle" >&2

echo "installing to $OUTDIR" >&2
mkdir -p "$OUTDIR"
rsync -aHAX --numeric-ids "${WORK}/bundle/rootfs/" "$OUTDIR/" >&2

echo "done. rootfs: $OUTDIR ($(du -sh "$OUTDIR" | cut -f1))" >&2

echo "$DIGEST"
