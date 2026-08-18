#!/usr/bin/env bash

set -euo pipefail

IMAGE="${1:?usage: extract-rootfs.sh <image-ref> <output-dir>}"
OUTDIR="${2:?usage: extract-rootfs.sh <image-ref> <output-dir>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "resolving $IMAGE"
DIGEST="$(skopeo inspect --format '{{.Digest}}' "docker://${IMAGE}")"
echo "digest: $DIGEST"

echo "copying to OCI layout"
skopeo copy --override-arch amd64 --override-os linux "docker://${IMAGE}" "oci:${WORK}/img:latest"

echo "unpacking"
umoci unpack --image "${WORK}/img:latest" "${WORK}/bundle"

echo "installing to $OUTDIR"
mkdir -p "$OUTDIR"
rsync -aHAX --numeric-ids "${WORK}/bundle/rootfs/" "$OUTDIR/"

# --- provenance

mkdir -p "$(dirname "$OUTDIR")/metadata"
cat > "$(dirname "$OUTDIR")/metadata/source.json" <<EOF
{
    "source_image": "${IMAGE}",
    "source_digest": "${DIGEST}",
    "extracted_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "extracted_by": "c2vm/extract-rootfs.sh",
    "host": "$(uname -srm)"
}
EOF

# ------------------------------------------------------

echo "done. rootfs: $OUTDIR ($(du -sh "$OUTDIR" | cut -f1))"
echo "provenance: $(dirname "$OUTDIR")/metadata/source.json"
