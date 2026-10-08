#!/usr/bin/env bash
# Download the decision model used for triage (Kev-4B, Apache-2.0) into
# state/models, pinned to one revision and checked against its SHA-256.
#
#   bash deploy/server/fetch-decider.sh && bash deploy/server/install.sh
#
# Runs on the host: the containers have no internet access, by design.
set -euo pipefail

REPO=ggml-org/Kev-4B-GGUF
REVISION=d924f2e2c3872da8b8aaf3eb4453b4126deceb79
FILE=Kev-4B-Q8_0.gguf
SHA256=7c2ebed90560522c2801389db482ac1dc4c36d828f201f6074c1d60e433948da

HERE="$(cd "$(dirname "$0")" && pwd)"
dest="$HERE/state/models/$FILE"
install -d -m 0755 "$HERE/state/models"

if [[ -f "$dest" ]] && echo "$SHA256  $dest" | sha256sum -c --quiet - 2>/dev/null; then
  echo "$FILE already present and verified"
  exit 0
fi

tmp="$dest.part"
echo "Downloading $REPO@${REVISION:0:12} $FILE (4.5 GB)"
curl -fL --retry 3 -C - -o "$tmp" "https://huggingface.co/$REPO/resolve/$REVISION/$FILE"
echo "$SHA256  $tmp" | sha256sum -c --quiet - || { echo "checksum mismatch; removing $tmp" >&2; rm -f "$tmp"; exit 1; }
mv "$tmp" "$dest"
chmod 0644 "$dest"
echo "Verified and saved to $dest"
