#!/usr/bin/env bash
#
# Train the stage-1 classifier on CIC-IDS2017 and install it.
#
#   sudo bash train-model.sh            # tune on a validation split, then fit
#   sudo bash train-model.sh --no-tune  # fit with the defaults only
#
# 1. Fetches the MachineLearningCVE CSVs (2,830,743 flows) if they are not
#    already in $DATA, from a Hugging Face mirror of UNB's release, and
#    checks every file against the SHA-256 the mirror publishes. UNB's own
#    links now lead to a registration form.
# 2. Trains in a throwaway container with no network, from this checkout's
#    backend code, so the feature definition is exactly the one the API runs.
# 3. Installs the model and its metrics report into the backend's model
#    volume and restarts the API, which then reports
#    model_source: "cicids2017".
#
# Takes roughly 40 minutes with tuning on 8 cores, 10 without.

set -euo pipefail
cd "$(dirname "$0")"

DATA=${DATA:-/srv/datasets/cicids2017}
MIRROR=https://huggingface.co/datasets/c01dsnap/CIC-IDS2017
TUNE=--tune
[[ "${1:-}" == --no-tune ]] && TUNE=

echo "==> Dataset in $DATA"
install -d "$DATA"
if [[ ! -f "$DATA/SHA256SUMS" ]]; then
  curl -fsS "https://huggingface.co/api/datasets/c01dsnap/CIC-IDS2017/tree/main" \
    | python3 -c 'import json,sys; [print(f["lfs"]["oid"], f["path"]) for f in json.load(sys.stdin) if f["path"].endswith(".csv")]' \
    > "$DATA/SHA256SUMS"
fi
while read -r _ name; do
  [[ -f "$DATA/$name" ]] || curl -fsSL --retry 3 -o "$DATA/$name" "$MIRROR/resolve/main/$name"
done < "$DATA/SHA256SUMS"
(cd "$DATA" && sha256sum --quiet -c SHA256SUMS) && echo "    all files verified"

echo "==> Training ${TUNE:+(with tuning)}"
docker rm -f hs-train >/dev/null 2>&1 || true
docker run --rm --name hs-train --network none -u 0 \
  -v "$(cd ../../backend && pwd)":/src:ro -v "$DATA":/data:ro \
  -v honeysentinel_models:/models honeysentinel-backend sh -c "
    set -e
    cp -r /src /t && cd /t && rm -rf models && mkdir models
    ENVIRONMENT=development SECRET_KEY=x ENCRYPTION_KEY=x HONEYPOT_INGEST_TOKEN=x \
      python -m ml.train --data /data $TUNE
    cp models/random_forest_model.pkl models/random_forest_model_metrics.json /models/
    chown 10001:10001 /models/random_forest_model.pkl /models/random_forest_model_metrics.json
  "

echo "==> Restarting the API on the new model"
docker compose restart backend >/dev/null
for _ in $(seq 1 60); do
  [[ $(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q backend)") == healthy ]] && break
  sleep 2
done
docker compose exec -T backend python -c \
  "from app.ai.classifier import classifier; classifier._ensure_loaded(); print('    model_source:', classifier.model_source)"
