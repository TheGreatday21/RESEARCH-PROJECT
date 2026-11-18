#!/bin/sh
# Run detect, evaluate, and report against the recorded Phase 2 demo package.
# Outputs go to a scratch directory (default /tmp/elijah-demo) so the workspace stays clean.
set -eu
OUT="${1:-/tmp/elijah-demo}"
CASE=C002
EID=d13a92df-dbbf-48dc-9784-59758a4c3456
ARGS="--evidence-id $EID --derived-root staging/phase2-demo/derived \
--evidence-root staging/phase2-demo/evidence --public-key staging/phase2-demo/ed25519.pub"

mkdir -p "$OUT"
# shellcheck disable=SC2086
.venv/bin/elijah analyze "$CASE" $ARGS --analysis-root "$OUT/analysis" > "$OUT/analyze.json"
# shellcheck disable=SC2086
.venv/bin/elijah detect "$CASE" $ARGS --analysis-root "$OUT/analysis" > "$OUT/detect.json"
# shellcheck disable=SC2086
.venv/bin/elijah evaluate "$CASE" $ARGS --labels lab/out/labels.jsonl \
  --bench-root "$OUT/bench" > "$OUT/evaluate.json"
# shellcheck disable=SC2086
.venv/bin/elijah report "$CASE" $ARGS --labels lab/out/labels.jsonl \
  --reports-root "$OUT/reports" > "$OUT/report.json"
echo "outputs in $OUT"
