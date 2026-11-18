#!/usr/bin/env bash
# Project Elijah — Live Pipeline Execution [EXTRACT -> LOAD -> TRANSFORM]
#
#   bash scripts/demo_live.sh              step-by-step execution (Enter per stage)
#   bash scripts/demo_live.sh --auto       continuous execution without pauses
#   bash scripts/demo_live.sh --live-lab   include live Docker SSH acquisition
#   bash scripts/demo_live.sh --keep       retain working output directory
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUTO=0
LIVE=0
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --auto) AUTO=1 ;;
    --live-lab) LIVE=1 ;;
    --keep) KEEP=1 ;;
    -h | --help)
      sed -n '2,7p' "$0"
      exit 0
      ;;
    *)
      echo "unknown option: $arg (try --help)" >&2
      exit 2
      ;;
  esac
done

export PATH="$PROJECT/.venv/bin:$PATH"
export PROJECT

if [ -t 1 ]; then
  BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); CYAN=$(printf '\033[36m')
  GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); RED=$(printf '\033[31m')
  RESET=$(printf '\033[0m')
else
  BOLD=""; DIM=""; CYAN=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

banner() {
  printf '\n%s==============================================================================%s\n' "$BOLD$CYAN" "$RESET"
  printf '%s  %s%s\n' "$BOLD$CYAN" "$1" "$RESET"
  printf '%s==============================================================================%s\n' "$BOLD$CYAN" "$RESET"
}

stage() {
  printf '\n%s[%s]%s %s%s%s\n' "$BOLD$CYAN" "$1" "$RESET" "$BOLD" "$2" "$RESET"
}

fail() {
  printf '\n%s[ERROR] %s%s\n' "$RED" "$1" "$RESET" >&2
  exit 1
}

run() {
  local cmd
  cmd="$(cat)"
  printf '\n%s$ %s%s\n' "$GREEN" "$cmd" "$RESET"
  if [ "$AUTO" != 1 ]; then
    printf '%s  [Press Enter]%s' "$DIM" "$RESET"
    read -r _ </dev/tty
  fi
  eval "$cmd"
  local status=$?
  if [ "$status" -ne 0 ]; then
    printf '%s[exit %s]%s\n' "$YELLOW" "$status" "$RESET"
  fi
  return 0
}

command -v elijah >/dev/null 2>&1 || fail "elijah binary not found in .venv/bin"
command -v jq >/dev/null 2>&1 || fail "jq not found"

WORK="$(mktemp -d)"
cleanup() {
  if [ "$KEEP" = 1 ]; then
    echo "Working directory retained at: $WORK"
    return
  fi
  chmod -R u+w "$WORK" 2>/dev/null
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

REAL_HOME="$HOME"

banner "ELIJAH v0.2.0 · CLOUD FORENSICS PIPELINE [EXTRACT -> LOAD -> TRANSFORM]"

# ===================================================================== EXTRACT
if [ "$LIVE" = 1 ]; then
  stage "EXTRACT · 1" "Target Container Provisioning & Synthetic Attack Traffic"
  docker info >/dev/null 2>&1 || fail "Docker daemon unreachable."
  cd "$PROJECT" || exit 1
  run <<'CMD'
make lab-down && make lab-up && make traffic
curl -sS -H 'X-Elijah-Trace: lapa-phase2-demo' http://127.0.0.1:8080/ -o /dev/null
curl -sS http://127.0.0.1:8080/assets/site.css -o /dev/null
CMD
  if [ ! -f "$REAL_HOME/.elijah/keys/ed25519.pem" ]; then
    run <<'CMD'
elijah keygen
CMD
  fi
  CASE="C010"
  while [ -e "$PROJECT/evidence/$CASE" ]; do
    n="${CASE#C}"
    CASE="$(printf 'C%03d' $((10#$n + 1)))"
  done
  export CASE
  LABELS="lab/out/labels.jsonl"
  export LABELS

  stage "EXTRACT · 2" "Non-Root SSH Acquisition, SHA-256 Prefix Hashing & Ed25519 Manifest"
  ACQ="$WORK/acquire.json"
  export ACQ
  run <<'CMD'
elijah acquire --inventory lab/inventory.ini --case-id $CASE --store local | tee $ACQ | jq .
CMD
  EID="$(jq -r '.evidence_id // empty' "$ACQ" 2>/dev/null)"
  [ -n "$EID" ] || fail "Acquisition failed."
  export EID
  run <<'CMD'
elijah parse $CASE --evidence-id $EID | jq .
CMD
else
  SRC="$PROJECT/staging/phase2-demo"
  KAGGLE_SRC="$PROJECT/staging/kaggle-demo"
  [ -d "$SRC/evidence" ] || fail "Missing $SRC"
  [ -d "$KAGGLE_SRC/evidence" ] || fail "Missing $KAGGLE_SRC"

  CASE="C002"
  EID="d13a92df-dbbf-48dc-9784-59758a4c3456"
  KCASE="C003"
  KEID="8b7f4a21-5d9c-4e1a-9b30-2c4e8a91d6f0"
  KPUB="$WORK/case/kaggle_ed25519.pub"

  mkdir -p "$WORK/home/.elijah/keys" "$WORK/case"
  cp "$SRC/ed25519.pub" "$WORK/home/.elijah/keys/ed25519.pub"
  cp "$KAGGLE_SRC/ed25519.pub" "$KPUB"
  cp -R "$SRC/evidence" "$SRC/derived" "$WORK/case/"
  cp -R "$KAGGLE_SRC/evidence/C003" "$WORK/case/evidence/"
  cp -R "$KAGGLE_SRC/derived/C003" "$WORK/case/derived/"
  cp "$PROJECT/lab/out/labels.jsonl" "$WORK/case/labels.jsonl"
  chmod -R u+w "$WORK"
  export HOME="$WORK/home"
  cd "$WORK/case" || exit 1
  LABELS="labels.jsonl"
  export CASE EID KCASE KEID KPUB LABELS

  stage "EXTRACT · 1" "Acquired Evidence Packages & SHA-256 Provenance Manifests"
  run <<'CMD'
ls evidence/$CASE/$EID evidence/$CASE/$EID/artifacts evidence/$KCASE/$KEID/artifacts
elijah show $CASE --evidence-id $EID | jq -c '.evidence[0] | {case_id, schema_version, target: .target.hostname, artifacts: [.artifacts[]|{stored_as,size_at_open,sha256_source: .sha256_source[0:16],verified}], signature: .signature.algorithm, clock_offset_s: .timing.estimated_offset_seconds}'
jq -c '{seq, actor, action, entry_hash: .entry_hash[0:16], prev_hash: .prev_hash[0:8]}' evidence/$CASE/$EID/custody.jsonl
CMD
fi

# ======================================================================== LOAD
banner "STAGE 2 · LOAD [VERIFICATION -> SIGNED MANIFEST -> IMMUTABLE STORE -> PARSE]"

stage "LOAD · 1" "Cryptographic Signature, Custody Chain & Artifact Hash Verification"
run <<'CMD'
elijah verify $CASE --evidence-id $EID | jq -c '.results[0] | {evidence_id, ok, total_checks: (.checks|length), failed_checks}'
elijah verify $KCASE --evidence-id $KEID --public-key $KPUB | jq -c '.results[0] | {evidence_id, ok, total_checks: (.checks|length), failed_checks}'
CMD

stage "LOAD · 2" "Single-Bit Tamper Rejection Test (Raw Evidence & Derived Manifest Gate)"
run <<'CMD'
CASE=$CASE EID=$EID KEY=$HOME/.elijah/keys/ed25519.pub sh "$PROJECT/scripts/demo_tamper.sh"
CMD

stage "LOAD · 3" "Verifiable Working Copy & Lossless Parquet Derivation Verification"
run <<'CMD'
elijah verify-derived $CASE --evidence-id $EID | jq -c '.results[0] | {evidence_id, ok, total_checks: (.checks|length), failed_checks}'
elijah verify-derived $KCASE --evidence-id $KEID --public-key $KPUB | jq -c '.results[0] | {evidence_id, ok, total_checks: (.checks|length), failed_checks}'
jq -c '{case: "C002-lab", total_lines, parsed_lines, unparsed_lines, total_bytes, byte_coverage}' derived/$CASE/$EID/parse_report.json
jq -c '{case: "C003-kaggle", total_lines, parsed_lines, unparsed_lines, total_bytes, byte_coverage}' derived/$KCASE/$KEID/parse_report.json
CMD

# =================================================================== TRANSFORM
banner "STAGE 3 · TRANSFORM [PARQUET -> ISOLATION FOREST & DETECTORS -> ATTACK TIMELINE]"

stage "TRANSFORM · 1" "DuckDB SQL Analytics & Byte-Offset Provenance Trace"
run <<'CMD'
elijah sql $CASE $EID "SELECT status, count(*) AS requests FROM access WHERE parse_ok GROUP BY 1 ORDER BY 1" | jq -c '.rows'
elijah sql $CASE $EID "SELECT artifact_path, line_no, byte_offset, byte_length, raw_line FROM access WHERE trace_id = 'lapa-phase2-demo' AND parse_ok ORDER BY line_no DESC LIMIT 1" | jq -c '.rows[0]'
CMD

TRACE_ROW="$(elijah sql "$CASE" "$EID" "SELECT artifact_path, line_no, byte_offset, byte_length, raw_line FROM access WHERE trace_id = 'lapa-phase2-demo' AND parse_ok ORDER BY line_no DESC LIMIT 1" 2>/dev/null)"
ART="$(printf '%s' "$TRACE_ROW" | jq -r '.rows[0][0] // empty')"
OFFSET="$(printf '%s' "$TRACE_ROW" | jq -r '.rows[0][2] // empty')"
LENGTH="$(printf '%s' "$TRACE_ROW" | jq -r '.rows[0][3] // empty')"
RAW="$(printf '%s' "$TRACE_ROW" | jq -r '.rows[0][4] // empty')"
export ART OFFSET LENGTH

run <<'CMD'
dd if=evidence/$CASE/$EID/$ART bs=1 skip=$OFFSET count=$LENGTH 2>/dev/null; echo ""
CMD
ORIGINAL="$(dd if="evidence/$CASE/$EID/$ART" bs=1 skip="$OFFSET" count="$LENGTH" 2>/dev/null)"
if [ -n "$RAW" ] && [ "$RAW" = "$ORIGINAL" ]; then
  printf '%s[PROVENANCE TRACE: EXACT BYTE MATCH (%s bytes @ offset %s)]%s\n' "$GREEN" "$LENGTH" "$OFFSET" "$RESET"
fi

stage "TRANSFORM · 2" "Log Consistency Checks & Attack Timeline Reconstruction (Lab Case C002)"
run <<'CMD'
elijah analyze $CASE --evidence-id $EID | jq -r '.results[0] | "events: \(.total_events)   gaps: \(.gaps)   ok: \(.ok)", (.checks[] | "  [\(.status|ascii_upcase)] \(.name): \(.message)")'
CMD

stage "TRANSFORM · 3" "Signature Detection, Isolation Forest ML & Ground-Truth Evaluation (Lab Case C002)"
run <<'CMD'
elijah detect $CASE --evidence-id $EID | jq '.results[0]'
elijah evaluate $CASE --evidence-id $EID --labels $LABELS | jq -c '.results[0] | {labelled_rows, overall_attack_vs_benign, per_class: (.per_class | map_values({precision, recall, f1}))}'
CMD

stage "TRANSFORM · 4" "Real-World Kaggle Nginx Dataset (5,000 Requests): Isolation Forest ML & Attack Insights (Case C003)"
run <<'CMD'
elijah analyze $KCASE --evidence-id $KEID --public-key $KPUB | jq -c '.results[0] | {evidence_id, ok, total_events, unparsed_count, gaps}'
elijah detect $KCASE --evidence-id $KEID --public-key $KPUB | jq '.results[0]'
jq -r '.isolation_forest | "Model: \(.model.algorithm) (\(.model.n_trees) trees, max_samples=\(.model.max_samples), threshold=\(.threshold_used))", "Scored: \(.total_scored) | Flagged Anomalies: \(.anomaly_count) | Distribution: min=\(.score_distribution.min) median=\(.score_distribution.median) p95=\(.score_distribution.p95) max=\(.score_distribution.max)", "\nTop Isolation Forest Anomalies:", (.anomalies[:6][] | "  #\(.rank) score=\(.anomaly_score) [L\(.line_no) @ byte \(.byte_offset)] \(.remote_addr) status=\(.status) features=(\(.top_features|join(", "))) uri=\(.uri_raw[0:95])")' analysis/$KCASE/$KEID/detections.json
jq -r '"\nRule-Based Attack Detections (Case C003):", (.detections[:10][] | "  [\(.attack_class)] L\(.line_no) @ byte \(.byte_offset) | \(.remote_addr) | status=\(.status) | \(.uri_raw[0:85])")' analysis/$KCASE/$KEID/detections.json
CMD

stage "TRANSFORM · 5" "Self-Verifying Forensic Report Generation (Cases C002 & C003)"
run <<'CMD'
elijah report $CASE --evidence-id $EID --labels $LABELS | jq -c '.results[0]'
elijah report $KCASE --evidence-id $KEID --public-key $KPUB | jq -c '.results[0]'
sed -n '1,34p' reports/$KCASE/$KEID/report.md
sed -n '/## Findings/,/## Limitations/p' reports/$KCASE/$KEID/report.md | sed '$d'
CMD

banner "PIPELINE COMPLETE · ALL INTEGRITY, ML & TIMELINE STAGES VERIFIED"
