#!/bin/sh
# Live-demo tamper test. Run from a directory that holds evidence/, derived/ and
# ed25519.pub (for example staging/phase2-demo) with the elijah venv active.
# It works only on COPIES in a scratch directory; the originals are never modified.
#
#   EID=<evidence-uuid> sh /path/to/scripts/demo_tamper.sh
set -u
CASE="${CASE:-C002}"
EID="${EID:?set EID to the evidence UUID}"
KEY="${KEY:-ed25519.pub}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# evidence/ is tampered in step 1; evidence.orig/ stays intact for steps 2 and 3.
cp -R evidence "$WORK/evidence"
cp -R evidence "$WORK/evidence.orig"
cp -R derived "$WORK/derived"
chmod -R u+w "$WORK"

flip() {
  python3 -c "
import sys
p = sys.argv[1]
data = bytearray(open(p, 'rb').read())
data[0] ^= 1
open(p, 'wb').write(bytes(data))
" "$1"
}

summary() {
  python3 -c "
import json, sys
for item in json.load(sys.stdin).get('results', []):
    print('  ok =', item['ok'], '| failed checks =', item['failed_checks'])
"
}

echo "1) Flip ONE byte in a copy of the stored access log, then verify the evidence"
flip "$WORK/evidence/$CASE/$EID/artifacts/0000-access.log"
elijah verify "$CASE" --evidence-id "$EID" --evidence-root "$WORK/evidence" \
  --public-key "$KEY" >"$WORK/out1.json"
echo "  exit status: $?"
summary <"$WORK/out1.json"

echo
echo "2) Flip ONE byte in a copy of the derived parse report, then verify the derived data"
flip "$WORK/derived/$CASE/$EID/parse_report.json"
elijah verify-derived "$CASE" --evidence-id "$EID" --derived-root "$WORK/derived" \
  --evidence-root "$WORK/evidence.orig" --public-key "$KEY" >"$WORK/out2.json"
echo "  exit status: $?"
summary <"$WORK/out2.json"

echo
echo "3) Ask for detection on the tampered derived data"
elijah detect "$CASE" --evidence-id "$EID" --derived-root "$WORK/derived" \
  --evidence-root "$WORK/evidence.orig" --public-key "$KEY" \
  --analysis-root "$WORK/analysis"
echo "  exit status: $?"
if [ -e "$WORK/analysis" ]; then
  echo "  UNEXPECTED: output was written"
else
  echo "  nothing was written to the analysis directory"
fi
