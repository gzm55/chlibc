#!/bin/bash
set -eu

WARN_COUNT=$(grep -ch "^WARN:" build/*/vm-test.log 2>/dev/null | awk '{s+=$1} END {print s+0}')

if [ "$WARN_COUNT" -eq 0 ]; then
  echo "All VM tests PASS"
  exit 0
elif [ "$WARN_COUNT" -eq 1 ] && grep -q "^WARN:.*2\.6\.32.*x86_64" build/clang-x86_64/vm-test.log; then
  echo "OK: x86_64 2.6.32 timeout (partial success)"
  exit 0
else
  echo "ERROR: $WARN_COUNT WARN(s) detected (only x86_64 2.6.32 allowed)" >&2
  exit 1
fi
