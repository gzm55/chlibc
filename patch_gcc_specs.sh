#!/bin/sh

set -e

COMPILER="$1"
BUILD_DIR="$2"
PATTERN='%{!static:-rpath [^}]*}'

SPECS_PATH=$("$COMPILER" -v 2>&1 | grep "Reading specs from" | awk '{print $4}')
[ -n "$SPECS_PATH" ] && [ -f "$SPECS_PATH" ] || exit 0
grep -qE "$PATTERN" "$SPECS_PATH" || exit 0

mkdir -p "$BUILD_DIR"
OUT_FILE="$BUILD_DIR/norpath.specs"

sed -E "s|${PATTERN}||g" "$SPECS_PATH" > "$OUT_FILE"

printf "%s\n" "$OUT_FILE"
