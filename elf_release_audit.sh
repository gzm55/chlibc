#!/bin/sh
# usage: elf_release_audit.sh <path>

TARGET="${1:?usage: elf_audit.sh <path>}"
: "${READELF_BIN:=readelf}"
TARGET_ARCH=$("${READELF_BIN}" -h "$TARGET" | sed -n '/Machine:/ s/.*Machine:[[:space:]]*// p')

case "$TARGET" in
*-dbg) exit 0 ;;
esac

case "$TARGET_ARCH" in
"Advanced Micro Devices X86-64") MAX_GLIBC="2.5" NO_IFUNC=true ;;
AArch64) MAX_GLIBC="2.17" NO_IFUNC=true ;;
*) echo "[ERROR] non support arch $TARGET_ARCH"
esac

EXIT_STATUS=0
log_error() {
  ERRORS="$ERRORS
  - [!] $1"
  EXIT_STATUS=1
}

# check version $1 >= version $2
is_ver_gt() {
  [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -n 1)" != "$1" ] || return 1
  return 0 # $1 is new
}

# Check NEEDED libraries
NEEDED_LIBS=$("$READELF_BIN" -d "$TARGET" | sed -n '/(NEEDED) /s/.*\[\(.*\)\].*/\1/p')
NEEDED_COUNT=$(printf "%s\n" "$NEEDED_LIBS" | grep -vc '^$')

if [ "$NEEDED_COUNT" -ne 1 ] || [ "$NEEDED_LIBS" != libc.so.6 ]; then
  log_error "Link libraries are only only libc.so.6. Found: $(printf "%s\n" "$NEEDED_LIBS" | xargs)"
fi

# Check required GLIBC VERSION
MAX_FOUND_GLIBC=$("$READELF_BIN" -V "$TARGET" | sed -n '/GLIBC_/ s/.*GLIBC_\([0-9.]*\).*/\1/ p' | sort -rV | head -n1)
if [ -z "$MAX_FOUND_GLIBC" ]; then
  log_error "no glibc symbol version"
elif is_ver_gt "$MAX_FOUND_GLIBC" "$MAX_GLIBC"; then
  log_error "Require GLIBC VERSION > $MAX_GLIBC, but found $MAX_FOUND_GLIBC"
fi

# Check no IFUNC
if $NO_IFUNC; then
  FOUND_IFUNC=false
  "$READELF_BIN" -sW "$TARGET" 2>/dev/null | grep -qE 'IFUNC|STT_GNU_IFUNC' && FOUND_IFUNC=true
  "$READELF_BIN" -rW "$TARGET" 2>/dev/null | grep -q 'IRELATIVE' && FOUND_IFUNC=true
  if $FOUND_IFUNC; then
    log_error "Found IFUNC functions"
  fi
fi

if [ "$EXIT_STATUS" -ne 0 ]; then
  printf "[ERROR] %s breaks some limits:%s\n" "$TARGET" "$ERRORS"
fi
exit "$EXIT_STATUS"
