#!/bin/sh
# usage ./loader_audit.sh file1.o file2.o ...

set -e

: "${READELF_BIN:=readelf}"

[ $# != 0 ] || exit 0
case "$1" in
*/Debug/*) exit 0 ;; # skip in Debug build
esac

EXIT_STATUS=0
log_error() {
  printf "%s [!] %s\n" "-" "$1"
  EXIT_STATUS=1
}

EXEMPT_SECTIONS="\.symtab|\.strtab|\.shstrtab|\.rela\..*|\.rel\..*|\.debug_.*|\.note\.gnu\.property|\.ARM\.attributes"

for file in "$@"; do
  echo "--- Auditing: $file ---"
  FAILED=0

  if [ ! -e "$file" ]; then
    log_error "file does not exist: $file"
    FAILED=1
  fi

  ILLEGAL_SECTIONS=$("$READELF_BIN" -SW "$file" \
  | sed 's/\[ /[/' \
  | awk '/\[[0-9]+\]/ && ("0x"$6) + 0 > 0 {print $2}' \
  | grep -vE "^($EXEMPT_SECTIONS)$" \
  | grep -vE "^\.(loader|loader\..*)$" \
  | xargs || :)

  # only .loader.* sections
  if [ -n "$ILLEGAL_SECTIONS" ]; then
    log_error "Unauthorized sections found (Must start with .loader):"
    log_error "   $ILLEGAL_SECTIONS"
    FAILED=1
  fi

  # no undefined functions
  UND_SYMS=$("$READELF_BIN" -sW "$file" | awk '$7 == "UND" && $8 != "" {print $8}' || :)
  if [ -n "$UND_SYMS" ]; then
    log_error "External/Undefined symbols detected:"
    log_error "    $UND_SYMS"
    FAILED=1
  fi

  # no outer relocations
  BAD_RELOCS=$("$READELF_BIN" -rW "$file" \
  | grep "R_X86_64_" \
  | grep -vE "PC32|PLT32" || :)
  if [ -n "$BAD_RELOCS" ]; then
    log_error "Non-relative relocations detected:"
    log_error "    $BAD_RELOCS"
    FAILED=1
  fi

  if [ $FAILED -eq 0 ]; then
    echo "[PASS] $file is fully compliant."
  fi
done

exit "$EXIT_STATUS"
