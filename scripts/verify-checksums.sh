#!/bin/bash
set -eu

echo "=== SHA256 Checksums Verification ==="
for cfg in "x86_64:build/clang-x86_64" "aarch64:build/clang-aarch64" "ppc64le:build/gcc-powerpc64le" "riscv64:build/gcc-riscv64"; do
  ARCH=${cfg%%:*}
  SRC_PATH=${cfg#*:}
  BIN_HASH=$(sha256sum "$SRC_PATH/bin/chlibc" | awk '{print $1}')
  case $ARCH in
    x86_64)  CONDA_ARCH="linux-64" ;;
    aarch64) CONDA_ARCH="linux-aarch64" ;;
    ppc64le) CONDA_ARCH="linux-ppc64le" ;;
    riscv64) CONDA_ARCH="linux-riscv64" ;;
    *)       echo "Unknown arch: $ARCH"; exit 1 ;;
  esac
  CONDA_DIR="build/output-conda/$CONDA_ARCH"
  if [ ! -d "$CONDA_DIR" ]; then echo "skip $ARCH: no dir"; continue; fi
  CONDA_PKG=$(ls -t "$CONDA_DIR"/chlibc-*.conda 2>/dev/null | head -1) || true
  if [ -z "$CONDA_PKG" ]; then echo "skip $ARCH: no pkg"; continue; fi
  PKG_HASH=$(unzip -p "$CONDA_PKG" "pkg-*.tar.zst" 2>/dev/null | tar --zstd -xf - -O bin/chlibc 2>/dev/null | sha256sum | awk '{print $1}')
  echo "Arch: $ARCH | Bin: $BIN_HASH | Pkg: $PKG_HASH"
  if [ "$BIN_HASH" != "$PKG_HASH" ]; then echo "Error: Checksum changed in $ARCH!" >&2; exit 1; fi
  echo "OK"
done
echo "All checksums verified successfully."
