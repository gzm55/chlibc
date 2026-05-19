#!/usr/bin/env bash

set -eufo pipefail

CACHE_DIR="$(dirname -- "$0")/dl-cache"

download() {
  local dest="${1:?dest}"
  local url="${2:?url}"
  mkdir -p -- "$(dirname -- "$dest")"
  if [[ -f "$dest" ]]; then
    printf "[SKIP] %s already cached.\n" "$dest"
    return 0
  fi

  printf "[DOWNLOAD] %s to %s\n" "$url" "$dest"
  curl -fsSL --retry 3 -o "$dest" "$url"
}

download_extract_rpm() {
  local dest="${1:?dest}"
  local url="${2:?url}"
  local inner_path="${3:?inner_path}"
  mkdir -p -- "$(dirname -- "$dest")"
  if [[ -f "$dest" && -s "$dest" ]]; then
    printf "[SKIP] %s already cached.\n" "$dest"
    return 0
  fi

  printf "[DOWNLOAD] extract %s of %s to %s\n" "$inner_path" "$url" "$dest"
  curl -fsSL --retry 3 "$url" | tar xzOf - "$inner_path" > "$dest"
}

### KERNELS
download "$CACHE_DIR/kernel/x86_64/vmlinuz-2.6.18" 'https://vault.centos.org/5.0/os/x86_64/isolinux/vmlinuz'
download "$CACHE_DIR/kernel/x86_64/vmlinuz-2.6.32" 'https://vault.centos.org/6.0/os/x86_64/isolinux/vmlinuz'
download "$CACHE_DIR/kernel/x86_64/vmlinuz-3.10.0" 'https://vault.centos.org/7.0.1406/os/x86_64/isolinux/vmlinuz'
download "$CACHE_DIR/kernel/ppc64le/vmlinuz-3.10.0" 'https://vault.centos.org/altarch/7.2.1511/os/ppc64le/ppc/ppc64/vmlinuz'
download_extract_rpm "$CACHE_DIR/kernel/aarch64/vmlinuz-3.19.0" \
	'https://vault.centos.org/altarch/7.1.1503/os/aarch64/Packages/kernel-3.19.0-0.79.aa7a.aarch64.rpm' \
	'./boot/vmlinuz-3.19.0-0.79.aa7a.aarch64'

# ppc64 big endian
# download "$CACHE_DIR/kernel/ppc64/vmlinuz-3.10.0" 'https://vault.centos.org/altarch/7.2.1511/os/ppc64/ppc/ppc64/vmlinuz'

### GLIBC
download "$CACHE_DIR/glibc/x86_64/glibc-2.3.4.rpm" 'https://vault.centos.org/4.0/os/x86_64/CentOS/RPMS/glibc-2.3.4-2.x86_64.rpm'
download "$CACHE_DIR/glibc/aarch64/glibc-2.17.rpm" 'https://vault.centos.org/altarch/7.1.1503/os/aarch64/Packages/glibc-2.17-78.el7.aarch64.rpm'
download "$CACHE_DIR/glibc/ppc64le/glibc-2.17.rpm" 'https://vault.centos.org/altarch/7.2.1511/os/ppc64le/Packages/glibc-2.17-105.el7.ppc64le.rpm'

# ppc64 big endian
# download "$CACHE_DIR/glibc/ppc64/glibc-2.17.rpm" 'https://vault.centos.org/altarch/7.2.1511/os/ppc64/Packages/glibc-2.17-105.el7.ppc64.rpm'
