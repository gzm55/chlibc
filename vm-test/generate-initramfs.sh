#!/usr/bin/env bash

set -eufo pipefail

arch="${1:?arch}"
output="${2:?output}"
pixi_env="${3:-default}"
rootfs_dir="${output}.dir"

case "$arch" in
x86_64)
  GLIBC_VER=2.3.4
  ARCH_TRIPLE=x86_64-conda-linux-gnu
  ;;
ppc64le)
  GLIBC_VER=2.17
  ARCH_TRIPLE=powerpc64le-conda-linux-gnu
  ;;
aarch64)
  GLIBC_VER=2.17
  ARCH_TRIPLE=aarch64-conda-linux-gnu
  ;;
riscv64)
  GLIBC_VER=2.31
  ARCH_TRIPLE=riscv64-conda-linux-gnu
  ;;
esac

CURR_DIR=$(cd -- "$(dirname -- "$0")"; pwd)
CACHE_DIR="$CURR_DIR/dl-cache"
if [[ ${PIXI_ENVIRONMENT_NAME-} != "$pixi_env" ]]; then
  # shellcheck disable=SC2016
  CONDA_PREFIX=$("$CURR_DIR/../pixiw" run -e "$pixi_env" sh -c 'echo "$CONDA_PREFIX"')
fi
if [[ ! $CONDA_PREFIX && ! -d "$CONDA_PREFIX/$ARCH_TRIPLE/sysroot/lib64" ]]; then
  echo "[ERROR] cannot find sysroot/lib64/ for env $pixi_env"
  exit 1
fi

"$CURR_DIR/prepare-kernel-glibc.sh"

if [[ ! -d "$CACHE_DIR/kernel/$arch" ]] || [[ ! -d "$CACHE_DIR/glibc/$arch" ]]; then
  echo "[ERROR] no kernel or glibc for arch $arch"
  exit 1
fi

mkdir -p -- "$rootfs_dir/sysroot"
mkdir -p -- "$rootfs_dir/bin"

if [[ $arch != riscv64 ]]; then
  if command -v rpm2cpio >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
    pushd -- "$rootfs_dir" || exit 1
    rpm2cpio "$CACHE_DIR/glibc/$arch/glibc-$GLIBC_VER.rpm" \
    | cpio -idmv '.*/lib*/ld*.so*' '.*/lib*/libc.so*' '.*/lib*/libc-*.so' 2>/dev/null
    popd
  else
    tar xzvf "$CACHE_DIR/glibc/$arch/glibc-$GLIBC_VER.rpm" -C "$rootfs_dir" --exclude='*/tls/*' 'lib*/ld*.so*' 'lib*/libc.so*' 'lib*/libc-*.so'
  fi
else # riscv64
  ar p "$CACHE_DIR/glibc/$arch/glibc-$GLIBC_VER.deb" data.tar.xz \
  | if tar --wildcards --version >/dev/null 2>&1; then
      tar xJf - --wildcards -C "$rootfs_dir" 'lib*/ld*.so*' 'lib*/libc.so*' 'lib*/libc-*.so'
    else
      tar xJf - -C "$rootfs_dir" 'lib*/ld*.so*' 'lib*/libc.so*' 'lib*/libc-*.so'
    fi
fi

cp -RPpf "$CONDA_PREFIX/$ARCH_TRIPLE/sysroot/lib64" "$rootfs_dir/sysroot/"
rm -rf "$rootfs_dir/sysroot/lib64/locale"
rm -rf "$rootfs_dir/sysroot/lib64/gconv"
find "$rootfs_dir/sysroot/lib64/" -name '*.a' -delete

cp "$rootfs_dir/../bin/init" "$rootfs_dir/"
cp "$rootfs_dir/../bin/chlibc" "$rootfs_dir/bin/"
cp "$rootfs_dir/../bin/chlibc-dbg" "$rootfs_dir/bin/"
cp "$rootfs_dir/../bin/dump-args" "$rootfs_dir/bin/"

output="$(cd -- "$rootfs_dir/.."; pwd)/$(basename -- "$output")"

pushd -- "$rootfs_dir"
find . \
| "$CURR_DIR/../pixiw" run cpio -o -H newc --owner 0:0 \
| gzip > "$output"
popd

gunzip -c "$output" | "$CURR_DIR/../pixiw" run cpio -itv
