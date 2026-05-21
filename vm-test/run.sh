#!/usr/bin/env bash

set -eufo pipefail

arch="${1:?arch}"
build_dir="${2:?build_dir}"
kernel_ver="${3:?kernel_ver}"
pixi_env="${4:-default}"

if [[ ! -x "$build_dir/bin/chlibc" ]];then
  echo "[ERROR] cannot find $build_dir/bin/chlibc"
  exit 1
fi

BASE_DIR=$(dirname -- "$0")
"$BASE_DIR"/generate-initramfs.sh "${arch}" "$build_dir/initramfs.cpio.gz" "${pixi_env}"

K_ARGS="quiet"

case "$arch" in
x86_64)
  MACHINE="pc,i8042=off"
  K_ARGS+=" console=ttyS0"
  if [[ $kernel_ver == "2.6.18" ]];then
    MACHINE+=",acpi=off"
    K_ARGS+=" noapic"
  fi
  CPU=Penryn
  QEMU="qemu-system-$arch"
  ;;
ppc64le)
  MACHINE="pseries"
  K_ARGS+=" console=hvc0"
  # chlibc supports power7, but the testing glibc in sysroot requires power8
  CPU=power8
  QEMU="qemu-system-ppc64"
  ;;
aarch64)
  MACHINE="virt,acpi=off"
  K_ARGS+=" console=ttyAMA0"
  CPU=cortex-a53
  QEMU="qemu-system-$arch"
  ;;
*) echo "[ERROR] unsupported arch $arch" ;;
esac

if ! command -v "$QEMU"; then
  echo "[ERROR] no qemu command qemu-system-$arch"
  exit 1
fi

run_with_timeout_killgroup() {
  local timeout_sec="$1"
  shift

  set -m
  "$@" &
  local qemu_pid=$!

  (
    sleep "$timeout_sec"
    kill -TERM "-$qemu_pid" 2>/dev/null
    sleep 1
    kill -KILL "-$qemu_pid" 2>/dev/null
  ) &
  local killer_pid=$!
  set +m

  wait "$qemu_pid" 2>/dev/null
  kill -9 "-$killer_pid" 2>/dev/null
}

run_with_timeout_killgroup 30 "$QEMU" \
  -machine "$MACHINE" \
  -cpu "$CPU" \
  -m 512m \
  -nographic \
  -no-reboot \
  -kernel "$BASE_DIR/dl-cache/kernel/$arch/vmlinuz-$kernel_ver" \
  -initrd "$build_dir/initramfs.cpio.gz" \
  -append "$K_ARGS PATH=/bin CHLIBC_GLIBC_HOME=/sysroot/lib64 chlibc-dbg dump-args AA BB" \
| tee "$build_dir/vm-test.log" || :

if grep -qF "FATAL: kernel too old" "$build_dir/vm-test.log"; then
  echo "PASS: old kernel $kernel_ver on $arch"
elif grep -qF "/sysroot/lib64/libdl.so" "$build_dir/vm-test.log"; then
  echo "PASS: kernel $kernel_ver on $arch"
else
  echo "FAIL: kernel $kernel_ver on $arch" >&2
  exit 1
fi
