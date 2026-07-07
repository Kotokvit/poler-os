#!/bin/bash
# POLER-OS QEMU Runner
# Usage: ./run-qemu.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL="$SCRIPT_DIR/zig-out/bin/poler-os"

export LD_LIBRARY_PATH="$SCRIPT_DIR/../tools/qemu-sys/usr/lib/x86_64-linux-gnu"
QEMU="$SCRIPT_DIR/../tools/qemu-sys/usr/bin/qemu-system-i386"

if [ ! -f "$KERNEL" ]; then
    echo "Kernel not found. Run 'zig build' first."
    exit 1
fi

exec "$QEMU" \
  -L "$SCRIPT_DIR/../tools/qemu-sys/usr/share/qemu" \
  -kernel "$KERNEL" \
  -m 128M \
  -serial stdio \
  -display none \
  -no-reboot \
  -vga std \
  -nic none \
  "$@"
