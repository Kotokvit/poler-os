#!/bin/bash
# POLER-OS QEMU ISO Runner (No VT-x required)
# Runs the built ISO in QEMU with graphical interface

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ISO="$SCRIPT_DIR/poler-os64.iso"

if [ ! -f "$ISO" ]; then
    echo "ISO not found. Building it first..."
    zig build iso
fi

echo "Starting POLER-OS v0.5.1 in QEMU (Software Emulation)..."
exec qemu-system-x86_64 \
  -cdrom "$ISO" \
  -m 256M \
  -serial stdio \
  -vga std \
  -no-reboot
