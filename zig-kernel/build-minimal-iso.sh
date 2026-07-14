#!/bin/bash
# POLER-OS Minimized ISO Builder with CPIO Initrd
# Eliminates themes, locales, fonts, and Apple hybrid-boot metadata to shrink size.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL="$SCRIPT_DIR/zig-out/bin/poler-os64"
ISO_DIR="$SCRIPT_DIR/iso"
ISO_OUT="$SCRIPT_DIR/poler-os64-minimal.iso"

if [ ! -f "$KERNEL" ]; then
    echo "Kernel not found. Building it first..."
    zig build
fi

# Ensure kernel is copied into the staging directory
mkdir -p "$ISO_DIR/boot"
cp "$KERNEL" "$ISO_DIR/boot/poler-os64"

# 1. Create a temporary staging folder for initrd
echo "Creating test initrd contents..."
INITRD_TMP="$SCRIPT_DIR/initrd_tmp"
rm -rf "$INITRD_TMP"
mkdir -p "$INITRD_TMP"

# 2. Add test files
echo "Hello from user-space initrd!" > "$INITRD_TMP/hello.txt"
echo "POLER Core v4 continuous epsilon is active." > "$INITRD_TMP/secrets.txt"

# 3. Build CPIO archive into staging ISO folder
echo "Packing initrd.cpio using cpio..."
cd "$INITRD_TMP"
find . | cpio -o -H newc > "$ISO_DIR/boot/initrd.cpio"
cd "$SCRIPT_DIR"
rm -rf "$INITRD_TMP"

# 4. Generate grub.cfg that loads the initrd module
echo "Generating bootable grub.cfg..."
mkdir -p "$ISO_DIR/boot/grub"
cat << 'EOF' > "$ISO_DIR/boot/grub/grub.cfg"
set timeout=0
set default=0

menuentry "poler-os" {
    multiboot2 /boot/poler-os64
    module2 /boot/initrd.cpio
    boot
}
EOF

# 5. Build the ISO
echo "Building minimized ISO..."
grub-mkrescue -o "$ISO_OUT" "$ISO_DIR" \
    --locales="" \
    --themes="" \
    --fonts="" \
    --compress=xz

echo "Clean bootable ISO created at: $ISO_OUT"
ls -lh "$ISO_OUT"
