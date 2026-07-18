#!/bin/bash
# ============================================================================
# POLER-OS ISO Builder — uses Alpine chroot for ISO creation
# ============================================================================
# Requires: ~/rootfs/alpine with grub, xorriso, mtools, dosfstools installed
# Usage: ./build-chroot.sh [--disk] [--run]
# ============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
CHROOT="/home/z/rootfs/alpine"
ENTER_CHROOT="/home/z/my-project/scripts/enter-chroot.sh"
ZIG="/home/z/my-project/poler-os-source/zig/zig"

echo "╔══════════════════════════════════════════════════╗"
echo "║     POLER-OS ISO Builder (Alpine chroot)         ║"
echo "╚══════════════════════════════════════════════════╝"

# Step 1: Build kernel
echo "[1/5] Building 64-bit kernel..."
$ZIG build 2>&1
echo "  Kernel built"

# Step 2: Copy kernel and prepare ISO structure
echo "[2/5] Preparing ISO structure..."
mkdir -p iso/boot/grub
cp -f zig-out/bin/poler-os64 iso/boot/poler-os64

# Step 3: GRUB config
cat > iso/boot/grub/grub.cfg << 'EOF'
set timeout=0
set default=0

serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1

# VBE graphics mode for -vga std framebuffer
set gfxpayload=800x600x8
set gfxmode=800x600x8

terminal_input serial
terminal_output gfxterm serial

menuentry "POLER-OS v0.9.1 (64-bit, serial + FB)" {
    insmod multiboot2
    insmod part_msdos
    insmod elf
    insmod vbe
    insmod vga
    echo "Loading POLER-OS v0.9.1..."
    multiboot2 /boot/poler-os64
    boot
}

menuentry "POLER-OS v0.9.1 (64-bit, 32-bit FB)" {
    insmod multiboot2
    insmod part_msdos
    insmod elf
    insmod vbe
    insmod vga
    set gfxpayload=1024x768x32
    echo "Loading POLER-OS v0.9.1 (32-bit FB)..."
    multiboot2 /boot/poler-os64
    boot
}

menuentry "POLER-OS v0.9.1 (64-bit, text mode)" {
    insmod multiboot2
    insmod part_msdos
    insmod elf
    set gfxpayload=text
    echo "Loading POLER-OS v0.9.1 (text mode)..."
    multiboot2 /boot/poler-os64
    boot
}
EOF
echo "  GRUB config written"

# Step 4: Create FAT32 disk image (if --disk)
if [[ "$1" == "--disk" || "$1" == "--run" ]]; then
    echo "[3/5] Creating FAT32 disk image..."
    dd if=/dev/zero of=disk.img bs=1M count=16 2>/dev/null
    cp disk.img $CHROOT/tmp/disk.img
    $ENTER_CHROOT $CHROOT /bin/sh -c "mkfs.fat -F 32 -n POLEROS /tmp/disk.img" 2>&1 | tail -2
    cp $CHROOT/tmp/disk.img disk.img
    echo "  FAT32 disk: disk.img (16MB)"
else
    echo "[3/5] Skipping disk image (use --disk)"
fi

# Step 5: Create ISO in Alpine chroot
echo "[4/5] Creating bootable ISO..."
rm -rf $CHROOT/tmp/iso
cp -r iso $CHROOT/tmp/iso
cp -f zig-out/bin/poler-os64 $CHROOT/tmp/iso/boot/poler-os64

$ENTER_CHROOT $CHROOT /bin/sh -c "
grub-mkrescue -o /tmp/poler-os64.iso /tmp/iso/ 2>&1
" 2>&1 | tail -5

cp $CHROOT/tmp/poler-os64.iso poler-os64.iso
echo "  ISO created: poler-os64.iso"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Build complete!                                 ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  ISO: $SCRIPT_DIR/poler-os64.iso"
echo ""
echo "  Test (serial only):"
echo "    qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio -nographic -boot d"
echo ""
echo "  Test (serial + VGA std framebuffer):"
echo "    qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio -vga std -boot d"
echo ""
echo "  Test with disk:"
echo "    qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio -vga std -boot d -drive file=disk.img,if=virtio,format=raw"

if [[ "$1" == "--run" ]]; then
    qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio \
        -no-reboot -boot d -vga std \
        -drive file=disk.img,if=virtio,format=raw
fi
