#!/bin/bash
# ============================================================================
# POLER-OS GRUB ISO Builder
# ============================================================================
# Creates a bootable ISO using grub-mkrescue / xorriso.
#
# Prerequisites:
#   - grub-mkrescue (from grub-pc-bin / grub2-common)
#   - xorriso (from libisoburn / xorriso)
#   - mformat, mcopy (from mtools — for FAT32 disk image)
#
# Usage:
#   ./build-iso.sh            # Build kernel + ISO
#   ./build-iso.sh --disk     # Also create a FAT32 disk.img for virtio-blk
#   ./build-iso.sh --run      # Build + run in QEMU with virtio-blk
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        POLER-OS ISO Builder (GRUB)               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"

# Step 1: Build the kernel
echo -e "${YELLOW}[1/4] Building 64-bit kernel...${NC}"
if ! command -v zig &> /dev/null; then
    echo -e "${RED}ERROR: zig not found. Install from https://ziglang.org/${NC}"
    exit 1
fi
zig build -Doptimize=ReleaseSmall 2>&1 || zig build 2>&1
echo -e "${GREEN}  ✓ Kernel built${NC}"

# Step 2: Copy kernel binary to ISO directory
echo -e "${YELLOW}[2/4] Preparing ISO structure...${NC}"
mkdir -p iso/boot/grub
cp -f zig-out/bin/poler-os64 iso/boot/poler-os64
echo -e "${GREEN}  ✓ Kernel copied to iso/boot/poler-os64${NC}"

# Step 3: Create GRUB config
cat > iso/boot/grub/grub.cfg << 'EOF'
set timeout=5
set default=0

menuentry "POLER-OS v0.7.0 (64-bit)" {
    insmod multiboot2
    insmod part_msdos
    insmod elf
    echo "Loading POLER-OS v0.7.0..."
    multiboot2 /boot/poler-os64
    boot
}

menuentry "POLER-OS v0.7.0 (64-bit, serial console)" {
    insmod multiboot2
    insmod part_msdos
    insmod elf
    echo "Loading POLER-OS v0.7.0 (serial)..."
    multiboot2 /boot/poler-os64 console=serial
    boot
}
EOF
echo -e "${GREEN}  ✓ GRUB config written${NC}"

# Step 4: Create the ISO
echo -e "${YELLOW}[3/4] Creating bootable ISO...${NC}"
if command -v grub-mkrescue &> /dev/null; then
    grub-mkrescue -o poler-os64.iso iso/ 2>&1
    echo -e "${GREEN}  ✓ ISO created: poler-os64.iso${NC}"
elif command -v xorriso &> /dev/null; then
    # Manual ISO creation with xorriso if grub-mkrescue not available
    xorriso -as mkisofs \
        -R -J -c boot/boot.cat \
        -b boot/grub/i386-pc/eltorito.img \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        --grub2-boot-info \
        -o poler-os64.iso iso/ 2>&1
    echo -e "${GREEN}  ✓ ISO created with xorriso: poler-os64.iso${NC}"
else
    echo -e "${RED}ERROR: Neither grub-mkrescue nor xorriso found!${NC}"
    echo -e "${YELLOW}Install with: sudo apt install grub-pc-bin xorriso${NC}"
    exit 1
fi

# Optional: Create FAT32 disk image for virtio-blk testing
if [[ "$1" == "--disk" || "$1" == "--run" ]]; then
    echo -e "${YELLOW}[4/4] Creating FAT32 disk image...${NC}"
    if command -v mformat &> /dev/null; then
        # Create a 16MB FAT32 disk image
        dd if=/dev/zero of=disk.img bs=1M count=16 2>/dev/null
        mformat -i disk.img -v POLEROS -F -c 1 ::
        echo -e "${GREEN}  ✓ FAT32 disk image created: disk.img (16MB)${NC}"
    else
        echo -e "${YELLOW}  mformat not found, creating raw disk image...${NC}"
        dd if=/dev/zero of=disk.img bs=1M count=16 2>/dev/null
        echo -e "${YELLOW}  ⚠ disk.img created but not formatted (no mtools)${NC}"
        echo -e "${YELLOW}  Format manually: mkfs.fat -F 32 disk.img${NC}"
    fi
else
    echo -e "${YELLOW}[4/4] Skipping disk image (use --disk to create one)${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Build complete!                                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "To test in QEMU:"
echo "  qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio"
echo ""
echo "With virtio-blk disk:"
echo "  qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio \\"
echo "    -drive file=disk.img,if=virtio,format=raw"
echo ""

# Optional: Run in QEMU
if [[ "$1" == "--run" ]]; then
    if command -v qemu-system-x86_64 &> /dev/null; then
        echo -e "${YELLOW}Launching QEMU...${NC}"
        qemu-system-x86_64 \
            -cdrom poler-os64.iso \
            -m 256M \
            -serial stdio \
            -no-reboot \
            -drive file=disk.img,if=virtio,format=raw
    else
        echo -e "${RED}ERROR: qemu-system-x86_64 not found!${NC}"
        exit 1
    fi
fi
