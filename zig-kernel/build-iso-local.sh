#!/bin/bash
# ============================================================================
# POLER-OS ISO Builder — uses locally installed tools (no sudo needed)
# ============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Local toolchain
LOCAL="/home/z/my-project/.local"
export PATH="$LOCAL/bin:$PATH"
export LD_LIBRARY_PATH="$LOCAL/lib:${LD_LIBRARY_PATH:-}"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     POLER-OS ISO Builder (local toolchain)       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"

# Verify tools
echo -e "${YELLOW}[0/4] Checking tools...${NC}"
command -v zig >/dev/null 2>&1 || { echo -e "${RED}ERROR: zig not found${NC}"; exit 1; }
command -v grub-mkrescue >/dev/null 2>&1 || { echo -e "${RED}ERROR: grub-mkrescue not found${NC}"; exit 1; }
command -v xorriso >/dev/null 2>&1 || { echo -e "${RED}ERROR: xorriso not found${NC}"; exit 1; }
echo -e "${GREEN}  ✓ zig $(zig version)${NC}"
echo -e "${GREEN}  ✓ grub-mkrescue $(grub-mkrescue --version 2>&1 | head -1)${NC}"
echo -e "${GREEN}  ✓ xorriso $(xorriso -version 2>&1 | head -1)${NC}"

# Step 1: Build kernel
echo -e "${YELLOW}[1/4] Building 64-bit kernel...${NC}"
zig build -Doptimize=ReleaseSmall 2>&1 || zig build 2>&1
echo -e "${GREEN}  ✓ Kernel built${NC}"

# Step 2: Copy kernel
echo -e "${YELLOW}[2/4] Preparing ISO structure...${NC}"
mkdir -p iso/boot/grub
cp -f zig-out/bin/poler-os64 iso/boot/poler-os64
echo -e "${GREEN}  ✓ Kernel copied to iso/boot/poler-os64${NC}"

# Step 3: GRUB config
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

# Step 4: Create ISO
echo -e "${YELLOW}[3/4] Creating bootable ISO...${NC}"
grub-mkrescue -o poler-os64.iso iso/ 2>&1
echo -e "${GREEN}  ✓ ISO created: poler-os64.iso${NC}"

# Optional: FAT32 disk for virtio-blk
if [[ "$1" == "--disk" || "$1" == "--run" ]]; then
    echo -e "${YELLOW}[4/4] Creating FAT32 disk image...${NC}"
    dd if=/dev/zero of=disk.img bs=1M count=16 2>/dev/null
    if command -v mformat >/dev/null 2>&1; then
        mformat -i disk.img -v POLEROS -F -c 1 ::
        echo -e "${GREEN}  ✓ FAT32 disk: disk.img (16MB)${NC}"
    else
        echo -e "${YELLOW}  ⚠ disk.img raw (no mtools for FAT32)${NC}"
    fi
else
    echo -e "${YELLOW}[4/4] Skipping disk image (use --disk)${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Build complete!                                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo "  ISO: $SCRIPT_DIR/poler-os64.iso"
echo "  Test: qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio"

if [[ "$1" == "--run" ]]; then
    qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio \
        -no-reboot -drive file=disk.img,if=virtio,format=raw
fi
