#!/bin/bash
# ============================================================================
# POLER-OS ISO Builder — portable, no hardcoded paths
# ============================================================================
# Fixed: grub-mkrescue requires --directory=<grub-i386-pc-path> to properly
# embed the El Torito boot record. Without it, the ISO has MBR only and
# cannot boot from CDROM in QEMU/VirtualBox.
# ============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Resolve GRUB platform directory (contains boot.img, cdboot.img, *.mod)
# Priority: 1) repo-local grub-local  2) system /usr/lib/grub/i386-pc
GRUB_DIR=""
if [ -d "$SCRIPT_DIR/../grub-local/lib/grub/i386-pc/boot.img" ]; then
    GRUB_DIR="$SCRIPT_DIR/../grub-local/lib/grub/i386-pc"
elif [ -d "/usr/lib/grub/i386-pc/boot.img" ]; then
    GRUB_DIR="/usr/lib/grub/i386-pc"
elif [ -d "/usr/share/grub/i386-pc/boot.img" ]; then
    GRUB_DIR="/usr/share/grub/i386-pc"
else
    # Fallback: let grub-mkrescue auto-detect
    GRUB_DIR=""
fi

# Resolve local toolchain paths
LOCAL="$SCRIPT_DIR/../grub-local"
export PATH="$LOCAL/bin:$PATH"
export LD_LIBRARY_PATH="$LOCAL/lib:${LD_LIBRARY_PATH:-}"

echo "╔══════════════════════════════════════════════════╗"
echo "║     POLER-OS ISO Builder (portable)              ║"
echo "╚══════════════════════════════════════════════════╝"

# Verify tools
echo "[0/4] Checking tools..."
command -v zig >/dev/null 2>&1 || { echo "ERROR: zig not found"; exit 1; }
command -v grub-mkrescue >/dev/null 2>&1 || { echo "ERROR: grub-mkrescue not found"; exit 1; }
command -v xorriso >/dev/null 2>&1 || { echo "ERROR: xorriso not found (install libisoburn)"; exit 1; }
echo "  zig $(zig version)"
echo "  grub-mkrescue $(grub-mkrescue --version 2>&1 | head -1)"
echo "  GRUB platform dir: ${GRUB_DIR:-auto-detect}"

# Step 1: Build kernel
echo "[1/4] Building 64-bit kernel..."
zig build 2>&1
echo "  Kernel built"

# Step 2: Copy kernel
echo "[2/4] Preparing ISO structure..."
mkdir -p iso/boot/grub
cp -f zig-out/bin/poler-os64 iso/boot/poler-os64
echo "  Kernel copied to iso/boot/poler-os64"

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

menuentry "POLER-OS v0.7.0 (64-bit, QEMU VT-d)" {
    insmod multiboot2
    insmod part_msdos
    insmod elf
    echo "Loading POLER-OS v0.7.0 with IOMMU/VT-d..."
    multiboot2 /boot/poler-os64 iommu=on
    boot
}
EOF
echo "  GRUB config written"

# Step 4: Create ISO with El Torito boot record
echo "[3/4] Creating bootable ISO..."
if [ -n "$GRUB_DIR" ]; then
    grub-mkrescue --directory="$GRUB_DIR" -o poler-os64.iso iso/ 2>&1
else
    grub-mkrescue -o poler-os64.iso iso/ 2>&1
fi

# Verify El Torito is present
if xorriso -indev poler-os64.iso 2>&1 | grep -q "El Torito"; then
    echo "  ISO created with El Torito boot record: poler-os64.iso"
else
    echo "  WARNING: El Torito boot record NOT found! ISO may not boot from CDROM."
    echo "  Try: grub-mkrescue --directory=/usr/lib/grub/i386-pc -o poler-os64.iso iso/"
fi

# Optional: FAT32 disk for virtio-blk
if [[ "$1" == "--disk" || "$1" == "--run" ]]; then
    echo "[4/4] Creating FAT32 disk image..."
    dd if=/dev/zero of=disk.img bs=1M count=16 2>/dev/null
    if command -v mformat >/dev/null 2>&1; then
        mformat -i disk.img -v POLEROS -F -c 1 ::
        echo "  FAT32 disk: disk.img (16MB)"
    else
        echo "  disk.img raw (no mtools for FAT32)"
    fi
else
    echo "[4/4] Skipping disk image (use --disk)"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Build complete!                                 ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  ISO: $SCRIPT_DIR/poler-os64.iso"
echo "  Test: qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio"

if [[ "$1" == "--run" ]]; then
    qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio \
        -no-reboot -drive file=disk.img,if=virtio,format=raw
fi
