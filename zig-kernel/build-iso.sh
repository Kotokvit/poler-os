#!/bin/bash
# ============================================================================
# POLER-OS ISO Builder — auto-detects GRUB modules (BIOS + UEFI)
# ============================================================================
#
# This script builds a bootable ISO using grub-mkrescue.
# It auto-detects available GRUB platform modules:
#
#   BIOS boot:  requires i386-pc modules (grub-pc-bin on Debian/Ubuntu)
#   UEFI boot:  requires x86_64-efi modules (grub-efi-amd64-bin)
#
# Installation:
#   BIOS-only:   sudo apt install grub-pc-bin xorriso
#   UEFI-only:   sudo apt install grub-efi-amd64-bin xorriso mtools
#   Dual-boot:   sudo apt install grub-pc-bin grub-efi-amd64-bin xorriso mtools
#
# The script passes the -d flag to grub-mkrescue ONLY for the BIOS modules
# directory. UEFI support is auto-detected by grub-mkrescue itself.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

ISO_NAME="poler-os64.iso"
ISO_DIR="iso"

echo "[ISO] Building POLER-OS bootable ISO..."
echo "[ISO] Working directory: $SCRIPT_DIR"

# --- Auto-detect GRUB BIOS modules directory ---
GRUB_BIOS_DIR=""

# Search paths for i386-pc GRUB modules (in priority order)
BIOS_SEARCH_PATHS=(
    "/usr/lib/grub/i386-pc"            # Standard Linux (apt install grub-pc-bin)
    "/usr/local/lib/grub/i386-pc"       # Manual build install
    "/usr/lib/grub2/i386-pc"            # Some distros (openSUSE, etc.)
    "$HOME/my-project/tools/local/usr/lib/grub/i386-pc"  # Z AI sandbox
)

for dir in "${BIOS_SEARCH_PATHS[@]}"; do
    if [ -d "$dir" ] && [ -f "$dir/boot.img" ]; then
        GRUB_BIOS_DIR="$dir"
        echo "[ISO] Found BIOS GRUB modules: $GRUB_BIOS_DIR"
        break
    fi
done

# --- Check for UEFI GRUB modules ---
UEFI_AVAILABLE=false
UEFI_SEARCH_PATHS=(
    "/usr/lib/grub/x86_64-efi"         # Standard Linux (apt install grub-efi-amd64-bin)
    "/usr/local/lib/grub/x86_64-efi"    # Manual build install
    "/usr/lib/grub2/x86_64-efi"         # Some distros
)

for dir in "${UEFI_SEARCH_PATHS[@]}"; do
    if [ -d "$dir" ] && [ -f "$dir/efi.sig" -o -f "$dir/multiboot2.mod" ]; then
        UEFI_AVAILABLE=true
        echo "[ISO] Found UEFI GRUB modules: $dir"
        break
    fi
done

# --- Build grub-mkrescue command ---
MKRESCUE_ARGS=("grub-mkrescue" "-o" "$ISO_NAME")

if [ -n "$GRUB_BIOS_DIR" ]; then
    MKRESCUE_ARGS+=("-d" "$GRUB_BIOS_DIR")
    echo "[ISO] Using BIOS modules: $GRUB_BIOS_DIR"
else
    echo "[ISO] WARNING: No BIOS GRUB modules found!"
    echo "[ISO]   Install with: sudo apt install grub-pc-bin"
    echo "[ISO]   Attempting build without explicit -d flag..."
fi

MKRESCUE_ARGS+=("$ISO_DIR")

# --- Report boot mode support ---
if $UEFI_AVAILABLE; then
    echo "[ISO] ISO will support: BIOS + UEFI (dual-boot)"
else
    echo "[ISO] ISO will support: BIOS only"
    echo "[ISO]   For UEFI support: sudo apt install grub-efi-amd64-bin mtools"
fi

# --- Build ISO ---
echo "[ISO] Running: ${MKRESCUE_ARGS[*]}"
if "${MKRESCUE_ARGS[@]}"; then
    ISO_SIZE=$(stat -c%s "$ISO_NAME" 2>/dev/null || echo "?")
    echo "[ISO] Build successful! $ISO_NAME ($ISO_SIZE bytes)"
    echo ""
    echo "[ISO] Boot modes:"
    echo "  BIOS:  Supported (i386-pc)"
    if $UEFI_AVAILABLE; then
        echo "  UEFI:  Supported (x86_64-efi)"
    else
        echo "  UEFI:  Not available (install grub-efi-amd64-bin)"
    fi
    echo ""
    echo "[ISO] Testing in QEMU:"
    echo "  qemu-system-x86_64 -cdrom $ISO_NAME -m 256M -serial stdio -no-reboot"
    echo ""
    echo "[ISO] For VirtualBox/VMware:"
    echo "  - BIOS mode: Should boot directly"
    echo "  - UEFI mode: Requires UEFI modules in ISO (see above)"
else
    echo "[ISO] ERROR: grub-mkrescue failed!"
    echo "[ISO] Make sure you have installed:"
    echo "  sudo apt install grub-pc-bin xorriso"
    exit 1
fi
