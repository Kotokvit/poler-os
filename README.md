# POLER-OS

x86_64 kernel written in Zig. Boots via Multiboot2/GRUB into 64-bit long mode.

## Current State: v0.6.0

- Boot: Multiboot2 → 32→64 transition → identity paging (4GB, 2MB pages)
- HAL: GDT, IDT, PIC remap, Local APIC timer (vector 48), IO-APIC, TSS
- ACPI: RSDP/RSDT/MADT/HPET parsing
- Memory: PMM (bitmap), VMM (4-level paging), kernel heap (free-list)
- Scheduler: Round-robin with APIC timer preemption
- Drivers: VGA text mode, framebuffer, PS/2 keyboard, serial COM1
- POLER Core: Deformed tensor product (⊗_ε algebra)
- Syscalls: syscall/sysretq (Ring 0 ↔ Ring 3)

## Build

```bash
zig build          # Build kernel
zig build iso      # Build bootable ISO (needs grub-mkrescue + xorriso)
zig build run64    # Run in QEMU (-kernel mode)
```

Requires: Zig 0.13.0, QEMU, GRUB (grub-mkrescue), xorriso

## Test in QEMU

```bash
qemu-system-x86_64 -cdrom poler-os64-v0.6.0.iso -m 256M
```

## Project Structure

```
zig-kernel/
├── src64/           # 64-bit kernel
│   ├── boot64.S     # Multiboot2 header, 32→64 transition, page tables
│   ├── isr64.S      # ISR/IRQ stubs + syscall entry
│   ├── main64.zig   # Kernel entry, boot sequence
│   ├── hal.zig      # GDT/IDT/PIC/APIC/IOAPIC/keyboard/serial
│   ├── acpi.zig     # RSDP/RSDT/MADT/HPET
│   ├── pmm64.zig    # Physical memory manager (bitmap)
│   ├── vmm64.zig    # Virtual memory manager (4-level paging)
│   ├── heap64.zig   # Kernel heap allocator
│   ├── scheduler.zig # Round-robin scheduler
│   ├── framebuffer.zig # Linear framebuffer graphics
│   ├── multiboot2.zig # Multiboot2 info parser
│   ├── cpio.zig     # CPIO initrd parser
│   ├── poler_core.zig  # ⊗_ε tensor algebra
│   └── linker64.ld  # Linker script
├── src/             # Legacy 32-bit kernel
├── iso/             # GRUB ISO structure
└── build.zig
```

## Roadmap

- [x] Boot into 64-bit long mode
- [x] HAL (GDT/IDT/PIC/APIC)
- [x] APIC timer on vector 48 (no PIC conflict)
- [x] Own GDT + TSS
- [x] PMM + VMM + kernel heap
- [x] Round-robin scheduler
- [ ] POLER Core freestanding (remove std dependency)
- [ ] FAT32 filesystem
- [ ] SMP (multi-core)
- [ ] User mode + ELF loader
- [ ] Intent Layer (semantic runtime)





## License

POLER-OS is licensed under the **GNU General Public License v3.0 or later** (GPLv3+).

This means you can freely use, study, modify, and redistribute this software.
Any derivative works **must** also be licensed under GPLv3+ and provide source code.
This ensures knowledge remains open and no one can appropriate it as proprietary.

See [LICENSE](LICENSE) for details.
