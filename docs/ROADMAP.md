# POLER-OS Development Roadmap

## Completed: v0.6.0

- [x] Multiboot2 boot into 64-bit long mode
- [x] Identity paging (4GB via 2MB huge pages)
- [x] GDT + TSS setup
- [x] IDT with ISR stubs (vectors 0–48)
- [x] PIC remap (IRQ0–15 → INT 32–47)
- [x] Local APIC timer (vector 48, PIT-calibrated)
- [x] IO-APIC keyboard routing
- [x] ACPI parsing (RSDP/RSDT/MADT/HPET)
- [x] PMM — bitmap physical frame allocator
- [x] VMM — 4-level paging with map/unmap
- [x] Kernel heap — free-list with split/coalesce
- [x] Round-robin scheduler
- [x] Syscall/sysretq mechanism
- [x] CPIO initrd parser
- [x] Framebuffer graphics
- [x] POLER Core ⊗_ε tensor algebra

## Next: v0.6.1 — POLER Core Freestanding

Remove `@import("std")` from poler_core.zig:
- Wrap std-dependent code with `comptime @import("builtin").is_test`
- Keep crypto functions as pure u32 arithmetic (no allocations)
- Real self-test in kernel: output test results via serial

## Next: v0.7.0 — Filesystem + Userspace

- FAT32 driver (reference: NovumOS fat.zig)
- ELF loader
- User mode (Ring 3) with syscall interface
- Process isolation (per-process page tables)

## Next: v0.8.0 — SMP + Networking

- Multi-core boot via SIPI
- Work-stealing scheduler (reference: NovumOS smp.zig)
- RTL8139/e1000 NIC driver
- TCP/IP stack (lwIP port or minimal custom)

## Next: v0.9.0 — Intent Layer

- Intent struct + dispatcher
- FS/NET/PROC adapters
- POLER Firewall integration (intent verification via ⊗_ε)
- Object table (capability-based access)

## Next: v1.0.0 — Shell + Self-Hosting

- Interactive shell with pipe/redirection
- Text editor
- Self-hosting Zig compiler (long-term)
