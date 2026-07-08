# POLER-OS Architecture

## Overview

POLER-OS is a monolithic x86_64 kernel built around a semantic runtime concept. Instead of programs calling specific OS APIs directly, they express intents (what they want to do), and the kernel dispatches those intents through adapters.

## Boot Sequence

```
GRUB (Multiboot2)
  → boot64.S: 32-bit entry, identity paging, long mode switch
  → poler_kernel_main() [Zig]
    → HAL init (GDT, IDT, PIC, APIC, TSS)
    → ACPI parse (RSDP → RSDT → MADT)
    → CPU detection (CPUID)
    → PMM init (physical memory bitmap)
    → VMM init (4-level page tables)
    → Heap init (free-list allocator)
    → Scheduler init (round-robin)
    → Idle loop
```

## Memory Layout

| Region | Address | Description |
|--------|---------|-------------|
| Kernel | 0x100000 | Identity-mapped, 1MB mark |
| Page tables | 0x102000 | PML4/PDPT/PD (boot64.S) |
| Kernel stack | ~0x106000 | 16KB, grows down |
| Heap | 0x200000000 | Virtual, mapped on demand |
| Framebuffer | 0xE0000000+ | LFB from Multiboot2 |

## Interrupt Architecture

| Vector | Source | Handler |
|--------|--------|---------|
| 0–31 | CPU exceptions | handleException() |
| 32–47 | PIC (IRQ0–15) | handleIRQ() — keyboard, serial |
| 48 | APIC Timer | Scheduler preemption tick |

## Key Components

### HAL (hal.zig)
Hardware abstraction: GDT/IDT setup, PIC remap, Local APIC timer calibration via PIT, IO-APIC keyboard routing, PS/2 keyboard driver, serial port (COM1).

### PMM (pmm64.zig)
Bitmap-based physical frame allocator. Reads memory map from Multiboot2 tags. 4KB granularity.

### VMM (vmm64.zig)
4-level paging (PML4 → PDPT → PD → PT). Maps virtual pages to physical frames using PMM for table allocation.

### Heap (heap64.zig)
Free-list kernel heap with block splitting and coalescing. Backed by VMM-mapped pages.

### Scheduler (scheduler.zig)
Round-robin cooperative/preemptive scheduler. APIC timer tick (vector 48) triggers context switch when quantum expires.

### POLER Core (poler_core.zig)
⊗_ε deformed tensor algebra — cryptographic primitive used for intent verification.

## Intent Layer (planned)

Programs express intents instead of making direct syscalls:

```
Intent{FS, Open, "/home/user/file.txt"}  →  FS Adapter
Intent{NET, Connect, "192.168.1.1:80"}   →  NET Adapter
Intent{PROC, Fork}                        →  PROC Adapter
```

Each intent carries a nonce and timestamp, verified by POLER Core before dispatch.
