// POLER-OS Boot Sector — Zig 0.13 freestanding x86_64
// Stage 1: MBR bootloader, loads Stage 2 from disk
// Target: x86 freestanding, real mode → protected mode → long mode

const arch = @import("../arch/x86_64/zig.zig");

// MBR Entry Point — loaded at 0x7C00 by BIOS
export fn _start() callconv(.Naked) noreturn {
    asm volatile (
        \\ .code16gcc
        \\ cli                    // Disable interrupts
        \\ xor %ax, %ax
        \\ mov %ax, %ds           // Zero data segments
        \\ mov %ax, %es
        \\ mov %ax, %ss
        \\ mov $0x7C00, %sp       // Stack at 0x7C00 (grows down)
        \\ sti                    // Re-enable interrupts
        \\
        \\ // Save boot drive
        \\ mov %dl, (boot_drive)
        \\
        \\ // Load Stage 2 kernel from disk (LBA 1-63)
        \\ mov $0x02, %ah         // BIOS read sectors
        \\ mov $0x40, %al         // 64 sectors = 32KB
        \\ mov $0x00, %ch         // Cylinder 0
        \\ mov $0x01, %cl         // Start from sector 1 (0-indexed from LBA)
        \\ mov $0x00, %dh         // Head 0
        \\ mov (boot_drive), %dl  // Boot drive
        \\ mov $0x1000, %bx       // Load at ES:BX = 0x1000:0x0000 = 0x10000
        \\ mov $0x1000, %ax
        \\ mov %ax, %es
        \\ xor %bx, %bx
        \\ int $0x13
        \\ jc disk_error
        \\
        \\ // Switch to protected mode
        \\ cli
        \\ lgdt (gdt_descriptor)  // Load GDT
        \\ mov %cr0, %eax
        \\ or $0x01, %eax         // Set PE bit
        \\ mov %eax, %cr0
        \\ 
        \\ // Far jump to 32-bit code
        \\ ljmpl $0x08, $protected_mode
        \\
        \\ disk_error:
        \\   mov $0x0E, %ah
        \\   mov $'E', %al
        \\   int $0x10
        \\   hlt
        \\
        \\ protected_mode:
        \\   .code32
        \\   // Set up protected mode segments
        \\   mov $0x10, %ax
        \\   mov %ax, %ds
        \\   mov %ax, %es
        \\   mov %ax, %fs
        \\   mov %ax, %gs
        \\   mov %ax, %ss
        \\   mov $0x90000, %esp    // Stack at 0x90000
        \\
        \\   // Set up page tables for long mode
        \\   call setup_page_tables
        \\   
        \\   // Enable PAE
        \\   mov %cr4, %eax
        \\   or $(1 << 5), %eax   // PAE bit
        \\   mov %eax, %cr4
        \\
        \\   // Load PML4 into CR3
        \\   mov $0x70000, %eax    // PML4 at 0x70000
        \\   mov %eax, %cr3
        \\
        \\   // Enable long mode via EFER MSR
        \\   mov $0xC0000080, %ecx // EFER MSR
        \\   rdmsr
        \\   or $(1 << 8), %eax   // LME bit
        \\   wrmsr
        \\
        \\   // Enable paging (sets PG bit)
        \\   mov %cr0, %eax
        \\   or $(1 << 31), %eax
        \\   mov %eax, %cr0
        \\
        \\   // Far jump to 64-bit code
        \\   ljmpl $0x08, $long_mode_entry
        \\
        \\ setup_page_tables:
        \\   // PML4[0] → PDPT
        \\   mov $0x70000, %eax
        \\   mov $0x71000, %ebx
        \\   or $0x03, %ebx        // Present + Writable
        \\   mov %ebx, (%eax)
        \\
        \\   // PDPT[0] → PD (identity map first 1GB)
        \\   mov $0x71000, %eax
        \\   mov $0x72000, %ebx
        \\   or $0x03, %ebx
        \\   mov %ebx, (%eax)
        \\
        \\   // PD: 2MB pages, identity map first 1GB
        \\   mov $0x72000, %edi
        \\   mov $0x83, %eax       // Present + Writable + Page Size (2MB)
        \\   mov $512, %ecx
        \\ fill_pd:
        \\   mov %eax, (%edi)
        \\   add $(2 << 20), %eax
        \\   add $8, %edi
        \\   dec %ecx
        \\   jnz fill_pd
        \\   ret
        \\
        \\ long_mode_entry:
        \\   .code64
        \\   // We're in 64-bit long mode!
        \\   // Set up 64-bit segments
        \\   mov $0x10, %ax
        \\   mov %ax, %ds
        \\   mov %ax, %es
        \\   mov %ax, %ss
        \\   
        \\   // Jump to kernel at 0x100000 (1MB mark)
        \\   mov $0x100000, %rax
        \\   jmp *%rax
    );

    unreachable;
}

// GDT for transition: null, code32, data32, code64
const gdt_descriptor = struct {
    limit: u16,
    base: u32,
};

var boot_drive: u8 = 0;
