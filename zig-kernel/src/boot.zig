// POLER-OS — Multiboot2 Boot Entry
// Provides multiboot2 header + naked _start entry point
// QEMU loads this directly via -kernel flag

// ─── Multiboot2 Header ─────────────────────────────────────────────────────
// Must be in first 32KB of binary, aligned to 8 bytes
// Placed in .rodata.boot section, linker puts it first

const MULTIBOOT2_MAGIC: u32 = 0xE85250D6;
const MULTIBOOT2_ARCH: u32 = 0; // 0 = i386 (protected mode, works for x86_64 multiboot)
const MULTIBOOT2_HEADER_LENGTH: u32 = 24; // 16 header + 8 framebuffer tag + 0 end tag

// Framebuffer tag: request text mode
const Multiboot2FramebufferTag = extern struct {
    tag_type: u16 = 5,     // framebuffer tag
    tag_flags: u16 = 0,    // optional
    tag_size: u32 = 20,
    width: u32 = 80,
    height: u32 = 25,
    depth: u32 = 0,        // text mode
};

export const multiboot2_header align(8) linksection(".rodata.boot") = [_]u32{
    MULTIBOOT2_MAGIC,
    MULTIBOOT2_ARCH,
    MULTIBOOT2_HEADER_LENGTH,
    0x100000000 - MULTIBOOT2_MAGIC - MULTIBOOT2_ARCH - MULTIBOOT2_HEADER_LENGTH, // checksum
    5,     // tag type = framebuffer
    0,     // tag flags
    20,    // tag size
    80,    // width
    25,    // height
    0,     // depth (text mode)
    0,     // end tag type
    0,     // end tag flags
};

// ─── Stack ──────────────────────────────────────────────────────────────────
var boot_stack: [16384]u8 align(16) linksection(".bss") = undefined;

// ─── Entry Point ────────────────────────────────────────────────────────────
// QEMU multiboot loads us in 32-bit protected mode with paging disabled
// We must: set stack → enable PAE → setup pages → enable long mode → jump to 64-bit

export fn _start() callconv(.naked) noreturn {
    asm volatile (
        \\ .code32
        \\ cli
        \\ movl $boot_stack + 16384, %%esp
        \\ xorl %%ebp, %%ebp
        \\
        \\ // Setup page tables for long mode (identity map first 2MB)
        \\ // PML4 at 0x70000, PDPT at 0x71000, PD at 0x72000
        \\ movl $0x71000, %%eax
        \\ orl $0x03, %%eax          // Present + Writable
        \\ movl %%eax, 0x70000       // PML4[0] → PDPT
        \\
        \\ movl $0x72000, %%eax
        \\ orl $0x03, %%eax
        \\ movl %%eax, 0x71000       // PDPT[0] → PD
        \\
        \\ // PD: one 2MB page mapping first 2MB
        \\ movl $0x00083, %%eax      // Present + Writable + PageSize (2MB)
        \\ movl %%eax, 0x72000       // PD[0] → 0x00000000 (2MB page)
        \\
        \\ // Map 1MB kernel region too (0x100000-0x300000)
        \\ movl $0x00083, %%eax
        \\ movl %%eax, 0x72008       // PD[1] → 2MB-4MB
        \\
        \\ // Enable PAE in CR4
        \\ movl %%cr4, %%eax
        \\ orl $(1 << 5), %%eax
        \\ movl %%eax, %%cr4
        \\
        \\ // Load PML4 into CR3
        \\ movl $0x70000, %%eax
        \\ movl %%eax, %%cr3
        \\
        \\ // Enable long mode in EFER MSR
        \\ movl $0xC0000080, %%ecx
        \\ rdmsr
        \\ orl $(1 << 8), %%eax      // LME bit
        \\ wrmsr
        \\
        \\ // Enable paging (PG bit in CR0)
        \\ movl %%cr0, %%eax
        \\ orl $(1 << 31), %%eax
        \\ movl %%eax, %%cr0
        \\
        \\ // Load 64-bit GDT
        \\ lgdt gdt64_ptr
        \\
        \\ // Far jump to 64-bit code segment
        \\ ljmpl $0x08, $long_mode_entry
        \\
        \\ .code64
        \\ long_mode_entry:
        \\   movl $0x10, %%eax
        \\   movl %%eax, %%ds
        \\   movl %%eax, %%es
        \\   movl %%eax, %%fs
        \\   movl %%eax, %%gs
        \\   movl %%eax, %%ss
        \\
        \\   // Set 64-bit stack
        \\   movq $boot_stack + 16384, %%rsp
        \\   xorq %%rbp, %%rbp
        \\
        \\   // Call kernel main
        \\   call kernel_main
        \\
        \\   // Should not return, but halt if it does
        \\   cli
        \\   hlt
        \\ 1:
        \\   jmp 1b
    );
}

// ─── 64-bit GDT ────────────────────────────────────────────────────────────
export const gdt64 align(16) linksection(".rodata") = [_]u64{
    0,                          // Null descriptor
    0x00209A0000000000,         // Code64: L+R+Present
    0x0000920000000000,         // Data: W+Present
};

export const gdt64_ptr align(4) linksection(".rodata") = extern struct {
    limit: u16 = @sizeOf(@TypeOf(gdt64)) - 1,
    base: u32 = @intFromPtr(&gdt64),
};
