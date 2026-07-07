# POLER-OS — Boot Entry (32-bit -> 64-bit transition)
# Multiboot1 header + entry point (QEMU -kernel compatible)
# Assembled separately and linked with Zig kernel

.section .rodata.boot, "a", @progbits
.align 4
multiboot_header:
    .long 0x1BADB002          # multiboot1 magic
    .long 0x00000003          # flags: align modules (bit 0) + meminfo (bit 1)
    .long -(0x1BADB002 + 0x00000003)  # checksum

.section .rodata.gdt, "a", @progbits
.align 16
gdt64:
    .quad 0                    # null descriptor
    .quad 0x00209A0000000000   # code64: L+R+Present
    .quad 0x0000920000000000   # data: W+Present
gdt64_end:

.align 4
gdt64_ptr:
    .word gdt64_end - gdt64 - 1   # limit
    .long gdt64                    # base (32-bit for lgdt in compat mode)
    .long 0                        # padding

.section .bss
.align 16
boot_stack:
    .skip 16384

.section .text.boot
.global _start
.type _start, @function
_start:
    .code32
    cli
    movl $boot_stack + 16384, %esp
    xorl %ebp, %ebp

    # Setup page tables for long mode
    # PML4 at 0x70000, PDPT at 0x71000, PD at 0x72000
    movl $0x71003, %eax           # PDPT: Present + Writable
    movl %eax, 0x70000            # PML4[0] -> PDPT

    movl $0x72003, %eax           # PD: Present + Writable
    movl %eax, 0x71000            # PDPT[0] -> PD

    # PD: two 2MB pages (0-4MB identity mapped)
    movl $0x00083, %eax           # 0MB: Present + Writable + PageSize
    movl %eax, 0x72000            # PD[0]
    movl $0x200083, %eax          # 2MB: Present + Writable + PageSize
    movl %eax, 0x72008            # PD[1]

    # Enable PAE in CR4
    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4

    # Load PML4 into CR3
    movl $0x70000, %eax
    movl %eax, %cr3

    # Enable long mode in EFER MSR
    movl $0xC0000080, %ecx
    rdmsr
    orl $(1 << 8), %eax           # LME bit
    wrmsr

    # Enable paging (PG bit in CR0)
    movl %cr0, %eax
    orl $(1 << 31), %eax
    movl %eax, %cr0

    # Load 64-bit GDT
    lgdt gdt64_ptr

    # Far jump to 64-bit code segment (0x08 = code64 selector)
    ljmpl $0x08, $long_mode_entry

.code64
long_mode_entry:
    movl $0x10, %eax
    movl %eax, %ds
    movl %eax, %es
    movl %eax, %fs
    movl %eax, %gs
    movl %eax, %ss

    # Set 64-bit stack
    movq $boot_stack + 16384, %rsp
    xorq %rbp, %rbp

    # Call kernel main
    call kernel_main

    # Should not return, but halt if it does
    cli
1:
    hlt
    jmp 1b

.size _start, . - _start
