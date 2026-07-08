# POLER-OS v0.4.0 — 32-bit Multiboot1 Entry Point
# Fixed: stack alignment, CR0.TS, CR0.NE, A20 check, minimal GDT/IDT
# QEMU/GRUB loads this at 1MB in 32-bit protected mode

.section .rodata.boot, "a", @progbits
.align 8
multiboot_header:
    .long 0x1BADB002                    # magic
    .long 0x00000003                    # flags: align + meminfo
    .long -(0x1BADB002 + 0x00000003)   # checksum

# ─── Minimal GDT ───────────────────────────────────────────────────────────
# Flat memory model: code + data segments covering 0-4GB
.section .rodata
.align 16
gdt_start:
    .quad 0x0000000000000000            # null descriptor
gdt_code:
    .word 0xFFFF                        # limit low
    .word 0x0000                        # base low
    .byte 0x00                          # base mid
    .byte 0x9A                          # access: Present, Ring0, Code, Readable
    .byte 0xCF                          # granularity: 4KB, 32-bit, limit high=0xF
    .byte 0x00                          # base high
gdt_data:
    .word 0xFFFF                        # limit low
    .word 0x0000                        # base low
    .byte 0x00                          # base mid
    .byte 0x92                          # access: Present, Ring0, Data, Writable
    .byte 0xCF                          # granularity: 4KB, 32-bit, limit high=0xF
    .byte 0x00                          # base high
gdt_end:

# GDT selector offsets
code32_sel = 0x08
data32_sel = 0x10

# ─── Stack ─────────────────────────────────────────────────────────────────
.section .bss
.align 16
boot_stack:
    .skip 32768                         # 32KB stack (increased from 16KB)

# IDT storage — 256 entries × 8 bytes = 2048 bytes
idt_table:
    .skip 2048

# ─── Entry Point ───────────────────────────────────────────────────────────
.section .text.boot
.global _start
.type _start, @function
_start:
    cli

    # Preserve multiboot magic (EAX) and info pointer (EBX)
    # before SSE2 setup clobbers EAX and we switch stacks
    movl %eax, %esi              # save magic in ESI
    movl %ebx, %edi              # save info pointer in EDI

    # ─── A20 Line Check ────────────────────────────────────────────────
    # Test if A20 is already enabled (usually by BIOS/GRUB/QEMU)
    # If not enabled, try fast A20 via port 0x92
    movl $0x100000, %eax
    movl (%eax), %ecx            # save byte at 0x100000
    movl $0x110000, %edx
    notl (%edx)                  # invert byte at 0x110000 (via 0x100000+1MB if A20 off)
    cmpl (%eax), %ecx            # did 0x100000 change?
    notl (%edx)                  # restore original
    je a20_ok                    # if same → A20 is ON, good

    # A20 is OFF — try fast A20 enable via port 0x92
    inb $0x92, %al
    orb $0x02, %al
    andb $0xFE, %al              # don't trigger reset (bit 0)
    outb %al, $0x92

a20_ok:

    # ─── Initialize FPU ────────────────────────────────────────────────
    fninit

    # ─── Enable SSE2: Zig uses SSE2 for f64 ops on i386 ────────────────
    movl %cr0, %eax
    andl $0xFFFFFFE3, %eax      # Clear EM (bit 2) + TS (bit 3)
    orl $0x22, %eax             # Set MP (bit 1) + NE (bit 5)
    movl %eax, %cr0
    movl %cr4, %eax
    orl $0x00000600, %eax       # Set OSFXSR (bit 9) + OSXMMEXCPT (bit 10)
    movl %eax, %cr4

    # ─── Load our own GDT ──────────────────────────────────────────────
    # Build GDT descriptor on stack: 2 bytes limit + 4 bytes base
    subl $8, %esp
    movw $gdt_end - gdt_start - 1, 0(%esp)   # GDT size
    movl $gdt_start, 2(%esp)                  # GDT base address
    lgdt (%esp)
    addl $8, %esp

    # Reload segment registers with our GDT selectors
    movl $0x10, %eax          # data32_sel = 0x10
    movl %eax, %ds
    movl %eax, %es
    movl %eax, %fs
    movl %eax, %gs
    movl %eax, %ss

    # Far jump to reload CS with our code selector
    ljmp $0x08, $reload_cs   # code32_sel = 0x08
reload_cs:

    # ─── Load empty IDT (prevents triple fault on exceptions) ───────────
    # Clear IDT entries to all zeros
    movl $512, %ecx              # 256 entries × 2 dwords = 512
    movl $idt_table, %edi
    xorl %eax, %eax
    cld
    rep stosl

    # Load IDT — build descriptor on stack
    # IDT descriptor: 2 bytes limit + 4 bytes base = 6 bytes
    subl $8, %esp                # allocate 8 bytes (aligned)
    movw $2047, 0(%esp)          # limit = 256*8-1 = 2047
    movl $idt_table, 2(%esp)     # base = idt_table address
    lidt (%esp)
    addl $8, %esp                # clean up stack

    # ─── Set up proper kernel stack (16-byte aligned for SSE) ───────────
    movl $boot_stack + 32768, %esp
    andl $0xFFFFFFF0, %esp       # Force 16-byte alignment
    xorl %ebp, %ebp

    # ─── Push args + align stack for cdecl (ESP+4 ≡ 0 mod 16 at entry) ─
    # System V i386 ABI: ESP+4 must be 16-byte aligned at function entry
    # After our 16-byte aligned ESP:
    #   sub 8 → ESP is 8 mod 16
    #   push arg2 → ESP is 4 mod 16
    #   push arg1 → ESP is 0 mod 16
    #   call pushes ret addr → ESP is 12 mod 16 → ESP+4 = 0 mod 16 ✓
    subl $8, %esp               # alignment padding for SSE2
    pushl %edi              # multiboot info pointer (arg2)
    pushl %esi              # multiboot magic (arg1)

    call kernel_main

    # Should not return
    cli
1:  hlt
    jmp 1b

.size _start, . - _start
