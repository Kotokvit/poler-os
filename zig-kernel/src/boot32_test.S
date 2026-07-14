# POLER-OS — Minimal Serial Test Kernel
# Just sends 'POK' to COM1 to verify boot works

.section .rodata.boot, "a", @progbits
.align 4
multiboot_header:
    .long 0x1BADB002                    # magic
    .long 0x00000003                    # flags: align + meminfo
    .long -(0x1BADB002 + 0x00000003)   # checksum

.section .bss
.align 16
boot_stack:
    .skip 16384

.section .text.boot
.global _start
.type _start, @function
_start:
    cli

    # Init FPU + SSE2
    fninit
    movl %cr0, %eax
    andl $0xFFFFFFFB, %eax
    orl $0x02, %eax
    movl %eax, %cr0
    movl %cr4, %eax
    orl $0x00000600, %eax
    movl %eax, %cr4

    movl $boot_stack + 16384, %esp
    xorl %ebp, %ebp

    # ===== Direct serial test in ASM =====
    # Init COM1
    movw $0x3F9, %dx
    xorb %al, %al
    outb %al, %dx

    movw $0x3FB, %dx
    movb $0x80, %al
    outb %al, %dx

    movw $0x3F8, %dx
    movb $0x01, %al
    outb %al, %dx

    movw $0x3F9, %dx
    xorb %al, %al
    outb %al, %dx

    movw $0x3FB, %dx
    movb $0x03, %al
    outb %al, %dx

    movw $0x3FA, %dx
    movb $0xC7, %al
    outb %al, %dx

    movw $0x3FC, %dx
    movb $0x0B, %al
    outb %al, %dx

    # Wait for transmit empty
1:
    movw $0x3FD, %dx
    inb %dx, %al
    testb $0x20, %al
    jz 1b

    # Send 'P'
    movw $0x3F8, %dx
    movb $0x50, %al
    outb %al, %dx

    # Wait
2:
    movw $0x3FD, %dx
    inb %dx, %al
    testb $0x20, %al
    jz 2b

    # Send 'O'
    movw $0x3F8, %dx
    movb $0x4F, %al
    outb %al, %dx

    # Wait
3:
    movw $0x3FD, %dx
    inb %dx, %al
    testb $0x20, %al
    jz 3b

    # Send 'K'
    movw $0x3F8, %dx
    movb $0x4B, %al
    outb %al, %dx

    # Wait
4:
    movw $0x3FD, %dx
    inb %dx, %al
    testb $0x20, %al
    jz 4b

    # Send '\n'
    movw $0x3F8, %dx
    movb $0x0A, %al
    outb %al, %dx

    # Now call kernel_main
    pushl %ebx
    pushl %eax
    call kernel_main

    cli
5:  hlt
    jmp 5b

.size _start, . - _start
