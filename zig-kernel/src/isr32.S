# POLER-OS v0.5.1 — ISR/IRQ Assembly Stubs
# 32 CPU exception handlers (ISR 0-31) + 16 IRQ handlers (IRQ 32-47)
# Each stub pushes ISR number (+ dummy error code if CPU doesn't push one)
# then jumps to the common handler which calls zig_isr_handler()

.section .text

# ─── CPU Exception Stubs (ISR 0-31) ───────────────────────────────────────

# ISR 0: Divide Error (no error code)
.global isr0
isr0:   pushl $0; pushl $0; jmp isr_common

# ISR 1: Debug (no error code)
.global isr1
isr1:   pushl $0; pushl $1; jmp isr_common

# ISR 2: NMI (no error code)
.global isr2
isr2:   pushl $0; pushl $2; jmp isr_common

# ISR 3: Breakpoint (no error code)
.global isr3
isr3:   pushl $0; pushl $3; jmp isr_common

# ISR 4: Overflow (no error code)
.global isr4
isr4:   pushl $0; pushl $4; jmp isr_common

# ISR 5: BOUND Range Exceeded (no error code)
.global isr5
isr5:   pushl $0; pushl $5; jmp isr_common

# ISR 6: Invalid Opcode (no error code)
.global isr6
isr6:   pushl $0; pushl $6; jmp isr_common

# ISR 7: Device Not Available (no error code)
.global isr7
isr7:   pushl $0; pushl $7; jmp isr_common

# ISR 8: Double Fault (CPU pushes error code)
.global isr8
isr8:   pushl $8; jmp isr_common

# ISR 9: Coprocessor Segment Overrun (no error code)
.global isr9
isr9:   pushl $0; pushl $9; jmp isr_common

# ISR 10: Invalid TSS (CPU pushes error code)
.global isr10
isr10:  pushl $10; jmp isr_common

# ISR 11: Segment Not Present (CPU pushes error code)
.global isr11
isr11:  pushl $11; jmp isr_common

# ISR 12: Stack Segment Fault (CPU pushes error code)
.global isr12
isr12:  pushl $12; jmp isr_common

# ISR 13: General Protection Fault (CPU pushes error code)
.global isr13
isr13:  pushl $13; jmp isr_common

# ISR 14: Page Fault (CPU pushes error code)
.global isr14
isr14:  pushl $14; jmp isr_common

# ISR 15: Reserved (no error code)
.global isr15
isr15:  pushl $0; pushl $15; jmp isr_common

# ISR 16: x87 FPU Error (no error code)
.global isr16
isr16:  pushl $0; pushl $16; jmp isr_common

# ISR 17: Alignment Check (CPU pushes error code)
.global isr17
isr17:  pushl $17; jmp isr_common

# ISR 18: Machine Check (no error code)
.global isr18
isr18:  pushl $0; pushl $18; jmp isr_common

# ISR 19: SIMD Floating-Point (no error code)
.global isr19
isr19:  pushl $0; pushl $19; jmp isr_common

# ISR 20-31: Reserved (no error codes)
.global isr20
isr20:  pushl $0; pushl $20; jmp isr_common

.global isr21
isr21:  pushl $0; pushl $21; jmp isr_common

.global isr22
isr22:  pushl $0; pushl $22; jmp isr_common

.global isr23
isr23:  pushl $0; pushl $23; jmp isr_common

.global isr24
isr24:  pushl $0; pushl $24; jmp isr_common

.global isr25
isr25:  pushl $0; pushl $25; jmp isr_common

.global isr26
isr26:  pushl $0; pushl $26; jmp isr_common

.global isr27
isr27:  pushl $0; pushl $27; jmp isr_common

.global isr28
isr28:  pushl $0; pushl $28; jmp isr_common

.global isr29
isr29:  pushl $0; pushl $29; jmp isr_common

.global isr30
isr30:  pushl $0; pushl $30; jmp isr_common

.global isr31
isr31:  pushl $0; pushl $31; jmp isr_common

# ─── IRQ Stubs (IRQ 32-47) ────────────────────────────────────────────────

.global irq32
irq32:  pushl $0; pushl $32; jmp isr_common   # Timer (PIT)

.global irq33
irq33:  pushl $0; pushl $33; jmp isr_common   # Keyboard

.global irq34
irq34:  pushl $0; pushl $34; jmp isr_common   # Cascade

.global irq35
irq35:  pushl $0; pushl $35; jmp isr_common   # COM2

.global irq36
irq36:  pushl $0; pushl $36; jmp isr_common   # COM1

.global irq37
irq37:  pushl $0; pushl $37; jmp isr_common   # LPT2

.global irq38
irq38:  pushl $0; pushl $38; jmp isr_common   # Floppy

.global irq39
irq39:  pushl $0; pushl $39; jmp isr_common   # LPT1

.global irq40
irq40:  pushl $0; pushl $40; jmp isr_common   # RTC

.global irq41
irq41:  pushl $0; pushl $41; jmp isr_common   # ACPI

.global irq42
irq42:  pushl $0; pushl $42; jmp isr_common   # Available

.global irq43
irq43:  pushl $0; pushl $43; jmp isr_common   # Available

.global irq44
irq44:  pushl $0; pushl $44; jmp isr_common   # Mouse

.global irq45
irq45:  pushl $0; pushl $45; jmp isr_common   # FPU

.global irq46
irq46:  pushl $0; pushl $46; jmp isr_common   # ATA Primary

.global irq47
irq47:  pushl $0; pushl $47; jmp isr_common   # ATA Secondary

# ─── Common ISR Handler ────────────────────────────────────────────────────
# Stack on entry: [error_code, isr_number] pushed by stub, then CPU's [EIP, CS, EFLAGS]
isr_common:
    pushal                      # save all 8 general-purpose registers

    # Save segment registers (as 32-bit pushes for alignment)
    movw %ds, %ax
    pushl %eax
    movw %es, %ax
    pushl %eax
    movw %fs, %ax
    pushl %eax
    movw %gs, %ax
    pushl %eax

    # Load kernel data segment selector (0x10)
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    # Extract ISR number and error code from the stack
    # Stack layout after pushal + 4 segment pushes (48 bytes above ESP):
    #   ESP+44: EAX, ESP+40: ECX, ESP+36: EDX, ESP+32: EBX
    #   ESP+28: original ESP, ESP+24: EBP, ESP+20: ESI, ESP+16: EDI
    #   ESP+12: saved GS, ESP+8: saved FS, ESP+4: saved ES, ESP+0: saved DS
    # Above that: ISR number at ESP+48, error code at ESP+52
    movl 48(%esp), %eax         # ISR number
    movl 52(%esp), %edx         # error code

    # Call Zig handler: zig_isr_handler(isr_number, error_code)
    pushl %edx                  # arg2: error_code
    pushl %eax                  # arg1: isr_number
    call zig_isr_handler
    addl $8, %esp               # clean up cdecl arguments

    # Restore segment registers
    popl %eax
    movw %ax, %gs
    popl %eax
    movw %ax, %fs
    popl %eax
    movw %ax, %es
    popl %eax
    movw %ax, %ds

    popal                       # restore all general-purpose registers
    addl $8, %esp               # remove error_code and isr_number pushed by stub
    iret                        # return from interrupt

# ─── ISR Address Table (for Zig to set up IDT entries) ────────────────────
.section .rodata
.global isr_table
isr_table:
    .long isr0,  isr1,  isr2,  isr3,  isr4,  isr5,  isr6,  isr7
    .long isr8,  isr9,  isr10, isr11, isr12, isr13, isr14, isr15
    .long isr16, isr17, isr18, isr19, isr20, isr21, isr22, isr23
    .long isr24, isr25, isr26, isr27, isr28, isr29, isr30, isr31
    .long irq32, irq33, irq34, irq35, irq36, irq37, irq38, irq39
    .long irq40, irq41, irq42, irq43, irq44, irq45, irq46, irq47
