// ============================================================================
// POLER-OS HAL (Hardware Abstraction Layer) — x86_64
// ============================================================================
const scheduler = @import("scheduler.zig");

// ISR stubs: isr64.S (assembly) → isr_common_handler() (this file)
// ============================================================================

// No std import — freestanding kernel

// ============================================================================
// CPU INSTRUCTIONS
// ============================================================================

pub fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "{dx}" (port),
    );
}

pub fn outw(port: u16, val: u16) void {
    asm volatile ("outw %[val], %[port]"
        :
        : [val] "{ax}" (val),
          [port] "{dx}" (port),
    );
}

pub fn outl(port: u16, val: u32) void {
    asm volatile ("outl %[val], %[port]"
        :
        : [val] "{eax}" (val),
          [port] "{dx}" (port),
    );
}

pub fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

pub fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "{dx}" (port),
    );
}

pub fn cli() void {
    asm volatile ("cli");
}

pub fn sti() void {
    asm volatile ("sti");
}

pub fn hlt() void {
    asm volatile ("hlt");
}

pub fn ltr(selector: u16) void {
    asm volatile ("ltr %[sel]"
        :
        : [sel] "{ax}" (selector),
    );
}

pub fn readCr0() u64 {
    return asm volatile ("mov %%cr0, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn readCr3() u64 {
    return asm volatile ("mov %%cr3, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn readCr4() u64 {
    return asm volatile ("mov %%cr4, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn readMsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

pub fn writeMsr(msr: u32, val: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (@as(u32, @truncate(val))),
          [high] "{edx}" (@as(u32, @truncate(val >> 32))),
    );
}

// ============================================================================
// MSR Constants
// ============================================================================

pub const MSR = struct {
    pub const EFER = 0xC0000080;
    pub const STAR = 0xC0000081;
    pub const LSTAR = 0xC0000082;
    pub const CSTAR = 0xC0000083;
    pub const SFMASK = 0xC0000084;
    pub const FS_BASE = 0xC0000100;
    pub const GS_BASE = 0xC0000101;
    pub const KERNEL_GS_BASE = 0xC0000102;
};

pub const EFER = struct {
    pub const SCE = 1 << 0;  // System Call Extensions
    pub const LME = 1 << 8;  // Long Mode Enable
    pub const LMA = 1 << 10; // Long Mode Active
    pub const NXE = 1 << 11; // No-Execute Enable
};

// ============================================================================
// GDT (Global Descriptor Table)
// ============================================================================

pub const GDT = struct {
    pub const Entry = packed struct {
        limit_low: u16,
        base_low: u24,
        type: u4,
        s: u1,
        dpl: u2,
        p: u1,
        limit_high: u4,
        avl: u1,
        l: u1,
        d: u1,
        g: u1,
        base_high: u8,
    };

    pub const Ptr = packed struct {
        limit: u16,
        base: u64,
    };

    pub const TSSDesc = packed struct {
        low: u64,
        high: u64,
    };

    pub const NUM_ENTRIES = 7; // null + kcode + kdata + ucode + udata + tss_low + tss_high

    var entries: [NUM_ENTRIES]u64 = undefined;
    var ptr: Ptr = undefined;

    pub fn init() void {
        Serial.puts("[GDT] entries address: ");
        Serial.putHex(@intFromPtr(&entries));
        Serial.puts("\n");

        // Entry 0: Null
        entries[0] = 0;

        // Entry 1: 64-bit Kernel Code (ring 0) — matches GRUB's CS=0x08
        entries[1] = 0x00209A0000000000;

        // Entry 2: 64-bit Kernel Data (ring 0) — matches GRUB's DS=0x10
        entries[2] = 0x0000920000000000;

        // Entry 3: 64-bit User Data (ring 3)
        entries[3] = 0x0000F20000000000;

        // Entry 4: 64-bit User Code (ring 3)
        entries[4] = 0x0020FA0000000000;

        // Entries 5-6: TSS (filled by setTSS)
        entries[5] = 0;
        entries[6] = 0;

        // Load our GDT — GRUB's selectors (0x08, 0x10) are compatible
        var gdt_ptr: [10]u8 = undefined;
        const limit: u16 = @intCast(@sizeOf(u64) * NUM_ENTRIES - 1);
        const base: u64 = @intFromPtr(&entries);
        gdt_ptr[0] = @truncate(limit);
        gdt_ptr[1] = @truncate(limit >> 8);
        gdt_ptr[2] = @truncate(base);
        gdt_ptr[3] = @truncate(base >> 8);
        gdt_ptr[4] = @truncate(base >> 16);
        gdt_ptr[5] = @truncate(base >> 24);
        gdt_ptr[6] = @truncate(base >> 32);
        gdt_ptr[7] = @truncate(base >> 40);
        gdt_ptr[8] = @truncate(base >> 48);
        gdt_ptr[9] = @truncate(base >> 56);
        asm volatile ("lgdt (%[p])"
            :
            : [p] "r" (@intFromPtr(&gdt_ptr)),
        );

        // DON'T reload segment registers — GRUB already set them correctly
        // and our GDT layout matches GRUB's (0x08=code, 0x10=data).
        // Reloading DS/SS with 0x10 is safe but unnecessary.
    }

    pub fn setTSS(cpu: u32, base: u64, limit: u64) void {
        _ = cpu;
        const entry_idx: usize = 5; // TSS starts at entry 5

        const base_low = base & 0xFFFFFF;
        const base_mid = (base >> 24) & 0xFF;
        const base_high = (base >> 32) & 0xFFFFFFFF;

        // TSS low 8 bytes
        entries[entry_idx] = (limit & 0xFFFF) |
            ((base_low & 0xFFFFFF) << 16) |
            (0x89 << 40) | // Present, TSS type
            ((limit >> 16) << 48) |
            (@as(u64, base_mid) << 56);

        // TSS high 8 bytes
        entries[entry_idx + 1] = base_high;
    }
};

// ============================================================================
// IDT (Interrupt Descriptor Table)
// ============================================================================

pub const InterruptFrame = packed struct {
    r15: u64, r14: u64, r13: u64, r12: u64,
    r11: u64, r10: u64, r9: u64, r8: u64,
    rdi: u64, rsi: u64, rbp: u64,
    rdx: u64, rcx: u64, rbx: u64, rax: u64,
    vector: u64,
    error_code: u64,
    rip: u64, cs: u64, rflags: u64, rsp: u64, ss: u64,
};

const GateType = enum(u4) {
    interrupt = 0xE,
    trap = 0xF,
};

pub const IDT = struct {
    pub const NUM_ENTRIES = 256;

    pub var entries: [NUM_ENTRIES]u128 = undefined;
    var ptr: packed struct { limit: u16, base: u64 } = undefined;

    // ISR stub table — linker-provided bounds of .rodata.isr_table section
    // LLD may resolve isr_stub_table to the wrong address, so we use
    // linker symbols __isr_table_start / __isr_table_end instead.
    pub extern const __isr_table_start: u8;
    pub extern const __isr_table_end: u8;

    pub fn init() void {
        // Read the ISR table from the linker-defined section bounds
        const table_start: u64 = @intFromPtr(&__isr_table_start);
        const table_end: u64 = @intFromPtr(&__isr_table_end);
        const num_entries = (table_end - table_start) / 8;

        for (0..num_entries) |i| {
            const ptr_arr: [*]const u64 = @ptrFromInt(table_start);
            const handler: u64 = ptr_arr[i];
            if (handler > 0x100000 and i < 49) {
                const dpl: u8 = if (i == 3) 3 else 0;
                setGate(@intCast(i), .interrupt, handler, 0x08, dpl);
            }
        }

        // Load IDT using raw 10-byte descriptor (2 bytes limit + 8 bytes base)
        var idt_ptr: [10]u8 = undefined;
        const limit: u16 = @intCast(@sizeOf(u128) * NUM_ENTRIES - 1);
        const base: u64 = @intFromPtr(&entries);
        // Little-endian: limit (2 bytes) then base (8 bytes)
        idt_ptr[0] = @truncate(limit);
        idt_ptr[1] = @truncate(limit >> 8);
        idt_ptr[2] = @truncate(base);
        idt_ptr[3] = @truncate(base >> 8);
        idt_ptr[4] = @truncate(base >> 16);
        idt_ptr[5] = @truncate(base >> 24);
        idt_ptr[6] = @truncate(base >> 32);
        idt_ptr[7] = @truncate(base >> 40);
        idt_ptr[8] = @truncate(base >> 48);
        idt_ptr[9] = @truncate(base >> 56);
        asm volatile ("lidt (%[p])"
            :
            : [p] "r" (@intFromPtr(&idt_ptr)),
        );
    }

    fn setGate(vector: u8, gate_type: GateType, handler: u64, selector: u16, dpl: u8) void {
        const low: u64 =
            (handler & 0x0000FFFF) | // Offset low
            (@as(u64, selector) << 16) | // Selector
            (@as(u64, @intFromEnum(gate_type)) << 40) | // Type
            (@as(u64, dpl) << 45) | // DPL
            (@as(u64, 1) << 47) | // Present
            ((handler >> 16) & 0xFFFF) << 48; // Offset mid

        const high: u64 = handler >> 32; // Offset high

        entries[vector] = (@as(u128, high) << 64) | @as(u128, low);
    }
};

// ============================================================================
// ISR Common Handler — called from isr64.S isr_common
// ============================================================================

pub export fn isr_common_handler(frame: *InterruptFrame) callconv(.C) *InterruptFrame {
    if (frame.vector < 32) {
        handleException(frame);
        return frame;
    } else {
        return handleIRQ(frame);
    }
}

pub var tick_count: u64 = 0;

fn handleIRQ(frame: *InterruptFrame) *InterruptFrame {
    var next_frame = frame;
    switch (frame.vector) {
        48 => {
            // APIC Timer tick — scheduler preemption
            tick_count += 1;
            next_frame = @ptrFromInt(scheduler.schedule(@intFromPtr(frame)));
        },
        33 => handleKeyboard(frame),
        36 => handleSerial(frame),
        else => {}, // Unknown interrupt — ignore for now
    }

    // Send EOI for hardware interrupts (IRQ0-15 = vectors 32-47)
    if (frame.vector >= 32 and frame.vector < 48) {
        PIC.sendEOI(@intCast(frame.vector - 32));
    }

    // APIC timer EOI (vector 48+)
    if (frame.vector >= 48) {
        if (APIC.base_addr != 0) {
            APIC.sendEOI();
        }
    }

    // Also send APIC EOI for PIC vectors if APIC is active
    if (APIC.base_addr != 0 and frame.vector >= 32 and frame.vector < 48) {
        APIC.sendEOI();
    }
    
    return next_frame;
}

fn handleException(frame: *InterruptFrame) void {
    Serial.puts("\n!!! CPU EXCEPTION !!!\n");
    Serial.puts("Vector: ");
    Serial.putHex(frame.vector);
    Serial.puts("\nError Code: ");
    Serial.putHex(frame.error_code);
    Serial.puts("\nRIP: ");
    Serial.putHex(frame.rip);
    Serial.puts("\nCS: ");
    Serial.putHex(frame.cs);
    Serial.puts("\nRFLAGS: ");
    Serial.putHex(frame.rflags);
    Serial.puts("\nRSP: ");
    Serial.putHex(frame.rsp);
    Serial.puts("\nSS: ");
    Serial.putHex(frame.ss);
    Serial.puts("\nHalting CPU...\n");
    while (true) {
        cli();
        hlt();
    }
}

fn handleTimer(frame: *InterruptFrame) void {
    _ = frame;
    tick_count += 1;
}

fn handleKeyboard(frame: *InterruptFrame) void {
    _ = frame;
    const scan = inb(0x60);

    // Extended key prefix
    if (scan == 0xE0) {
        kbd_extended = true;
        return;
    }

    // Key release (bit 7 set)
    if (scan & 0x80 != 0) {
        const released = scan & 0x7F;
        if (released == 0x2A or released == 0x36) kbd_shift = false;
        if (released == 0x1D) kbd_ctrl = false;
        if (released == 0x38) kbd_alt = false;
        kbd_extended = false;
        return;
    }

    // Extended key handling
    if (kbd_extended) {
        kbd_extended = false;
        // Arrow keys
        if (scan == 0x48) kbd_push(0x11); // Up
        if (scan == 0x50) kbd_push(0x12); // Down
        if (scan == 0x4B) kbd_push(0x13); // Left
        if (scan == 0x4D) kbd_push(0x14); // Right
        return;
    }

    // Modifier keys
    if (scan == 0x2A or scan == 0x36) { kbd_shift = true; return; }
    if (scan == 0x1D) { kbd_ctrl = true; return; }
    if (scan == 0x38) { kbd_alt = true; return; }

    // Convert scan code to ASCII
    if (scan < 128) {
        if (kbd_ctrl and scan == 0x2E) { kbd_push(0x03); return; } // Ctrl-C
        if (kbd_ctrl and scan == 0x15) { kbd_push(0x18); return; } // Ctrl-X
        if (kbd_ctrl and scan == 0x31) { kbd_push(0x1A); return; } // Ctrl-Z
        const ch = if (kbd_shift) scan_to_ascii_shift[scan] else scan_to_ascii[scan];
        if (ch != 0) {
            kbd_push(ch);
        }
    }
}

fn handleSerial(frame: *InterruptFrame) void {
    _ = frame;
    // TODO: Serial port interrupt handler
}

// ============================================================================
// PIC (8259 Programmable Interrupt Controller)
// ============================================================================

pub const PIC = struct {
    const PIC1_CMD: u16 = 0x20;
    const PIC1_DATA: u16 = 0x21;
    const PIC2_CMD: u16 = 0xA0;
    const PIC2_DATA: u16 = 0xA1;

    const ICW1_ICW4: u8 = 0x01;
    const ICW1_INIT: u8 = 0x10;
    const ICW4_8086: u8 = 0x01;

    pub fn init() void {
        // Remap PIC: IRQ 0-15 → INT 32-47

        // ICW1: Init + ICW4 needed
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);

        // ICW2: Vector offsets
        outb(PIC1_DATA, 32); // Master: IRQ 0-7 → INT 32-39
        outb(PIC2_DATA, 40); // Slave:  IRQ 8-15 → INT 40-47

        // ICW3: Wiring
        outb(PIC1_DATA, 0x04); // Master: slave on IRQ2
        outb(PIC2_DATA, 0x02); // Slave: identity

        // ICW4: 8086 mode
        outb(PIC1_DATA, ICW4_8086);
        outb(PIC2_DATA, ICW4_8086);

        // Mask all PIC interrupts — we use APIC timer (vector 32)
        // and IO-APIC for keyboard. Only unmask IRQ1 (keyboard) as fallback.
        // IRQ0 (PIT) is masked because APIC timer replaces it.
        outb(PIC1_DATA, 0xFD); // Mask all except IRQ1 (keyboard)
        outb(PIC2_DATA, 0xFF); // Mask all slave
    }

    pub fn sendEOI(irq: u8) void {
        if (irq >= 8) {
            outb(PIC2_CMD, 0x20); // EOI to slave
        }
        outb(PIC1_CMD, 0x20); // EOI to master
    }
};

// ============================================================================
// Programmable Interval Timer (PIT) — Calibration helper
// ============================================================================
pub const PIT = struct {
    const CH2_DATA: u16 = 0x42;
    const CMD: u16 = 0x43;
    const GATE: u16 = 0x61;

    /// Калибровка через PIT channel 2 (метод из OSDev, без побочных IRQ).
    /// Возвращает число APIC-тиков за calibration_ms миллисекунд.
    pub fn calibrateApicTicks(comptime calibration_ms: u32) u32 {
        // PIT работает на 1.193182 MHz
        const pit_freq: u32 = 1193182;
        const pit_count: u32 = pit_freq / (1000 / calibration_ms);

        // Включаем gate PIT ch2, отключаем спикер-выход
        const gate_val = inb(GATE);
        outb(GATE, (gate_val & 0xFC) | 0x01);

        // Mode 0 (one-shot), channel 2, lobyte/hibyte
        outb(CMD, 0b10110000);
        outb(CH2_DATA, @truncate(pit_count));
        outb(CH2_DATA, @truncate(pit_count >> 8));

        // Взводим APIC-таймер на максимум и засекаем сколько он "проедет"
        APIC.writeReg(APIC.REG_TIMER_DIV, APIC.DIV_BY_16);
        APIC.writeReg(APIC.REG_TIMER_INIT, 0xFFFFFFFF);

        // Ждём пока PIT ch2 (OUT, бит 5 порта 0x61) досчитает до 0
        while ((inb(GATE) & 0x20) == 0) {}

        const remaining = APIC.readReg(APIC.REG_TIMER_CURRENT);
        return 0xFFFFFFFF - remaining; // тиков APIC за calibration_ms
    }
};

// ============================================================================
// Local APIC
// Local APIC
// ============================================================================

pub const APIC = struct {
    pub const BASE_MSR = 0x0000001B;
    pub const DEFAULT_PHYS_BASE: u64 = 0xFEE00000;

    pub const REG_ID = 0x020;
    pub const REG_VERSION = 0x030;
    pub const REG_TPR = 0x080;
    pub const REG_EOI = 0x0B0;
    pub const REG_SVR = 0x0F0;
    pub const REG_ICR_LOW = 0x300;
    pub const REG_ICR_HIGH = 0x310;
    pub const REG_LVT_TIMER = 0x320;
    pub const REG_LVT_ERROR = 0x370;
    pub const REG_TIMER_INIT = 0x380;
    pub const REG_TIMER_CURRENT = 0x390;
    pub const REG_TIMER_DIV = 0x3E0;

    pub const SVR_APIC_ENABLE: u32 = 1 << 8;
    pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
    pub const LVT_MASKED: u32 = 1 << 16;
    pub const DIV_BY_16: u32 = 0x03;

    var base_addr: u64 = 0;

    pub fn init() void {
        Serial.puts("[APIC] Reading MSR 0x1B...\n");
        const msr_val = readMsr(BASE_MSR);
        Serial.puts("[APIC] MSR value: ");
        Serial.putHex(msr_val);
        Serial.puts("\n");

        base_addr = msr_val & 0xFFFFFF000;
        Serial.puts("[APIC] Base addr: ");
        Serial.putHex(base_addr);
        Serial.puts("\n");

        // Если APIC глобально выключен — включаем
        if ((msr_val & (1 << 11)) == 0) {
            Serial.puts("[APIC] Enabling APIC...\n");
            writeMsr(BASE_MSR, msr_val | (1 << 11));
        } else {
            Serial.puts("[APIC] APIC already enabled\n");
        }

        // Set Spurious Interrupt Vector Register
        Serial.puts("[APIC] Setting SVR...\n");
        writeReg(REG_SVR, SVR_APIC_ENABLE | 0xFF);

        // Set up timer
        Serial.puts("[APIC] Setting timer...\n");
        writeReg(REG_LVT_TIMER, 48 | LVT_TIMER_PERIODIC); // Vector 48 — avoids PIC IRQ0-15 conflict
        writeReg(REG_TIMER_DIV, DIV_BY_16);

        // Калибровка: считаем сколько APIC-тиков в 10мс, целимся в 100 Гц context-switch
        const ticks_per_10ms = PIT.calibrateApicTicks(10);
        writeReg(REG_TIMER_INIT, ticks_per_10ms);

        // Mask error LVT
        writeReg(REG_LVT_ERROR, LVT_MASKED);
        Serial.puts("[APIC] Timer configured via PIT calibration\n");
    }

    pub fn writeReg(offset: u32, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(base_addr + offset);
        ptr.* = val;
    }

    pub fn readReg(offset: u32) u32 {
        const ptr: *volatile u32 = @ptrFromInt(base_addr + offset);
        return ptr.*;
    }

    pub fn sendEOI() void {
        writeReg(REG_EOI, 0);
    }

    pub fn getId() u32 {
        return readReg(REG_ID) >> 24;
    }
};

// ============================================================================
// IO-APIC (I/O Advanced Programmable Interrupt Controller)
// ============================================================================
pub const IOAPIC = struct {
    const BASE_ADDR: u64 = 0xFEC00000;
    const REG_SEL: *volatile u32 = @ptrFromInt(BASE_ADDR);
    const REG_WIN: *volatile u32 = @ptrFromInt(BASE_ADDR + 0x10);

    pub fn write(reg: u32, val: u32) void {
        REG_SEL.* = reg;
        REG_WIN.* = val;
    }

    pub fn read(reg: u32) u32 {
        REG_SEL.* = reg;
        return REG_WIN.*;
    }

    pub fn init() void {
        // Redirection table entry for Keyboard (IRQ 1) -> Vector 33
        // 0x12: redirection register for IRQ1 low 32 bits (vector 33, active high, edge triggered)
        // 0x13: redirection register for IRQ1 high 32 bits (destination APIC ID 0)
        write(0x12, 33);
        write(0x13, 0);
        Serial.puts("[IOAPIC] Keyboard redirection configured (IRQ1 -> Vector 33)\n");
    }
};

// ============================================================================
// PS/2 Keyboard Driver & Buffer
// ============================================================================
var kbd_shift: bool = false;
var kbd_ctrl: bool = false;
var kbd_alt: bool = false;
var kbd_extended: bool = false;

const scan_to_ascii = [128]u8{
    0, 0x1B, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\x08', 0,
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 0,
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 0,
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const scan_to_ascii_shift = [128]u8{
    0, 0x1B, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\x08', 0,
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0, 0,
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|', 0,
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

var kbd_buffer: [256]u8 = undefined;
var kbd_head: usize = 0;
var kbd_tail: usize = 0;

pub fn kbd_push(ch: u8) void {
    const next = (kbd_head + 1) % kbd_buffer.len;
    if (next != kbd_tail) {
        kbd_buffer[kbd_head] = ch;
        kbd_head = next;
    }
}

pub fn kbd_pop() u8 {
    if (kbd_head == kbd_tail) return 0;
    const ch = kbd_buffer[kbd_tail];
    kbd_tail = (kbd_tail + 1) % kbd_buffer.len;
    return ch;
}

fn kbd_init() void {
    // Flush pending data
    while ((inb(0x64) & 0x01) != 0) {
        _ = inb(0x60);
    }
    // Enable keyboard device
    outb(0x64, 0xAE);
    // Get command byte
    outb(0x64, 0x20);
    var config = inb(0x60);
    config |= 0x01; // Enable IRQ1
    config &= ~@as(u8, 0x10); // Enable keyboard port
    outb(0x64, 0x60);
    outb(0x60, config);
    // Reset keyboard
    outb(0x60, 0xFF);
    // Wait for ACK
    var timeout: u32 = 0;
    while (timeout < 10000) : (timeout += 1) {
        if ((inb(0x64) & 0x01) != 0) {
            const resp = inb(0x60);
            if (resp == 0xFA or resp == 0xAA) break;
        }
    }
    // Set scan code set 1
    outb(0x60, 0xF0);
    while ((inb(0x64) & 0x02) != 0) {}
    outb(0x60, 0x01);

    kbd_head = 0;
    kbd_tail = 0;
    Serial.puts("[KBD] Keyboard initialized\n");
}

// Global print and clear screen functions (registered by main kernel)
pub var print_fn: ?*const fn ([]const u8) void = null;
pub var clear_screen_fn: ?*const fn () void = null;

// ============================================================================
// Page Table Flags
// Page table flags
// ============================================================================

pub const PAGE = struct {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NX: u64 = 1 << 63;

    pub const KERNEL_RW: u64 = PRESENT | WRITABLE;
    pub const KERNEL_RX: u64 = PRESENT;
    pub const USER_RW: u64 = PRESENT | WRITABLE | USER;
    pub const USER_RX: u64 = PRESENT | USER;
};

// ============================================================================
// TSS (Task State Segment)
// Task State Segment
// ============================================================================

pub const TSS = packed struct {
    _reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    _reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,
};

var tss: TSS = .{
    ._reserved0 = 0,
    .rsp0 = 0,
    .rsp1 = 0,
    .rsp2 = 0,
    ._reserved1 = 0,
    .ist1 = 0,
    .ist2 = 0,
    .ist3 = 0,
    .ist4 = 0,
    .ist5 = 0,
    .ist6 = 0,
    .ist7 = 0,
    ._reserved2 = 0,
    ._reserved3 = 0,
    .iomap_base = 104,
};

pub fn setKernelStack(stack: u64) void {
    tss.rsp0 = stack;
}

// ============================================================================
// Serial Port (для early debug)
// ============================================================================

pub const Serial = struct {
    const COM1: u16 = 0x3F8;

    pub fn init() void {
        outb(COM1 + 1, 0x00); // Disable interrupts
        outb(COM1 + 3, 0x80); // Enable DLAB
        outb(COM1 + 0, 0x01); // Baud divisor low = 1 → 115200
        outb(COM1 + 1, 0x00); // Baud divisor high = 0
        outb(COM1 + 3, 0x03); // 8N1
        outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // Enable RTS/DSR/DTR
    }

    pub fn puts(str: []const u8) void {
        for (str) |ch| {
            if (ch == '\n') {
                while ((inb(COM1 + 5) & 0x20) == 0) {}
                outb(COM1, '\r');
            }
            while ((inb(COM1 + 5) & 0x20) == 0) {}
            outb(COM1, ch);
        }
    }

    pub fn putHex(val: u64) void {
        const hex = "0123456789ABCDEF";
        puts("0x");
        var i: usize = 60;
        while (true) {
            puts(&.{hex[@intCast((val >> @intCast(i)) & 0xF)]});
            if (i == 0) break;
            i -= 4;
        }
    }
};

pub fn initSyscalls(handler_addr: u64) void {
    // 1. Enable System Call Extensions (SCE) in EFER MSR
    const efer = readMsr(MSR.EFER);
    writeMsr(MSR.EFER, efer | EFER.SCE);

    // 2. Set segment selectors in STAR MSR (0xC0000081)
    const star: u64 = (@as(u64, 0x10) << 48) | (@as(u64, 0x08) << 32);
    writeMsr(MSR.STAR, star);

    // 3. Set entry point in LSTAR MSR (0xC0000082)
    writeMsr(MSR.LSTAR, handler_addr);

    // 4. Set RFLAGS mask in SFMASK MSR (0xC0000084)
    const sfmask: u64 = (1 << 9) | (1 << 10);
    writeMsr(MSR.SFMASK, sfmask);

    Serial.puts("[HAL] Syscall mechanism initialized\n");
}

pub export fn zig_syscall_handler(arg1: u64, arg2: u64, arg3: u64, arg4: u64, syscall_num: u64) callconv(.C) u64 {
    _ = arg3;
    _ = arg4;
    switch (syscall_num) {
        1 => {
            // Syscall 1: Print string
            const ptr: [*]const u8 = @ptrFromInt(arg1);
            const len: usize = @intCast(arg2);
            const slice = ptr[0..len];
            if (print_fn) |f| {
                f(slice);
            } else {
                Serial.puts(slice);
            }
            return 0;
        },
        2 => {
            // Syscall 2: Read key (non-blocking)
            return kbd_pop();
        },
        3 => {
            // Syscall 3: Clear screen
            if (clear_screen_fn) |f| {
                f();
            }
            return 0;
        },
        else => {
            return @as(u64, @bitCast(@as(i64, -1)));
        }
    }
}

// ============================================================================
// HAL Initialization
// ============================================================================

pub fn init() void {
    // 1. Initialize serial port (early debug)
    Serial.init();
    Serial.puts("[HAL] Serial port initialized\n");

    // 2. GDT — Initialize and load our own 64-bit GDT
    GDT.init();
    Serial.puts("[HAL] GDT loaded\n");

    // 3. Initialize IDT (using ISR stubs from isr64.S)
    IDT.init();
    Serial.puts("[HAL] IDT loaded\n");

    // 4. Initialize PIC (remap IRQs)
    PIC.init();
    Serial.puts("[HAL] PIC remapped\n");

    // 5. TSS — Initialize Task State Segment
    GDT.setTSS(0, @intFromPtr(&tss), @sizeOf(TSS) - 1);
    ltr(0x28);
    Serial.puts("[HAL] TSS loaded\n");

    // 6. Initialize Local APIC
    APIC.init();
    Serial.puts("[HAL] Local APIC initialized\n");

    // 6.5. Initialize IO-APIC & Keyboard
    IOAPIC.init();
    kbd_init();

    // 7. Enable interrupts!
    sti();
    Serial.puts("[HAL] Interrupts enabled\n");
}
