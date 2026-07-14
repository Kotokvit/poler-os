// POLER-OS x86_64 Interrupt Descriptor Table
// Sets up IDT for exception handlers and hardware interrupts

const std = @import("std");

pub const InterruptFrame = packed struct {
    r15: u64, r14: u64, r13: u64, r12: u64,
    r11: u64, r10: u64, r9: u64, r8: u64,
    rdi: u64, rsi: u64, rbp: u64, rdx: u64,
    rcx: u64, rbx: u64, rax: u64,
    int_no: u64,
    err_code: u64,
    rip: u64, cs: u64, rflags: u64,
    rsp: u64, ss: u64,
};

const GateType = enum(u4) {
    Interrupt = 0xE,
    Trap = 0xF,
};

const IdtEntry = packed struct {
    offset_low: u16,       // bits 0-15
    selector: u16,         // code segment selector
    ist: u3,               // interrupt stack table offset
    reserved: u5 = 0,
    gate_type: GateType,
    zero: u3 = 0,
    dpl: u2,               // descriptor privilege level
    present: u1,
    offset_mid: u16,       // bits 16-31
    offset_high: u32,      // bits 32-63
    reserved2: u32 = 0,
};

const IdtPtr = packed struct {
    limit: u16,
    base: u64,
};

var idt: [256]IdtEntry = undefined;
var idt_ptr: IdtPtr = undefined;

fn makeEntry(handler: u64, selector: u16, gate: GateType, dpl: u2) IdtEntry {
    return .{
        .offset_low = @truncate(handler),
        .selector = selector,
        .ist = 0,
        .gate_type = gate,
        .dpl = dpl,
        .present = 1,
        .offset_mid = @truncate(handler >> 16),
        .offset_high = @truncate(handler >> 32),
    };
}

pub fn init() void {
    // Zero out IDT
    for (&idt) |*entry| {
        entry.* = std.mem.zeroes(IdtEntry);
    }
    
    // CPU exception handlers (0-31)
    idt[0] = makeEntry(@intFromPtr(&exception0), 0x08, .Interrupt, 0);  // #DE Divide Error
    idt[1] = makeEntry(@intFromPtr(&exception1), 0x08, .Interrupt, 0);  // #DB Debug
    idt[2] = makeEntry(@intFromPtr(&exception2), 0x08, .Interrupt, 0);  // NMI
    idt[3] = makeEntry(@intFromPtr(&exception3), 0x08, .Trap, 0);      // #BP Breakpoint
    idt[6] = makeEntry(@intFromPtr(&exception6), 0x08, .Interrupt, 0);  // #UD Invalid Opcode
    idt[8] = makeEntry(@intFromPtr(&exception8), 0x08, .Interrupt, 0);  // #DF Double Fault
    idt[13] = makeEntry(@intFromPtr(&exception13), 0x08, .Interrupt, 0); // #GP General Protection
    idt[14] = makeEntry(@intFromPtr(&exception14), 0x08, .Interrupt, 0); // #PF Page Fault
    
    // Hardware IRQs (32-47) — remapped PIC
    idt[32] = makeEntry(@intFromPtr(&irq0), 0x08, .Interrupt, 0);   // Timer
    idt[33] = makeEntry(@intFromPtr(&irq1), 0x08, .Interrupt, 0);   // Keyboard
    
    // Load IDT
    idt_ptr.limit = @sizeOf(@TypeOf(idt)) - 1;
    idt_ptr.base = @intFromPtr(&idt);
    asm volatile ("lidt (%[ptr])"
        :
        : [ptr] "r" (&idt_ptr)
    );
    
    asm volatile ("sti");
}

// Exception handlers (stubs)
fn exception0() callconv(.Naked) noreturn {
    asm volatile ("push $0; push $0");
    handlerCommon();
}
fn exception1() callconv(.Naked) noreturn {
    asm volatile ("push $0; push $1");
    handlerCommon();
}
fn exception2() callconv(.Naked) noreturn {
    asm volatile ("push $0; push $2");
    handlerCommon();
}
fn exception3() callconv(.Naked) noreturn {
    asm volatile ("push $0; push $3");
    handlerCommon();
}
fn exception6() callconv(.Naked) noreturn {
    asm volatile ("push $0; push $6");
    handlerCommon();
}
fn exception8() callconv(.Naked) noreturn {
    // Double fault has error code already pushed
    asm volatile ("push $8");
    handlerCommon();
}
fn exception13() callconv(.Naked) noreturn {
    // GP fault has error code already pushed
    asm volatile ("push $13");
    handlerCommon();
}
fn exception14() callconv(.Naked) noreturn {
    // Page fault has error code already pushed
    asm volatile ("push $14");
    handlerCommon();
}

// IRQ handlers
fn irq0() callconv(.Naked) noreturn {
    asm volatile ("push $0; push $32");
    handlerCommon();
}
fn irq1() callconv(.Naked) noreturn {
    asm volatile ("push $0; push $33");
    handlerCommon();
}

fn handlerCommon() callconv(.Naked) noreturn {
    asm volatile (
        \\ cli
        \\ push %rax
        \\ push %rbx
        \\ push %rcx
        \\ push %rdx
        \\ push %rsi
        \\ push %rdi
        \\ push %rbp
        \\ push %r8
        \\ push %r9
        \\ push %r10
        \\ push %r11
        \\ push %r12
        \\ push %r13
        \\ push %r14
        \\ push %r15
        \\
        \\ mov %rsp, %rdi        // Pass frame to handler
        \\ call idt_handler
        \\
        \\ pop %r15
        \\ pop %r14
        \\ pop %r13
        \\ pop %r12
        \\ pop %r11
        \\ pop %r10
        \\ pop %r9
        \\ pop %r8
        \\ pop %rbp
        \\ pop %rdi
        \\ pop %rsi
        \\ pop %rdx
        \\ pop %rcx
        \\ pop %rbx
        \\ pop %rax
        \\ add $16, %rsp        // Remove int_no and err_code
        \\ sti
        \\ iretq
    );
    unreachable;
}

export fn idt_handler(frame: *InterruptFrame) void {
    _ = frame;
    // TODO: Route to Rust safety core for policy decisions
    // POLER-OS: all interrupts go through Rust safety barrier
}
