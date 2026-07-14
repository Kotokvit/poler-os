export fn kernel_main() noreturn {
    // Write 'A' to COM1 port 0x3F8
    const PORT: usize = 0x3F8;
    // Init serial
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x00)), [port] "N{dx}" (@as(u16, @intCast(PORT + 1))));
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x80)), [port] "N{dx}" (@as(u16, @intCast(PORT + 3))));
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x01)), [port] "N{dx}" (@as(u16, @intCast(PORT + 0))));
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x00)), [port] "N{dx}" (@as(u16, @intCast(PORT + 1))));
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x03)), [port] "N{dx}" (@as(u16, @intCast(PORT + 3))));
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0xC7)), [port] "N{dx}" (@as(u16, @intCast(PORT + 2))));
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x0B)), [port] "N{dx}" (@as(u16, @intCast(PORT + 4))));
    
    // Wait for transmit buffer empty
    while (true) {
        var val: u8 = 0;
        asm volatile ("inb %[port], %[result]" : [result] "=al" (val) : [port] "N{dx}" (@as(u16, @intCast(PORT + 5))));
        if (val & 0x20 != 0) break;
    }
    // Write 'P' for POLER
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x50)), [port] "N{dx}" (@as(u16, @intCast(PORT))));
    // Write 'O'
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x4F)), [port] "N{dx}" (@as(u16, @intCast(PORT))));
    // Write 'K'
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x4B)), [port] "N{dx}" (@as(u16, @intCast(PORT))));
    // Write '\n'
    asm volatile ("outb %[val], %[port]" : : [val] "{al}" (@as(u8, 0x0A)), [port] "N{dx}" (@as(u16, @intCast(PORT))));

    // Halt
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn panic(msg: []const u8, error_return_trace: ?*@import("std").builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = msg; _ = error_return_trace; _ = ret_addr;
    while (true) { asm volatile ("hlt"); }
}
