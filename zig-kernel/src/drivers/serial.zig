// POLER-OS — Serial Port Driver (COM1)
// For QEMU -serial stdio output

const PORT_COM1: u16 = 0x3F8;

pub fn init() void {
    // Disable interrupts
    outb(PORT_COM1 + 1, 0x00);
    // Enable DLAB
    outb(PORT_COM1 + 3, 0x80);
    // Baud rate divisor = 1 (115200 baud)
    outb(PORT_COM1 + 0, 0x01);
    outb(PORT_COM1 + 1, 0x00);
    // 8 bits, no parity, one stop bit
    outb(PORT_COM1 + 3, 0x03);
    // Enable FIFO
    outb(PORT_COM1 + 2, 0xC7);
    // IRQs enabled, RTS/DSR set
    outb(PORT_COM1 + 4, 0x0B);
}

pub fn writeChar(ch: u8) void {
    // Wait for transmit buffer to be empty
    while ((inb(PORT_COM1 + 5) & 0x20) == 0) {}
    outb(PORT_COM1, ch);
}

pub fn writeString(str: []const u8) void {
    for (str) |ch| writeChar(ch);
}

fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "N{dx}" (port),
    );
}

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "=al" (-> u8),
        : [port] "N{dx}" (port),
    );
}
