// =============================================================================
// POLER-OS v0.2.0 — Kernel Main
// =============================================================================
// Zig 0.13 x86_64 freestanding — POLER Cognitive Architecture
// Called from boot.S after transition to 64-bit long mode

// =============================================================================
// VGA Text Mode Driver (80x25)
// =============================================================================

pub const Color = enum(u8) {
    black = 0,
    blue = 1,
    green = 2,
    cyan = 3,
    red = 4,
    magenta = 5,
    brown = 6,
    light_grey = 7,
    dark_grey = 8,
    light_blue = 9,
    light_green = 10,
    light_cyan = 11,
    light_red = 12,
    light_magenta = 13,
    yellow = 14,
    white = 15,
};

const VgaEntry = packed struct(u16) {
    char: u8,
    color: u8,
};

const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_BUFFER: [*]volatile VgaEntry = @ptrFromInt(0xB8000);

var vga_row: usize = 0;
var vga_col: usize = 0;
var vga_fg: Color = .light_grey;
var vga_bg: Color = .black;

fn vga_init() void {
    vga_row = 0;
    vga_col = 0;
    vga_fg = .light_grey;
    vga_bg = .black;
    vga_clear();
}

fn vga_clear() void {
    const attr = vga_makeColor(.light_grey, .black);
    var i: usize = 0;
    while (i < VGA_WIDTH * VGA_HEIGHT) : (i += 1) {
        VGA_BUFFER[i] = .{ .char = ' ', .color = attr };
    }
}

fn vga_setColor(f: Color, b: Color) void {
    vga_fg = f;
    vga_bg = b;
}

fn vga_writeChar(ch: u8) void {
    if (ch == '\n') {
        vga_col = 0;
        vga_row += 1;
    } else {
        const attr = vga_makeColor(vga_fg, vga_bg);
        VGA_BUFFER[vga_row * VGA_WIDTH + vga_col] = .{ .char = ch, .color = attr };
        vga_col += 1;
        if (vga_col >= VGA_WIDTH) {
            vga_col = 0;
            vga_row += 1;
        }
    }
    if (vga_row >= VGA_HEIGHT) {
        vga_scroll();
        vga_row = VGA_HEIGHT - 1;
    }
}

fn vga_writeString(str: []const u8) void {
    for (str) |ch| vga_writeChar(ch);
}

fn vga_makeColor(f: Color, b: Color) u8 {
    return @as(u8, @intFromEnum(f)) | (@as(u8, @intFromEnum(b)) << 4);
}

fn vga_scroll() void {
    var y: usize = 0;
    while (y < VGA_HEIGHT - 1) : (y += 1) {
        var x: usize = 0;
        while (x < VGA_WIDTH) : (x += 1) {
            VGA_BUFFER[y * VGA_WIDTH + x] = VGA_BUFFER[(y + 1) * VGA_WIDTH + x];
        }
    }
    const attr = vga_makeColor(.light_grey, .black);
    var x: usize = 0;
    while (x < VGA_WIDTH) : (x += 1) {
        VGA_BUFFER[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = .{ .char = ' ', .color = attr };
    }
}

// =============================================================================
// Serial Port Driver (COM1) — for QEMU -serial stdio
// =============================================================================

const PORT_COM1: u16 = 0x3F8;

fn serial_init() void {
    outb(PORT_COM1 + 1, 0x00);
    outb(PORT_COM1 + 3, 0x80);
    outb(PORT_COM1 + 0, 0x01);
    outb(PORT_COM1 + 1, 0x00);
    outb(PORT_COM1 + 3, 0x03);
    outb(PORT_COM1 + 2, 0xC7);
    outb(PORT_COM1 + 4, 0x0B);
}

fn serial_writeChar(ch: u8) void {
    while ((inb(PORT_COM1 + 5) & 0x20) == 0) {}
    outb(PORT_COM1, ch);
}

fn serial_writeString(str: []const u8) void {
    for (str) |ch| serial_writeChar(ch);
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

// =============================================================================
// POLER Tensor Engine (kernel-space, zero-alloc)
// =============================================================================

pub const Matrix4x4 = [4][4]f64;

pub fn zero() Matrix4x4 {
    return .{.{ 0, 0, 0, 0 }} ** 4;
}

pub fn identity() Matrix4x4 {
    var m = zero();
    m[0][0] = 1.0;
    m[1][1] = 1.0;
    m[2][2] = 1.0;
    m[3][3] = 1.0;
    return m;
}

pub fn tensorProduct(a: Matrix4x4, b: Matrix4x4) Matrix4x4 {
    var result = zero();
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var j: usize = 0;
        while (j < 4) : (j += 1) {
            var k: usize = 0;
            var sum: f64 = 0;
            while (k < 4) : (k += 1) {
                sum += a[i][k] * b[k][j];
            }
            result[i][j] = sum;
        }
    }
    return result;
}

pub fn hadamard(a: Matrix4x4, b: Matrix4x4) Matrix4x4 {
    var result = zero();
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var j: usize = 0;
        while (j < 4) : (j += 1) {
            result[i][j] = a[i][j] * b[i][j];
        }
    }
    return result;
}

pub fn trace(m: Matrix4x4) f64 {
    var s: f64 = 0;
    var i: usize = 0;
    while (i < 4) : (i += 1) s += m[i][i];
    return s;
}

pub fn frobeniusNorm(m: Matrix4x4) f64 {
    var s: f64 = 0;
    for (m) |row| {
        for (row) |v| {
            s += v * v;
        }
    }
    return sqrt(s);
}

fn sqrt(x: f64) f64 {
    if (x <= 0) return 0;
    var z: f64 = x;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        z = 0.5 * (z + x / z);
    }
    return z;
}

fn absF64(x: f64) f64 {
    if (x < 0) return -x;
    return x;
}

// ─── POLER Cycle ───────────────────────────────────────────────────────────

const PolerMetrics = struct {
    entropy: f64,
    knowledge_density: f64,
    semantic_drift: f64,
    responsibility_purity: f64,
    cognitive_load: f64,
    compression_score: f64,
    evo_resonance: f64,
    health_score: f64,
};

const PolerCycle = struct {
    density: Matrix4x4,
    archetype: Matrix4x4,
    dissipation: f64,
    metrics: PolerMetrics,
    has_converged: bool,
    iteration: u32,

    pub fn init(density: Matrix4x4, archetype: Matrix4x4, dissipation: f64) PolerCycle {
        return .{
            .density = density,
            .archetype = archetype,
            .dissipation = dissipation,
            .metrics = .{
                .entropy = 0,
                .knowledge_density = 0,
                .semantic_drift = 0,
                .responsibility_purity = 0,
                .cognitive_load = 0,
                .compression_score = 0,
                .evo_resonance = 0,
                .health_score = 0,
            },
            .has_converged = false,
            .iteration = 0,
        };
    }

    pub fn iterate(self: *PolerCycle) bool {
        const perceived = tensorProduct(self.density, self.archetype);
        const resonance = hadamard(perceived, self.archetype);

        var dissipated = zero();
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            var j: usize = 0;
            while (j < 4) : (j += 1) {
                dissipated[i][j] = resonance[i][j] * (1.0 - self.dissipation);
            }
        }

        const old_trace = trace(self.density);
        const new_trace = trace(dissipated);
        const norm = frobeniusNorm(dissipated);

        self.metrics.entropy = 1.0 - (new_trace / 4.0);
        self.metrics.knowledge_density = new_trace / 4.0;
        self.metrics.semantic_drift = absF64(new_trace - old_trace);
        self.metrics.responsibility_purity = dissipated[0][0] / (norm + 0.001);
        self.metrics.cognitive_load = 1.0 - self.metrics.responsibility_purity;
        self.metrics.compression_score = 4.0 / (norm + 0.001);
        self.metrics.evo_resonance = new_trace / (old_trace + 0.001);
        self.metrics.health_score = (self.metrics.knowledge_density + self.metrics.responsibility_purity + self.metrics.evo_resonance) / 3.0;

        if (self.metrics.semantic_drift < 0.001 and self.iteration > 0) {
            self.has_converged = true;
        }

        self.density = dissipated;
        self.iteration += 1;
        return self.has_converged;
    }
};

// =============================================================================
// Kernel Main — called from boot.S after long mode transition
// =============================================================================

export fn kernel_main() noreturn {
    vga_init();
    serial_init();

    // Banner
    vga_setColor(.light_cyan, .black);
    vga_writeString("POLER-OS v0.2.0\n");
    vga_writeString("Zig Kernel + POLER Cognitive Engine\n");
    vga_writeString("x86_64 freestanding\n\n");
    serial_writeString("POLER-OS v0.2.0 boot\n");

    // Boot sequence
    vga_setColor(.light_grey, .black);
    vga_writeString("[BOOT] VGA initialized\n");
    vga_writeString("[BOOT] COM1 serial initialized\n");
    vga_writeString("[BOOT] Long mode active\n");
    vga_writeString("[BOOT] Identity map: 0-4MB\n\n");

    // ─── POLER Cognitive Cycle ──────────────────────────────────────────
    vga_setColor(.yellow, .black);
    vga_writeString("=== POLER Cognitive Cycle ===\n\n");
    vga_setColor(.white, .black);

    var initial_state: Matrix4x4 = zero();
    initial_state[0][0] = 0.8;
    initial_state[1][1] = 0.6;
    initial_state[2][2] = 0.4;
    initial_state[3][3] = 0.2;
    initial_state[0][1] = 0.1;
    initial_state[1][0] = 0.05;

    var archetype: Matrix4x4 = identity();
    archetype[0][0] = 0.9;
    archetype[1][1] = 0.8;
    archetype[2][2] = 0.7;
    archetype[3][3] = 0.5;

    var cycle = PolerCycle.init(initial_state, archetype, 0.1);

    var iter: u32 = 0;
    while (iter < 10 and !cycle.has_converged) : (iter += 1) {
        _ = cycle.iterate();
    }

    // Display 8 Architecture Metrics
    vga_setColor(.yellow, .black);
    vga_writeString("=== 8 Architecture Metrics ===\n");
    vga_setColor(.white, .black);

    vga_writeString("  Entropy:       "); printFloat(cycle.metrics.entropy); vga_writeString("\n");
    vga_writeString("  Know.Density:  "); printFloat(cycle.metrics.knowledge_density); vga_writeString("\n");
    vga_writeString("  Sem.Drift:     "); printFloat(cycle.metrics.semantic_drift); vga_writeString("\n");
    vga_writeString("  Purity:        "); printFloat(cycle.metrics.responsibility_purity); vga_writeString("\n");
    vga_writeString("  Cogn.Load:     "); printFloat(cycle.metrics.cognitive_load); vga_writeString("\n");
    vga_writeString("  Compression:   "); printFloat(cycle.metrics.compression_score); vga_writeString("x\n");
    vga_writeString("  Evo.Resonance: "); printFloat(cycle.metrics.evo_resonance); vga_writeString("\n");
    vga_writeString("  Health:        "); printFloat(cycle.metrics.health_score); vga_writeString("\n\n");

    vga_setColor(.light_green, .black);
    if (cycle.has_converged) {
        vga_writeString("  Status: CONVERGED\n");
        serial_writeString("POLER cycle CONVERGED\n");
    } else {
        vga_setColor(.light_red, .black);
        vga_writeString("  Status: MAX ITERATIONS\n");
        serial_writeString("POLER cycle MAX ITERATIONS\n");
    }

    vga_setColor(.light_cyan, .black);
    vga_writeString("\n=== Hardware ===\n");
    vga_setColor(.white, .black);
    vga_writeString("  Target: x86_64 (Intel i7-3770K)\n");
    vga_writeString("  Memory: 128MB QEMU\n\n");

    vga_setColor(.light_green, .black);
    vga_writeString("POLER-OS idle. System ready.\n");
    vga_setColor(.light_grey, .black);
    serial_writeString("POLER-OS kernel idle. System ready.\n");

    while (true) {
        asm volatile ("hlt");
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn printFloat(val: f64) void {
    var value = val;
    if (value < 0) {
        vga_writeChar('-');
        value = -value;
    }
    const int_part: u32 = @intFromFloat(value);
    const dec_part: u32 = @intFromFloat((value - @as(f64, @floatFromInt(int_part))) * 100.0);
    printUint(int_part);
    vga_writeChar('.');
    if (dec_part < 10) vga_writeChar('0');
    printUint(dec_part);
}

fn printUint(value: u32) void {
    if (value == 0) {
        vga_writeChar('0');
        return;
    }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = value;
    while (v > 0) : (i += 1) {
        buf[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }
    var j: usize = 0;
    while (j < i / 2) : (j += 1) {
        const tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
    var k: usize = 0;
    while (k < i) : (k += 1) {
        vga_writeChar(buf[k]);
    }
}

// Panic handler — required for freestanding
pub fn panic(msg: []const u8, error_return_trace: ?*@import("std").builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    vga_setColor(.red, .black);
    vga_writeString("\n!!! KERNEL PANIC !!!\n");
    vga_writeString("Message: ");
    vga_writeString(msg);
    vga_writeString("\nSystem halted.\n");
    serial_writeString("KERNEL PANIC: ");
    serial_writeString(msg);
    serial_writeString("\n");
    while (true) {
        asm volatile ("hlt");
    }
}
