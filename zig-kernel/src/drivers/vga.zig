// POLER-OS — VGA Text Mode Driver (80x25)
// Direct memory-mapped VGA buffer at 0xB8000

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

var row: usize = 0;
var col: usize = 0;
var fg: Color = .light_grey;
var bg: Color = .black;

pub fn init() void {
    row = 0;
    col = 0;
    fg = .light_grey;
    bg = .black;
    clear();
}

pub fn clear() void {
    const attr = makeColor(.light_grey, .black);
    var i: usize = 0;
    while (i < VGA_WIDTH * VGA_HEIGHT) : (i += 1) {
        VGA_BUFFER[i] = .{ .char = ' ', .color = attr };
    }
}

pub fn setColor(foreground: Color, background: Color) void {
    fg = foreground;
    bg = background;
}

pub fn writeChar(ch: u8) void {
    if (ch == '\n') {
        col = 0;
        row += 1;
    } else {
        const attr = makeColor(fg, bg);
        VGA_BUFFER[row * VGA_WIDTH + col] = .{ .char = ch, .color = attr };
        col += 1;
        if (col >= VGA_WIDTH) {
            col = 0;
            row += 1;
        }
    }
    if (row >= VGA_HEIGHT) {
        scroll();
        row = VGA_HEIGHT - 1;
    }
}

pub fn writeString(str: []const u8) void {
    for (str) |ch| writeChar(ch);
}

fn makeColor(f: Color, b: Color) u8 {
    return @as(u8, @intFromEnum(f)) | (@as(u8, @intFromEnum(b)) << 4);
}

fn scroll() void {
    // Move all rows up by one
    var y: usize = 0;
    while (y < VGA_HEIGHT - 1) : (y += 1) {
        var x: usize = 0;
        while (x < VGA_WIDTH) : (x += 1) {
            VGA_BUFFER[y * VGA_WIDTH + x] = VGA_BUFFER[(y + 1) * VGA_WIDTH + x];
        }
    }
    // Clear last row
    const attr = makeColor(.light_grey, .black);
    var x: usize = 0;
    while (x < VGA_WIDTH) : (x += 1) {
        VGA_BUFFER[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = .{ .char = ' ', .color = attr };
    }
}
