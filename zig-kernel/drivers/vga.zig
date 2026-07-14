// POLER-OS VGA Text Mode Driver
// Writes directly to 0xB8000 (VGA text buffer)
// 80x25 text mode, 2 bytes per character (char + attribute)

const std = @import("std");

pub const Color = enum(u4) {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGrey = 7,
    DarkGrey = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    LightMagenta = 13,
    Yellow = 14,
    White = 15,
};

const VgaChar = packed struct {
    char: u8,
    attr: u8,
};

const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_BUFFER = 0xB8000;

var row: usize = 0;
var col: usize = 0;
var fg: Color = .White;
var bg: Color = .Black;

pub fn init() void {
    row = 0;
    col = 0;
}

pub fn setColor(foreground: Color, background: Color) void {
    fg = foreground;
    bg = background;
}

pub fn clear() void {
    const buf = @as([*]VgaChar, @ptrFromInt(VGA_BUFFER));
    const attr = @intFromEnum(bg) << 4 | @intFromEnum(fg);
    var i: usize = 0;
    while (i < VGA_WIDTH * VGA_HEIGHT) : (i += 1) {
        buf[i] = .{ .char = ' ', .attr = attr };
    }
    row = 0;
    col = 0;
}

pub fn putChar(ch: u8) void {
    const buf = @as([*]VgaChar, @ptrFromInt(VGA_BUFFER));
    const attr = @intFromEnum(bg) << 4 | @intFromEnum(fg);
    
    if (ch == '\n') {
        col = 0;
        row += 1;
        if (row >= VGA_HEIGHT) {
            scroll();
            row = VGA_HEIGHT - 1;
        }
        return;
    }
    
    buf[row * VGA_WIDTH + col] = .{ .char = ch, .attr = attr };
    col += 1;
    if (col >= VGA_WIDTH) {
        col = 0;
        row += 1;
        if (row >= VGA_HEIGHT) {
            scroll();
            row = VGA_HEIGHT - 1;
        }
    }
}

pub fn print(str: []const u8) void {
    for (str) |ch| {
        putChar(ch);
    }
}

fn scroll() void {
    const buf = @as([*]VgaChar, @ptrFromInt(VGA_BUFFER));
    // Move all rows up by 1
    var r: usize = 0;
    while (r < VGA_HEIGHT - 1) : (r += 1) {
        var c: usize = 0;
        while (c < VGA_WIDTH) : (c += 1) {
            buf[r * VGA_WIDTH + c] = buf[(r + 1) * VGA_WIDTH + c];
        }
    }
    // Clear last row
    const attr = @intFromEnum(bg) << 4 | @intFromEnum(fg);
    var c: usize = 0;
    while (c < VGA_WIDTH) : (c += 1) {
        buf[(VGA_HEIGHT - 1) * VGA_WIDTH + c] = .{ .char = ' ', .attr = attr };
    }
}
