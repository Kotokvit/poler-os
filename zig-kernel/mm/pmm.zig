// POLER-OS Physical Memory Manager
// Manages physical page frames using a bitmap allocator
// Each bit = 1 page (4KB), 0 = free, 1 = used

const std = @import("std");
const vga = @import("../drivers/vga.zig");

const PAGE_SIZE: u64 = 4096;
const MAX_PAGES: u64 = 0x100000000 / PAGE_SIZE; // Support up to 4GB

// Bitmap: 1 bit per page
var bitmap: [MAX_PAGES / 8]u8 = undefined;
var total_pages: u64 = 0;
var used_pages: u64 = 0;

pub fn init() void {
    // Zero the bitmap (all pages initially free)
    @memset(&bitmap, 0);
    
    // Mark first 1MB as used (BIOS, VGA, kernel)
    var addr: u64 = 0;
    while (addr < 0x100000) : (addr += PAGE_SIZE) {
        setPage(addr);
    }
    
    // Mark kernel at 1MB as used (assume 2MB kernel)
    addr = 0x100000;
    while (addr < 0x300000) : (addr += PAGE_SIZE) {
        setPage(addr);
    }
    
    total_pages = MAX_PAGES;
    used_pages = (0x300000) / PAGE_SIZE; // First 3MB
    
    vga.print("[PMM] Total pages: ");
    printNumber(total_pages);
    vga.print("\n[PMM] Used pages: ");
    printNumber(used_pages);
    vga.print("\n");
}

pub fn allocPage() ?u64 {
    var i: u64 = 0;
    while (i < total_pages) : (i += 1) {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) == 0) {
            setPage(i * PAGE_SIZE);
            used_pages += 1;
            return i * PAGE_SIZE;
        }
    }
    return null; // Out of memory
}

pub fn freePage(addr: u64) void {
    const page_idx = addr / PAGE_SIZE;
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0) {
        bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
        used_pages -= 1;
    }
}

fn setPage(addr: u64) void {
    const page_idx = addr / PAGE_SIZE;
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
}

fn printNumber(n: u64) void {
    if (n == 0) {
        vga.print("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 19;
    var num = n;
    while (num > 0) {
        buf[i] = '0' + @as(u8, @intCast(num % 10));
        num /= 10;
        if (i == 0) break;
        i -= 1;
    }
    vga.print(buf[i..]);
}
