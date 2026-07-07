// ============================================================================
// POLER-OS Kernel Dynamic Heap Allocator (kmalloc/kfree) — x86_64
// ============================================================================

const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const hal = @import("hal.zig");
const std = @import("std");

pub const Block = struct {
    size: usize,
    free: bool,
    next: ?*Block,
    padding: u64 = 0,
};

pub const HEAP_START: u64 = 0x200000000; // 8GB mark
pub const HEAP_MAX: u64 =   0x300000000; // 12GB mark (4GB max heap)

var heap_end: u64 = HEAP_START;
var first_block: ?*Block = null;

const vtable = std.mem.Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .free = free,
};

pub var allocator: std.mem.Allocator = undefined;

pub fn init() void {
    // Allocate the first physical page for the heap
    const phys = pmm.allocPage() orelse {
        hal.Serial.puts("[HEAP] Failed to allocate first physical page!\n");
        return;
    };

    vmm.mapPage(HEAP_START, phys, vmm.PTE_WRITABLE) catch |err| {
        hal.Serial.puts("[HEAP] Failed to map first page: ");
        hal.Serial.puts(@errorName(err));
        hal.Serial.puts("\n");
        return;
    };

    heap_end = HEAP_START + vmm.PAGE_SIZE;

    const block: *Block = @ptrFromInt(HEAP_START);
    block.size = vmm.PAGE_SIZE - @sizeOf(Block);
    block.free = true;
    block.next = null;
    block.padding = 0;

    first_block = block;

    allocator = std.mem.Allocator{
        .ptr = undefined,
        .vtable = &vtable,
    };

    hal.Serial.puts("[HEAP] Kernel heap initialized from ");
    hal.Serial.putHex(HEAP_START);
    hal.Serial.puts(" to ");
    hal.Serial.putHex(heap_end);
    hal.Serial.puts("\n");
}

fn alignUp(val: u64, alignment: u64) u64 {
    return (val + alignment - 1) & ~(alignment - 1);
}

fn getBlockFromPayload(ptr: [*]u8) *Block {
    return @ptrFromInt(@intFromPtr(ptr) - @sizeOf(Block));
}

fn alloc(
    ctx: *anyopaque,
    len: usize,
    ptr_align: u8,
    ret_addr: usize,
) ?[*]u8 {

    const alignment = @as(usize, 1) << @as(u6, @intCast(ptr_align));
    // Align the requested size to a multiple of 16
    const aligned_len = alignUp(len, 16);

    hal.cli();
    defer hal.sti();

    var current = first_block;
    var prev: ?*Block = null;

    while (current) |block| {
        if (block.free) {
            const payload_addr = @intFromPtr(block) + @sizeOf(Block);
            const aligned_payload_addr = alignUp(payload_addr, alignment);
            const padding_needed = aligned_payload_addr - payload_addr;
            const total_required = aligned_len + padding_needed;

            if (block.size >= total_required) {
                // To keep it simple, if no padding is needed (standard 16-byte alignment),
                // we can split the block if there is enough space left.
                if (padding_needed == 0) {
                    if (block.size >= aligned_len + @sizeOf(Block) + 16) {
                        const next_block_addr = @intFromPtr(block) + @sizeOf(Block) + aligned_len;
                        const next_block: *Block = @ptrFromInt(next_block_addr);
                        next_block.size = block.size - aligned_len - @sizeOf(Block);
                        next_block.free = true;
                        next_block.next = block.next;
                        next_block.padding = 0;

                        block.size = aligned_len;
                        block.next = next_block;
                    }
                    block.free = false;
                    return @ptrFromInt(payload_addr);
                } else {
                    // If padding is needed (large alignments like 4KB), we can satisfy it
                    // but we don't split to avoid offset complications.
                    block.free = false;
                    return @ptrFromInt(aligned_payload_addr);
                }
            }
        }
        prev = current;
        current = block.next;
    }

    // Out of memory, expand the heap!
    const expand_size = alignUp(aligned_len + @sizeOf(Block), vmm.PAGE_SIZE);
    const pages_needed = expand_size / vmm.PAGE_SIZE;

    var i: usize = 0;
    while (i < pages_needed) : (i += 1) {
        if (heap_end >= HEAP_MAX) {
            hal.Serial.puts("[HEAP] Out of virtual heap space!\n");
            return null;
        }

        const phys = pmm.allocPage() orelse {
            hal.Serial.puts("[HEAP] Out of physical memory during heap expansion!\n");
            return null;
        };

        vmm.mapPage(heap_end, phys, vmm.PTE_WRITABLE) catch |err| {
            hal.Serial.puts("[HEAP] Failed to map expanded page: ");
            hal.Serial.puts(@errorName(err));
            hal.Serial.puts("\n");
            return null;
        };

        heap_end += vmm.PAGE_SIZE;
    }

    // Append free space to last block or create a new one
    if (prev) |last_block| {
        if (last_block.free) {
            last_block.size += expand_size;
            return alloc(ctx, len, ptr_align, ret_addr);
        } else {
            const new_block_addr = @intFromPtr(last_block) + @sizeOf(Block) + last_block.size;
            const new_block: *Block = @ptrFromInt(new_block_addr);
            new_block.size = expand_size - @sizeOf(Block);
            new_block.free = true;
            new_block.next = null;
            new_block.padding = 0;

            last_block.next = new_block;
            return alloc(ctx, len, ptr_align, ret_addr);
        }
    }

    return null;
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: u8,
    new_len: usize,
    ret_addr: usize,
) bool {
    _ = ctx;
    _ = buf_align;
    _ = ret_addr;

    const block = getBlockFromPayload(buf.ptr);
    const aligned_new_len = alignUp(new_len, 16);

    hal.cli();
    defer hal.sti();

    if (aligned_new_len <= block.size) {
        // Shrink block
        if (block.size - aligned_new_len >= @sizeOf(Block) + 16) {
            const next_block_addr = @intFromPtr(block) + @sizeOf(Block) + aligned_new_len;
            const next_block: *Block = @ptrFromInt(next_block_addr);
            next_block.size = block.size - aligned_new_len - @sizeOf(Block);
            next_block.free = true;
            next_block.next = block.next;
            next_block.padding = 0;

            block.size = aligned_new_len;
            block.next = next_block;
        }
        return true;
    } else {
        // Grow block in-place if next block is free and large enough
        if (block.next) |next_b| {
            if (next_b.free and (block.size + @sizeOf(Block) + next_b.size >= aligned_new_len)) {
                const remaining = (block.size + @sizeOf(Block) + next_b.size) - aligned_new_len;
                if (remaining >= @sizeOf(Block) + 16) {
                    const new_next_addr = @intFromPtr(block) + @sizeOf(Block) + aligned_new_len;
                    const new_next: *Block = @ptrFromInt(new_next_addr);
                    new_next.size = remaining - @sizeOf(Block);
                    new_next.free = true;
                    new_next.next = next_b.next;
                    new_next.padding = 0;

                    block.size = aligned_new_len;
                    block.next = new_next;
                } else {
                    block.size += @sizeOf(Block) + next_b.size;
                    block.next = next_b.next;
                }
                return true;
            }
        }
        return false;
    }
}

fn free(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: u8,
    ret_addr: usize,
) void {
    _ = ctx;
    _ = buf_align;
    _ = ret_addr;

    if (buf.ptr == undefined) return;

    hal.cli();
    defer hal.sti();

    const block = getBlockFromPayload(buf.ptr);
    block.free = true;

    // Coalesce contiguous free blocks
    var current = first_block;
    while (current) |b| {
        if (b.free) {
            while (b.next) |next_b| {
                if (next_b.free) {
                    b.size += @sizeOf(Block) + next_b.size;
                    b.next = next_b.next;
                } else {
                    break;
                }
            }
        }
        current = b.next;
    }
}

pub fn kmalloc(len: usize) ?[*]u8 {
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

pub fn kfree(ptr: [*]u8) void {
    const block = getBlockFromPayload(ptr);
    allocator.free(ptr[0..block.size]);
}

pub fn printHeapStatus() void {
    hal.Serial.puts("=== KERNEL HEAP STATUS ===\n");
    var current = first_block;
    var idx: usize = 0;
    while (current) |block| : (idx += 1) {
        hal.Serial.puts("  Block ");
        printDec(idx);
        hal.Serial.puts(": Addr=");
        hal.Serial.putHex(@intFromPtr(block));
        hal.Serial.puts(" Size=");
        printDec(block.size);
        hal.Serial.puts(" Free=");
        hal.Serial.puts(if (block.free) "true" else "false");
        hal.Serial.puts("\n");
        current = block.next;
    }
    hal.Serial.puts("==========================\n");
}

fn printDec(val: u64) void {
    if (val == 0) {
        hal.Serial.puts("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 19;
    var temp = val;
    while (temp > 0) {
        buf[i] = '0' + @as(u8, @intCast(temp % 10));
        temp /= 10;
        if (i == 0) break;
        i -= 1;
    }
    hal.Serial.puts(buf[i + 1..]);
}
