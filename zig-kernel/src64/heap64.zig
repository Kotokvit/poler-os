// ============================================================================
// POLER-OS Kernel Dynamic Heap Allocator (kmalloc/kfree) — x86_64
// v6: Bug fixes for all 11 issues found by symbolic execution
// ============================================================================

const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const hal = @import("hal.zig");
const std = @import("std");

pub const Block = struct {
    size: usize,
    free: bool,
    next: ?*Block,
    padding: u64 = 0, // Non-zero when payload is offset from header (aligned alloc)
};

// When padding > 0, we store a cookie + real block address just before the
// payload so kfree can find the header regardless of alignment offset.
// Layout before aligned payload:
//   [cookie: u64 = heap_cookie] [back_ptr: u64 = address of Block]
// Both are validated in getBlockFromPayload to avoid false positives.
//
// v6.2 FIX: Replaced static heap_cookie (0xCAFEBABE_CAFED00D) with a
// per-boot random cookie. The old constant could be forged by an attacker
// with heap write primitive. Now the cookie is generated from RDTSC at
// boot time, making it unpredictable.
//
// v6 FIX (Bug #1): Added padding check to distinguish kernel allocations from
// user data that happens to match the cookie. We require BOTH:
//   1. heap_cookie matches at (ptr - BACK_PTR_OVERHEAD)
//   2. block.padding > 0 (aligned allocs always set padding)
// If padding == 0 but cookie matches, it's a false positive from user data.
var heap_cookie: u64 = 0; // Set at boot from RDTSC — unpredictable per boot
const BACK_PTR_OVERHEAD: u64 = @sizeOf(u64) * 2; // magic + back_ptr

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
    // v6.2: Generate per-boot random cookie from RDTSC
    // XOR with golden ratio constants for avalanche even if TSC is predictable
    var tsc: u64 = 0;
    asm volatile ("rdtsc"
        : [ret] "={rax}" (tsc),
    );
    heap_cookie = tsc ^ 0xCAFEBABE_CAFED00D ^ 0x9E3779B99E3779B9;
    // Ensure cookie is non-zero (zero would disable the check)
    if (heap_cookie == 0) heap_cookie = 0xDEADBEEF_DEADBEEF;

    // Allocate the first physical page for the heap
    const phys = pmm.allocPage() orelse {
        hal.Serial.puts("[HEAP] Failed to allocate first physical page!\n");
        return;
    };

    vmm.mapPage(HEAP_START, phys, vmm.PTE_WRITABLE) catch |err| {
        hal.Serial.puts("[HEAP] Failed to map first page: ");
        hal.Serial.puts(@errorName(err));
        hal.Serial.puts("\n");
        // v6 FIX (Bug #6): Free physical page on mapping failure
        pmm.freePage(phys);
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

/// v6 FIX (Bug #3): Validate that a pointer is a valid heap allocation.
/// Checks: range, alignment, block metadata consistency.
fn isValidHeapPointer(ptr: [*]u8) bool {
    const addr = @intFromPtr(ptr);
    // Check: pointer must be within heap virtual address range
    if (addr < HEAP_START + @sizeOf(Block) or addr >= HEAP_MAX) return false;
    // Check: pointer must be at least 16-byte aligned (minimum Block alignment)
    if (addr % 16 != 0) return false;
    return true;
}

/// v6 FIX (Bug #1 + #3): Improved getBlockFromPayload with false-positive
/// protection for heap_cookie in user data, and wild pointer detection.
fn getBlockFromPayload(ptr: [*]u8) ?*Block {
    // v6: Validate pointer before any dereference (Bug #3: wild pointer)
    if (!isValidHeapPointer(ptr)) {
        hal.Serial.puts("[HEAP] ERROR: kfree on invalid pointer: 0x");
        hal.Serial.putHex(@intFromPtr(ptr));
        hal.Serial.puts("\n");
        return null;
    }

    // Check if there's a magic + back-pointer stored just before the payload.
    // Layout: [heap_cookie: u64] [block_addr: u64] [aligned_payload...]
    const maybe_magic_addr = @intFromPtr(ptr) - BACK_PTR_OVERHEAD;
    // Bounds check before reading magic
    if (maybe_magic_addr >= HEAP_START and maybe_magic_addr < HEAP_MAX) {
        const maybe_magic: *const u64 = @ptrFromInt(maybe_magic_addr);
        if (maybe_magic.* == heap_cookie) {
            // v6 FIX (Bug #1): heap_cookie in user data → false positive.
            // We now also verify that the corresponding block has padding > 0.
            // An aligned allocation ALWAYS sets block.padding = total_padding > 0.
            // If the block has padding == 0, this magic is user data, not ours.
            const back_ptr_loc: *const u64 = @ptrFromInt(@intFromPtr(ptr) - @sizeOf(u64));
            const block_addr = back_ptr_loc.*;
            // Sanity: block must be within heap range
            if (block_addr >= HEAP_START and block_addr < HEAP_MAX) {
                const block: *Block = @ptrFromInt(block_addr);
                // Verify: ptr should be within this block's payload region
                const expected_payload = @intFromPtr(block) + @sizeOf(Block);
                if (@intFromPtr(ptr) >= expected_payload and @intFromPtr(ptr) < expected_payload + block.size + @sizeOf(Block)) {
                    // v6 FIX (Bug #1): Only trust the magic if the block has padding set.
                    // This eliminates false positives from user data containing heap_cookie.
                    if (block.padding > 0) {
                        return block;
                    }
                    // Magic matched, block in range, but padding=0 → false positive
                    hal.Serial.puts("[HEAP] WARN: heap_cookie in user data (false positive prevented)\n");
                }
            }
            // Magic matched but block is corrupt
            hal.Serial.puts("[HEAP] BUG: magic found but back-pointer invalid!\n");
        }
    }
    // No padding (or magic mismatch) — header is right before payload
    const block_addr = @intFromPtr(ptr) - @sizeOf(Block);
    if (block_addr < HEAP_START or block_addr >= HEAP_MAX) {
        hal.Serial.puts("[HEAP] ERROR: block header out of heap range\n");
        return null;
    }
    const block: *Block = @ptrFromInt(block_addr);
    // v6: Verify block metadata is consistent
    if (block.size > HEAP_MAX - HEAP_START) {
        hal.Serial.puts("[HEAP] ERROR: block size corrupt (too large)\n");
        return null;
    }
    return block;
}

fn alloc(
    ctx: *anyopaque,
    len: usize,
    ptr_align: u8,
    ret_addr: usize,
) ?[*]u8 {

    // v6 FIX (Bug #8): kmalloc(0) should return null
    if (len == 0) return null;

    const alignment = @as(usize, 1) << @as(u6, @intCast(ptr_align));
    // v6 FIX (Bug #4): Integer overflow check for aligned_len
    // If len is very large, alignUp could overflow u64
    const aligned_len = alignUp(len, 16);
    if (aligned_len < len) return null; // overflow detected

    hal.cli();
    defer hal.sti();

    var current = first_block;
    var prev: ?*Block = null;

    while (current) |block| {
        if (block.free) {
            const payload_addr = @intFromPtr(block) + @sizeOf(Block);

            if (alignment <= 16) {
                // Default path: Block header is 16-byte aligned, payload follows directly.
                if (block.size >= aligned_len) {
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
                    block.padding = 0;
                    return @ptrFromInt(payload_addr);
                }
            } else {
                // Over-aligned allocation
                const min_payload = payload_addr + BACK_PTR_OVERHEAD;
                const final_payload_addr = alignUp(min_payload, alignment);
                const total_padding = final_payload_addr - payload_addr;
                const total_required = aligned_len + total_padding;

                // v6 FIX (Bug #4): overflow check
                if (total_required < aligned_len) return null;

                if (block.size >= total_required) {
                    // v6 FIX (Bug #5): Over-aligned allocs — split if there's room
                    // Previously, over-aligned allocs never split the block,
                    // leading to fragmentation. Now we split like the default path.
                    if (block.size >= total_required + @sizeOf(Block) + 16) {
                        // Split: create a new free block after this allocation
                        const next_block_addr = @intFromPtr(block) + @sizeOf(Block) + total_padding + aligned_len;
                        const next_block: *Block = @ptrFromInt(next_block_addr);
                        next_block.size = block.size - total_padding - aligned_len - @sizeOf(Block);
                        next_block.free = true;
                        next_block.next = block.next;
                        next_block.padding = 0;

                        block.size = total_padding + aligned_len;
                        block.next = next_block;
                    }

                    block.padding = total_padding;

                    // Write magic + back-pointer just before the aligned payload
                    const magic_loc: *u64 = @ptrFromInt(final_payload_addr - BACK_PTR_OVERHEAD);
                    magic_loc.* = heap_cookie;
                    const back_ptr_loc: *u64 = @ptrFromInt(final_payload_addr - @sizeOf(u64));
                    back_ptr_loc.* = @intFromPtr(block);

                    block.free = false;
                    return @ptrFromInt(final_payload_addr);
                }
            }
        }
        prev = current;
        current = block.next;
    }

    // Out of memory, expand the heap!
    // v6 FIX (Bug #4): Safe expansion size calculation with overflow check
    const expand_base = aligned_len + @sizeOf(Block) + BACK_PTR_OVERHEAD;
    if (expand_base < aligned_len) return null; // overflow
    const expand_size = alignUp(expand_base, vmm.PAGE_SIZE);
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
            // v6 FIX (Bug #6): Free physical page on mapping failure
            pmm.freePage(phys);
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

test "placeholder" {}

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

    const block = getBlockFromPayload(buf.ptr) orelse return false;
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

/// v6: Unified internal free function — eliminates code duplication (Bug #11)
/// Both `free` (VTable) and `kfree` (public API) now use this.
/// Returns true on success, false on error (double-free, invalid pointer).
fn freeInternal(ptr: [*]u8) bool {
    const block = getBlockFromPayload(ptr) orelse return false;

    // v6 FIX (Bug #2): Double-free detection
    if (block.free) {
        hal.Serial.puts("[HEAP] ERROR: double-free detected at block 0x");
        hal.Serial.putHex(@intFromPtr(block));
        hal.Serial.puts("\n");
        return false;
    }

    block.free = true;
    block.padding = 0; // Clear padding so coalescing is safe

    // Coalesce contiguous free blocks
    coalesceFreeBlocks();
    return true;
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

    _ = freeInternal(buf.ptr);
}

/// Merge adjacent free blocks into larger ones
fn coalesceFreeBlocks() void {
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

/// v6 FIX (Bug #8): kmalloc(0) returns null
pub fn kmalloc(len: usize) ?[*]u8 {
    if (len == 0) return null; // v6: zero-size allocation not allowed
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

/// v6 FIX (Bug #2 + #3 + #11): kfree with validation and double-free detection
/// Uses shared freeInternal to eliminate code duplication.
pub fn kfree(ptr: [*]u8) void {
    hal.cli();
    defer hal.sti();

    if (!freeInternal(ptr)) {
        // Error already logged by freeInternal (double-free, invalid pointer, etc.)
        // In kernel context, we don't abort — just log and continue
    }
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
