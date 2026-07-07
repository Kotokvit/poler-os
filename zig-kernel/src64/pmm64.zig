// ============================================================================
// POLER-OS Physical Memory Manager — x86_64
// ============================================================================

const multiboot2 = @import("multiboot2.zig");
const hal = @import("hal.zig");

const PAGE_SIZE: u64 = 4096;
const MAX_MEM_SUPPORTED: u64 = 0x100000000; // 4GB support for Phase 1
const MAX_PAGES: u64 = MAX_MEM_SUPPORTED / PAGE_SIZE;

// Bitmap: 1 bit per page (128 KB bitmap for 4GB RAM)
var bitmap: [MAX_PAGES / 8]u8 = undefined;
var total_ram_bytes: u64 = 0;
var usable_pages: u64 = 0;
var allocated_pages: u64 = 0;

extern var _kernel_start: anyopaque;
extern var _kernel_end: anyopaque;

pub fn init(mbi_ptr: u64) void {
    // 1. Mark all memory as reserved/used initially
    @memset(&bitmap, 0xFF);

    const parser = multiboot2.Parser.init(mbi_ptr);
    
    // 2. Parse basic memory info tag if present
    if (parser.findTag(4)) |tag_addr| {
        const mem_tag: *const multiboot2.BasicMemTag = @ptrFromInt(tag_addr);
        total_ram_bytes = @as(u64, mem_tag.mem_upper) * 1024 + 1024 * 1024;
    }

    // 3. Parse memory map tag (type 6)
    if (parser.findTag(6)) |tag_addr| {
        const mmap_tag: *const multiboot2.MmapTag = @ptrFromInt(tag_addr);
        const entries = mmap_tag.getEntries();

        for (entries) |entry| {
            // entry_type == 1 is usable RAM
            if (entry.entry_type == 1) {
                var addr = entry.addr;
                const end_addr = entry.addr + entry.len;
                
                // Align start address to PAGE_SIZE
                addr = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

                while (addr + PAGE_SIZE <= end_addr) : (addr += PAGE_SIZE) {
                    if (addr < MAX_MEM_SUPPORTED) {
                        freePageInternal(addr);
                        usable_pages += 1;
                    }
                }
            }
        }
    }

    // 4. Protect the first 1MB (BIOS, VGA, early tables)
    var addr: u64 = 0;
    while (addr < 0x100000) : (addr += PAGE_SIZE) {
        setPageInternal(addr);
    }

    // 5. Protect the kernel memory space (starts at 1MB mark)
    const k_start = 0x100000;
    const k_end = @intFromPtr(&_kernel_end);
    
    // Align kernel end to page boundary
    const k_end_aligned = (k_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    addr = k_start;
    while (addr < k_end_aligned) : (addr += PAGE_SIZE) {
        setPageInternal(addr);
    }

    // 6. Protect the Multiboot2 info structure itself
    const mbi_header: *const multiboot2.InfoHeader = @ptrFromInt(mbi_ptr);
    const mbi_size = mbi_header.total_size;
    const mbi_end = (mbi_ptr + mbi_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    addr = mbi_ptr & ~(PAGE_SIZE - 1);
    while (addr < mbi_end) : (addr += PAGE_SIZE) {
        if (addr < MAX_MEM_SUPPORTED) {
            setPageInternal(addr);
        }
    }

    // Calculate how many usable pages are allocated now
    allocated_pages = 0;
    var i: u64 = 0;
    while (i < MAX_PAGES) : (i += 1) {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0) {
            // This is a marked (used) page. If it is within usable RAM, we count it.
            // (We initialized the bitmap to 0xFF, so non-RAM regions remain 1).
        }
    }
}

pub fn allocPage() ?u64 {
    var i: u64 = 0;
    while (i < MAX_PAGES) : (i += 1) {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) == 0) {
            setPageInternal(i * PAGE_SIZE);
            allocated_pages += 1;
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
        if (allocated_pages > 0) allocated_pages -= 1;
    }
}

fn setPageInternal(addr: u64) void {
    const page_idx = addr / PAGE_SIZE;
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
}

fn freePageInternal(addr: u64) void {
    const page_idx = addr / PAGE_SIZE;
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
}

pub fn getStats() struct { total_kb: u64, usable_pages: u64, allocated_pages: u64 } {
    return .{
        .total_kb = total_ram_bytes / 1024,
        .usable_pages = usable_pages,
        .allocated_pages = allocated_pages,
    };
}
