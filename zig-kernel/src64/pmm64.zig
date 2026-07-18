// ============================================================================
// POLER-OS Physical Memory Manager — x86_64
// ============================================================================
//
// v0.9.0: Added reference counting for COW pages
//
// Reference Counting Architecture:
//   - Every physical page has a 32-bit reference counter
//   - allocPage() sets refcount to 1
//   - refPage(addr) atomically increments refcount (used by COW clone)
//   - unrefPage(addr) atomically decrements refcount; returns true when
//     refcount drops to 0, meaning the page should actually be freed
//   - freePage() is now a thin wrapper: it decrements refcount and only
//     releases the page when refcount reaches 0
//
// This prevents the COW bug where munmap() frees a physical page that
// is still referenced by another process's page tables after fork().
// ============================================================================

const multiboot2 = @import("multiboot2.zig");
const hal = @import("hal.zig");

const PAGE_SIZE: u64 = 4096;
const MAX_MEM_SUPPORTED: u64 = 0x100000000; // 4GB for Phase 1
const MAX_PAGES: u64 = MAX_MEM_SUPPORTED / PAGE_SIZE;

// Bitmap: 1 bit per page (128 KB bitmap for 4GB RAM)
var bitmap: [MAX_PAGES / 8]u8 = undefined;
var total_ram_bytes: u64 = 0;
var usable_pages: u64 = 0;
var allocated_pages: u64 = 0;
var next_free_hint: u64 = 0; // Next-fit hint to avoid O(n) scan from 0

// ============================================================================
// v0.9.0: Reference counting array for COW pages
// ============================================================================
//
// Each physical page has a u32 reference counter.
//   refcount == 0: page is free (not allocated)
//   refcount == 1: page is owned by exactly one process (normal case)
//   refcount >= 2: page is shared between processes via COW fork
//
// All operations on refcounts are atomic to ensure correctness on SMP.
// The array itself is 256KB * 4 = 1MB for 4GB RAM, which is acceptable
// for a kernel that already uses 128KB for the bitmap.
// ============================================================================

var refcounts: [MAX_PAGES]u32 = undefined;

extern var _kernel_start: anyopaque;
extern var _kernel_end: anyopaque;

pub fn init(mbi_ptr: u64) void {
    // 1. Mark all memory as reserved initially
    @memset(&bitmap, 0xFF);

    // 2. Zero all reference counts
    @memset(&refcounts, 0);

    const parser = multiboot2.Parser.init(mbi_ptr);

    // 3. Parse basic memory info tag if present
    if (parser.findTag(4)) |tag_addr| {
        const mem_tag: *const multiboot2.BasicMemTag = @ptrFromInt(tag_addr);
        total_ram_bytes = @as(u64, mem_tag.mem_upper) * 1024 + 1024 * 1024;
    }

    // 4. Parse memory map tag (type 6) — mark usable regions as free
    if (parser.findTag(6)) |tag_addr| {
        const mmap_tag: *const multiboot2.MmapTag = @ptrFromInt(tag_addr);
        const entries = mmap_tag.getEntries();

        for (entries) |entry| {
            if (entry.entry_type == 1) {
                var addr = entry.addr;
                const end_addr = entry.addr + entry.len;
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

    // 5. Protect the first 1MB (BIOS, VGA, early tables)
    var addr: u64 = 0;
    while (addr < 0x100000) : (addr += PAGE_SIZE) {
        setPageInternal(addr);
    }

    // 6. Protect the kernel image
    const k_start: u64 = 0x100000;
    const k_end = @intFromPtr(&_kernel_end);
    const k_end_aligned = (k_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    addr = k_start;
    while (addr < k_end_aligned) : (addr += PAGE_SIZE) {
        setPageInternal(addr);
    }

    // 7. Protect the Multiboot2 info structure
    const mbi_header: *const multiboot2.InfoHeader = @ptrFromInt(mbi_ptr);
    const mbi_size = mbi_header.total_size;
    const mbi_end = (mbi_ptr + mbi_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    addr = mbi_ptr & ~(PAGE_SIZE - 1);
    while (addr < mbi_end) : (addr += PAGE_SIZE) {
        if (addr < MAX_MEM_SUPPORTED) {
            setPageInternal(addr);
        }
    }

    // allocated_pages will be incremented on each allocPage() call
    allocated_pages = 0;
    next_free_hint = 0;
}

/// Allocate a single physical page. Sets refcount to 1.
pub fn allocPage() ?u64 {
    // Start from the next-fit hint instead of always scanning from 0
    var i: u64 = next_free_hint;
    var wrapped = false;
    while (true) {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) == 0) {
            setPageInternal(i * PAGE_SIZE);
            allocated_pages += 1;
            next_free_hint = i + 1; // Next scan starts after this page
            if (next_free_hint >= MAX_PAGES) next_free_hint = 0;

            // v0.9.0: Set initial refcount to 1
            refcounts[i] = 1;

            return i * PAGE_SIZE;
        }
        i += 1;
        if (i >= MAX_PAGES) {
            if (wrapped) return null; // Full scan done, no free pages
            i = 0;
            wrapped = true;
        }
    }
}

/// Free a physical page. v0.9.0: Now refcount-aware.
///
/// This function decrements the page's reference count. If the count
/// drops to 0, the page is actually freed back to the PMM. If other
/// processes still hold references (COW), the page stays allocated.
///
/// For non-COW pages (refcount == 1), this behaves identically to
/// the old freePage — immediate deallocation.
pub fn freePage(addr: u64) void {
    // v6 FIX (Bug #7): Boundary check — addr >= 4GB causes OOB bitmap access
    if (addr >= MAX_MEM_SUPPORTED) {
        hal.Serial.puts("[PMM] ERROR: freePage addr out of range: 0x");
        hal.Serial.putHex(addr);
        hal.Serial.puts("\n");
        return;
    }
    // v6: Check alignment — must be page-aligned
    if (addr % PAGE_SIZE != 0) {
        hal.Serial.puts("[PMM] ERROR: freePage addr not page-aligned: 0x");
        hal.Serial.putHex(addr);
        hal.Serial.puts("\n");
        return;
    }

    const page_idx = addr / PAGE_SIZE;

    // v0.9.0: Decrement refcount. Only free when it reaches 0.
    if (refcounts[page_idx] > 1) {
        // Other processes still reference this page (COW)
        _ = @atomicRmw(u32, &refcounts[page_idx], .Sub, 1, .release);
        hal.Serial.puts("[PMM] freePage: COW refcount decremented for 0x");
        hal.Serial.putHex(addr);
        hal.Serial.puts(" refcount=");
        hal.Serial.putDecimal(refcounts[page_idx] - 1);
        hal.Serial.puts("\n");
        return;
    }

    // refcount is 1 or 0 — free the page unconditionally
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0) {
        bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
        if (allocated_pages > 0) allocated_pages -= 1;
        // Update hint to point near freed page for better locality
        if (page_idx < next_free_hint) {
            next_free_hint = page_idx;
        }
    }

    // Clear refcount
    refcounts[page_idx] = 0;
}

// ============================================================================
// v0.9.0: Reference counting API for COW
// ============================================================================

/// Increment the reference count for a physical page.
/// Used by clonePML4_COW() when sharing a page between parent and child.
///
/// This MUST be called for every PTE that points to a shared physical page
/// during fork(). The refcount tracks how many page table entries reference
/// this physical page across all processes.
///
/// Thread safety: uses atomic RMW to ensure correctness on SMP.
pub fn refPage(addr: u64) void {
    if (addr >= MAX_MEM_SUPPORTED) return;
    if (addr % PAGE_SIZE != 0) return;

    const page_idx = addr / PAGE_SIZE;

    // Atomic increment — safe for concurrent access from multiple cores
    const old = @atomicRmw(u32, &refcounts[page_idx], .Add, 1, .acquire);

    // Safety check: if the page was at 0 refs, something is wrong
    // (incrementing from 0 means we're adding a ref to a free page)
    if (old == 0) {
        hal.Serial.puts("[PMM] WARNING: refPage on free page 0x");
        hal.Serial.putHex(addr);
        hal.Serial.puts("\n");
    }
}

/// Decrement the reference count for a physical page.
/// Returns true if the page should be freed (refcount reached 0).
///
/// Used by:
///   - unmapPageInPML4() when unmapping from a process's page tables
///   - handleCowPageFault() when the old shared page loses a reference
///   - processMgrTerminate() when cleaning up a process's pages
///
/// The caller should call freePage() if this returns true.
pub fn unrefPage(addr: u64) bool {
    if (addr >= MAX_MEM_SUPPORTED) return false;
    if (addr % PAGE_SIZE != 0) return false;

    const page_idx = addr / PAGE_SIZE;

    if (refcounts[page_idx] == 0) {
        // Already at 0 — page is free, nothing to unref
        return false;
    }

    // Atomic decrement
    const old = @atomicRmw(u32, &refcounts[page_idx], .Sub, 1, .release);

    // If the old count was 1, it's now 0 — page should be freed
    return old == 1;
}

/// Get the current reference count for a physical page.
/// Useful for debugging and diagnostics.
pub fn getRefCount(addr: u64) u32 {
    if (addr >= MAX_MEM_SUPPORTED) return 0;
    if (addr % PAGE_SIZE != 0) return 0;
    const page_idx = addr / PAGE_SIZE;
    return @atomicLoad(u32, &refcounts[page_idx], .monotonic);
}

/// Force-set the reference count for a physical page.
/// Used during early boot for kernel pages that are permanently allocated.
pub fn setRefCount(addr: u64, count: u32) void {
    if (addr >= MAX_MEM_SUPPORTED) return;
    if (addr % PAGE_SIZE != 0) return;
    const page_idx = addr / PAGE_SIZE;
    @atomicStore(u32, &refcounts[page_idx], count, .release);
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

/// Allocate N contiguous page-aligned physical pages.
/// Returns the physical address of the first page, or null if not enough
/// contiguous free pages are available.
pub fn allocContiguousPages(count: u64) ?u64 {
    if (count == 0) return null;
    if (count > MAX_PAGES) return null;

    // Scan for a run of `count` consecutive free pages
    var run_start: u64 = 0;
    var run_len: u64 = 0;
    var i: u64 = 0;
    while (i < MAX_PAGES) : (i += 1) {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) == 0) {
            // Free page
            if (run_len == 0) run_start = i;
            run_len += 1;
            if (run_len >= count) {
                // Found a contiguous run — mark all as allocated
                var j: u64 = run_start;
                while (j < run_start + count) : (j += 1) {
                    setPageInternal(j * PAGE_SIZE);
                    allocated_pages += 1;
                    refcounts[j] = 1; // v0.9.0: set refcount
                }
                next_free_hint = run_start + count;
                if (next_free_hint >= MAX_PAGES) next_free_hint = 0;
                return run_start * PAGE_SIZE;
            }
        } else {
            // Allocated page — reset run
            run_len = 0;
        }
    }
    return null; // No contiguous run found
}

/// Free N contiguous pages starting at the given physical address
pub fn freeContiguousPages(addr: u64, count: u64) void {
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        freePage(addr + i * PAGE_SIZE);
    }
}

pub fn getStats() struct { total_kb: u64, usable_pages: u64, allocated_pages: u64 } {
    return .{
        .total_kb = total_ram_bytes / 1024,
        .usable_pages = usable_pages,
        .allocated_pages = allocated_pages,
    };
}
