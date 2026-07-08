// ============================================================================
// POLER-OS Virtual Memory Manager — x86_64
// ============================================================================

const pmm = @import("pmm64.zig");
const hal = @import("hal.zig");

pub const PTE_PRESENT: u64 = 0x01;
pub const PTE_WRITABLE: u64 = 0x02;
pub const PTE_USER: u64 = 0x04;
pub const PTE_WRITE_THROUGH: u64 = 0x08;
pub const PTE_CACHE_DISABLE: u64 = 0x10;
pub const PTE_ACCESSED: u64 = 0x20;
pub const PTE_DIRTY: u64 = 0x40;
pub const PTE_HUGE: u64 = 0x80;
pub const PTE_GLOBAL: u64 = 0x100;
pub const PTE_NO_EXECUTE: u64 = @as(u64, 1) << 63;

pub const PAGE_SIZE: u64 = 4096;

pub const VmmError = error{
    OutOfMemory,
    InvalidAddress,
    AlreadyMapped,
};

var pml4_phys: u64 = 0;

pub fn init() void {
    pml4_phys = hal.readCr3() & 0x000FFFFFFFFFF000;
    hal.Serial.puts("[VMM] Virtual Memory Manager initialized, PML4 at ");
    hal.Serial.putHex(pml4_phys);
    hal.Serial.puts("\n");
}

fn getOrCreateTable(table_phys: u64, index: usize) !u64 {
    const table: [*]volatile u64 = @ptrFromInt(table_phys);
    const entry = table[index];

    if (entry & PTE_PRESENT != 0) {
        if (entry & PTE_HUGE != 0) {
            return VmmError.AlreadyMapped;
        }
        return entry & 0x000FFFFFFFFFF000;
    }

    const new_table_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
    const ptr: [*]volatile u64 = @ptrFromInt(new_table_phys);
    @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);

    table[index] = new_table_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
    return new_table_phys;
}

/// Check if a page table (512 entries) is entirely empty
fn isTableEmpty(table_phys: u64) bool {
    const table: [*]const volatile u64 = @ptrFromInt(table_phys);
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        if (table[i] & PTE_PRESENT != 0) return false;
    }
    return true;
}

pub fn mapPage(virt: u64, phys: u64, flags: u64) !void {
    if (virt % PAGE_SIZE != 0 or phys % PAGE_SIZE != 0) {
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    // v6 FIX (Bug #6): Track pages allocated during table creation
    // so we can free them on failure
    var allocated_pages: [3]?u64 = .{ null, null, null };

    // PDPT table
    const pml4: [*]volatile u64 = @ptrFromInt(pml4_phys);
    const pdpt_phys: u64 = blk: {
        if (pml4[pml4_idx] & PTE_PRESENT != 0) {
            break :blk pml4[pml4_idx] & 0x000FFFFFFFFFF000;
        }
        const page = pmm.allocPage() orelse return VmmError.OutOfMemory;
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        pml4[pml4_idx] = page | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        allocated_pages[0] = page;
        break :blk page;
    };

    // PD table
    const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
    const pd_phys: u64 = blk: {
        if (pdpt[pdpt_idx] & PTE_PRESENT != 0) {
            break :blk pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;
        }
        const page = pmm.allocPage() orelse {
            // v6 FIX: Free already-allocated PDPT page on failure
            if (allocated_pages[0]) |p| { pmm.freePage(p); pml4[pml4_idx] = 0; }
            return VmmError.OutOfMemory;
        };
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        pdpt[pdpt_idx] = page | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        allocated_pages[1] = page;
        break :blk page;
    };

    // PT table
    const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
    const pt_phys: u64 = blk: {
        if (pd[pd_idx] & PTE_PRESENT != 0) {
            break :blk pd[pd_idx] & 0x000FFFFFFFFFF000;
        }
        const page = pmm.allocPage() orelse {
            // v6 FIX: Free already-allocated pages on failure
            if (allocated_pages[1]) |p| { pmm.freePage(p); pdpt[pdpt_idx] = 0; }
            if (allocated_pages[0]) |p| { pmm.freePage(p); pml4[pml4_idx] = 0; }
            return VmmError.OutOfMemory;
        };
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        pd[pd_idx] = page | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        allocated_pages[2] = page;
        break :blk page;
    };

    // Check if the PTE is already occupied — refuse to silently overwrite
    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    if (pt[pt_idx] & PTE_PRESENT != 0) {
        // v6 FIX: Free newly allocated page tables since we didn't need them
        // (They might be shared with other mappings, so only free if we just allocated them)
        // Actually, we should NOT free them here — other entries might already exist.
        // Just return the error; the allocated tables will be reused or freed later by unmapPage.
        return VmmError.AlreadyMapped;
    }

    pt[pt_idx] = phys | flags | PTE_PRESENT;

    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );
}

/// v6 FIX (Bug #9): unmapPage now returns error instead of silently
/// ignoring misaligned addresses. Caller should handle the error.
pub fn unmapPage(virt: u64) VmmError!void {
    if (virt % PAGE_SIZE != 0) {
        hal.Serial.puts("[VMM] ERROR: unmapPage misaligned address: 0x");
        hal.Serial.putHex(virt);
        hal.Serial.puts("\n");
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const pml4: [*]volatile u64 = @ptrFromInt(pml4_phys);
    if (pml4[pml4_idx] & PTE_PRESENT == 0) return;
    const pdpt_phys = pml4[pml4_idx] & 0x000FFFFFFFFFF000;

    const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
    if (pdpt[pdpt_idx] & PTE_PRESENT == 0) return;
    const pd_phys = pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;

    const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
    if (pd[pd_idx] & PTE_PRESENT == 0) return;
    const pt_phys = pd[pd_idx] & 0x000FFFFFFFFFF000;

    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    pt[pt_idx] = 0;

    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );

    // Free empty page tables back to PMM (walk up from PT → PD → PDPT)
    if (isTableEmpty(pt_phys)) {
        pmm.freePage(pt_phys);
        pd[pd_idx] = 0;

        if (isTableEmpty(pd_phys)) {
            pmm.freePage(pd_phys);
            pdpt[pdpt_idx] = 0;

            if (isTableEmpty(pdpt_phys)) {
                pmm.freePage(pdpt_phys);
                pml4[pml4_idx] = 0;
            }
        }
    }
}
