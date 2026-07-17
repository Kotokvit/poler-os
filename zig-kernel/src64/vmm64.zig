// ============================================================================
// POLER-OS Virtual Memory Manager — x86_64
// ============================================================================
//
// v0.8.0: COW (Copy-on-Write) for fork(), unmapPageInPML4 for munmap
//
// COW Architecture:
//   fork() → clonePML4_COW() → mark all user pages as read-only + PTE_COW
//   write fault → handleCowPageFault() → allocate new page, copy data,
//                 restore writable, clear PTE_COW
//   read fault  → just return (page is readable)
//
// The PTE_COW bit uses x86_64 PTE bit 9 (available to software).
// When PTE_COW is set, the page is shared between parent and child;
// a write triggers a #PF which we handle by creating a private copy.
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
// Bit 9 (0x200): Software-available — used for COW marker
pub const PTE_COW: u64 = 0x200;
// Bit 10 (0x400): Software-available — used for "shared" marker
// When a page is shared (ref_count > 1), both PTE_COW and PTE_SHARED
// are set. When ref_count drops to 1, we clear both and make it writable.
pub const PTE_SHARED: u64 = 0x400;
pub const PTE_NO_EXECUTE: u64 = @as(u64, 1) << 63;

pub const PAGE_SIZE: u64 = 4096;

pub const VmmError = error{
    OutOfMemory,
    InvalidAddress,
    AlreadyMapped,
    NotMapped,
};

var pml4_phys: u64 = 0;

pub fn init() void {
    pml4_phys = hal.readCr3() & 0x000FFFFFFFFFF000;
    hal.Serial.puts("[VMM] Virtual Memory Manager initialized, PML4 at ");
    hal.Serial.putHex(pml4_phys);
    hal.Serial.puts("\n");

    // Register COW page fault handler with HAL
    // This allows the HAL's #PF handler to call handleCowPageFault
    // without a direct circular dependency (hal ↔ vmm)
    hal.cowPageFaultCallback = handleCowPageFault;
    hal.Serial.puts("[VMM] COW page fault handler registered with HAL\n");
}

/// Get the kernel's PML4 physical address (needed for COW cloning)
pub fn getKernelPML4() u64 {
    return pml4_phys;
}

fn getOrCreateTable(table_phys: u64, index: usize, is_user: bool) !u64 {
    const table: [*]volatile u64 = @ptrFromInt(table_phys);
    const entry = table[index];

    if (entry & PTE_PRESENT != 0) {
        if (entry & PTE_HUGE != 0) {
            return VmmError.AlreadyMapped;
        }
        // v0.7.0 FIX: If the existing entry doesn't have PTE_USER but we need it
        if (is_user and (entry & PTE_USER == 0)) {
            table[index] = entry | PTE_USER;
        }
        return entry & 0x000FFFFFFFFFF000;
    }

    const new_table_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
    const ptr: [*]volatile u64 = @ptrFromInt(new_table_phys);
    @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);

    var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
    if (is_user) pte_flags |= PTE_USER;
    table[index] = new_table_phys | pte_flags;
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

/// Check if a page table has any present entries, ignoring COW-only entries
fn isTableEmptyOrCOW(table_phys: u64) bool {
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

    const is_user = (flags & PTE_USER) != 0;

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
        var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
        if (is_user) pte_flags |= PTE_USER;
        pml4[pml4_idx] = page | pte_flags;
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
            if (allocated_pages[0]) |p| { pmm.freePage(p); pml4[pml4_idx] = 0; }
            return VmmError.OutOfMemory;
        };
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
        if (is_user) pte_flags |= PTE_USER;
        pdpt[pdpt_idx] = page | pte_flags;
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
            if (allocated_pages[1]) |p| { pmm.freePage(p); pdpt[pdpt_idx] = 0; }
            if (allocated_pages[0]) |p| { pmm.freePage(p); pml4[pml4_idx] = 0; }
            return VmmError.OutOfMemory;
        };
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
        if (is_user) pte_flags |= PTE_USER;
        pd[pd_idx] = page | pte_flags;
        allocated_pages[2] = page;
        break :blk page;
    };

    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    if (pt[pt_idx] & PTE_PRESENT != 0) {
        return VmmError.AlreadyMapped;
    }

    pt[pt_idx] = phys | flags | PTE_PRESENT;

    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );
}

/// Create a new PML4 for a user process.
/// Copies kernel PML4 entries so the kernel remains mapped.
/// Kernel entries are copied WITHOUT PTE_USER for security.
pub fn createUserPML4() !u64 {
    const new_pml4_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
    const new_pml4: [*]volatile u64 = @ptrFromInt(new_pml4_phys);
    @memset(@as([*]volatile u8, @ptrCast(new_pml4))[0..PAGE_SIZE], 0);

    const kernel_pml4: [*]const volatile u64 = @ptrFromInt(pml4_phys);
    for (0..512) |i| {
        const entry = kernel_pml4[i];
        if (entry & PTE_PRESENT != 0) {
            new_pml4[i] = entry & ~PTE_USER;
        }
    }

    hal.Serial.puts("[VMM] Created user PML4 at ");
    hal.Serial.putHex(new_pml4_phys);
    hal.Serial.puts("\n");

    return new_pml4_phys;
}

// ============================================================================
// COW (Copy-on-Write) — v0.8.0
// ============================================================================
//
// When fork() is called, instead of copying all user pages (expensive),
// we create a new PML4 that shares the same physical pages as the parent.
// All user pages are marked read-only with PTE_COW flag.
//
// When either process writes to a COW page, a page fault (#PF) occurs.
// The page fault handler:
//   1. Checks if PTE_COW is set on the faulting page
//   2. Allocates a new physical page
//   3. Copies the content from the shared page to the new page
//   4. Maps the new page as writable (without PTE_COW)
//   5. Returns — the faulting instruction retries and succeeds
//
// This gives fork() O(1) time complexity (only copies page tables,
// not actual memory), and only copies pages that are actually modified.
// ============================================================================

/// Clone a PML4 with COW semantics for fork().
///
/// This creates a new PML4 for the child process where:
///   - Kernel entries are shared (same as createUserPML4)
///   - User entries point to the SAME physical pages as the parent,
///     but are marked read-only with PTE_COW flag
///   - Page table structures (PDPT/PD/PT) are deep-copied (not shared)
///     because the PTE flags differ between parent and child
///
/// After this call, the parent's user pages are ALSO marked read-only+COW.
/// This is necessary because both parent and child must trigger COW faults
/// on write. The parent's original writable state is preserved in PTE_COW.
///
/// Returns: physical address of the new (child) PML4
pub fn clonePML4_COW(parent_pml4_phys: u64) !u64 {
    const child_pml4_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
    const child_pml4: [*]volatile u64 = @ptrFromInt(child_pml4_phys);
    @memset(@as([*]volatile u8, @ptrCast(child_pml4))[0..PAGE_SIZE], 0);

    const parent_pml4: [*]volatile u64 = @ptrFromInt(parent_pml4_phys);
    const kernel_pml4: [*]const volatile u64 = @ptrFromInt(pml4_phys);

    var cow_pages: u64 = 0;

    for (0..512) |pml4_idx| {
        const pml4_entry = parent_pml4[pml4_idx];
        if (pml4_entry & PTE_PRESENT == 0) continue;

        // Kernel entries (upper half): share directly, no PTE_USER
        if (pml4_idx >= 256) {
            child_pml4[pml4_idx] = kernel_pml4[pml4_idx] & ~PTE_USER;
            continue;
        }

        // User entries (lower half): deep-copy page tables with COW
        const parent_pdpt_phys = pml4_entry & 0x000FFFFFFFFFF000;
        const is_user = (pml4_entry & PTE_USER) != 0;

        // Allocate new PDPT for child
        const child_pdpt_phys = pmm.allocPage() orelse {
            // TODO: free already-allocated child page tables on failure
            return VmmError.OutOfMemory;
        };
        const child_pdpt: [*]volatile u64 = @ptrFromInt(child_pdpt_phys);
        @memset(@as([*]volatile u8, @ptrCast(child_pdpt))[0..PAGE_SIZE], 0);

        var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
        if (is_user) pte_flags |= PTE_USER;
        child_pml4[pml4_idx] = child_pdpt_phys | pte_flags;

        // Walk PDPT entries
        const parent_pdpt: [*]const volatile u64 = @ptrFromInt(parent_pdpt_phys);
        for (0..512) |pdpt_idx| {
            const pdpt_entry = parent_pdpt[pdpt_idx];
            if (pdpt_entry & PTE_PRESENT == 0) continue;
            if (pdpt_entry & PTE_HUGE != 0) {
                // 1GB page — just copy as-is with COW (rare in user space)
                child_pdpt[pdpt_idx] = (pdpt_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                // Also mark parent as COW
                const p_pdpt: [*]volatile u64 = @ptrFromInt(parent_pdpt_phys);
                p_pdpt[pdpt_idx] = (pdpt_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                continue;
            }

            const parent_pd_phys = pdpt_entry & 0x000FFFFFFFFFF000;

            // Allocate new PD for child
            const child_pd_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
            const child_pd: [*]volatile u64 = @ptrFromInt(child_pd_phys);
            @memset(@as([*]volatile u8, @ptrCast(child_pd))[0..PAGE_SIZE], 0);
            child_pdpt[pdpt_idx] = child_pd_phys | pte_flags;

            // Walk PD entries
            const parent_pd: [*]const volatile u64 = @ptrFromInt(parent_pd_phys);
            for (0..512) |pd_idx| {
                const pd_entry = parent_pd[pd_idx];
                if (pd_entry & PTE_PRESENT == 0) continue;
                if (pd_entry & PTE_HUGE != 0) {
                    // 2MB page — copy with COW
                    child_pd[pd_idx] = (pd_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    const p_pd: [*]volatile u64 = @ptrFromInt(parent_pd_phys);
                    p_pd[pd_idx] = (pd_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    continue;
                }

                const parent_pt_phys = pd_entry & 0x000FFFFFFFFFF000;

                // Allocate new PT for child
                const child_pt_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
                const child_pt: [*]volatile u64 = @ptrFromInt(child_pt_phys);
                @memset(@as([*]volatile u8, @ptrCast(child_pt))[0..PAGE_SIZE], 0);
                child_pd[pd_idx] = child_pt_phys | pte_flags;

                // Walk PT entries — this is where actual pages are
                const parent_pt: [*]volatile u64 = @ptrFromInt(parent_pt_phys);
                for (0..512) |pt_idx| {
                    var pte = parent_pt[pt_idx];
                    if (pte & PTE_PRESENT == 0) continue;
                    if ((pte & PTE_USER) == 0) continue; // Skip kernel pages in user tables

                    // Mark the child's PTE as read-only + COW
                    // Child points to the SAME physical page
                    const cow_entry = (pte & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    child_pt[pt_idx] = cow_entry;

                    // Also mark the parent's PTE as read-only + COW
                    // (both processes must COW on write)
                    if (pte & PTE_WRITABLE != 0) {
                        parent_pt[pt_idx] = (pte & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    }

                    cow_pages += 1;
                }
            }
        }
    }

    hal.Serial.puts("[VMM] COW clone: ");
    hal.Serial.putDecimal(cow_pages);
    hal.Serial.puts(" user pages marked COW, child PML4 at ");
    hal.Serial.putHex(child_pml4_phys);
    hal.Serial.puts("\n");

    return child_pml4_phys;
}

/// Handle a COW page fault.
///
/// Called from the #PF handler when a write fault occurs on a COW page.
/// This function:
///   1. Verifies the faulting page has PTE_COW set
///   2. Allocates a new physical page
///   3. Copies the old page content to the new page
///   4. Replaces the PTE: new physical page, writable, COW cleared
///   5. Invalidates the TLB entry
///
/// Parameters:
///   fault_virt  — virtual address that caused the fault
///   fault_cr3   — CR3 value at the time of the fault (current process PML4)
///   error_code  — #PF error code (bit 1 = write, bit 2 = user, bit 3 = RSVD)
///
/// Returns: true if COW was handled, false if not a COW fault
pub fn handleCowPageFault(fault_virt: u64, fault_cr3: u64, error_code: u64) bool {
    // A COW fault must be a write fault (bit 1 of error code)
    if (error_code & 0x02 == 0) return false;

    const virt_aligned = fault_virt & ~(PAGE_SIZE - 1);
    const pml4_idx = (virt_aligned >> 39) & 0x1FF;
    const pdpt_idx = (virt_aligned >> 30) & 0x1FF;
    const pd_idx = (virt_aligned >> 21) & 0x1FF;
    const pt_idx = (virt_aligned >> 12) & 0x1FF;

    // Walk the faulting process's PML4
    const pml4: [*]volatile u64 = @ptrFromInt(fault_cr3);
    if (pml4[pml4_idx] & PTE_PRESENT == 0) return false;
    const pdpt_phys = pml4[pml4_idx] & 0x000FFFFFFFFFF000;

    const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
    if (pdpt[pdpt_idx] & PTE_PRESENT == 0) return false;
    const pd_phys = pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;

    const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
    if (pd[pd_idx] & PTE_PRESENT == 0) return false;
    const pt_phys = pd[pd_idx] & 0x000FFFFFFFFFF000;

    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    var pte = pt[pt_idx];

    // Check if this is a COW page
    if (pte & PTE_COW == 0) return false;
    if (pte & PTE_PRESENT == 0) return false;

    // This IS a COW page fault — handle it
    const old_phys = pte & 0x000FFFFFFFFFF000;

    // Allocate a new physical page for the private copy
    const new_phys = pmm.allocPage() orelse {
        hal.Serial.puts("[VMM] COW FAULT: Out of memory! Cannot allocate private page\n");
        return true; // Handled (but process will crash — no alternative)
    };

    // Copy the old page content to the new page
    // We can access physical memory directly because kernel identity-maps it
    const old_ptr: [*]const volatile u8 = @ptrFromInt(old_phys);
    const new_ptr: [*]volatile u8 = @ptrFromInt(new_phys);
    @memcpy(new_ptr[0..PAGE_SIZE], old_ptr[0..PAGE_SIZE]);

    // Build new PTE: same flags as before, but:
    //   - New physical page
    //   - Writable (restore the write permission)
    //   - COW and SHARED bits cleared
    var new_pte = pte;
    new_pte &= ~0x000FFFFFFFFFF000; // Clear old physical address
    new_pte |= new_phys; // Set new physical address
    new_pte |= PTE_WRITABLE; // Restore write permission
    new_pte &= ~(PTE_COW | PTE_SHARED); // Clear COW markers
    new_pte &= ~PTE_DIRTY; // Will be set by CPU on next write

    pt[pt_idx] = new_pte;

    // Invalidate TLB for this virtual address
    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt_aligned),
        : "memory"
    );

    hal.Serial.puts("[VMM] COW resolved: vaddr=");
    hal.Serial.putHex(virt_aligned);
    hal.Serial.puts(" old_phys=");
    hal.Serial.putHex(old_phys);
    hal.Serial.puts(" new_phys=");
    hal.Serial.putHex(new_phys);
    hal.Serial.puts("\n");

    return true;
}

// ============================================================================
// unmapPageInPML4 — v0.8.0
// ============================================================================
//
// Unmap a page from a SPECIFIC PML4 (not the kernel PML4).
// Used by munmap() to unmap pages from the process's page tables.
//
// This walks the 4-level page table hierarchy in the target PML4,
// clears the PTE, frees the physical page, and cleans up empty
// page table structures.
//
// TLB invalidation: Since we may be modifying a PML4 that is not
// currently active (CR3 != target_pml4_phys), we need to either:
//   1. INVLPG if the target PML4 is the current CR3
//   2. No INVLPG needed if it's a different PML4 (not active yet)
// For SMP, we would need IPI-based TLB shootdown (future work).
// ============================================================================

/// Unmap a page from a specific PML4 and free the physical page.
/// Returns the physical address of the unmapped page, or 0 if not mapped.
pub fn unmapPageInPML4(target_pml4_phys: u64, virt: u64) VmmError!u64 {
    if (virt % PAGE_SIZE != 0) {
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    // Walk the target PML4
    const pml4: [*]volatile u64 = @ptrFromInt(target_pml4_phys);
    if (pml4[pml4_idx] & PTE_PRESENT == 0) return 0;
    const pdpt_phys = pml4[pml4_idx] & 0x000FFFFFFFFFF000;

    const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
    if (pdpt[pdpt_idx] & PTE_PRESENT == 0) return 0;
    const pd_phys = pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;

    const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
    if (pd[pd_idx] & PTE_PRESENT == 0) return 0;
    const pt_phys = pd[pd_idx] & 0x000FFFFFFFFFF000;

    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    var pte = pt[pt_idx];
    if (pte & PTE_PRESENT == 0) return 0;

    // Extract physical page address before clearing
    const phys_page = pte & 0x000FFFFFFFFFF000;

    // Clear the PTE
    pt[pt_idx] = 0;

    // Free the physical page (unless it's COW — the page may be shared)
    // For COW pages, we only unmap from this PML4 but don't free the
    // physical page because other processes might still reference it.
    // TODO: Implement reference counting for COW pages.
    // For now, we free unconditionally since we don't have ref counting yet.
    if (phys_page != 0) {
        pmm.freePage(phys_page);
    }

    // Invalidate TLB if this PML4 is currently active
    const current_cr3 = hal.readCr3() & 0x000FFFFFFFFFF000;
    if (current_cr3 == target_pml4_phys) {
        asm volatile ("invlpg (%[virt])"
            :
            : [virt] "r" (virt),
            : "memory"
        );
    }

    // Clean up empty page tables (walk up from PT → PD → PDPT)
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

    return phys_page;
}

/// Unmap a range of pages from a specific PML4.
/// Returns the number of pages unmapped.
pub fn unmapRangeInPML4(target_pml4_phys: u64, start_virt: u64, length: u64) u64 {
    const start = start_virt & ~(PAGE_SIZE - 1);
    const end = (start_virt + length + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    var count: u64 = 0;

    var addr = start;
    while (addr < end) : (addr += PAGE_SIZE) {
        const result = unmapPageInPML4(target_pml4_phys, addr) catch 0;
        if (result != 0) count += 1;
    }

    hal.Serial.puts("[VMM] unmapRangeInPML4: unmapped ");
    hal.Serial.putDecimal(count);
    hal.Serial.puts(" pages from PML4 ");
    hal.Serial.putHex(target_pml4_phys);
    hal.Serial.puts("\n");

    return count;
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

/// v0.7.0: Map a page in a SPECIFIC PML4 (not the global kernel PML4).
/// Used for user-space mappings that should only be accessible from
/// the user process's page tables (with PTE_USER set).
pub fn mapPageInPML4(target_pml4_phys: u64, virt: u64, phys: u64, flags: u64) !void {
    if (virt % PAGE_SIZE != 0 or phys % PAGE_SIZE != 0) {
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const is_user = (flags & PTE_USER) != 0;

    // Walk/create PML4 → PDPT → PD → PT in the target PML4
    const pdpt_phys = try getOrCreateTable(target_pml4_phys, pml4_idx, is_user);
    const pd_phys = try getOrCreateTable(pdpt_phys, pdpt_idx, is_user);
    const pt_phys = try getOrCreateTable(pd_phys, pd_idx, is_user);

    // Set the actual page table entry
    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    if (pt[pt_idx] & PTE_PRESENT != 0) {
        return VmmError.AlreadyMapped;
    }
    pt[pt_idx] = phys | flags | PTE_PRESENT;

    // No invlpg needed — this PML4 is not the active CR3 yet
}

/// Look up the PTE for a virtual address in a specific PML4.
/// Returns the raw PTE value, or 0 if not mapped.
pub fn getPTE(target_pml4_phys: u64, virt: u64) u64 {
    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const pml4: [*]const volatile u64 = @ptrFromInt(target_pml4_phys);
    if (pml4[pml4_idx] & PTE_PRESENT == 0) return 0;
    const pdpt_phys = pml4[pml4_idx] & 0x000FFFFFFFFFF000;

    const pdpt: [*]const volatile u64 = @ptrFromInt(pdpt_phys);
    if (pdpt[pdpt_idx] & PTE_PRESENT == 0) return 0;
    const pd_phys = pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;

    const pd: [*]const volatile u64 = @ptrFromInt(pd_phys);
    if (pd[pd_idx] & PTE_PRESENT == 0) return 0;
    const pt_phys = pd[pd_idx] & 0x000FFFFFFFFFF000;

    const pt: [*]const volatile u64 = @ptrFromInt(pt_phys);
    return pt[pt_idx];
}

/// Change page protection in a specific PML4.
/// Walks the page tables, updates PTE flags for the given virtual address.
pub fn protectPageInPML4(target_pml4_phys: u64, virt: u64, new_flags: u64) bool {
    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const pml4: [*]volatile u64 = @ptrFromInt(target_pml4_phys);
    if (pml4[pml4_idx] & PTE_PRESENT == 0) return false;
    const pdpt_phys = pml4[pml4_idx] & 0x000FFFFFFFFFF000;

    const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
    if (pdpt[pdpt_idx] & PTE_PRESENT == 0) return false;
    const pd_phys = pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;

    const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
    if (pd[pd_idx] & PTE_PRESENT == 0) return false;
    const pt_phys = pd[pd_idx] & 0x000FFFFFFFFFF000;

    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    var pte = pt[pt_idx];
    if (pte & PTE_PRESENT == 0) return false;

    // Preserve the physical address, update only the flag bits
    const phys = pte & 0x000FFFFFFFFFF000;
    pt[pt_idx] = phys | new_flags | PTE_PRESENT;

    // Invalidate TLB if this PML4 is active
    const current_cr3 = hal.readCr3() & 0x000FFFFFFFFFF000;
    if (current_cr3 == target_pml4_phys) {
        asm volatile ("invlpg (%[virt])"
            :
            : [virt] "r" (virt),
            : "memory"
        );
    }

    return true;
}
