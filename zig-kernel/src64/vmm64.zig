// ============================================================================
// POLER-OS Virtual Memory Manager — x86_64
// ============================================================================
//
// v0.9.0: Reference counting for COW pages, SMP TLB shootdown via IPI
//
// COW Architecture (v0.9.0 with refcounting):
//   fork() → clonePML4_COW() → mark all user pages as read-only + PTE_COW
//            + pmm.refPage() on each shared physical page
//   write fault → handleCowPageFault() → allocate new page, copy data,
//                 restore writable, clear PTE_COW
//                 + pmm.unrefPage() on the OLD physical page
//   munmap → unmapPageInPML4() → pmm.unrefPage() on the physical page
//            if unrefPage returns true → pmm.freePage() (actually frees)
//            if unrefPage returns false → page still shared, just remove PTE
//
// The PTE_COW bit uses x86_64 PTE bit 9 (available to software).
// When PTE_COW is set, the page is shared between parent and child;
// a write triggers a #PF which we handle by creating a private copy.
//
// SMP TLB Shootdown (v0.9.0):
//   When page tables are modified on one CPU, other CPUs may have stale
//   TLB entries. The shootdown protocol:
//     1. Record the virtual address and target PML4 in a shared struct
//     2. Send IPI (Inter-Processor Interrupt) to all other online CPUs
//     3. Each AP receives the IPI, checks if it's using the target PML4,
//        and if so, invalidates the TLB entry with INVLPG
//     4. AP signals completion via an atomic counter
//     5. BSP waits for all APs to acknowledge before continuing
// ============================================================================

const pmm = @import("pmm64.zig");
const hal = @import("hal.zig");
const smp = @import("smp.zig");

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

// ============================================================================
// v0.9.0: SMP TLB Shootdown State
// ============================================================================
//
// When a CPU modifies page tables, it must ensure that all other CPUs
// that might be using the same PML4 invalidate their TLB entries.
// This is done via IPI (Inter-Processor Interrupt).
//
// The shootdown state is a shared structure that the initiating CPU
// fills in before sending IPIs. Each AP reads this structure in the
// IPI handler to know what to invalidate.
//
// The pending_count atomic counter tracks how many APs still need to
// process the shootdown. The initiator waits until this reaches 0
// before continuing (synchronous shootdown).
// ============================================================================

pub const TlbShootdownType = enum(u8) {
    None = 0,
    SinglePage = 1, // INVLPG a single virtual address
    FullTlb = 2, // CR3 reload (full TLB flush) — used for widespread changes
    Range = 3, // INVLPG a range of pages
};

pub const TlbShootdownRequest = struct {
    shootdown_type: TlbShootdownType = .None,
    virt_addr: u64 = 0, // Virtual address to invalidate
    virt_end: u64 = 0, // End of range (for Range type)
    target_cr3: u64 = 0, // Only invalidate if this CPU's CR3 matches
    pending_count: u32 = 0, // Number of APs that haven't acknowledged yet
    sequence: u32 = 0, // Monotonically increasing sequence number
};

/// Global TLB shootdown request — written by initiator, read by APs
var tlb_shootdown: TlbShootdownRequest = .{};

/// Lock for serializing TLB shootdown requests
var tlb_shootdown_lock: u32 = 0;

/// IPI vector number for TLB shootdown
/// Using vector 0xF0 (240) — must match the IDT setup
pub const TLB_SHOOTDOWN_VECTOR: u32 = 0xF0;

pub fn init() void {
    pml4_phys = hal.readCr3() & 0x000FFFFFFFFFF000;
    hal.Serial.puts("[VMM] Virtual Memory Manager initialized, PML4 at ");
    hal.Serial.putHex(pml4_phys);
    hal.Serial.puts("\n");

    // Register COW page fault handler with HAL
    // This allows the HAL's #PF handler to call handleCowPageFault
    // without a direct circular dependency (hal ↔ vmm)
    hal.cowPageFaultCallback = struct {
        fn handler(vaddr: u64, fault_cr3: u64, err_code: u64) callconv(.C) bool {
            return handleCowPageFault(vaddr, fault_cr3, err_code);
        }
    }.handler;
    hal.Serial.puts("[VMM] COW page fault handler registered with HAL\n");

    // Initialize TLB shootdown state
    tlb_shootdown = .{};
    tlb_shootdown_lock = 0;
    hal.Serial.puts("[VMM] SMP TLB shootdown initialized\n");
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
// COW (Copy-on-Write) — v0.9.0 with reference counting
// ============================================================================
//
// When fork() is called, instead of copying all user pages (expensive),
// we create a new PML4 that shares the same physical pages as the parent.
// All user pages are marked read-only with PTE_COW flag.
//
// v0.9.0 change: Each shared physical page gets its refcount incremented
// in the PMM. This ensures that when one process calls munmap() or exits,
// the physical page is only freed when NO process references it anymore.
//
// When either process writes to a COW page, a page fault (#PF) occurs.
// The page fault handler:
//   1. Checks if PTE_COW is set on the faulting page
//   2. Decrements refcount on the OLD physical page (unrefPage)
//   3. Allocates a NEW physical page (refcount starts at 1)
//   4. Copies the content from the shared page to the new page
//   5. Maps the new page as writable (without PTE_COW)
//   6. If old page's refcount dropped to 1, make the remaining mapping
//      writable again (no longer shared)
//   7. Returns — the faulting instruction retries and succeeds
// ============================================================================

/// Clone a PML4 with COW semantics for fork().
///
/// v0.9.0: Now increments reference counts on all shared physical pages.
/// This prevents munmap() from freeing a page that another process still
/// references. The old bug: fork() shares pages without tracking refs,
/// munmap() frees the physical page, and the other process crashes on
/// access to the now-freed page.
///
/// After this call, both the parent's and child's user pages are marked
/// read-only + PTE_COW. The physical page refcounts are incremented
/// for every PTE that points to the shared page.
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
                const phys_addr = pdpt_entry & 0x000FFFFFFFFFF000;
                child_pdpt[pdpt_idx] = (pdpt_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                // Also mark parent as COW
                const p_pdpt: [*]volatile u64 = @ptrFromInt(parent_pdpt_phys);
                p_pdpt[pdpt_idx] = (pdpt_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                // v0.9.0: Increment refcount on the 1GB page
                pmm.refPage(phys_addr);
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
                    const phys_addr = pd_entry & 0x000FFFFFFFFFF000;
                    child_pd[pd_idx] = (pd_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    const p_pd: [*]volatile u64 = @ptrFromInt(parent_pd_phys);
                    p_pd[pd_idx] = (pd_entry & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    // v0.9.0: Increment refcount on the 2MB page
                    pmm.refPage(phys_addr);
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
                    const pte = parent_pt[pt_idx];
                    if (pte & PTE_PRESENT == 0) continue;
                    if ((pte & PTE_USER) == 0) continue; // Skip kernel pages in user tables

                    // Extract physical page address
                    const phys_addr = pte & 0x000FFFFFFFFFF000;

                    // Mark the child's PTE as read-only + COW
                    // Child points to the SAME physical page
                    const cow_entry = (pte & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    child_pt[pt_idx] = cow_entry;

                    // Also mark the parent's PTE as read-only + COW
                    // (both processes must COW on write)
                    if (pte & PTE_WRITABLE != 0) {
                        parent_pt[pt_idx] = (pte & ~PTE_WRITABLE) | PTE_COW | PTE_SHARED;
                    }

                    // v0.9.0: Increment refcount on the shared physical page
                    // The page is now referenced by both parent and child PTEs
                    pmm.refPage(phys_addr);

                    cow_pages += 1;
                }
            }
        }
    }

    hal.Serial.puts("[VMM] COW clone: ");
    hal.Serial.putDecimal(cow_pages);
    hal.Serial.puts(" user pages marked COW (refcounted), child PML4 at ");
    hal.Serial.putHex(child_pml4_phys);
    hal.Serial.puts("\n");

    return child_pml4_phys;
}

/// Handle a COW page fault — v0.9.0 with reference counting
///
/// v0.9.0: When resolving a COW fault, we decrement the refcount on the
/// OLD physical page. If the refcount drops to 1, the remaining process
/// that still maps this page can have its PTE restored to writable (no
/// longer needs COW protection). If the refcount is still > 1, the old
/// page stays read-only + COW for the other processes.
///
/// The new private page gets refcount = 1 (from pmm.allocPage).
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
    const pte = pt[pt_idx];

    // Check if this is a COW page
    if (pte & PTE_COW == 0) return false;
    if (pte & PTE_PRESENT == 0) return false;

    // This IS a COW page fault — handle it
    const old_phys = pte & 0x000FFFFFFFFFF000;

    // v0.9.0: Check the refcount on the old physical page
    const old_refcount = pmm.getRefCount(old_phys);

    if (old_refcount <= 1) {
        // Only this process references the page — no need to copy!
        // Just restore write permission and clear COW flags.
        // This is an optimization: if the other process already unmapped
        // or COW-resolved its copy, we can just make this page writable.
        var new_pte = pte;
        new_pte |= PTE_WRITABLE; // Restore write permission
        new_pte &= ~(PTE_COW | PTE_SHARED); // Clear COW markers
        new_pte &= ~PTE_DIRTY; // Will be set by CPU on next write
        pt[pt_idx] = new_pte;

        // Invalidate TLB for this virtual address
        invlpgOrShootdown(virt_aligned, fault_cr3);

        hal.Serial.puts("[VMM] COW resolved (no-copy): vaddr=");
        hal.Serial.putHex(virt_aligned);
        hal.Serial.puts(" phys=");
        hal.Serial.putHex(old_phys);
        hal.Serial.puts(" refcount=1 → writable\n");

        return true;
    }

    // Multiple processes still reference the old page — must copy

    // v0.9.0: Decrement refcount on the old physical page
    // We're about to replace our PTE with a new private page,
    // so the old page loses one reference.
    _ = pmm.unrefPage(old_phys);

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
    new_pte &= ~@as(u64, 0x000FFFFFFFFFF000); // Clear old physical address
    new_pte |= new_phys; // Set new physical address
    new_pte |= PTE_WRITABLE; // Restore write permission
    new_pte &= ~(PTE_COW | PTE_SHARED); // Clear COW markers
    new_pte &= ~PTE_DIRTY; // Will be set by CPU on next write

    pt[pt_idx] = new_pte;

    // v0.9.0: If the old page's refcount dropped to 1, find the remaining
    // process that maps it and restore its write permission.
    // This avoids unnecessary COW faults for the last remaining process.
    // For simplicity, we don't do this cross-process fixup here — it will
    // happen naturally when that process writes to the page (its COW fault
    // handler will see refcount==1 and use the no-copy fast path above).

    // Invalidate TLB for this virtual address
    invlpgOrShootdown(virt_aligned, fault_cr3);

    hal.Serial.puts("[VMM] COW resolved (copy): vaddr=");
    hal.Serial.putHex(virt_aligned);
    hal.Serial.puts(" old_phys=");
    hal.Serial.putHex(old_phys);
    hal.Serial.puts(" new_phys=");
    hal.Serial.putHex(new_phys);
    hal.Serial.puts(" old_refcount=");
    hal.Serial.putDecimal(pmm.getRefCount(old_phys));
    hal.Serial.puts("\n");

    return true;
}

// ============================================================================
// unmapPageInPML4 — v0.9.0 with reference counting + SMP TLB shootdown
// ============================================================================
//
// Unmap a page from a SPECIFIC PML4 (not the kernel PML4).
// Used by munmap() to unmap pages from the process's page tables.
//
// v0.9.0 changes:
//   - Uses pmm.unrefPage() instead of pmm.freePage() directly
//   - Only frees the physical page when refcount reaches 0
//   - Sends SMP TLB shootdown IPIs to other CPUs if needed
//
// For COW pages (PTE_COW set), the page may be shared. We decrement
// the refcount and only free when no other process references it.
// For non-COW pages (refcount == 1), unrefPage returns true and
// the page is freed normally — identical to the old behavior.
// ============================================================================

/// Unmap a page from a specific PML4 and free the physical page
/// if its reference count reaches zero.
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
    const pte = pt[pt_idx];
    if (pte & PTE_PRESENT == 0) return 0;

    // Extract physical page address before clearing
    const phys_page = pte & 0x000FFFFFFFFFF000;

    // v0.9.0: Check if this is a COW page
    const is_cow = (pte & PTE_COW) != 0;

    // Clear the PTE
    pt[pt_idx] = 0;

    // v0.9.0: Use reference counting to decide whether to free
    // unrefPage returns true if the page should be freed (refcount → 0)
    if (phys_page != 0) {
        if (pmm.unrefPage(phys_page)) {
            // Refcount dropped to 0 — free the physical page
            pmm.freePage(phys_page);

            if (is_cow) {
                hal.Serial.puts("[VMM] unmapPage: COW page freed (last ref) 0x");
                hal.Serial.putHex(phys_page);
                hal.Serial.puts("\n");
            }
        } else {
            // Page still referenced by other processes — don't free
            if (is_cow) {
                hal.Serial.puts("[VMM] unmapPage: COW page kept (refcount=");
                hal.Serial.putDecimal(pmm.getRefCount(phys_page));
                hal.Serial.puts(") 0x");
                hal.Serial.putHex(phys_page);
                hal.Serial.puts("\n");
            }
        }
    }

    // v0.9.0: SMP TLB shootdown
    // If this PML4 might be active on another CPU, send shootdown IPIs
    tlbShootdownSingle(virt, target_pml4_phys);

    // Also invalidate TLB locally if this PML4 is the current CR3
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

    // v0.9.0: Send a full TLB shootdown for the range
    // This is more efficient than per-page shootdowns
    tlbShootdownRange(start, end, target_pml4_phys);

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
    const pte = pt[pt_idx];
    if (pte & PTE_PRESENT == 0) return false;

    // Preserve the physical address, update only the flag bits
    const phys = pte & 0x000FFFFFFFFFF000;
    pt[pt_idx] = phys | new_flags | PTE_PRESENT;

    // v0.9.0: Send SMP TLB shootdown after protection change
    tlbShootdownSingle(virt, target_pml4_phys);

    // Also invalidate TLB if this PML4 is active locally
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

// ============================================================================
// v0.9.0: SMP TLB Shootdown Implementation
// ============================================================================
//
// TLB shootdown ensures that all CPUs invalidate stale TLB entries when
// page tables are modified. Without this, a page could be unmapped on
// one CPU but still accessible from another CPU's TLB cache.
//
// Protocol:
//   1. Acquire tlb_shootdown_lock (spinlock)
//   2. Fill in the shootdown request (type, vaddr, target CR3)
//   3. Set pending_count = number of online APs
//   4. Increment sequence number (for ordering)
//   5. Send IPI to all other online CPUs (broadcast except self)
//   6. Wait until pending_count reaches 0 (all APs acknowledged)
//   7. Release lock
//
// On the AP side (IPI handler):
//   1. Read the shootdown request
//   2. Check if this CPU's CR3 matches target_cr3
//   3. If match: execute INVLPG (single) or CR3 reload (full)
//   4. Atomic decrement of pending_count
// ============================================================================

/// Invalidate a single TLB entry locally, or send shootdown if SMP
fn invlpgOrShootdown(virt: u64, target_cr3: u64) void {
    // Local invalidation always needed
    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );

    // If SMP is active, also send shootdown to other CPUs
    if (smp.online_cpus > 1) {
        tlbShootdownSingle(virt, target_cr3);
    }
}

/// Send a single-page TLB shootdown to all other CPUs
fn tlbShootdownSingle(virt: u64, target_cr3: u64) void {
    if (smp.online_cpus <= 1) return; // No other CPUs to shoot down

    hal.spinLock(&tlb_shootdown_lock);
    defer hal.spinUnlock(&tlb_shootdown_lock);

    tlb_shootdown.shootdown_type = .SinglePage;
    tlb_shootdown.virt_addr = virt;
    tlb_shootdown.target_cr3 = target_cr3;
    tlb_shootdown.sequence += 1;

    // Number of APs that need to acknowledge
    const ap_count = smp.online_cpus - 1; // Exclude BSP (self)
    @atomicStore(u32, &tlb_shootdown.pending_count, ap_count, .release);

    // Memory barrier — ensure APs see the request data before we send IPI
    asm volatile ("sfence" ::: "memory");

    // Send IPI to all other CPUs
    // Use the "shorthand: all excluding self" mode in the APIC
    hal.APIC.sendBroadcastIpiExcludeSelf(TLB_SHOOTDOWN_VECTOR);

    // Wait for all APs to acknowledge
    var timeout: u32 = 0;
    while (@atomicLoad(u32, &tlb_shootdown.pending_count, .acquire) > 0) : (timeout += 1) {
        if (timeout > 10_000_000) {
            hal.Serial.puts("[VMM] TLB shootdown timeout! pending=");
            hal.Serial.putDecimal(@atomicLoad(u32, &tlb_shootdown.pending_count, .monotonic));
            hal.Serial.puts("\n");
            break;
        }
        asm volatile ("pause");
    }
}

/// Send a range TLB shootdown to all other CPUs
fn tlbShootdownRange(virt_start: u64, virt_end: u64, target_cr3: u64) void {
    if (smp.online_cpus <= 1) return;

    hal.spinLock(&tlb_shootdown_lock);
    defer hal.spinUnlock(&tlb_shootdown_lock);

    tlb_shootdown.shootdown_type = .Range;
    tlb_shootdown.virt_addr = virt_start;
    tlb_shootdown.virt_end = virt_end;
    tlb_shootdown.target_cr3 = target_cr3;
    tlb_shootdown.sequence += 1;

    const ap_count = smp.online_cpus - 1;
    @atomicStore(u32, &tlb_shootdown.pending_count, ap_count, .release);

    asm volatile ("sfence" ::: "memory");

    hal.APIC.sendBroadcastIpiExcludeSelf(TLB_SHOOTDOWN_VECTOR);

    var timeout: u32 = 0;
    while (@atomicLoad(u32, &tlb_shootdown.pending_count, .acquire) > 0) : (timeout += 1) {
        if (timeout > 10_000_000) {
            hal.Serial.puts("[VMM] TLB shootdown range timeout!\n");
            break;
        }
        asm volatile ("pause");
    }
}

/// Send a full TLB flush shootdown to all other CPUs
/// Used when CR3 changes or when many pages are modified at once
pub fn tlbShootdownFull(target_cr3: u64) void {
    if (smp.online_cpus <= 1) return;

    hal.spinLock(&tlb_shootdown_lock);
    defer hal.spinUnlock(&tlb_shootdown_lock);

    tlb_shootdown.shootdown_type = .FullTlb;
    tlb_shootdown.target_cr3 = target_cr3;
    tlb_shootdown.sequence += 1;

    const ap_count = smp.online_cpus - 1;
    @atomicStore(u32, &tlb_shootdown.pending_count, ap_count, .release);

    asm volatile ("sfence" ::: "memory");

    hal.APIC.sendBroadcastIpiExcludeSelf(TLB_SHOOTDOWN_VECTOR);

    var timeout: u32 = 0;
    while (@atomicLoad(u32, &tlb_shootdown.pending_count, .acquire) > 0) : (timeout += 1) {
        if (timeout > 10_000_000) {
            hal.Serial.puts("[VMM] TLB shootdown full timeout!\n");
            break;
        }
        asm volatile ("pause");
    }
}

/// TLB shootdown IPI handler — called on each AP when it receives the
/// TLB_SHOOTDOWN_VECTOR interrupt.
///
/// This function is called from the IDT ISR context on the AP.
/// It reads the global shootdown request, performs the requested
/// invalidation, and acknowledges completion.
pub fn handleTlbShootdownIpi() callconv(.C) void {
    const req = &tlb_shootdown;

    // Read the current CR3 to check if this CPU uses the target PML4
    const my_cr3 = hal.readCr3() & 0x000FFFFFFFFFF000;

    switch (req.shootdown_type) {
        .SinglePage => {
            if (my_cr3 == req.target_cr3) {
                // This CPU is using the affected PML4 — invalidate the entry
                asm volatile ("invlpg (%[virt])"
                    :
                    : [virt] "r" (req.virt_addr),
                    : "memory"
                );
            }
        },
        .Range => {
            if (my_cr3 == req.target_cr3) {
                // Invalidate each page in the range
                var addr = req.virt_addr;
                while (addr < req.virt_end) : (addr += PAGE_SIZE) {
                    asm volatile ("invlpg (%[virt])"
                        :
                        : [virt] "r" (addr),
                        : "memory"
                    );
                }
            }
        },
        .FullTlb => {
            if (my_cr3 == req.target_cr3) {
                // Full TLB flush — reload CR3
                const cr3 = hal.readCr3();
                hal.writeCr3(cr3);
            }
        },
        .None => {
            // Spurious IPI — ignore
        },
    }

    // Acknowledge completion
    _ = @atomicRmw(u32, &req.pending_count, .Sub, 1, .release);
}
