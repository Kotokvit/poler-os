// ============================================================================
// POLER-OS Virtual Memory Manager — x86_64
// ============================================================================

const std = @import("std");
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

// Active PML4 physical address (retrieved from CR3)
var pml4_phys: u64 = 0;

pub fn init() void {
    pml4_phys = hal.readCr3() & 0x000FFFFFFFFFF000;
    hal.Serial.puts("[VMM] Virtual Memory Manager initialized, PML4 at ");
    hal.Serial.putHex(pml4_phys);
    hal.Serial.puts("\n");
}

/// Helper to get or allocate a page table level
fn getOrCreateTable(table_phys: u64, index: usize) !u64 {
    const table: [*]volatile u64 = @ptrFromInt(table_phys);
    const entry = table[index];

    if (entry & PTE_PRESENT != 0) {
        if (entry & PTE_HUGE != 0) {
            return VmmError.AlreadyMapped;
        }
        return entry & 0x000FFFFFFFFFF000;
    }


    // Allocate a new page table page via PMM
    const new_table_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
    
    // Clear the new table page
    const ptr: [*]volatile u64 = @ptrFromInt(new_table_phys);
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        ptr[i] = 0;
    }

    // Set the table entry pointing to the new page table (Writable + User + Present)
    table[index] = new_table_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
    
    return new_table_phys;
}

pub fn mapPage(virt: u64, phys: u64, flags: u64) !void {
    if (virt % PAGE_SIZE != 0 or phys % PAGE_SIZE != 0) {
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const pdpt_phys = try getOrCreateTable(pml4_phys, pml4_idx);
    const pd_phys = try getOrCreateTable(pdpt_phys, pdpt_idx);
    const pt_phys = try getOrCreateTable(pd_phys, pd_idx);

    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    pt[pt_idx] = phys | flags | PTE_PRESENT;

    // Flush TLB entry
    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );
}

pub fn unmapPage(virt: u64) void {
    if (virt % PAGE_SIZE != 0) return;

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

    // Flush TLB
    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );
}
