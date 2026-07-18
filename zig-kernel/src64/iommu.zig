// ============================================================================
// POLER-OS Intel VT-d IOMMU Driver — iommu.zig
// ============================================================================
//
// Zig 0.13.0 · freestanding kernel module (no std)
//
// Implements Intel Virtualization Technology for Directed I/O (VT-d) to
// protect against DMA attacks. Without IOMMU, a malicious or compromised
// device (e.g. virtio-blk in a malicious hypervisor scenario) can DMA to
// any physical address — including kernel code, page tables, and credentials.
//
// P0 Implementation:
//   - DMAR table detection via ACPI
//   - Root Table + Context Table + Second-Level Page Tables
//   - Identity-mapped IOMMU translations for approved DMA regions only
//   - Graceful fallback to identity mapping when VT-d unavailable
//
// Usage:
//   iommu.init()                           — detect & enable VT-d
//   iommu.mapVirtioDma(bus, slot, ...)    — approve DMA region for device
//   iommu.isDmaAllowed(bus, dev, ...)     — check if DMA is approved
//
// QEMU: -machine q35 -device intel-iommu,intremap=on
// ============================================================================

const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");

// ============================================================================
// §1  VT-d Register Offsets & Flags
// ============================================================================

const VTD_REG_VER: u32 = 0x00;
const VTD_REG_CAP: u32 = 0x08;
const VTD_REG_ECAP: u32 = 0x10;
const VTD_REG_GCMD: u32 = 0x18;
const VTD_REG_GSTS: u32 = 0x1C;
const VTD_REG_RTADDR: u32 = 0x20;
const VTD_REG_CCMD: u32 = 0x28;
const VTD_REG_FSTS: u32 = 0x34;
const VTD_REG_FECTL: u32 = 0x38;

const GCMD_TE: u32 = 1 << 31; // Translation Enable
const GCMD_SRTP: u32 = 1 << 30; // Set Root Table Pointer
const GSTS_TES: u32 = 1 << 31; // Translation Enable Status
const GSTS_RTPS: u32 = 1 << 30; // Root Table Pointer Status

// CCMD (Context Command) flags
const CCMD_ICC: u64 = 1 << 63; // Invalidate Context-Cache
const CCMD_CIRG_GLOBAL: u64 = 1 << 61; // Global invalidation

// IOTLB invalidation
const VTD_REG_IVA: u32 = 0x48; // Invalidate Address
const VTD_REG_IOTLB: u32 = 0x40; // IOTLB Invalidate
const IOTLB_IVT: u64 = 1 << 63; // Invalidate IOTLB
const IOTLB_IIRG_GLOBAL: u64 = 0 << 60; // Global invalidation
const IOTLB_DR: u64 = 1 << 49; // Drain Reads
const IOTLB_DW: u64 = 1 << 48; // Drain Writes

// ============================================================================
// §2  VT-d Data Structures
// ============================================================================

/// Root Table Entry (16 bytes) — one per PCI bus (256 entries = 4KB)
const VtdRootEntry = packed struct {
    present: u1,
    _rsvd1: u11,
    context_table_ptr: u52, // Physical address of context table (4KB aligned)
    _rsvd2: u64,
};

/// Context Table Entry (16 bytes) — one per Device:Function (256 entries = 4KB)
const VtdContextEntry = packed struct {
    present: u1,
    _rsvd1: u11,
    second_level_ptr: u52, // Physical address of second-level page table
    address_width: u2, // 0=39-bit, 1=48-bit, 2=57-bit, 3=64-bit
    _rsvd2: u6,
    _rsvd3: u32,
    _rsvd4: u64,
};

/// Second-Level Page Table Entry (8 bytes) — maps IOVA → physical page
const VtdSlpte = packed struct {
    present: u1,
    write: u1, // Write permission
    read: u1, // Read permission (if 0, write-only if write=1)
    _rsvd1: u5,
    page_frame: u40, // Physical page frame number
    _rsvd2: u7,
    pat: u1,
    _rsvd3: u1,
    _rsvd4: u7,
};

/// Approved DMA region — tracks which physical ranges a device can access
const DmaRegion = struct {
    bus: u8,
    dev: u8,
    func: u8,
    phys_start: u64,
    size: u64,
    active: bool,
};

// ============================================================================
// §3  Global VT-d State
// ============================================================================

const MAX_DMA_REGIONS: usize = 32;
const VTD_AW_39BIT: u2 = 0; // 3-level paging, 30-bit IOVA
const VTD_AW_48BIT: u2 = 1; // 4-level paging, 39-bit IOVA

var vtd_state: struct {
    register_base: u64 = 0,
    is_enabled: bool = false,
    is_available: bool = false,
    root_table_phys: u64 = 0,
    // Track allocated context tables (one per bus that has devices)
    context_tables: [256]?u64 = .{null} ** 256,
    // Track allocated second-level page tables (keyed by bus*32 + dev*8 + func)
    slpt_tables: [256]?u64 = .{null} ** 256,
    // Approved DMA regions
    approved_regions: [MAX_DMA_REGIONS]DmaRegion = undefined,
    approved_count: usize = 0,
} = .{};

// ============================================================================
// §4  Register Access Helpers
// ============================================================================

fn readReg32(offset: u32) u32 {
    if (vtd_state.register_base == 0) return 0;
    const ptr: *volatile u32 = @ptrFromInt(vtd_state.register_base + offset);
    return ptr.*;
}

fn writeReg32(offset: u32, val: u32) void {
    if (vtd_state.register_base == 0) return;
    const ptr: *volatile u32 = @ptrFromInt(vtd_state.register_base + offset);
    ptr.* = val;
}

fn readReg64(offset: u32) u64 {
    if (vtd_state.register_base == 0) return 0;
    const ptr: *volatile u64 = @ptrFromInt(vtd_state.register_base + offset);
    return ptr.*;
}

fn writeReg64(offset: u32, val: u64) void {
    if (vtd_state.register_base == 0) return;
    const ptr: *volatile u64 = @ptrFromInt(vtd_state.register_base + offset);
    ptr.* = val;
}

// ============================================================================
// §5  DMAR Table Detection
// ============================================================================

/// ACPI DMAR table header (standard ACPI header + DMAR-specific fields)
const DmarHeader = extern struct {
    signature: [4]u8, // "DMAR"
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: [4]u8,
    creator_revision: u32,
    host_address_width: u8, // Maximum DMA physical address width - 1
    flags: u8, // bit 0: INTR_REMAP, bit 1: X2APIC_OPT_OUT
    _rsvd: [2]u8,
};

/// DMA Remapping Hardware Unit Definition (DRHD) — type 0
const DmarDrhd = extern struct {
    type: u16, // 0 = DRHD
    length: u16,
    flags: u8, // bit 0: INCLUDE_PCI_ALL
    _rsvd: u8,
    segment: u16,
    register_base: u64, // VT-d register base address
};

/// Scan a memory range for the DMAR table signature
fn scanForDmar(start: u64, end: u64) ?u64 {
    // ACPI tables are 16-byte aligned
    var addr = start;
    while (addr + @sizeOf(DmarHeader) <= end) : (addr += 16) {
        const header: *const DmarHeader = @ptrFromInt(addr);
        if (header.signature[0] == 'D' and
            header.signature[1] == 'M' and
            header.signature[2] == 'A' and
            header.signature[3] == 'R')
        {
            if (header.length >= @sizeOf(DmarHeader)) {
                return addr;
            }
        }
    }
    return null;
}

// ============================================================================
// §6  VT-d Initialization
// ============================================================================

pub fn init() void {
    hal.Serial.puts("[IOMMU] Initializing Intel VT-d...\n");

    // 1. Check CPUID for VT-d support (VMX/EPT doesn't guarantee VT-d,
    //    but we check for IOMMU via ACPI DMAR table)
    // Actually, VT-d is chipset-level, not CPU-level. We detect via ACPI.

    // 2. Search for DMAR table in common ACPI locations
    //    ACPI RSDP is typically at 0xE0000-0xFFFFF or 0x40E pointer
    var dmar_addr: ?u64 = null;

    // Search EBDA (Extended BIOS Data Area) region and ACPI area
    // The RSDP pointer is stored at physical 0x40E (16-bit pointer to EBDA)
    const ebda_ptr_phys: u16 = @as(*volatile u16, @ptrFromInt(0x40E)).*;
    if (ebda_ptr_phys != 0) {
        dmar_addr = scanForDmar(@as(u64, ebda_ptr_phys) << 4, (@as(u64, ebda_ptr_phys) << 4) + 0x400);
    }

    // Search BIOS ROM area
    if (dmar_addr == null) {
        dmar_addr = scanForDmar(0xE0000, 0x100000);
    }

    if (dmar_addr == null) {
        hal.Serial.puts("[IOMMU] DMAR table not found — VT-d unavailable\n");
        hal.Serial.puts("[IOMMU] DMA protection DISABLED (identity mapping fallback)\n");
        vtd_state.is_available = false;
        return;
    }

    hal.Serial.puts("[IOMMU] DMAR table found at ");
    hal.Serial.putHex(dmar_addr.?);
    hal.Serial.puts("\n");

    // 3. Parse DMAR header
    const dmar: *const DmarHeader = @ptrFromInt(dmar_addr.?);
    hal.Serial.puts("[IOMMU] Host Address Width: ");
    hal.Serial.putDecimal(dmar.host_address_width);
    hal.Serial.puts(" bits\n");

    // 4. Walk DMAR remapping structures to find DRHD entries
    var offset: usize = @sizeOf(DmarHeader);
    var found_engine: bool = false;
    while (offset + 4 <= dmar.length) {
        const sub: *const DmarDrhd = @ptrFromInt(dmar_addr.? + offset);

        if (sub.type == 0) { // DRHD
            hal.Serial.puts("[IOMMU] DRHD: segment=");
            hal.Serial.putHex(sub.segment);
            hal.Serial.puts(" reg_base=0x");
            hal.Serial.putHex(sub.register_base);
            hal.Serial.puts(" flags=0x");
            hal.Serial.putHex(sub.flags);
            hal.Serial.puts("\n");

            // Use the first DRHD with INCLUDE_PCI_ALL or the first one found
            if (!found_engine) {
                vtd_state.register_base = sub.register_base;
                found_engine = true;

                // If INCLUDE_PCI_ALL flag is set, this covers all devices
                if (sub.flags & 0x01 != 0) {
                    hal.Serial.puts("[IOMMU] INCLUDE_PCI_ALL — covers all PCI devices\n");
                }
            }
        }

        if (sub.length == 0) break; // Prevent infinite loop
        offset += sub.length;
    }

    if (!found_engine) {
        hal.Serial.puts("[IOMMU] No DRHD remapping unit found in DMAR\n");
        vtd_state.is_available = false;
        return;
    }

    // 5. Read VT-d version and capabilities
    const ver = readReg32(VTD_REG_VER);
    hal.Serial.puts("[IOMMU] VT-d version: ");
    hal.Serial.putHex((ver >> 16) & 0xFF);
    hal.Serial.puts(".");
    hal.Serial.putHex((ver >> 8) & 0xFF);
    hal.Serial.puts(".");
    hal.Serial.putHex(ver & 0xFF);
    hal.Serial.puts("\n");

    const cap = readReg64(VTD_REG_CAP);
    const ecap = readReg64(VTD_REG_ECAP);
    hal.Serial.puts("[IOMMU] CAP: 0x");
    hal.Serial.putHex(cap);
    hal.Serial.puts(" ECAP: 0x");
    hal.Serial.putHex(ecap);
    hal.Serial.puts("\n");

    // 6. Allocate root table (must be 4KB aligned)
    const root_phys = pmm.allocPage() orelse {
        hal.Serial.puts("[IOMMU] ERROR: Failed to allocate root table\n");
        vtd_state.is_available = false;
        return;
    };
    const root_ptr: [*]volatile u8 = @ptrFromInt(root_phys);
    @memset(root_ptr[0..4096], 0);
    vtd_state.root_table_phys = root_phys;

    hal.Serial.puts("[IOMMU] Root table at 0x");
    hal.Serial.putHex(root_phys);
    hal.Serial.puts("\n");

    // 7. Initialize approved regions array
    for (&vtd_state.approved_regions) |*region| {
        region.active = false;
    }
    vtd_state.approved_count = 0;

    vtd_state.is_available = true;
    hal.Serial.puts("[IOMMU] VT-d hardware detected and configured (not yet enabled)\n");
    hal.Serial.puts("[IOMMU] Call enable() after setting up DMA mappings\n");
}

// ============================================================================
// §7  DMA Mapping Setup
// ============================================================================

/// Add a DMA region to the approved list and set up IOMMU mappings.
/// Returns true if IOMMU is available and mapping succeeded.
/// Returns false if IOMMU is not available (caller should use identity mapping).
pub fn mapVirtioDma(pci_bus: u8, pci_slot: u8, dma_phys: u64, dma_size: u64) bool {
    if (!vtd_state.is_available) {
        return false;
    }

    hal.Serial.puts("[IOMMU] Mapping DMA for bus=0x");
    hal.Serial.putHex(pci_bus);
    hal.Serial.puts(" slot=0x");
    hal.Serial.putHex(pci_slot);
    hal.Serial.puts(" phys=0x");
    hal.Serial.putHex(dma_phys);
    hal.Serial.puts(" size=0x");
    hal.Serial.putHex(dma_size);
    hal.Serial.puts("\n");

    // Add to approved regions
    if (!addApprovedRegion(pci_bus, pci_slot, 0, dma_phys, dma_size)) {
        hal.Serial.puts("[IOMMU] WARNING: Failed to add approved region (table full)\n");
    }

    // Set up IOMMU page tables for this device
    if (!setupDmaMapping(pci_bus, pci_slot, 0, dma_phys, dma_size)) {
        hal.Serial.puts("[IOMMU] WARNING: Failed to set up IOMMU mapping\n");
        return false;
    }

    return true;
}

/// Check if a DMA access is allowed for a device
pub fn isDmaAllowed(bus: u8, dev: u8, func: u8, phys: u64, size: u64) bool {
    // If IOMMU is not enabled, all DMA is allowed (legacy mode)
    if (!vtd_state.is_enabled) return true;

    for (vtd_state.approved_regions[0..vtd_state.approved_count]) |region| {
        if (region.active and region.bus == bus and region.dev == dev and region.func == func) {
            if (phys >= region.phys_start and phys + size <= region.phys_start + region.size) {
                return true;
            }
        }
    }
    return false;
}

fn addApprovedRegion(bus: u8, dev: u8, func: u8, phys_start: u64, size: u64) bool {
    if (vtd_state.approved_count >= MAX_DMA_REGIONS) return false;

    // Check for overlap with existing regions — merge if adjacent/overlapping
    for (&vtd_state.approved_regions) |*region| {
        if (region.active and region.bus == bus and region.dev == dev and region.func == func) {
            // Extend existing region if overlapping or adjacent
            const new_end = phys_start + size;
            const old_end = region.phys_start + region.size;
            if (phys_start <= old_end and new_end >= region.phys_start) {
                // Regions overlap or are adjacent — merge
                const merged_start = if (phys_start < region.phys_start) phys_start else region.phys_start;
                const merged_end = if (new_end > old_end) new_end else old_end;
                region.phys_start = merged_start;
                region.size = merged_end - merged_start;
                return true;
            }
        }
    }

    // Add new region
    vtd_state.approved_regions[vtd_state.approved_count] = DmaRegion{
        .bus = bus,
        .dev = dev,
        .func = func,
        .phys_start = phys_start,
        .size = size,
        .active = true,
    };
    vtd_state.approved_count += 1;
    return true;
}

// ============================================================================
// §8  IOMMU Page Table Setup
// ============================================================================

/// Set up second-level page tables for a device's DMA.
/// Uses identity mapping (IOVA == physical address) for approved regions.
fn setupDmaMapping(bus: u8, dev: u8, func: u8, phys_start: u64, size: u64) bool {
    if (vtd_state.root_table_phys == 0) return false;

    const root_table: [*]volatile VtdRootEntry = @ptrFromInt(vtd_state.root_table_phys);

    // 1. Get or create root entry for this bus
    const root_entry = &root_table[bus];

    // Determine context table physical address
    const ctx_phys: u64 = blk: {
        if (root_entry.present != 0) {
            break :blk root_entry.context_table_ptr << 12;
        }
        // Allocate context table for this bus
        const new_ctx = pmm.allocPage() orelse {
            hal.Serial.puts("[IOMMU] ERROR: Failed to allocate context table\n");
            return false;
        };
        const ctx_ptr: [*]volatile u8 = @ptrFromInt(new_ctx);
        @memset(ctx_ptr[0..4096], 0);

        root_entry.* = VtdRootEntry{
            .present = 1,
            ._rsvd1 = 0,
            .context_table_ptr = @intCast(new_ctx >> 12),
            ._rsvd2 = 0,
        };
        vtd_state.context_tables[bus] = new_ctx;

        hal.Serial.puts("[IOMMU] Created context table for bus 0x");
        hal.Serial.putHex(bus);
        hal.Serial.puts(" at 0x");
        hal.Serial.putHex(new_ctx);
        hal.Serial.puts("\n");
        break :blk new_ctx;
    };

    // 2. Get or create context entry for this device:function
    const ctx_table: [*]volatile VtdContextEntry = @ptrFromInt(ctx_phys);
    const ctx_idx = (dev & 0x1F) * 8 + (func & 0x7);
    const ctx_entry = &ctx_table[ctx_idx];

    // Determine second-level page table physical address
    const slpt_phys: u64 = blk2: {
        if (ctx_entry.present != 0) {
            break :blk2 ctx_entry.second_level_ptr << 12;
        }
        // Allocate second-level page table
        const new_slpt = pmm.allocPage() orelse {
            hal.Serial.puts("[IOMMU] ERROR: Failed to allocate SLPT\n");
            return false;
        };
        const slpt_ptr: [*]volatile u8 = @ptrFromInt(new_slpt);
        @memset(slpt_ptr[0..4096], 0);

        ctx_entry.* = VtdContextEntry{
            .present = 1,
            ._rsvd1 = 0,
            .second_level_ptr = @intCast(new_slpt >> 12),
            .address_width = VTD_AW_48BIT,
            ._rsvd2 = 0,
            ._rsvd3 = 0,
            ._rsvd4 = 0,
        };

        const slpt_key = @as(usize, bus) * 32 + @as(usize, dev) * 8 + @as(usize, func);
        if (slpt_key < 256) {
            vtd_state.slpt_tables[slpt_key] = new_slpt;
        }

        hal.Serial.puts("[IOMMU] Created SLPT for 0x");
        hal.Serial.putHex(bus);
        hal.Serial.putHex(dev);
        hal.Serial.putHex(func);
        hal.Serial.puts(" at 0x");
        hal.Serial.putHex(new_slpt);
        hal.Serial.puts("\n");
        break :blk2 new_slpt;
    };

    // 3. Map the DMA region in the second-level page table (identity mapping)
    //    Using 4KB pages for precise control over approved regions
    const start_page = phys_start & ~@as(u64, 0xFFF); // Page-align down
    const end_addr = (phys_start + size + 0xFFF) & ~@as(u64, 0xFFF); // Page-align up
    const num_pages = (end_addr - start_page) / 4096;

    // For 4-level IOMMU paging (AW=48-bit), we need 4 levels like regular x86_64
    // But for simplicity in P0, we'll use 2MB huge pages in the SLPT
    // This means we map 512 contiguous 4KB regions per huge page entry

    // Actually, for VT-d with AW=48BIT, the second-level page table structure is:
    //   Level 4 (PML4) → Level 3 (PDPT) → Level 2 (PD) → Level 0 (PT)
    //   Note: VT-d skips level 1, using levels 4/3/2/0
    // For P0, we'll use a simpler approach: create a flat identity mapping
    // at the second-level page table level using 2MB pages (512 entries per table)

    mapIdentityRegion(slpt_phys, start_page, num_pages) catch {
        hal.Serial.puts("[IOMMU] ERROR: Failed to map identity region\n");
        return false;
    };

    return true;
}

/// Map a physical region as identity-mapped (IOVA == physical) in the SLPT.
/// P0 FIX 4: Rewritten from scratch — the old implementation had two critical bugs:
///
///   BUG 1: Wrote 512 entries as 2MB huge pages, then OVERWROTE some as 4KB pages.
///           The huge page entries at indices 0-511 conflict with the 4KB entries.
///   BUG 2: PTE bits were 0x03 (present + write) but VT-d requires read=1 for
///           write=1 to work. Correct value: 0x07 (present + write + read).
///
/// New implementation: proper 4-level IOMMU page tables (PML4 → PDPT → PD → PT)
/// using 4KB pages for precise control over approved DMA regions only.
fn mapIdentityRegion(slpt_top_phys: u64, phys_start: u64, num_pages: u64) !void {
    // VT-d with AW=48BIT uses 4-level second-level page tables:
    //   Level 4 (SPTP/PML4) → Level 3 (PDPT) → Level 2 (PD) → Level 0 (PT)
    //   Note: VT-d skips Level 1, using levels 4/3/2/0
    //
    // Each level table is 4KB = 512 entries × 8 bytes.
    // IOVA breakdown (48-bit):
    //   [47:39] = PML4 index (9 bits)
    //   [38:30] = PDPT index (9 bits)
    //   [29:21] = PD index (9 bits)
    //   [20:12] = PT index (9 bits)
    //   [11:00] = page offset (12 bits)

    var page_idx: u64 = 0;
    while (page_idx < num_pages) : (page_idx += 1) {
        const page_phys = phys_start + page_idx * 4096;
        const iova = page_phys; // Identity mapping: IOVA == physical address

        // Extract indices from IOVA
        const pml4_idx = (iova >> 39) & 0x1FF;
        const pdpt_idx = (iova >> 30) & 0x1FF;
        const pd_idx   = (iova >> 21) & 0x1FF;
        const pt_idx   = (iova >> 12) & 0x1FF;

        // Walk/create PML4 → PDPT → PD → PT
        const pml4: [*]volatile u64 = @ptrFromInt(slpt_top_phys);

        // Level 4: Get or create PDPT
        const pdpt_phys: u64 = blk1: {
            if (pml4[pml4_idx] & 0x01 != 0) {
                break :blk1 pml4[pml4_idx] & 0x000FFFFFFFFFF000;
            }
            const new_pdpt = pmm.allocPage() orelse return error.OutOfMemory;
            const ptr: [*]volatile u8 = @ptrFromInt(new_pdpt);
            @memset(ptr[0..4096], 0);
            pml4[pml4_idx] = new_pdpt | 0x07; // present + write + read
            break :blk1 new_pdpt;
        };

        // Level 3: Get or create PD
        const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
        const pd_phys: u64 = blk2: {
            if (pdpt[pdpt_idx] & 0x01 != 0) {
                break :blk2 pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;
            }
            const new_pd = pmm.allocPage() orelse return error.OutOfMemory;
            const ptr: [*]volatile u8 = @ptrFromInt(new_pd);
            @memset(ptr[0..4096], 0);
            pdpt[pdpt_idx] = new_pd | 0x07;
            break :blk2 new_pd;
        };

        // Level 2: Get or create PT
        const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
        const pt_phys: u64 = blk3: {
            if (pd[pd_idx] & 0x01 != 0) {
                break :blk3 pd[pd_idx] & 0x000FFFFFFFFFF000;
            }
            const new_pt = pmm.allocPage() orelse return error.OutOfMemory;
            const ptr: [*]volatile u8 = @ptrFromInt(new_pt);
            @memset(ptr[0..4096], 0);
            pd[pd_idx] = new_pt | 0x07;
            break :blk3 new_pt;
        };

        // Level 0: Map the 4KB page
        // P0 FIX: Use 0x07 (present + write + read), NOT 0x03
        const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
        const pfn = page_phys >> 12;
        pt[pt_idx] = (pfn << 12) | 0x07; // present + write + read
    }

    hal.Serial.puts("[IOMMU] Identity-mapped ");
    hal.Serial.putDecimal(num_pages);
    hal.Serial.puts(" pages (4KB, 4-level PT) starting at 0x");
    hal.Serial.putHex(phys_start);
    hal.Serial.puts("\n");
}

// ============================================================================
// §9  VT-d Enable / Disable
// ============================================================================

pub fn enable() bool {
    if (!vtd_state.is_available) {
        hal.Serial.puts("[IOMMU] Cannot enable — VT-d not available\n");
        return false;
    }

    if (vtd_state.root_table_phys == 0) {
        hal.Serial.puts("[IOMMU] Cannot enable — no root table\n");
        return false;
    }

    hal.Serial.puts("[IOMMU] Enabling VT-d translation...\n");

    // 1. Set Root Table Pointer
    // RTADDR register: bits 12-63 = root table physical address
    writeReg64(VTD_REG_RTADDR, vtd_state.root_table_phys);

    // 2. Set SRTP (Set Root Table Pointer) bit in GCMD
    writeReg32(VTD_REG_GCMD, GCMD_SRTP);

    // 3. Wait for RTPS (Root Table Pointer Status) in GSTS
    var timeout: u32 = 0;
    while ((readReg32(VTD_REG_GSTS) & GSTS_RTPS) == 0) {
        timeout += 1;
        if (timeout > 1000000) {
            hal.Serial.puts("[IOMMU] ERROR: RTPS timeout\n");
            return false;
        }
        asm volatile ("pause");
    }

    // 4. Invalidate context cache (global)
    writeReg64(VTD_REG_CCMD, CCMD_ICC | CCMD_CIRG_GLOBAL);

    // 5. Invalidate IOTLB (global)
    writeReg64(VTD_REG_IOTLB, IOTLB_IVT | IOTLB_IIRG_GLOBAL | IOTLB_DR | IOTLB_DW);

    // 6. Enable translation (TE bit in GCMD)
    writeReg32(VTD_REG_GCMD, GCMD_TE);

    // 7. Wait for TES (Translation Enable Status) in GSTS
    timeout = 0;
    while ((readReg32(VTD_REG_GSTS) & GSTS_TES) == 0) {
        timeout += 1;
        if (timeout > 1000000) {
            hal.Serial.puts("[IOMMU] ERROR: TES timeout\n");
            return false;
        }
        asm volatile ("pause");
    }

    vtd_state.is_enabled = true;
    hal.Serial.puts("[IOMMU] VT-d translation ENABLED\n");
    return true;
}

pub fn disable() void {
    if (!vtd_state.is_available or !vtd_state.is_enabled) return;

    // Clear TE bit to disable translation
    writeReg32(VTD_REG_GCMD, 0);

    // Wait for TES to clear
    var timeout: u32 = 0;
    while ((readReg32(VTD_REG_GSTS) & GSTS_TES) != 0) {
        timeout += 1;
        if (timeout > 1000000) break;
        asm volatile ("pause");
    }

    vtd_state.is_enabled = false;
    hal.Serial.puts("[IOMMU] VT-d translation DISABLED\n");
}

pub fn isEnabled() bool {
    return vtd_state.is_enabled;
}

pub fn isAvailable() bool {
    return vtd_state.is_available;
}

// ============================================================================
// §10  IOTLB Invalidation
// ============================================================================

pub fn invalidateIotlb() void {
    if (!vtd_state.is_enabled) return;

    // Global IOTLB invalidation
    writeReg64(VTD_REG_IOTLB, IOTLB_IVT | IOTLB_IIRG_GLOBAL | IOTLB_DR | IOTLB_DW);

    // Wait for invalidation to complete
    var timeout: u32 = 0;
    while ((readReg64(VTD_REG_IOTLB) & IOTLB_IVT) != 0) {
        timeout += 1;
        if (timeout > 1000000) break;
        asm volatile ("pause");
    }
}
