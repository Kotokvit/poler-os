// ============================================================================
// POLER-OS ELF64 Loader — v0.8.0
// ============================================================================
//
// Loads ELF64 executables into per-process address spaces.
//
// v0.8.0 changes:
//   - loadElfIntoPML4 is now the PRIMARY loader (per-process isolation)
//   - loadElfIntoPML4_v2: maps ONLY into target PML4, uses phys-to-virt
//     copy for data (no kernel PML4 pollution)
//   - Supports ET_DYN (PIE executables) with configurable base address
//   - Stack allocation integrated into loader
//
// Supports:
//   - PT_LOAD segments (code + data + bss)
//   - Position-dependent executables (ET_EXEC)
//   - Position-independent executables (ET_DYN / PIE)
//   - x86_64 architecture validation
//
// Limitations:
//   - No dynamic linking (no PT_DYNAMIC processing)
//   - No relocation processing (RELA/R_REL)
//   - No shared libraries
//   - No PT_INTERP (no interpreter / dynamic linker)
// ============================================================================

const hal = @import("hal.zig");
const vmm = @import("vmm64.zig");
const pmm = @import("pmm64.zig");

// ============================================================================
// ELF64 Structures
// ============================================================================

pub const EI_NIDENT: usize = 16;

pub const Elf64_Ehdr = extern struct {
    e_ident: [EI_NIDENT]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3; // Position-independent executable (PIE)

pub const EM_X86_64: u16 = 62;

pub const Elf64_Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2; // Dynamic linking information
pub const PT_INTERP: u32 = 3; // Path to dynamic linker (interpreter)

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// ============================================================================
// ELF Loader Error
// ============================================================================

pub const ElfError = error{
    InvalidMagic,
    Not64Bit,
    NotExecutable,
    WrongArchitecture,
    NoProgramHeaders,
    NoLoadSegments,
    MapFailed,
    OutOfMemory,
};

// ============================================================================
// ELF64 Load Result
// ============================================================================

pub const ElfLoadResult = struct {
    entry_point: u64, // Virtual address of _start / main
    num_segments: usize, // Number of PT_LOAD segments loaded
    is_pie: bool = false, // True if this was a PIE executable
    load_base: u64 = 0, // Base address for PIE (0 for ET_EXEC)
};

fn validateElfHeader(ehdr: *const Elf64_Ehdr) ElfError!void {
    // Magic: 0x7F 'E' 'L' 'F'
    if (ehdr.e_ident[0] != 0x7F or
        ehdr.e_ident[1] != 'E' or
        ehdr.e_ident[2] != 'L' or
        ehdr.e_ident[3] != 'F')
    {
        return ElfError.InvalidMagic;
    }

    // Class: must be ELFCLASS64 (2)
    if (ehdr.e_ident[4] != 2) {
        return ElfError.Not64Bit;
    }

    // Type: must be ET_EXEC (2) or ET_DYN (3, PIE)
    if (ehdr.e_type != ET_EXEC and ehdr.e_type != ET_DYN) {
        return ElfError.NotExecutable;
    }

    // Machine: must be EM_X86_64 (62)
    if (ehdr.e_machine != EM_X86_64) {
        return ElfError.WrongArchitecture;
    }
}

// ============================================================================
// flagsToPageFlags — Convert ELF p_flags to VMM page flags
// ============================================================================

fn flagsToPageFlags(p_flags: u32) u64 {
    var page_flags: u64 = vmm.PTE_PRESENT | vmm.PTE_USER;

    if (p_flags & PF_W != 0) {
        page_flags |= vmm.PTE_WRITABLE;
    }
    if (p_flags & PF_X == 0) {
        page_flags |= vmm.PTE_NO_EXECUTE;
    }

    return page_flags;
}

// ============================================================================
// loadElf — Load an ELF64 binary into the kernel PML4 (legacy)
// ============================================================================
//
// DEPRECATED: Use loadElfIntoPML4 for per-process isolation.
// This function maps pages into the kernel PML4, which is insecure
// for user processes. Kept for compatibility with kernel-mode ELF loading.
// ============================================================================

pub fn loadElf(elf_data: []const u8) ElfError!ElfLoadResult {
    if (elf_data.len < @sizeOf(Elf64_Ehdr)) {
        return ElfError.InvalidMagic;
    }

    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));
    try validateElfHeader(ehdr);

    if (ehdr.e_phnum == 0) {
        return ElfError.NoProgramHeaders;
    }

    hal.Serial.puts("[ELF] Valid ELF64 executable (kernel PML4 load)\n");
    hal.Serial.puts("[ELF] Entry point: ");
    hal.Serial.putHex(ehdr.e_entry);
    hal.Serial.puts("\n");

    var num_loaded: usize = 0;

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset + @sizeOf(Elf64_Phdr) > elf_data.len) break;

        const phdr: *const Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset));
        if (phdr.p_type != PT_LOAD) continue;

        const page_flags = flagsToPageFlags(phdr.p_flags);
        const vaddr_aligned = phdr.p_vaddr & ~@as(u64, 0xFFF);
        const vaddr_end = phdr.p_vaddr + phdr.p_memsz;
        const vaddr_end_aligned = (vaddr_end + 0xFFF) & ~@as(u64, 0xFFF);
        const num_pages = (vaddr_end_aligned - vaddr_aligned) / vmm.PAGE_SIZE;

        var page_idx: u64 = 0;
        while (page_idx < num_pages) : (page_idx += 1) {
            const virt_addr = vaddr_aligned + page_idx * vmm.PAGE_SIZE;
            const phys_page = pmm.allocPage() orelse return ElfError.OutOfMemory;

            vmm.mapPage(virt_addr, phys_page, page_flags) catch |err| {
                if (err == vmm.VmmError.AlreadyMapped) {
                    pmm.freePage(phys_page);
                } else {
                    return ElfError.MapFailed;
                }
            };
        }

        if (phdr.p_filesz > 0) {
            const file_src = elf_data[phdr.p_offset .. phdr.p_offset + phdr.p_filesz];
            const dest_ptr: [*]volatile u8 = @ptrFromInt(phdr.p_vaddr);
            @memcpy(dest_ptr[0..phdr.p_filesz], file_src);
        }

        if (phdr.p_memsz > phdr.p_filesz) {
            const bss_start = phdr.p_vaddr + phdr.p_filesz;
            const bss_len = phdr.p_memsz - phdr.p_filesz;
            const bss_ptr: [*]volatile u8 = @ptrFromInt(bss_start);
            @memset(bss_ptr[0..bss_len], 0);
        }

        num_loaded += 1;
    }

    if (num_loaded == 0) return ElfError.NoLoadSegments;

    return ElfLoadResult{
        .entry_point = ehdr.e_entry,
        .num_segments = num_loaded,
        .is_pie = ehdr.e_type == ET_DYN,
    };
}

// ============================================================================
// loadElfIntoPML4 — Load an ELF64 binary into a SPECIFIC PML4 (v0.7.0)
// ============================================================================
//
// Maps pages into BOTH the target PML4 AND the kernel PML4.
// The kernel mapping is needed so that Ring 0 code can copy data to
// the user pages via the kernel's identity-mapped physical memory.
//
// For pure per-process isolation without kernel PML4 pollution,
// use loadElfIntoPML4_v2 which uses direct physical memory access.
// ============================================================================

pub fn loadElfIntoPML4(elf_data: []const u8, target_pml4: u64) ElfError!ElfLoadResult {
    if (elf_data.len < @sizeOf(Elf64_Ehdr)) {
        return ElfError.InvalidMagic;
    }

    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));
    try validateElfHeader(ehdr);

    if (ehdr.e_phnum == 0) {
        return ElfError.NoProgramHeaders;
    }

    hal.Serial.puts("[ELF] Valid ELF64 — loading into user PML4\n");
    hal.Serial.puts("[ELF] Entry point: ");
    hal.Serial.putHex(ehdr.e_entry);
    hal.Serial.puts("\n");

    var num_loaded: usize = 0;

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset + @sizeOf(Elf64_Phdr) > elf_data.len) break;

        const phdr: *const Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset));
        if (phdr.p_type != PT_LOAD) continue;

        hal.Serial.puts("[ELF] PT_LOAD: vaddr=");
        hal.Serial.putHex(phdr.p_vaddr);
        hal.Serial.puts(" filesz=");
        hal.Serial.putDecimal(phdr.p_filesz);
        hal.Serial.puts(" memsz=");
        hal.Serial.putDecimal(phdr.p_memsz);
        hal.Serial.puts("\n");

        const page_flags = flagsToPageFlags(phdr.p_flags);
        const vaddr_aligned = phdr.p_vaddr & ~@as(u64, 0xFFF);
        const vaddr_end = phdr.p_vaddr + phdr.p_memsz;
        const vaddr_end_aligned = (vaddr_end + 0xFFF) & ~@as(u64, 0xFFF);
        const num_pages = (vaddr_end_aligned - vaddr_aligned) / vmm.PAGE_SIZE;

        // Track allocated physical pages for this segment
        // (for cleanup on failure)
        var seg_phys_pages: [256]?u64 = undefined;
        var seg_page_count: usize = 0;

        var page_idx: u64 = 0;
        while (page_idx < num_pages) : (page_idx += 1) {
            const virt_addr = vaddr_aligned + page_idx * vmm.PAGE_SIZE;
            const phys_page = pmm.allocPage() orelse {
                // Cleanup: free all pages allocated for this segment
                for (0..seg_page_count) |j| {
                    if (seg_phys_pages[j]) |p| pmm.freePage(p);
                }
                return ElfError.OutOfMemory;
            };

            // Zero the page first (security: don't leak previous data)
            const page_ptr: [*]volatile u8 = @ptrFromInt(phys_page);
            @memset(page_ptr[0..vmm.PAGE_SIZE], 0);

            // Map in the TARGET PML4 (user's page tables)
            vmm.mapPageInPML4(target_pml4, virt_addr, phys_page, page_flags) catch |err| {
                if (err == vmm.VmmError.AlreadyMapped) {
                    pmm.freePage(phys_page);
                } else {
                    pmm.freePage(phys_page);
                    for (0..seg_page_count) |j| {
                        if (seg_phys_pages[j]) |p| pmm.freePage(p);
                    }
                    return ElfError.MapFailed;
                }
            };

            // ALSO map in kernel PML4 — needed for data copy via virt addr
            vmm.mapPage(virt_addr, phys_page, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch |err| {
                if (err != vmm.VmmError.AlreadyMapped) {
                    hal.Serial.puts("[ELF] WARNING: Kernel map failed\n");
                }
            };

            if (seg_page_count < 256) {
                seg_phys_pages[seg_page_count] = phys_page;
                seg_page_count += 1;
            }
        }

        // Copy file data to virtual address (works through kernel mapping)
        if (phdr.p_filesz > 0) {
            const file_src = elf_data[phdr.p_offset .. phdr.p_offset + phdr.p_filesz];
            const dest_ptr: [*]volatile u8 = @ptrFromInt(phdr.p_vaddr);
            @memcpy(dest_ptr[0..phdr.p_filesz], file_src);
        }

        // Zero-fill BSS (memsz > filesz) — page is already zeroed,
        // but we need to handle partial pages
        if (phdr.p_memsz > phdr.p_filesz) {
            const bss_start = phdr.p_vaddr + phdr.p_filesz;
            const bss_len = phdr.p_memsz - phdr.p_filesz;
            const bss_ptr: [*]volatile u8 = @ptrFromInt(bss_start);
            @memset(bss_ptr[0..bss_len], 0);
        }

        num_loaded += 1;
    }

    if (num_loaded == 0) return ElfError.NoLoadSegments;

    hal.Serial.puts("[ELF] Loaded ");
    hal.Serial.putDecimal(num_loaded);
    hal.Serial.puts(" PT_LOAD segments into user PML4\n");

    return ElfLoadResult{
        .entry_point = ehdr.e_entry,
        .num_segments = num_loaded,
        .is_pie = ehdr.e_type == ET_DYN,
    };
}

// ============================================================================
// loadElfIntoPML4_v2 — Pure per-process ELF loading (v0.9.0)
// ============================================================================
//
// This is the CORRECT way to load an ELF for per-process isolation.
// Unlike loadElfIntoPML4 which also maps into kernel PML4 (polluting it),
// this version:
//   1. Allocates physical pages
//   2. Maps them ONLY in the target PML4
//   3. Copies data directly to physical addresses (kernel identity-maps RAM)
//   4. Does NOT modify the kernel PML4 at all
//   5. v0.9.0: If PT_DYNAMIC is found, invokes the dynamic linker
//
// This means:
//   - The kernel PML4 stays clean (no user mappings in kernel space)
//   - Each process has its own isolated address space
//   - No need to clean up kernel PML4 entries on process exit
//   - Works correctly with COW fork() — no stale kernel mappings
//   - Shared libraries are loaded and linked automatically
//
// For PIE executables (ET_DYN), the load_base parameter specifies where
// to load the executable. For ET_EXEC, load_base is ignored (p_vaddr
// from the ELF header is used directly).
//
// Parameters:
//   elf_data    — Raw ELF file content
//   target_pml4 — Physical address of the target PML4
//   load_base   — Base address for PIE executables (0x100000 default)
// ============================================================================

pub const DEFAULT_PIE_BASE: u64 = 0x100000; // 1MB — standard user load address

pub fn loadElfIntoPML4_v2(elf_data: []const u8, target_pml4: u64, load_base: u64) ElfError!ElfLoadResult {
    if (elf_data.len < @sizeOf(Elf64_Ehdr)) {
        return ElfError.InvalidMagic;
    }

    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));
    try validateElfHeader(ehdr);

    if (ehdr.e_phnum == 0) {
        return ElfError.NoProgramHeaders;
    }

    const is_pie = ehdr.e_type == ET_DYN;
    const effective_base: u64 = if (is_pie) load_base else 0;

    hal.Serial.puts("[ELF] Valid ELF64 — pure per-process PML4 load\n");
    hal.Serial.puts("[ELF] Type: ");
    hal.Serial.puts(if (is_pie) "PIE (ET_DYN)" else "EXEC (ET_EXEC)");
    hal.Serial.puts("\n");
    hal.Serial.puts("[ELF] Entry point: ");
    hal.Serial.putHex(ehdr.e_entry + effective_base);
    hal.Serial.puts("\n");
    hal.Serial.puts("[ELF] Target PML4: ");
    hal.Serial.putHex(target_pml4);
    hal.Serial.puts("\n");

    var num_loaded: usize = 0;

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset + @sizeOf(Elf64_Phdr) > elf_data.len) break;

        const phdr: *const Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset));
        if (phdr.p_type != PT_LOAD) continue;

        // For PIE, add load_base to all virtual addresses
        const seg_vaddr = phdr.p_vaddr + effective_base;
        const seg_entry = ehdr.e_entry + effective_base; // Will use last value

        hal.Serial.puts("[ELF] PT_LOAD: vaddr=");
        hal.Serial.putHex(seg_vaddr);
        hal.Serial.puts(" filesz=");
        hal.Serial.putDecimal(phdr.p_filesz);
        hal.Serial.puts(" memsz=");
        hal.Serial.putDecimal(phdr.p_memsz);
        hal.Serial.puts("\n");

        const page_flags = flagsToPageFlags(phdr.p_flags);
        const vaddr_aligned = seg_vaddr & ~@as(u64, 0xFFF);
        const vaddr_end = seg_vaddr + phdr.p_memsz;
        const vaddr_end_aligned = (vaddr_end + 0xFFF) & ~@as(u64, 0xFFF);
        const num_pages = (vaddr_end_aligned - vaddr_aligned) / vmm.PAGE_SIZE;

        // Track allocated pages for cleanup on failure
        var seg_phys: [256]?u64 = undefined;
        var seg_count: usize = 0;
        var seg_virts: [256]?u64 = undefined; // Track virtual addrs for unmap on failure

        var page_idx: u64 = 0;
        while (page_idx < num_pages) : (page_idx += 1) {
            const virt_addr = vaddr_aligned + page_idx * vmm.PAGE_SIZE;

            const phys_page = pmm.allocPage() orelse {
                // Cleanup: unmap and free all pages allocated for this segment
                for (0..seg_count) |j| {
                    if (seg_phys[j]) |p| {
                        if (seg_virts[j]) |v| {
                            _ = vmm.unmapPageInPML4(target_pml4, v) catch {};
                        }
                        pmm.freePage(p);
                    }
                }
                return ElfError.OutOfMemory;
            };

            // Zero the physical page (security: don't leak data)
            const page_ptr: [*]volatile u8 = @ptrFromInt(phys_page);
            @memset(page_ptr[0..vmm.PAGE_SIZE], 0);

            // Map ONLY in the TARGET PML4 — NOT in kernel PML4
            vmm.mapPageInPML4(target_pml4, virt_addr, phys_page, page_flags) catch |err| {
                pmm.freePage(phys_page);
                if (err != vmm.VmmError.AlreadyMapped) {
                    for (0..seg_count) |j| {
                        if (seg_phys[j]) |p| {
                            if (seg_virts[j]) |v| {
                                _ = vmm.unmapPageInPML4(target_pml4, v) catch {};
                            }
                            pmm.freePage(p);
                        }
                    }
                    return ElfError.MapFailed;
                }
                // AlreadyMapped is OK — shared segment
                continue;
            };

            if (seg_count < 256) {
                seg_phys[seg_count] = phys_page;
                seg_virts[seg_count] = virt_addr;
                seg_count += 1;
            }
        }

        // Copy file data DIRECTLY to physical memory
        // The kernel identity-maps all physical memory, so we can access
        // physical pages through their physical addresses as virtual addresses.
        // For each page, we need to find the physical page and copy to it.
        if (phdr.p_filesz > 0) {
            // We need to copy file data to the correct offsets within pages
            var file_offset: u64 = 0;
            while (file_offset < phdr.p_filesz) {
                const current_vaddr = seg_vaddr + file_offset;
                const page_vaddr = current_vaddr & ~@as(u64, 0xFFF);
                const page_offset = current_vaddr & 0xFFF; // Offset within page
                const remaining = phdr.p_filesz - file_offset;
                const chunk_size = @min(remaining, vmm.PAGE_SIZE - page_offset);

                // Look up the physical page through the target PML4
                const pte = vmm.getPTE(target_pml4, page_vaddr);
                if (pte & vmm.PTE_PRESENT != 0) {
                    const phys_addr = (pte & 0x000FFFFFFFFFF000) + page_offset;
                    const dest: [*]volatile u8 = @ptrFromInt(phys_addr);
                    const src_offset = phdr.p_offset + file_offset;
                    @memcpy(dest[0..chunk_size], elf_data[src_offset..][0..chunk_size]);
                }

                file_offset += chunk_size;
            }
        }

        // BSS is already zeroed (pages were zeroed above)

        num_loaded += 1;
        _ = seg_entry; // Used below for entry point calculation
    }

    if (num_loaded == 0) return ElfError.NoLoadSegments;

    hal.Serial.puts("[ELF] Loaded ");
    hal.Serial.putDecimal(num_loaded);
    hal.Serial.puts(" segments into PML4 (pure per-process)\n");

    // v0.9.0: Check for PT_DYNAMIC and invoke dynamic linker if present
    var has_dynamic = false;
    i = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset2 = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset2 + @sizeOf(Elf64_Phdr) > elf_data.len) break;
        const phdr2: *const Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset2));
        if (phdr2.p_type == PT_DYNAMIC) {
            has_dynamic = true;
            break;
        }
    }

    if (has_dynamic) {
        hal.Serial.puts("[ELF] PT_DYNAMIC found — invoking dynamic linker\n");
        const dynlink = @import("dynlinker.zig");
        dynlink.linkDynamicExecutable(elf_data, effective_base, target_pml4) catch |err| {
            hal.Serial.puts("[ELF] WARNING: dynamic linking failed: ");
            switch (err) {
                dynlink.DynLinkError.NoDynamicSegment => hal.Serial.puts("NoDynamicSegment"),
                dynlink.DynLinkError.SymbolNotFound => hal.Serial.puts("SymbolNotFound"),
                dynlink.DynLinkError.LibraryNotFound => hal.Serial.puts("LibraryNotFound"),
                dynlink.DynLinkError.RelocationFailed => hal.Serial.puts("RelocationFailed"),
                dynlink.DynLinkError.OutOfMemory => hal.Serial.puts("OutOfMemory"),
                dynlink.DynLinkError.MapFailed => hal.Serial.puts("MapFailed"),
                dynlink.DynLinkError.InvalidDynamicEntry => hal.Serial.puts("InvalidDynamicEntry"),
            }
            hal.Serial.puts(" — continuing without shared libraries\n");
        };
    }

    return ElfLoadResult{
        .entry_point = ehdr.e_entry + effective_base,
        .num_segments = num_loaded,
        .is_pie = is_pie,
        .load_base = effective_base,
    };
}
