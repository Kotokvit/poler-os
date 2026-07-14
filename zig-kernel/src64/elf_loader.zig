// ============================================================================
// POLER-OS ELF64 Loader — v0.7.0
// ============================================================================
//
// Loads ELF64 executables into user address space.
// Supports:
//   - PT_LOAD segments (code + data + bss)
//   - Position-dependent executables (e_type = ET_EXEC)
//   - x86_64 architecture validation
//
// Limitations (v0.7.0):
//   - No dynamic linking (ET_DYN not supported)
//   - No relocation processing
//   - No shared libraries
//   - User pages mapped via kernel VMM (shared page tables until v0.7.1)
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

    // Type: must be ET_EXEC (2)
    if (ehdr.e_type != ET_EXEC) {
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
    var page_flags: u64 = vmm.PTE_PRESENT | vmm.PTE_USER; // Always present + user-accessible

    if (p_flags & PF_W != 0) {
        page_flags |= vmm.PTE_WRITABLE;
    }
    if (p_flags & PF_X == 0) {
        page_flags |= vmm.PTE_NO_EXECUTE;
    }

    return page_flags;
}

// ============================================================================
// loadElf — Load an ELF64 binary from a memory buffer
// ============================================================================
//
// This function:
//   1. Validates the ELF header
//   2. Iterates over PT_LOAD program headers
//   3. Maps pages at p_vaddr with appropriate permissions
//   4. Copies file data from p_offset to p_vaddr
//   5. Zero-fills BSS (p_memsz - p_filesz)
//
// Returns: ElfLoadResult with the entry point address
//
// IMPORTANT: Pages are mapped via the kernel VMM (vmm.mapPage).
// For per-process isolation, the caller should create a user PML4
// AFTER calling loadElf (so the user PML4 inherits the mappings).
// ============================================================================

pub fn loadElf(elf_data: []const u8) ElfError!ElfLoadResult {
    if (elf_data.len < @sizeOf(Elf64_Ehdr)) {
        return ElfError.InvalidMagic;
    }

    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));

    // Validate header
    try validateElfHeader(ehdr);

    if (ehdr.e_phnum == 0) {
        return ElfError.NoProgramHeaders;
    }

    hal.Serial.puts("[ELF] Valid ELF64 executable\n");
    hal.Serial.puts("[ELF] Entry point: ");
    hal.Serial.putHex(ehdr.e_entry);
    hal.Serial.puts("\n");
    hal.Serial.puts("[ELF] Program headers: ");
    hal.Serial.putDecimal(ehdr.e_phnum);
    hal.Serial.puts("\n");

    var num_loaded: usize = 0;

    // Iterate over program headers
    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset + @sizeOf(Elf64_Phdr) > elf_data.len) {
            hal.Serial.puts("[ELF] WARNING: Program header out of bounds\n");
            break;
        }

        const phdr: *const Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset));

        if (phdr.p_type != PT_LOAD) {
            continue; // Skip non-LOAD segments
        }

        hal.Serial.puts("[ELF] PT_LOAD: vaddr=");
        hal.Serial.putHex(phdr.p_vaddr);
        hal.Serial.puts(" filesz=");
        hal.Serial.putDecimal(phdr.p_filesz);
        hal.Serial.puts(" memsz=");
        hal.Serial.putDecimal(phdr.p_memsz);
        hal.Serial.puts(" flags=");
        hal.Serial.putHex(phdr.p_flags);
        hal.Serial.puts("\n");

        const page_flags = flagsToPageFlags(phdr.p_flags);

        // Calculate number of pages needed for this segment
        const vaddr_aligned = phdr.p_vaddr & ~@as(u64, 0xFFF); // Page-align down
        const vaddr_end = phdr.p_vaddr + phdr.p_memsz;
        const vaddr_end_aligned = (vaddr_end + 0xFFF) & ~@as(u64, 0xFFF); // Page-align up
        const num_pages = (vaddr_end_aligned - vaddr_aligned) / vmm.PAGE_SIZE;

        // Map pages for this segment
        var page_idx: u64 = 0;
        while (page_idx < num_pages) : (page_idx += 1) {
            const virt_addr = vaddr_aligned + page_idx * vmm.PAGE_SIZE;

            // Allocate a physical page
            const phys_page = pmm.allocPage() orelse {
                hal.Serial.puts("[ELF] ERROR: Out of memory mapping user pages\n");
                return ElfError.OutOfMemory;
            };

            // Map the page (this may fail if already mapped, which is OK for shared segments)
            vmm.mapPage(virt_addr, phys_page, page_flags) catch |err| {
                if (err == vmm.VmmError.AlreadyMapped) {
                    // Page already mapped (e.g., from a previous segment)
                    // Free the allocated physical page since it's not needed
                    pmm.freePage(phys_page);
                } else {
                    hal.Serial.puts("[ELF] ERROR: Failed to map page at ");
                    hal.Serial.putHex(virt_addr);
                    hal.Serial.puts(": ");
                    hal.Serial.puts(@errorName(err));
                    hal.Serial.puts("\n");
                    return ElfError.MapFailed;
                }
            };
        }

        // Copy file data to virtual address
        if (phdr.p_filesz > 0) {
            const file_src = elf_data[phdr.p_offset .. phdr.p_offset + phdr.p_filesz];
            const dest_ptr: [*]volatile u8 = @ptrFromInt(phdr.p_vaddr);
            @memcpy(dest_ptr[0..phdr.p_filesz], file_src);
        }

        // Zero-fill BSS (memsz > filesz)
        if (phdr.p_memsz > phdr.p_filesz) {
            const bss_start = phdr.p_vaddr + phdr.p_filesz;
            const bss_len = phdr.p_memsz - phdr.p_filesz;
            const bss_ptr: [*]volatile u8 = @ptrFromInt(bss_start);
            @memset(bss_ptr[0..bss_len], 0);
        }

        num_loaded += 1;
    }

    if (num_loaded == 0) {
        return ElfError.NoLoadSegments;
    }

    hal.Serial.puts("[ELF] Loaded ");
    hal.Serial.putDecimal(num_loaded);
    hal.Serial.puts(" PT_LOAD segments\n");

    return ElfLoadResult{
        .entry_point = ehdr.e_entry,
        .num_segments = num_loaded,
    };
}

// ============================================================================
// loadElfIntoPML4 — Load an ELF64 binary into a SPECIFIC PML4
// ============================================================================
//
// v0.7.0: Per-process address space isolation requires loading user ELF
// segments into the user's PML4 (not the kernel PML4). This function:
//   1. Validates the ELF header
//   2. Iterates over PT_LOAD program headers
//   3. Maps pages at p_vaddr in the TARGET PML4 with PTE_USER flag
//   4. Copies file data from p_offset to p_vaddr
//   5. Zero-fills BSS (p_memsz - p_filesz)
//
// The data copy works because we're in Ring 0 and the kernel identity-maps
// all physical memory — the physical pages allocated here are accessible
// through the kernel's virtual address space.
//
// Returns: ElfLoadResult with the entry point address
// ============================================================================

pub fn loadElfIntoPML4(elf_data: []const u8, target_pml4: u64) ElfError!ElfLoadResult {
    if (elf_data.len < @sizeOf(Elf64_Ehdr)) {
        return ElfError.InvalidMagic;
    }

    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));

    // Validate header
    try validateElfHeader(ehdr);

    if (ehdr.e_phnum == 0) {
        return ElfError.NoProgramHeaders;
    }

    hal.Serial.puts("[ELF] Valid ELF64 — loading into user PML4\n");
    hal.Serial.puts("[ELF] Entry point: ");
    hal.Serial.putHex(ehdr.e_entry);
    hal.Serial.puts("\n");

    var num_loaded: usize = 0;

    // Iterate over program headers
    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset + @sizeOf(Elf64_Phdr) > elf_data.len) {
            hal.Serial.puts("[ELF] WARNING: Program header out of bounds\n");
            break;
        }

        const phdr: *const Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset));

        if (phdr.p_type != PT_LOAD) {
            continue; // Skip non-LOAD segments
        }

        hal.Serial.puts("[ELF] PT_LOAD: vaddr=");
        hal.Serial.putHex(phdr.p_vaddr);
        hal.Serial.puts(" filesz=");
        hal.Serial.putDecimal(phdr.p_filesz);
        hal.Serial.puts(" memsz=");
        hal.Serial.putDecimal(phdr.p_memsz);
        hal.Serial.puts("\n");

        const page_flags = flagsToPageFlags(phdr.p_flags);

        // Calculate number of pages needed for this segment
        const vaddr_aligned = phdr.p_vaddr & ~@as(u64, 0xFFF);
        const vaddr_end = phdr.p_vaddr + phdr.p_memsz;
        const vaddr_end_aligned = (vaddr_end + 0xFFF) & ~@as(u64, 0xFFF);
        const num_pages = (vaddr_end_aligned - vaddr_aligned) / vmm.PAGE_SIZE;

        // Map pages for this segment IN THE TARGET PML4 (with PTE_USER)
        var page_idx: u64 = 0;
        while (page_idx < num_pages) : (page_idx += 1) {
            const virt_addr = vaddr_aligned + page_idx * vmm.PAGE_SIZE;

            // Allocate a physical page
            const phys_page = pmm.allocPage() orelse {
                hal.Serial.puts("[ELF] ERROR: Out of memory mapping user pages\n");
                return ElfError.OutOfMemory;
            };

            // Map in the TARGET PML4 (user's page tables)
            vmm.mapPageInPML4(target_pml4, virt_addr, phys_page, page_flags) catch |err| {
                if (err == vmm.VmmError.AlreadyMapped) {
                    pmm.freePage(phys_page);
                } else {
                    hal.Serial.puts("[ELF] ERROR: Failed to map page at ");
                    hal.Serial.putHex(virt_addr);
                    hal.Serial.puts(": ");
                    hal.Serial.puts(@errorName(err));
                    hal.Serial.puts("\n");
                    return ElfError.MapFailed;
                }
            };

            // ALSO map in kernel PML4 — needed so the kernel can copy data
            // to the user pages. We add PTE_USER so that when the kernel PML4
            // is used (without CR3 switch), Ring 3 can still access user pages.
            vmm.mapPage(virt_addr, phys_page, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch |err| {
                if (err != vmm.VmmError.AlreadyMapped) {
                    hal.Serial.puts("[ELF] WARNING: Kernel map failed at ");
                    hal.Serial.putHex(virt_addr);
                    hal.Serial.puts(": ");
                    hal.Serial.puts(@errorName(err));
                    hal.Serial.puts("\n");
                }
                // Already mapped in kernel PML4 is OK — might share the page
            };
        }

        // Copy file data to virtual address (works through kernel mapping)
        if (phdr.p_filesz > 0) {
            const file_src = elf_data[phdr.p_offset .. phdr.p_offset + phdr.p_filesz];
            const dest_ptr: [*]volatile u8 = @ptrFromInt(phdr.p_vaddr);
            @memcpy(dest_ptr[0..phdr.p_filesz], file_src);
        }

        // Zero-fill BSS (memsz > filesz)
        if (phdr.p_memsz > phdr.p_filesz) {
            const bss_start = phdr.p_vaddr + phdr.p_filesz;
            const bss_len = phdr.p_memsz - phdr.p_filesz;
            const bss_ptr: [*]volatile u8 = @ptrFromInt(bss_start);
            @memset(bss_ptr[0..bss_len], 0);
        }

        num_loaded += 1;
    }

    if (num_loaded == 0) {
        return ElfError.NoLoadSegments;
    }

    hal.Serial.puts("[ELF] Loaded ");
    hal.Serial.putDecimal(num_loaded);
    hal.Serial.puts(" PT_LOAD segments into user PML4\n");

    return ElfLoadResult{
        .entry_point = ehdr.e_entry,
        .num_segments = num_loaded,
    };
}
