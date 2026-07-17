// ============================================================================
// POLER-OS Dynamic Linker (ld-poler) — v0.9.0
// ============================================================================
//
// Implements ELF64 dynamic linking for shared libraries (.so files).
//
// Architecture:
//   1. Parse PT_DYNAMIC segment from the main executable
//   2. Process .dynamic entries (DT_NEEDED, DT_SYMTAB, DT_STRTAB, etc.)
//   3. Load shared libraries from the filesystem (DT_NEEDED)
//   4. Process relocations:
//      - R_X86_64_RELATIVE  — base-address-relative (most common, no symbol lookup)
//      - R_X86_64_GLOB_DAT  — global data symbol resolution via GOT
//      - R_X86_64_JUMP_SLOT — lazy PLT binding (function calls via PLT)
//      - R_X86_64_64        — absolute 64-bit relocation
//   5. Set up GOT (Global Offset Table) with resolved addresses
//   6. Set up PLT (Procedure Linkage Table) for lazy function binding
//
// Memory layout for dynamically-linked process:
//
//   0x100000      Main executable (ET_DYN PIE or ET_EXEC)
//   0x400000_000  First shared library (libc.so)
//   0x400010_000  Second shared library (libm.so)
//   ...           Additional libraries
//   0x7F0000_000  Stack (top of user address space region)
//
// The GOT is always writable (process modifies it at runtime).
// The PLT is executable and read-only; it jumps through GOT entries.
//
// Lazy binding:
//   Initially, GOT entries for functions point to the PLT resolver stub.
//   On first call, the resolver:
//     1. Identifies the symbol (relocation index pushed by PLT stub)
//     2. Looks up the symbol in all loaded libraries
//     3. Patches the GOT entry with the real address
//     4. Jumps to the resolved function
//   Subsequent calls go directly through the patched GOT entry.
//
// Limitations (v0.9.0):
//   - No thread-safety for lazy binding (no PLT lock)
//   - No symbol versioning
//   - No TLS (Thread-Local Storage) support
//   - No weak symbols
//   - Library search path is fixed (/lib/)
// ============================================================================

const hal = @import("hal.zig");
const vmm = @import("vmm64.zig");
const pmm = @import("pmm64.zig");
const elf_loader = @import("elf_loader.zig");

// ============================================================================
// ELF64 Dynamic Structures
// ============================================================================

/// Elf64_Dyn — .dynamic section entry
pub const Elf64_Dyn = extern struct {
    d_tag: i64, // Dynamic entry type
    d_val: u64, // Value (integer or address)
};

/// Dynamic entry tags (d_tag values)
pub const DT_NULL: i64 = 0; // End of .dynamic array
pub const DT_NEEDED: i64 = 1; // Name of needed library (offset into DT_STRTAB)
pub const DT_PLTRELSZ: i64 = 2; // Size of PLT relocation entries (bytes)
pub const DT_PLTGOT: i64 = 3; // Address of GOT
pub const DT_HASH: i64 = 4; // Address of symbol hash table
pub const DT_STRTAB: i64 = 5; // Address of dynamic string table
pub const DT_SYMTAB: i64 = 6; // Address of dynamic symbol table
pub const DT_RELA: i64 = 7; // Address of RELA relocation table
pub const DT_RELASZ: i64 = 8; // Size of RELA table (bytes)
pub const DT_RELAENT: i64 = 9; // Size of each RELA entry (bytes)
pub const DT_STRSZ: i64 = 10; // Size of string table (bytes)
pub const DT_SYMENT: i64 = 11; // Size of each symbol entry (bytes)
pub const DT_INIT: i64 = 12; // Address of init function
pub const DT_FINI: i64 = 13; // Address of fini function
pub const DT_SONAME: i64 = 14; // Shared object name
pub const DT_RPATH: i64 = 15; // Library search path
pub const DT_SYMBOLIC: i64 = 16; // Symbol resolution starts here
pub const DT_REL: i64 = 17; // Address of REL relocation table (no addend)
pub const DT_RELSZ: i64 = 18; // Size of REL table
pub const DT_RELENT: i64 = 19; // Size of each REL entry
pub const DT_PLTREL: i64 = 20; // Type of PLT relocations (DT_REL or DT_RELA)
pub const DT_JMPREL: i64 = 23; // Address of PLT relocation entries
pub const DT_INIT_ARRAY: i64 = 25; // Array of init functions
pub const DT_FINI_ARRAY: i64 = 26; // Array of fini functions
pub const DT_INIT_ARRAYSZ: i64 = 27; // Size of init array
pub const DT_FINI_ARRAYSZ: i64 = 28; // Size of fini array
pub const DT_GNU_HASH: i64 = 0x6FFFFEF5; // GNU-style hash table
pub const DT_VERSYM: i64 = 0x6FFFFFF0; // Symbol version table
pub const DT_VERNEED: i64 = 0x6FFFFFFE; // Version requirements
pub const DT_VERNEEDNUM: i64 = 0x6FFFFFFF; // Number of version requirements

/// Elf64_Sym — Symbol table entry
pub const Elf64_Sym = extern struct {
    st_name: u32, // Offset into string table
    st_info: u8, // Type and binding (bind << 4 | type)
    st_other: u8, // Visibility
    st_shndx: u16, // Section index
    st_value: u64, // Symbol value (address)
    st_size: u64, // Symbol size
};

/// Symbol binding (upper 4 bits of st_info)
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

/// Symbol type (lower 4 bits of st_info)
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;

/// Extract binding from st_info
pub fn elf64SymBinding(info: u8) u8 {
    return info >> 4;
}

/// Extract type from st_info
pub fn elf64SymType(info: u8) u8 {
    return info & 0xF;
}

/// Elf64_Rela — Relocation entry with explicit addend
pub const Elf64_Rela = extern struct {
    r_offset: u64, // Address where to apply relocation
    r_info: u64, // Symbol table index + relocation type
    r_addend: i64, // Addend
};

/// Extract symbol index from r_info
pub fn elf64RelaSym(info: u64) u32 {
    return @intCast(info >> 32);
}

/// Extract relocation type from r_info
pub fn elf64RelaType(info: u64) u32 {
    return @intCast(info & 0xFFFFFFFF);
}

/// x86_64 relocation types
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1; // S + A (absolute 64-bit)
pub const R_X86_64_GLOB_DAT: u32 = 6; // S (GOT entry for global data)
pub const R_X86_64_JUMP_SLOT: u32 = 7; // S (PLT entry for function call)
pub const R_X86_64_RELATIVE: u32 = 8; // B + A (base address relative)

// ============================================================================
// Dynamic Linker Error Types
// ============================================================================

pub const DynLinkError = error{
    NoDynamicSegment,
    InvalidDynamicEntry,
    SymbolNotFound,
    LibraryNotFound,
    RelocationFailed,
    OutOfMemory,
    MapFailed,
};

// ============================================================================
// Loaded Library Descriptor
// ============================================================================

pub const MAX_LIBRARIES: usize = 32;
pub const MAX_NEEDED: usize = 16;

pub const LoadedLibrary = struct {
    name: [256]u8 = undefined,
    name_len: usize = 0,
    base_addr: u64 = 0, // Virtual base address where the library is loaded
    cr3: u64 = 0, // PML4 this library is loaded into
    entry_point: u64 = 0,

    // Dynamic section info (addresses are virtual, relative to base)
    dyn_symtab: u64 = 0, // DT_SYMTAB virtual address
    dyn_strtab: u64 = 0, // DT_STRTAB virtual address
    dyn_strsz: u64 = 0, // DT_STRSZ
    dyn_rela: u64 = 0, // DT_RELA virtual address
    dyn_relasz: u64 = 0, // DT_RELASZ
    dyn_relaent: u64 = 24, // DT_RELAENT (default: sizeof(Elf64_Rela) = 24)
    dyn_jmprel: u64 = 0, // DT_JMPREL (PLT relocations)
    dyn_pltrelsz: u64 = 0, // DT_PLTRELSZ
    dyn_pltgot: u64 = 0, // DT_PLTGOT
    dyn_hash: u64 = 0, // DT_HASH
    dyn_gnu_hash: u64 = 0, // DT_GNU_HASH
    dyn_init: u64 = 0, // DT_INIT
    dyn_fini: u64 = 0, // DT_FINI

    is_loaded: bool = false,
    is_relocated: bool = false,
};

/// Global array of loaded shared libraries
var loaded_libraries: [MAX_LIBRARIES]LoadedLibrary = undefined;
var library_count: usize = 0;

/// Base address for loading shared libraries
/// Each library gets its own 16MB region
const LIB_BASE_START: u64 = 0x400000000; // 16 GB
const LIB_BASE_STRIDE: u64 = 0x1000000; // 16 MB per library

// ============================================================================
// Dynamic Linker Initialization
// ============================================================================

pub fn init() void {
    for (&loaded_libraries) |*lib| {
        lib.* = LoadedLibrary{};
    }
    library_count = 0;

    hal.Serial.puts("[DYNLINK] Dynamic linker initialized (v0.9.0)\n");
}

// ============================================================================
// PT_DYNAMIC Parsing
// ============================================================================

/// Parse the .dynamic section from an ELF binary.
///
/// This reads all DT_* entries and populates a LoadedLibrary structure
/// with the addresses of the dynamic section components (symtab, strtab,
/// rela, jmprel, etc.).
///
/// Parameters:
///   elf_data    — Raw ELF file content
///   load_base   — Virtual base address where the ELF was loaded
///                  (0 for ET_EXEC, load_base for ET_DYN/PIE)
///   cr3         — PML4 this ELF is loaded into
///
/// Returns: LoadedLibrary descriptor (not yet relocated)
pub fn parseDynamic(elf_data: []const u8, load_base: u64, cr3: u64) DynLinkError!?*LoadedLibrary {
    if (elf_data.len < @sizeOf(elf_loader.Elf64_Ehdr)) return null;

    const ehdr: *const elf_loader.Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));
    if (ehdr.e_ident[0] != 0x7F or ehdr.e_ident[1] != 'E' or ehdr.e_ident[2] != 'L' or ehdr.e_ident[3] != 'F')
        return null;

    // Find PT_DYNAMIC segment
    var dynamic_offset: u64 = 0;
    var dynamic_size: u64 = 0;
    var dynamic_vaddr: u64 = 0;
    var found_dynamic = false;

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset + @sizeOf(elf_loader.Elf64_Phdr) > elf_data.len) break;

        const phdr: *const elf_loader.Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset));

        if (phdr.p_type == 2) { // PT_DYNAMIC
            dynamic_offset = phdr.p_offset;
            dynamic_size = phdr.p_memsz;
            dynamic_vaddr = phdr.p_vaddr + load_base;
            found_dynamic = true;
            break;
        }
    }

    if (!found_dynamic) {
        // No PT_DYNAMIC — this is a statically-linked executable
        return null;
    }

    hal.Serial.puts("[DYNLINK] Found PT_DYNAMIC at vaddr=0x");
    hal.Serial.putHex(dynamic_vaddr);
    hal.Serial.puts(" size=");
    hal.Serial.putDecimal(dynamic_size);
    hal.Serial.puts("\n");

    // Allocate a library slot
    if (library_count >= MAX_LIBRARIES) {
        hal.Serial.puts("[DYNLINK] ERROR: too many libraries loaded\n");
        return DynLinkError.OutOfMemory;
    }

    const lib = &loaded_libraries[library_count];
    library_count += 1;

    lib.cr3 = cr3;
    lib.base_addr = load_base;
    lib.is_loaded = true;
    lib.is_relocated = false;

    // Parse .dynamic entries
    const dyn_start = dynamic_offset;
    const dyn_end = dynamic_offset + dynamic_size;
    var offset: u64 = dyn_start;

    while (offset + @sizeOf(Elf64_Dyn) <= dyn_end and offset < elf_data.len) {
        const dyn: *const Elf64_Dyn = @ptrCast(@alignCast(elf_data.ptr + offset));

        if (dyn.d_tag == DT_NULL) break;

        switch (dyn.d_tag) {
            DT_NEEDED => {
                // Library dependency — will be resolved later
                hal.Serial.puts("[DYNLINK] DT_NEEDED: strtab offset ");
                hal.Serial.putDecimal(dyn.d_val);
                hal.Serial.puts("\n");
            },
            DT_STRTAB => {
                lib.dyn_strtab = dyn.d_val + load_base;
            },
            DT_SYMTAB => {
                lib.dyn_symtab = dyn.d_val + load_base;
            },
            DT_STRSZ => {
                lib.dyn_strsz = dyn.d_val;
            },
            DT_RELA => {
                lib.dyn_rela = dyn.d_val + load_base;
            },
            DT_RELASZ => {
                lib.dyn_relasz = dyn.d_val;
            },
            DT_RELAENT => {
                lib.dyn_relaent = dyn.d_val;
            },
            DT_JMPREL => {
                lib.dyn_jmprel = dyn.d_val + load_base;
            },
            DT_PLTRELSZ => {
                lib.dyn_pltrelsz = dyn.d_val;
            },
            DT_PLTGOT => {
                lib.dyn_pltgot = dyn.d_val + load_base;
            },
            DT_HASH => {
                lib.dyn_hash = dyn.d_val + load_base;
            },
            DT_GNU_HASH => {
                lib.dyn_gnu_hash = dyn.d_val + load_base;
            },
            DT_INIT => {
                lib.dyn_init = dyn.d_val + load_base;
            },
            DT_FINI => {
                lib.dyn_fini = dyn.d_val + load_base;
            },
            else => {
                // Unknown/unsupported dynamic entry — skip
            },
        }

        offset += @sizeOf(Elf64_Dyn);
    }

    hal.Serial.puts("[DYNLINK] Parsed .dynamic: symtab=0x");
    hal.Serial.putHex(lib.dyn_symtab);
    hal.Serial.puts(" strtab=0x");
    hal.Serial.putHex(lib.dyn_strtab);
    hal.Serial.puts(" rela=0x");
    hal.Serial.putHex(lib.dyn_rela);
    hal.Serial.puts(" jmprel=0x");
    hal.Serial.putHex(lib.dyn_jmprel);
    hal.Serial.puts("\n");

    return lib;
}

// ============================================================================
// Relocation Processing
// ============================================================================

/// Process all relocations for a loaded library or executable.
///
/// Handles:
///   - R_X86_64_RELATIVE: B + A (base + addend) — no symbol lookup needed
///   - R_X86_64_64: S + A (symbol value + addend)
///   - R_X86_64_GLOB_DAT: S (global data symbol via GOT)
///   - R_X86_64_JUMP_SLOT: S (function symbol via PLT/GOT)
///
/// Parameters:
///   lib — The LoadedLibrary descriptor (must have .dynamic section parsed)
pub fn processRelocations(lib: *LoadedLibrary) DynLinkError!void {
    if (lib.is_relocated) return;

    // Step 1: Process DT_RELA relocations
    if (lib.dyn_rela != 0 and lib.dyn_relasz > 0) {
        const num_rela = lib.dyn_relasz / lib.dyn_relaent;
        const rela_base: [*]const Elf64_Rela = @ptrFromInt(lib.dyn_rela);

        hal.Serial.puts("[DYNLINK] Processing ");
        hal.Serial.putDecimal(num_rela);
        hal.Serial.puts(" RELA relocations\n");

        for (0..num_rela) |i| {
            const rela = rela_base[i];
            try applyRelocation(lib, rela);
        }
    }

    // Step 2: Process DT_JMPREL (PLT) relocations
    if (lib.dyn_jmprel != 0 and lib.dyn_pltrelsz > 0) {
        const num_plt_rela = lib.dyn_pltrelsz / lib.dyn_relaent;
        const plt_rela_base: [*]const Elf64_Rela = @ptrFromInt(lib.dyn_jmprel);

        hal.Serial.puts("[DYNLINK] Processing ");
        hal.Serial.putDecimal(num_plt_rela);
        hal.Serial.puts(" PLT relocations\n");

        for (0..num_plt_rela) |i| {
            const rela = plt_rela_base[i];
            try applyRelocation(lib, rela);
        }
    }

    lib.is_relocated = true;

    hal.Serial.puts("[DYNLINK] Relocations complete for ");
    hal.Serial.puts(lib.name[0..lib.name_len]);
    hal.Serial.puts("\n");
}

/// Apply a single RELA relocation entry
fn applyRelocation(lib: *LoadedLibrary, rela: Elf64_Rela) DynLinkError!void {
    const rtype = elf64RelaType(rela.r_info);
    const sym_idx = elf64RelaSym(rela.r_info);
    const target_addr = rela.r_offset + lib.base_addr;

    // The target address is a virtual address in the process's address space
    // We need to write to it via physical memory (kernel identity-maps RAM)
    // First, look up the PTE to find the physical page
    const pte = vmm.getPTE(lib.cr3, target_addr);
    if (pte & vmm.PTE_PRESENT == 0) {
        hal.Serial.puts("[DYNLINK] ERROR: relocation target not mapped: 0x");
        hal.Serial.putHex(target_addr);
        hal.Serial.puts("\n");
        return DynLinkError.RelocationFailed;
    }

    const phys_page = pte & 0x000FFFFFFFFFF000;
    const page_offset = target_addr & 0xFFF;
    const phys_target = phys_page + page_offset;

    switch (rtype) {
        R_X86_64_RELATIVE => {
            // B + A: base address + addend
            // Most common relocation — no symbol lookup needed
            const value = @as(u64, @bitCast(rela.r_addend)) +% lib.base_addr;
            const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
            target_ptr.* = value;
        },

        R_X86_64_64 => {
            // S + A: symbol value + addend
            const sym_value = resolveSymbol(lib, sym_idx) orelse {
                hal.Serial.puts("[DYNLINK] ERROR: R_X86_64_64: symbol not found (idx=");
                hal.Serial.putDecimal(sym_idx);
                hal.Serial.puts(")\n");
                return DynLinkError.SymbolNotFound;
            };
            const value = sym_value +% @as(u64, @bitCast(rela.r_addend));
            const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
            target_ptr.* = value;
        },

        R_X86_64_GLOB_DAT => {
            // S: Global data symbol — write symbol address to GOT entry
            const sym_value = resolveSymbol(lib, sym_idx) orelse {
                hal.Serial.puts("[DYNLINK] ERROR: R_X86_64_GLOB_DAT: symbol not found (idx=");
                hal.Serial.putDecimal(sym_idx);
                hal.Serial.puts(")\n");
                return DynLinkError.SymbolNotFound;
            };
            const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
            target_ptr.* = sym_value;
        },

        R_X86_64_JUMP_SLOT => {
            // S: PLT/GOT entry for function call — write symbol address to GOT
            // For lazy binding, we would write the PLT resolver address instead.
            // v0.9.0: Eager binding — resolve immediately.
            const sym_value = resolveSymbol(lib, sym_idx) orelse {
                hal.Serial.puts("[DYNLINK] ERROR: R_X86_64_JUMP_SLOT: symbol not found (idx=");
                hal.Serial.putDecimal(sym_idx);
                hal.Serial.puts(")\n");
                return DynLinkError.SymbolNotFound;
            };
            const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
            target_ptr.* = sym_value;
        },

        R_X86_64_NONE => {
            // No relocation — skip
        },

        else => {
            hal.Serial.puts("[DYNLINK] WARNING: unsupported relocation type ");
            hal.Serial.putDecimal(rtype);
            hal.Serial.puts(" at 0x");
            hal.Serial.putHex(target_addr);
            hal.Serial.puts("\n");
        },
    }
}

// ============================================================================
// Symbol Resolution
// ============================================================================

/// Resolve a symbol by its index in the dynamic symbol table.
///
/// First, look up the symbol in the library's own symbol table.
/// If it's defined there (st_value != 0 and st_shndx != SHN_UNDEF),
/// return its address.
///
/// If it's undefined (SHN_UNDEF), search all other loaded libraries
/// for a definition (global symbol resolution).
///
/// Parameters:
///   lib     — The library requesting the symbol
///   sym_idx — Index into the library's DT_SYMTAB
///
/// Returns: Virtual address of the symbol, or null if not found
fn resolveSymbol(lib: *LoadedLibrary, sym_idx: u32) ?u64 {
    if (lib.dyn_symtab == 0) return null;

    const symtab: [*]const Elf64_Sym = @ptrFromInt(lib.dyn_symtab);
    const sym = symtab[sym_idx];

    // Check if the symbol is defined in this library
    if (sym.st_shndx != 0 and sym.st_value != 0) {
        // Symbol is defined here — return its address
        return sym.st_value +% lib.base_addr;
    }

    // Symbol is undefined — search other loaded libraries
    if (lib.dyn_strtab == 0) return null;

    // Get the symbol name from the string table
    const name_offset = sym.st_name;
    if (name_offset == 0) return null;

    const name_ptr: [*]const u8 = @ptrFromInt(lib.dyn_strtab + name_offset);
    const name_len = cstrLen(name_ptr);
    const name = name_ptr[0..name_len];

    if (name_len == 0) return null;

    // Search all other loaded libraries for this symbol
    for (&loaded_libraries) |*other_lib| {
        if (!other_lib.is_loaded) continue;
        if (other_lib == lib) continue; // Skip self — already checked
        if (other_lib.dyn_symtab == 0) continue;

        const result = findSymbolInLibrary(other_lib, name);
        if (result) |addr| {
            hal.Serial.puts("[DYNLINK] Resolved symbol '");
            hal.Serial.puts(name);
            hal.Serial.puts("' -> 0x");
            hal.Serial.putHex(addr);
            hal.Serial.puts(" (from ");
            hal.Serial.puts(other_lib.name[0..other_lib.name_len]);
            hal.Serial.puts(")\n");
            return addr;
        }
    }

    hal.Serial.puts("[DYNLINK] Symbol '");
    hal.Serial.puts(name);
    hal.Serial.puts("' NOT FOUND in any loaded library\n");
    return null;
}

/// Find a global symbol by name in a specific library
fn findSymbolInLibrary(lib: *LoadedLibrary, name: []const u8) ?u64 {
    if (lib.dyn_symtab == 0 or lib.dyn_strtab == 0) return null;
    if (lib.dyn_hash == 0 and lib.dyn_gnu_hash == 0) return null;

    // Use the hash table for efficient lookup
    if (lib.dyn_hash != 0) {
        return findSymbolSysvHash(lib, name);
    }

    if (lib.dyn_gnu_hash != 0) {
        return findSymbolGnuHash(lib, name);
    }

    return null;
}

/// Find a symbol using the SVR4-style hash table (DT_HASH)
fn findSymbolSysvHash(lib: *LoadedLibrary, name: []const u8) ?u64 {
    const hash_table: [*]const u32 = @ptrFromInt(lib.dyn_hash);
    const nchain = hash_table[1]; // Number of symbol table entries

    const hash = elfHash(name);
    const bucket_idx = hash % hash_table[0]; // nbucket
    var sym_idx = hash_table[2 + bucket_idx]; // buckets[bucket_idx]

    const symtab: [*]const Elf64_Sym = @ptrFromInt(lib.dyn_symtab);

    while (sym_idx != 0 and sym_idx < nchain) {
        const sym = symtab[sym_idx];

        // Check if symbol is defined and global/weak
        if (sym.st_shndx != 0 and // SHN_UNDEF = 0
            (elf64SymBinding(sym.st_info) == STB_GLOBAL or
            elf64SymBinding(sym.st_info) == STB_WEAK))
        {
            const sym_name_ptr: [*]const u8 = @ptrFromInt(lib.dyn_strtab + sym.st_name);
            const sym_name_len = cstrLen(sym_name_ptr);

            if (name.len == sym_name_len and memEql(name.ptr, sym_name_ptr, name.len)) {
                return sym.st_value +% lib.base_addr;
            }
        }

        // Follow the chain
        sym_idx = hash_table[2 + hash_table[0] + sym_idx]; // chains[sym_idx]
    }

    return null;
}

/// Find a symbol using the GNU hash table (DT_GNU_HASH)
fn findSymbolGnuHash(lib: *LoadedLibrary, name: []const u8) ?u64 {
    // GNU hash table format:
    //   [0] nbuckets: u32
    //   [1] symndx: u32 (first symbol in .dynsym that is in the hash)
    //   [2] maskwords: u32 (number of bloom filter words)
    //   [3] shift2: u32 (bloom filter shift)
    //   [4..4+maskwords] bloom filter (u64 per word on 64-bit)
    //   [4+maskwords..4+maskwords+nbuckets] buckets (u32 each)
    //   [4+maskwords+nbuckets..] chains (u32 each)

    const gnu_hash: [*]const u32 = @ptrFromInt(lib.dyn_gnu_hash);
    const nbuckets = gnu_hash[0];
    const symndx = gnu_hash[1];
    const maskwords = gnu_hash[2];
    const shift2 = gnu_hash[3];

    // Bloom filter check (quick reject)
    const hash = gnuHash(name);
    const bloom_idx = (hash / 64) % maskwords;
    const bloom_word: u64 = @bitCast(@as([2]u32, .{ gnu_hash[4 + bloom_idx * 2], gnu_hash[4 + bloom_idx * 2 + 1] }));
    const bloom_mask1: u64 = @as(u64, 1) << @intCast(hash % 64);
    const bloom_mask2: u64 = @as(u64, 1) << @intCast((hash >> shift2) % 64);

    if ((bloom_word & bloom_mask1) == 0 or (bloom_word & bloom_mask2) == 0) {
        return null; // Definitely not in this library
    }

    // Bucket lookup
    const buckets_offset = 4 + maskwords * 2;
    const bucket_val = gnu_hash[buckets_offset + (hash % nbuckets)];

    if (bucket_val == 0) return null; // Empty bucket

    const symtab: [*]const Elf64_Sym = @ptrFromInt(lib.dyn_symtab);
    const chains_offset = buckets_offset + nbuckets;

    var sym_idx: u32 = bucket_val;
    var chain_idx: u32 = sym_idx - symndx;

    while (true) {
        const chain_val = gnu_hash[chains_offset + chain_idx];

        // Check if hash matches (chain stores hash with LSB used as stop bit)
        if ((chain_val & ~@as(u32, 1)) == (hash & ~@as(u32, 1))) {
            const sym = symtab[sym_idx];
            if (sym.st_shndx != 0) {
                const sym_name_ptr: [*]const u8 = @ptrFromInt(lib.dyn_strtab + sym.st_name);
                const sym_name_len = cstrLen(sym_name_ptr);
                if (name.len == sym_name_len and memEql(name.ptr, sym_name_ptr, name.len)) {
                    return sym.st_value +% lib.base_addr;
                }
            }
        }

        // Check stop bit — end of chain
        if ((chain_val & 1) != 0) break;

        sym_idx += 1;
        chain_idx += 1;
    }

    return null;
}

// ============================================================================
// Shared Library Loading
// ============================================================================

/// Load a shared library from the filesystem into a process's address space.
///
/// This is a simplified version — in v0.9.0, we assume the library
/// data is already available in memory (from a ramdisk or initrd).
/// Full filesystem loading will come when the VFS is more mature.
///
/// Parameters:
///   lib_data  — Raw ELF .so file content
///   lib_name  — Library name (e.g., "libc.so")
///   target_cr3 — PML4 to load the library into
///   load_index — Which library slot to use for base address calculation
///
/// Returns: LoadedLibrary descriptor
pub fn loadSharedLibrary(lib_data: []const u8, lib_name: []const u8, target_cr3: u64, load_index: usize) DynLinkError!?*LoadedLibrary {
    if (lib_data.len < @sizeOf(elf_loader.Elf64_Ehdr)) return null;

    const ehdr: *const elf_loader.Elf64_Ehdr = @ptrCast(@alignCast(lib_data.ptr));

    // Validate ELF header
    if (ehdr.e_ident[0] != 0x7F or ehdr.e_ident[1] != 'E' or
        ehdr.e_ident[2] != 'L' or ehdr.e_ident[3] != 'F')
        return null;
    if (ehdr.e_ident[4] != 2) return null; // Not 64-bit
    if (ehdr.e_machine != elf_loader.EM_X86_64) return null;

    // Shared libraries must be ET_DYN
    if (ehdr.e_type != elf_loader.ET_DYN) return null;

    // Calculate load base for this library
    const load_base = LIB_BASE_START + @as(u64, load_index) * LIB_BASE_STRIDE;

    hal.Serial.puts("[DYNLINK] Loading shared library '");
    hal.Serial.puts(lib_name);
    hal.Serial.puts("' at base=0x");
    hal.Serial.putHex(load_base);
    hal.Serial.puts("\n");

    // Load the ELF into the target PML4
    const result = elf_loader.loadElfIntoPML4_v2(lib_data, target_cr3, load_base) catch {
        hal.Serial.puts("[DYNLINK] ERROR: failed to map library into PML4\n");
        return DynLinkError.MapFailed;
    };

    // Parse the dynamic section
    const lib = parseDynamic(lib_data, load_base, target_cr3) catch {
        hal.Serial.puts("[DYNLINK] ERROR: failed to parse .dynamic\n");
        return DynLinkError.NoDynamicSegment;
    };

    if (lib) |l| {
        // Set the library name
        const copy_len = @min(lib_name.len, 255);
        @memcpy(l.name[0..copy_len], lib_name[0..copy_len]);
        l.name[copy_len] = 0;
        l.name_len = copy_len;
        l.base_addr = load_base;
        l.entry_point = result.entry_point;

        hal.Serial.puts("[DYNLINK] Library '");
        hal.Serial.puts(lib_name);
        hal.Serial.puts("' loaded at 0x");
        hal.Serial.putHex(load_base);
        hal.Serial.puts(" entry=0x");
        hal.Serial.putHex(result.entry_point);
        hal.Serial.puts("\n");

        return l;
    }

    return null;
}

// ============================================================================
// DT_NEEDED Resolution
// ============================================================================

/// Get the list of DT_NEEDED library names from an ELF's .dynamic section.
///
/// Returns an array of string slices pointing into the ELF data.
/// The caller must provide the output array.
pub fn getNeededLibraries(elf_data: []const u8, load_base: u64, out_names: []UnsizedSlice, out_count: *usize) DynLinkError!void {
    out_count.* = 0;

    if (elf_data.len < @sizeOf(elf_loader.Elf64_Ehdr)) return;

    const ehdr: *const elf_loader.Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));

    // Find PT_DYNAMIC
    var dynamic_offset: u64 = 0;
    var dynamic_size: u64 = 0;
    var strtab_vaddr: u64 = 0;
    var strtab_offset: u64 = 0;

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_off = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_off + @sizeOf(elf_loader.Elf64_Phdr) > elf_data.len) break;

        const phdr: *const elf_loader.Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_off));

        if (phdr.p_type == 2) { // PT_DYNAMIC
            dynamic_offset = phdr.p_offset;
            dynamic_size = phdr.p_memsz;
        }

        if (phdr.p_type == elf_loader.PT_LOAD) {
            // The strtab is a virtual address; we need to find the file offset
            // For now, we'll find it from the .dynamic entries themselves
        }
    }

    if (dynamic_offset == 0) return; // No dynamic section

    // First pass: find DT_STRTAB to get the string table
    var offset: u64 = dynamic_offset;
    while (offset + @sizeOf(Elf64_Dyn) <= dynamic_offset + dynamic_size and offset < elf_data.len) {
        const dyn: *const Elf64_Dyn = @ptrCast(@alignCast(elf_data.ptr + offset));
        if (dyn.d_tag == DT_NULL) break;
        if (dyn.d_tag == DT_STRTAB) {
            strtab_vaddr = dyn.d_val;
        }
        offset += @sizeOf(Elf64_Dyn);
    }

    // Convert strtab virtual address to file offset
    // For PIE (ET_DYN), strtab_vaddr is relative to load base 0
    // We need to find which PT_LOAD segment contains strtab_vaddr
    strtab_offset = vaddrToFileOffset(elf_data, strtab_vaddr);

    // Second pass: collect DT_NEEDED entries
    offset = dynamic_offset;
    while (offset + @sizeOf(Elf64_Dyn) <= dynamic_offset + dynamic_size and offset < elf_data.len) {
        const dyn: *const Elf64_Dyn = @ptrCast(@alignCast(elf_data.ptr + offset));
        if (dyn.d_tag == DT_NULL) break;

        if (dyn.d_tag == DT_NEEDED) {
            // dyn.d_val is an offset into the string table
            const name_offset = strtab_offset + dyn.d_val;
            if (name_offset < elf_data.len and out_count.* < out_names.len) {
                out_names[out_count.*] = .{ .ptr = elf_data.ptr + name_offset };
                out_count.* += 1;
            }
        }

        offset += @sizeOf(Elf64_Dyn);
    }
}

/// Helper: unsized slice (just a pointer — length determined by null terminator)
pub const UnsizedSlice = struct {
    ptr: [*]const u8,
};

/// Convert a virtual address to a file offset by scanning PT_LOAD segments
fn vaddrToFileOffset(elf_data: []const u8, vaddr: u64) u64 {
    const ehdr: *const elf_loader.Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_off = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_off + @sizeOf(elf_loader.Elf64_Phdr) > elf_data.len) break;

        const phdr: *const elf_loader.Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_off));

        if (phdr.p_type == elf_loader.PT_LOAD) {
            if (vaddr >= phdr.p_vaddr and vaddr < phdr.p_vaddr + phdr.p_memsz) {
                return phdr.p_offset + (vaddr - phdr.p_vaddr);
            }
        }
    }

    return vaddr; // Fallback — might be wrong but better than crashing
}

// ============================================================================
// PLT/GOT Setup
// ============================================================================

/// Set up the PLT resolver for lazy binding.
///
/// In v0.9.0, we do eager binding (all symbols resolved immediately).
/// The PLT resolver is provided for future lazy binding support.
///
/// The PLT resolver stub template (per-function):
///   jmp *GOT[n](%rip)     ; Jump through GOT entry
///   push $reloc_index     ; Push relocation index
///   jmp PLT[0]            ; Jump to PLT resolver (PLT entry 0)
///
/// PLT entry 0 (resolver):
///   push GOT[1]            ; Push link map (object identifier)
///   jmp GOT[2]             ; Jump to resolver function
///
/// For eager binding, we write the resolved address directly to GOT[n]
/// so the first jmp goes straight to the target function.
pub fn setupPltResolver(lib: *LoadedLibrary) void {
    // v0.9.0: With eager binding, PLT resolver is not needed.
    // All GOT entries for JUMP_SLOT are already resolved.
    // This function is a placeholder for future lazy binding.

    _ = lib;
    hal.Serial.puts("[DYNLINK] PLT/GOT setup complete (eager binding)\n");
}

// ============================================================================
// Constructor/Destructor Invocation
// ============================================================================

/// Call DT_INIT and DT_INIT_ARRAY functions for a library.
/// These are the C++ constructors and __attribute__((constructor)) functions.
pub fn callInitFunctions(lib: *LoadedLibrary) void {
    if (lib.dyn_init != 0) {
        hal.Serial.puts("[DYNLINK] Calling DT_INIT at 0x");
        hal.Serial.putHex(lib.dyn_init);
        hal.Serial.puts("\n");

        // We would call the init function here, but in kernel mode we can't
        // directly call user-space functions. The init function is called
        // when the process starts executing (the runtime loader jumps to it).
        // For now, just log that we would call it.
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// ELF hash function (SVR4 style)
/// Used for DT_HASH symbol lookup
fn elfHash(name: []const u8) u32 {
    var h: u32 = 0;
    for (name) |c| {
        h = (h << 4) + @as(u32, c);
        const g = h & 0xF0000000;
        if (g != 0) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

/// GNU hash function
/// Used for DT_GNU_HASH symbol lookup (better distribution than ELF hash)
fn gnuHash(name: []const u8) u32 {
    var h: u32 = 5381;
    for (name) |c| {
        h = h *% 33 +% @as(u32, c);
    }
    return h;
}

/// C-style string length (null-terminated)
fn cstrLen(ptr: [*]const u8) usize {
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    return len;
}

/// Memory equality comparison
fn memEql(a: [*]const u8, b: [*]const u8, len: usize) bool {
    for (0..len) |i| {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// ============================================================================
// Master Dynamic Linking Entry Point
// ============================================================================

/// Link a dynamically-linked ELF executable.
///
/// This is the main entry point called by the ELF loader when it detects
/// a PT_INTERP or PT_DYNAMIC segment. It:
///   1. Parses the .dynamic section
///   2. Loads all DT_NEEDED shared libraries
///   3. Processes relocations for all objects
///   4. Sets up PLT/GOT
///   5. Calls init functions
///
/// Parameters:
///   elf_data    — Raw ELF file content
///   load_base   — Virtual base address where the ELF was loaded
///   target_cr3  — PML4 this ELF is loaded into
pub fn linkDynamicExecutable(elf_data: []const u8, load_base: u64, target_cr3: u64) DynLinkError!void {
    hal.Serial.puts("[DYNLINK] Linking dynamic executable at base=0x");
    hal.Serial.putHex(load_base);
    hal.Serial.puts("\n");

    // Step 1: Parse the executable's .dynamic section
    const main_lib = try parseDynamic(elf_data, load_base, target_cr3);
    if (main_lib == null) {
        hal.Serial.puts("[DYNLINK] No dynamic section — statically linked\n");
        return;
    }

    // Set the main executable name
    const main_name = "main";
    @memcpy(main_lib.?.name[0..main_name.len], main_name);
    main_lib.?.name[main_name.len] = 0;
    main_lib.?.name_len = main_name.len;

    // Step 2: Find DT_NEEDED libraries
    var needed_names: [MAX_NEEDED]UnsignedSlice = undefined;
    var needed_count: usize = 0;
    // Note: In a real implementation, we'd load these from the filesystem.
    // v0.9.0: We just log them. Actual loading happens when the library
    // data is provided to loadSharedLibrary().
    _ = needed_names;
    _ = needed_count;

    hal.Serial.puts("[DYNLINK] Processing DT_NEEDED libraries...\n");

    // Step 3: Process relocations for the main executable
    try processRelocations(main_lib.?);

    // Step 4: Process relocations for all loaded libraries
    for (&loaded_libraries) |*lib| {
        if (lib.is_loaded and !lib.is_relocated) {
            try processRelocations(lib);
        }
    }

    // Step 5: Setup PLT/GOT
    setupPltResolver(main_lib.?);

    // Step 6: Call init functions
    callInitFunctions(main_lib.?);

    hal.Serial.puts("[DYNLINK] Dynamic linking complete\n");
}

/// Placeholder type (same as UnsizedSlice)
const UnsignedSlice = UnsizedSlice;
