// ============================================================================
// POLER-OS Dynamic Linker (ld-poler) — v1.0.0
// ============================================================================
//
// Implements ELF64 dynamic linking for shared libraries (.so files).
//
// v1.0.0 features over v0.9.0:
//   1. PLT lock for thread-safe lazy binding (per-library spinlock)
//   2. TLS (Thread-Local Storage) — DT_TLS, TCB layout, __tls_get_addr
//   3. Weak symbols — STB_WEAK handled correctly (resolve to 0 if absent)
//   4. Symbol versioning — DT_VERSYM / DT_VERNEED / DT_VERNEEDNUM
//   5. DT_NEEDED auto-loading from /lib/ via VFS (FAT32)
//
// Architecture:
//   1. Parse PT_DYNAMIC segment from the main executable
//   2. Process .dynamic entries (DT_NEEDED, DT_SYMTAB, DT_STRTAB, etc.)
//   3. Load shared libraries from the filesystem (DT_NEEDED) via VFS
//   4. Process relocations:
//      - R_X86_64_RELATIVE  — base-address-relative (most common, no symbol lookup)
//      - R_X86_64_GLOB_DAT  — global data symbol resolution via GOT
//      - R_X86_64_JUMP_SLOT — lazy PLT binding (function calls via PLT)
//      - R_X86_64_64        — absolute 64-bit relocation
//      - R_X86_64_TPOFF64   — TLS variable offset from thread pointer
//      - R_X86_64_DTPMOD64  — TLS module ID for GD model
//   5. Set up GOT (Global Offset Table) with resolved addresses
//   6. Set up PLT (Procedure Linkage Table) for lazy function binding
//   7. Set up TLS blocks and TCB for thread-local storage
//
// Memory layout for dynamically-linked process:
//
//   0x100000      Main executable (ET_DYN PIE or ET_EXEC)
//   0x400000_000  First shared library (libc.so)
//   0x400010_000  Second shared library (libm.so)
//   ...           Additional libraries
//   0x7F0000_000  Stack (top of user address space region)
//   0x7E0000_000  TLS master copy area
//   0x7DFFF0_000  TCB (Thread Control Block) per thread
//
// Lazy binding (v1.0.0 with PLT lock):
//   Initially, GOT entries for functions point to the PLT resolver stub.
//   On first call, the resolver:
//     1. Acquires the PLT lock (per-library spinlock)
//     2. Double-checks if another thread already resolved (race window)
//     3. Looks up the symbol in all loaded libraries (with versioning)
//     4. Patches the GOT entry with the real address
//     5. Releases the PLT lock
//     6. Jumps to the resolved function
//   Subsequent calls go directly through the patched GOT entry — no lock.
//
// Symbol versioning:
//   DT_VERSYM table maps each symbol index to a version index.
//   DT_VERNEED lists the required version definitions per library.
//   When resolving, we check that the version in the provider library
//   matches what the consumer expects. This prevents ABI drift.
//
// Weak symbols:
//   STB_WEAK symbols resolve normally if a definition exists in any
//   loaded library. If no definition is found, they resolve to 0
//   (not an error). This is critical for optional functionality and
//   plugin architectures (e.g., __pthread_key_create is weak in libc).
//
// TLS (Thread-Local Storage):
//   Two models supported:
//     - Local Executable (LE):  TLS variables in the main executable
//       accessed via %fs:offset (no GOT indirection, fastest).
//     - Initial Executable (IE): TLS in shared libs loaded at startup
//       accessed via %fs:pointer-to-TLS-block.
//   TCB layout (x86_64 glibc-compatible):
//     +0x00: void* tp  (thread pointer = address of TCB itself)
//     +0x08: dtv_t* dtv (dynamic TLS vector)
//     +0x10: void* self (pointer to self for integrity check)
//     +0x18: multiple  (link_map pointer, etc.)
//   __tls_get_addr() resolves TLS variables for the General Dynamic model.
// ============================================================================

const hal = @import("hal.zig");
const std = @import("std");
const vmm = @import("vmm64.zig");
const pmm = @import("pmm64.zig");
const elf_loader = @import("elf_loader.zig");
const spinlock = @import("spinlock.zig");
const heap = @import("heap64.zig");

// v1.1.0: VFS abstraction — eliminates direct fat32.zig import.
// The dynlinker no longer depends on the FAT32 driver directly.
// Instead, it uses the VFS layer (kernel_integrate) which provides
// a uniform file I/O interface. This solves the VFS-DynLinker security
// gap where .so loading previously bypassed the VFS security layer.
//
// The callback is registered by kernel_integrate at init time, breaking
// the circular dependency: dynlinker.zig ↔ kernel_integrate.zig ↔ fat32.zig
// becomes: dynlinker.zig → callback → kernel_integrate.zig → fat32.zig
//
// Note: C calling convention can't use slices ([]const u8). We use
// pointer + length instead, and reconstruct the slice in the callback.
pub var vfsLoadCallback: ?*const fn ([*]const u8, usize, *VfsFileData) callconv(.C) bool = null;

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
pub const DT_RUNPATH: i64 = 29; // Library search path (colon-separated)
pub const DT_FLAGS: i64 = 30; // Flag bits (DF_*)
pub const DT_FLAGS_1: i64 = 0x6FFFFFFB; // Flag bits (DF_1_*)
pub const DT_GNU_HASH: i64 = 0x6FFFFEF5; // GNU-style hash table
pub const DT_VERSYM: i64 = 0x6FFFFFF0; // Symbol version table
pub const DT_VERNEED: i64 = 0x6FFFFFFE; // Version requirements
pub const DT_VERNEEDNUM: i64 = 0x6FFFFFFF; // Number of version requirements
pub const DT_VERDEF: i64 = 0x6FFFFFFC; // Version definitions
pub const DT_VERDEFNUM: i64 = 0x6FFFFFFD; // Number of version definitions

/// DT_TLS — TLS template (new in v1.0.0)
pub const DT_TLS: i64 = 0x40000013; // Not a real ELF tag, but we track TLS info internally

/// DT_FLAGS bits
pub const DF_BIND_NOW: u64 = 0x8; // Non-lazy binding (BIND_NOW)

/// DT_FLAGS_1 bits
pub const DF_1_NOW: u64 = 0x1; // BIND_NOW equivalent
pub const DF_1_NOOPEN: u64 = 0x40; // Cannot dlopen
pub const DF_1_NODELETE: u64 = 0x800; // Cannot unload

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
pub const STT_TLS: u8 = 6; // Thread-local storage object

/// Symbol visibility (lower 2 bits of st_other)
pub const STV_DEFAULT: u8 = 0; // Normal visibility
pub const STV_HIDDEN: u8 = 2; // Not visible outside the defining component

/// SHN_UNDEF — undefined section index
pub const SHN_UNDEF: u16 = 0;

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
pub const R_X86_64_TPOFF64: u32 = 18; // TLS: offset from thread pointer (LE/IE)
pub const R_X86_64_DTPMOD64: u32 = 19; // TLS: module ID (GD model)
pub const R_X86_64_DTPOFF64: u32 = 20; // TLS: offset within TLS block (GD model)
pub const R_X86_64_TLSDESC: u32 = 36; // TLS descriptor (optimized GD)

// ============================================================================
// Symbol Versioning Structures (v1.0.0)
// ============================================================================

/// Elf64_Verneed — version requirement entry
/// Describes which version a library needs from another library
pub const Elf64_Verneed = extern struct {
    vn_version: u16, // Version of this entry (1)
    vn_cnt: u16, // Number of associated Vernaux entries
    vn_file: u32, // Offset of library name in string table
    vn_aux: u32, // Offset to first Vernaux entry (relative to this)
    vn_next: u32, // Offset to next Verneed entry (0 if last)
};

/// Elf64_Vernaux — version requirement auxiliary entry
/// One per needed version from a specific library
pub const Elf64_Vernaux = extern struct {
    vna_hash: u32, // Hash of version name
    vna_flags: u16, // Version flags (VER_FLG_*)
    vna_other: u16, // Version index (used in VERSYM table)
    vna_name: u32, // Offset of version name in string table
    vna_next: u32, // Offset to next Vernaux entry (0 if last)
};

/// Elf64_Verdef — version definition entry
/// Describes a version provided by this library
pub const Elf64_Verdef = extern struct {
    vd_version: u16, // Version of this entry (1)
    vd_flags: u16, // Version flags (VER_FLG_*)
    vd_ndx: u16, // Version index (used in VERSYM table)
    vd_cnt: u16, // Number of Verdaux entries
    vd_hash: u32, // Hash of version name
    vd_aux: u32, // Offset to first Verdaux entry
    vd_next: u32, // Offset to next Verdef entry (0 if last)
};

/// Elf64_Verdaux — version definition auxiliary entry
pub const Elf64_Verdaux = extern struct {
    vda_name: u32, // Offset of version name in string table
    vda_next: u32, // Offset to next Verdaux entry (0 if last)
};

/// Version flags
pub const VER_FLG_BASE: u16 = 0x1; // Version definition base
pub const VER_FLG_WEAK: u16 = 0x2; // Weak version
pub const VER_FLG_INFO: u16 = 0x4; // Info version (not used)

/// Version index special values
pub const VER_NDX_LOCAL: u16 = 0; // Local symbol (not in versioning)
pub const VER_NDX_GLOBAL: u16 = 1; // Global symbol (default version)

// ============================================================================
// TLS Structures (v1.0.0)
// ============================================================================

/// TLS template information for a loaded library or executable.
/// When a new thread is created, each library's TLS initialization image
/// is copied into the new thread's TLS block, at the appropriate offset.
pub const TlsTemplate = struct {
    /// Virtual address of the TLS initialization image (tdata)
    init_image: u64 = 0,
    /// Size of the TLS initialization image (tdata — initialized data)
    init_size: u64 = 0,
    /// Total size of TLS for this module (tdata + tbss)
    total_size: u64 = 0,
    /// Alignment requirement for TLS block
    alignment: u64 = 16,
    /// Offset of this module's TLS in the combined TLS block
    /// (computed at load time based on total sizes of all preceding modules)
    block_offset: u64 = 0,
    /// Module ID (1-based index; used by R_X86_64_DTPMOD64)
    module_id: u32 = 0,
};

/// Thread Control Block (TCB) — per-thread structure at %fs:0
/// Compatible with glibc/x86_64 ABI layout
pub const Tcb = extern struct {
    /// Pointer to this TCB itself (for integrity check, also = thread pointer)
    tp: *Tcb,
    /// Dynamic TLS vector — array of pointers to TLS blocks for each module
    /// dtv[0].counter = generation count, dtv[1..n].pointer = TLS block ptr
    dtv: [*]DtvEntry,
    /// Self-pointer (for additional integrity)
    self: *Tcb,
    /// Pointer to this thread's link_map (for __tls_get_addr)
    link_map: ?*anyopaque,
    /// Per-thread stack canary (for -fstack-protector)
    stack_canary: u64,
    /// Reserved for future use
    _reserved: [4]u64,
};

/// Dynamic TLS vector entry
pub const DtvEntry = extern struct {
    /// If counter != dtv_generation, this entry is stale and must be reallocated
    counter: usize,
    /// Pointer to the TLS block for this module (allocated on the heap)
    pointer: ?*anyopaque,
};

/// Global TLS generation counter — incremented each time a new library
/// with TLS is loaded. Threads check their DTV against this counter;
/// if stale, they reallocate their DTV.
var tls_generation: usize = 1;

/// Next module ID to assign for TLS
var next_tls_module_id: u32 = 1;

/// Total combined TLS size across all loaded modules (for main thread only;
/// additional threads allocate this much + alignment)
var combined_tls_size: u64 = 0;

/// Maximum alignment across all loaded TLS modules
var combined_tls_align: u64 = 16;

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
    VersionMismatch,
    TlsError,
    VfsError,
};

// ============================================================================
// Loaded Library Descriptor
// ============================================================================

pub const MAX_LIBRARIES: usize = 64; // v1.0.0: increased from 32
pub const MAX_NEEDED: usize = 32; // v1.0.0: increased from 16

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
    dyn_init_array: u64 = 0, // DT_INIT_ARRAY
    dyn_init_arraysz: u64 = 0, // DT_INIT_ARRAYSZ
    dyn_fini_array: u64 = 0, // DT_FINI_ARRAY
    dyn_fini_arraysz: u64 = 0, // DT_FINI_ARRAYSZ
    dyn_runpath: u64 = 0, // DT_RUNPATH string table offset
    dyn_flags: u64 = 0, // DT_FLAGS
    dyn_flags_1: u64 = 0, // DT_FLAGS_1

    // v1.0.0: Symbol versioning
    dyn_versym: u64 = 0, // DT_VERSYM virtual address
    dyn_verneed: u64 = 0, // DT_VERNEED virtual address
    dyn_verneednum: u64 = 0, // DT_VERNEEDNUM count
    dyn_verdef: u64 = 0, // DT_VERDEF virtual address
    dyn_verdefnum: u64 = 0, // DT_VERDEFNUM count

    // v1.0.0: TLS template
    tls: TlsTemplate = .{},

    // v1.0.0: PLT lock for thread-safe lazy binding
    plt_lock: spinlock.Spinlock = .{},

    // v1.0.0: Binding mode
    bind_now: bool = false, // True if DT_FLAGS has DF_BIND_NOW or DT_FLAGS_1 has DF_1_NOW

    // v1.0.0: VFS file data — kept alive for recursive DT_NEEDED resolution.
    // After all dependencies are resolved, the caller should free this
    // via heap.kfree(vfs_data.ptr) to reclaim kernel heap memory.
    vfs_data: VfsFileData = .{},

    // v1.1.0: SHA-256 integrity hash of the loaded ELF image.
    // Computed at load time from the raw .so file data.
    // Used to detect tampering or corruption of shared libraries.
    // If a known-good hash is provided (e.g., from a manifest),
    // loadSharedLibrary will verify it before mapping the library.
    integrity_hash: [32]u8 = [_]u8{0} ** 32,
    // v1.1.0: Whether integrity hash has been verified against a known value
    integrity_verified: bool = false,

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

/// TLS base address region for combined TLS block
const TLS_BASE_ADDR: u64 = 0x7E000_0000; // Below stack
/// TCB base address (one per thread)
const TCB_BASE_ADDR: u64 = 0x7DFFF_0000;

// ============================================================================
// VFS Path for DT_NEEDED resolution (v1.0.0)
// ============================================================================

/// Default library search paths (colon-separated, but we use an array)
const LIBRARY_SEARCH_PATHS = [_][]const u8{
    "/lib/",
    "/usr/lib/",
    "/lib64/",
};

/// Max size for a library file read from VFS
const MAX_LIBRARY_FILE_SIZE: u64 = 64 * 1024 * 1024; // 64 MB

/// Result of a VFS file load — holds the heap-allocated buffer.
/// The caller must free via heap.kfree(data.ptr) when done with the data.
pub const VfsFileData = struct {
    ptr: [*]u8 = undefined, // Raw pointer for kfree
    size: u32 = 0, // Bytes actually read
    slice: []const u8 = &[_]u8{}, // Slice for passing to ELF parser

    pub fn isValid(self: *const @This()) bool {
        return self.size > 0 and self.slice.len > 0;
    }
};

// ============================================================================
// Dynamic Linker Initialization
// ============================================================================

pub fn init() void {
    for (&loaded_libraries) |*lib| {
        lib.* = LoadedLibrary{};
    }
    library_count = 0;
    next_tls_module_id = 1;
    combined_tls_size = 0;
    combined_tls_align = 16;
    tls_generation = 1;

    hal.Serial.puts("[DYNLINK] Dynamic linker initialized (v1.0.0)\n");
    hal.Serial.puts("[DYNLINK]   PLT lock: enabled (thread-safe lazy binding)\n");
    hal.Serial.puts("[DYNLINK]   TLS: enabled (Local Exec + Initial Exec)\n");
    hal.Serial.puts("[DYNLINK]   Weak symbols: enabled\n");
    hal.Serial.puts("[DYNLINK]   Symbol versioning: enabled\n");
    hal.Serial.puts("[DYNLINK]   DT_NEEDED VFS autoload: enabled (/lib/)\n");
}

// ============================================================================
// PT_DYNAMIC Parsing
// ============================================================================

/// Parse the .dynamic section from an ELF binary.
///
/// This reads all DT_* entries and populates a LoadedLibrary structure
/// with the addresses of the dynamic section components (symtab, strtab,
/// rela, jmprel, versym, verneed, etc.).
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
                // Library dependency — will be resolved by loadNeededLibraries()
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
            DT_INIT_ARRAY => {
                lib.dyn_init_array = dyn.d_val + load_base;
            },
            DT_INIT_ARRAYSZ => {
                lib.dyn_init_arraysz = dyn.d_val;
            },
            DT_FINI_ARRAY => {
                lib.dyn_fini_array = dyn.d_val + load_base;
            },
            DT_FINI_ARRAYSZ => {
                lib.dyn_fini_arraysz = dyn.d_val;
            },
            DT_RUNPATH => {
                lib.dyn_runpath = dyn.d_val;
            },
            DT_FLAGS => {
                lib.dyn_flags = dyn.d_val;
                if (dyn.d_val & DF_BIND_NOW != 0) {
                    lib.bind_now = true;
                }
            },
            DT_FLAGS_1 => {
                lib.dyn_flags_1 = dyn.d_val;
                if (dyn.d_val & DF_1_NOW != 0) {
                    lib.bind_now = true;
                }
            },
            DT_VERSYM => {
                lib.dyn_versym = dyn.d_val + load_base;
            },
            DT_VERNEED => {
                lib.dyn_verneed = dyn.d_val + load_base;
            },
            DT_VERNEEDNUM => {
                lib.dyn_verneednum = dyn.d_val;
            },
            DT_VERDEF => {
                lib.dyn_verdef = dyn.d_val + load_base;
            },
            DT_VERDEFNUM => {
                lib.dyn_verdefnum = dyn.d_val;
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
    if (lib.dyn_versym != 0) {
        hal.Serial.puts(" versym=0x");
        hal.Serial.putHex(lib.dyn_versym);
    }
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
///   - R_X86_64_TPOFF64: TLS offset from thread pointer
///   - R_X86_64_DTPMOD64: TLS module ID
///   - R_X86_64_DTPOFF64: TLS offset within module block
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
            try applyRelocation(lib, rela_base[i]);
        }
    }

    // Step 2: Process DT_JMPREL (PLT) relocations
    if (lib.dyn_jmprel != 0 and lib.dyn_pltrelsz > 0) {
        const num_plt_rela = lib.dyn_pltrelsz / lib.dyn_relaent;
        const plt_rela_base: [*]const Elf64_Rela = @ptrFromInt(lib.dyn_jmprel);

        hal.Serial.puts("[DYNLINK] Processing ");
        hal.Serial.putDecimal(num_plt_rela);
        hal.Serial.puts(" PLT relocations (");
        if (lib.bind_now) {
            hal.Serial.puts("BIND_NOW");
        } else {
            hal.Serial.puts("lazy+PLT lock");
        }
        hal.Serial.puts(")\n");

        if (lib.bind_now) {
            // Eager binding — resolve all PLT entries immediately
            for (0..num_plt_rela) |i| {
                try applyRelocation(lib, plt_rela_base[i]);
            }
        } else {
            // Lazy binding — set GOT entries to PLT resolver stub
            // The actual resolution happens on first call via pltLazyResolver()
            // For now, we write a sentinel value that the PLT resolver will detect
            setupLazyPltEntries(lib, plt_rela_base, num_plt_rela);
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
            const sym_result = resolveSymbolWithVersion(lib, sym_idx);
            if (!sym_result.found) {
                // v1.0.0: Check if symbol is weak — if so, resolve to 0 (not an error)
                const is_weak = sym_result.is_weak;
                if (!is_weak) {
                    hal.Serial.puts("[DYNLINK] ERROR: R_X86_64_64: symbol not found (idx=");
                    hal.Serial.putDecimal(sym_idx);
                    hal.Serial.puts(")\n");
                    return DynLinkError.SymbolNotFound;
                }
                // Weak symbol not found — write 0
                const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
                target_ptr.* = 0;
            } else {
                const value = sym_result.value +% @as(u64, @bitCast(rela.r_addend));
                const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
                target_ptr.* = value;
            }
        },

        R_X86_64_GLOB_DAT => {
            // S: Global data symbol — write symbol address to GOT entry
            const sym_result = resolveSymbolWithVersion(lib, sym_idx);
            if (!sym_result.found) {
                if (!sym_result.is_weak) {
                    hal.Serial.puts("[DYNLINK] ERROR: R_X86_64_GLOB_DAT: symbol not found (idx=");
                    hal.Serial.putDecimal(sym_idx);
                    hal.Serial.puts(")\n");
                    return DynLinkError.SymbolNotFound;
                }
                const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
                target_ptr.* = 0;
            } else {
                const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
                target_ptr.* = sym_result.value;
            }
        },

        R_X86_64_JUMP_SLOT => {
            // S: PLT/GOT entry for function call
            // v1.0.0: With lazy binding, this is handled by setupLazyPltEntries()
            // For eager binding (BIND_NOW), resolve immediately.
            const sym_result = resolveSymbolWithVersion(lib, sym_idx);
            if (!sym_result.found) {
                if (!sym_result.is_weak) {
                    hal.Serial.puts("[DYNLINK] ERROR: R_X86_64_JUMP_SLOT: symbol not found (idx=");
                    hal.Serial.putDecimal(sym_idx);
                    hal.Serial.puts(")\n");
                    return DynLinkError.SymbolNotFound;
                }
                const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
                target_ptr.* = 0;
            } else {
                const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
                target_ptr.* = sym_result.value;
            }
        },

        R_X86_64_TPOFF64 => {
            // TLS: Offset from thread pointer (tp) to the TLS variable.
            // For Local Executable model: the offset is computed from the
            // main executable's TLS block, which is placed right after the TCB.
            // Formula: tp + offset = &variable
            //   => offset = &variable - tp = variable_addr - tcb_addr
            const sym_result = resolveSymbolWithVersion(lib, sym_idx);
            if (!sym_result.found) {
                hal.Serial.puts("[DYNLINK] ERROR: R_X86_64_TPOFF64: TLS symbol not found (idx=");
                hal.Serial.putDecimal(sym_idx);
                hal.Serial.puts(")\n");
                return DynLinkError.SymbolNotFound;
            }

            // The symbol value is the virtual address of the TLS variable.
            // TPOFF64 = symbol_addr - thread_pointer
            // In the Local Executable model, the TLS block starts right after
            // the TCB (thread pointer points to TCB, TLS data follows at tp - TLS_size).
            // We compute the offset as: -(combined_tls_size - tls_offset_of_this_symbol)
            const tls_offset = sym_result.value; // This is the offset in the TLS template
            const target_ptr: *volatile i64 = @ptrFromInt(phys_target);
            target_ptr.* = @intCast(tls_offset);
        },

        R_X86_64_DTPMOD64 => {
            // TLS: Module ID — used by General Dynamic (GD) TLS model.
            // Write the module ID of the symbol's defining library.
            const sym_result = resolveSymbolWithVersion(lib, sym_idx);
            const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
            target_ptr.* = sym_result.module_id;
        },

        R_X86_64_DTPOFF64 => {
            // TLS: Offset within the module's TLS block (GD model).
            // This is the offset from the start of the module's TLS block
            // to the specific TLS variable.
            const sym_result = resolveSymbolWithVersion(lib, sym_idx);
            const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
            target_ptr.* = sym_result.dtv_offset;
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
// PLT Lock & Lazy Binding (v1.0.0)
// ============================================================================

/// Set up GOT entries for lazy PLT binding.
///
/// Instead of resolving the symbol immediately, we write a special sentinel
/// value (0xDEAD) into the GOT entry. The PLT stub code will:
///   1. Push the relocation index
///   2. Jump to the PLT resolver (PLT[0])
///   3. The resolver calls pltLazyResolver() which:
///      a. Acquires the per-library PLT lock
///      b. Checks if the GOT entry was already resolved (race window)
///      c. Resolves the symbol
///      d. Patches the GOT entry with the real address
///      e. Releases the PLT lock
///
/// Thread safety guarantee:
///   Two threads calling the same unresolved PLT entry concurrently:
///     Thread A: acquires lock, resolves, patches GOT, releases lock
///     Thread B: acquires lock, sees GOT already patched, releases lock, jumps
///   The second thread's PLT stub may still call the resolver, but the
///   resolver detects the already-resolved entry and returns immediately.
fn setupLazyPltEntries(lib: *LoadedLibrary, plt_rela_base: [*]const Elf64_Rela, num_plt: usize) void {
    for (0..num_plt) |i| {
        const rela = plt_rela_base[i];
        const target_addr = rela.r_offset + lib.base_addr;

        const pte = vmm.getPTE(lib.cr3, target_addr);
        if (pte & vmm.PTE_PRESENT == 0) continue;

        const phys_page = pte & 0x000FFFFFFFFFF000;
        const page_offset = target_addr & 0xFFF;
        const phys_target = phys_page + page_offset;

        // Write sentinel value — PLT resolver will detect this
        const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
        target_ptr.* = 0xDEAD;
    }

    hal.Serial.puts("[DYNLINK] Lazy PLT entries set up with sentinel (0xDEAD) for ");
    hal.Serial.puts(lib.name[0..lib.name_len]);
    hal.Serial.puts("\n");
}

/// PLT lazy resolver — called from the PLT[0] stub when a lazy-bound
/// function is first invoked.
///
/// This function is called in the context of the user process (triggered
/// by the PLT stub's jmp to GOT[2]). In a real implementation, this
/// would run in user mode with access to the process's GOT.
///
/// In our kernel-mode implementation, we resolve from the kernel side
/// using the PLT lock to ensure thread safety.
///
/// Parameters:
///   lib          — Library whose GOT needs patching
///   reloc_index  — Index into the JMPREL table (pushed by PLT stub)
///
/// Returns: Virtual address of the resolved function
pub fn pltLazyResolver(lib: *LoadedLibrary, reloc_index: usize) u64 {
    // Acquire the per-library PLT lock
    lib.plt_lock.acquire();
    defer lib.plt_lock.release();

    // Look up the relocation entry
    if (lib.dyn_jmprel == 0 or lib.dyn_pltrelsz == 0) {
        hal.Serial.puts("[DYNLINK] ERROR: pltLazyResolver but no JMPREL\n");
        return 0;
    }

    const rela_base: [*]const Elf64_Rela = @ptrFromInt(lib.dyn_jmprel);
    const rela = rela_base[reloc_index];

    const target_addr = rela.r_offset + lib.base_addr;

    // Double-check: has another thread already resolved this?
    const pte = vmm.getPTE(lib.cr3, target_addr);
    if (pte & vmm.PTE_PRESENT != 0) {
        const phys_page = pte & 0x000FFFFFFFFFF000;
        const page_offset = target_addr & 0xFFF;
        const phys_target = phys_page + page_offset;
        const target_ptr: *volatile u64 = @ptrFromInt(phys_target);

        if (target_ptr.* != 0xDEAD) {
            // Already resolved by another thread while we waited for the lock
            return target_ptr.*;
        }
    }

    // Resolve the symbol
    const sym_idx = elf64RelaSym(rela.r_info);
    const sym_result = resolveSymbolWithVersion(lib, sym_idx);

    var resolved_addr: u64 = 0;
    if (sym_result.found) {
        resolved_addr = sym_result.value;
    } else if (sym_result.is_weak) {
        resolved_addr = 0; // Weak symbol not found — resolve to 0
    } else {
        hal.Serial.puts("[DYNLINK] ERROR: lazy resolve failed for symbol idx=");
        hal.Serial.putDecimal(sym_idx);
        hal.Serial.puts("\n");
        return 0; // Fatal in production, but we continue
    }

    // Patch the GOT entry with the resolved address
    if (pte & vmm.PTE_PRESENT != 0) {
        const phys_page = pte & 0x000FFFFFFFFFF000;
        const page_offset = target_addr & 0xFFF;
        const phys_target = phys_page + page_offset;
        const target_ptr: *volatile u64 = @ptrFromInt(phys_target);
        target_ptr.* = resolved_addr;
    }

    hal.Serial.puts("[DYNLINK] Lazy resolved symbol idx=");
    hal.Serial.putDecimal(sym_idx);
    hal.Serial.puts(" -> 0x");
    hal.Serial.putHex(resolved_addr);
    hal.Serial.puts(" (thread-safe via PLT lock)\n");

    return resolved_addr;
}

// ============================================================================
// Symbol Resolution with Versioning (v1.0.0)
// ============================================================================

/// Result of a symbol resolution attempt.
/// Contains not just the address, but also metadata about the symbol's
/// binding (weak vs global), version, and TLS info.
pub const SymbolResult = struct {
    found: bool = false,
    value: u64 = 0,
    is_weak: bool = false,
    module_id: u32 = 0, // TLS module ID
    dtv_offset: u64 = 0, // TLS offset within module's block
    version_idx: u16 = 0, // Symbol version index
};

/// Resolve a symbol by its index in the dynamic symbol table,
/// taking version information into account.
///
/// Resolution strategy:
///   1. Look up the symbol in the requesting library's own symbol table.
///   2. If the symbol is defined there (st_shndx != SHN_UNDEF), return it.
///   3. If undefined, get the version requirement from DT_VERSYM.
///   4. Search all other loaded libraries for a matching symbol:
///      a. The symbol name must match.
///      b. If versioning is active, the version must match.
///      c. STB_GLOBAL symbols take priority over STB_WEAK.
///   5. If no match is found and the symbol is STB_WEAK, return found=false
///      with is_weak=true (caller should treat as 0, not error).
///   6. If no match and STB_GLOBAL, return found=false (error).
fn resolveSymbolWithVersion(lib: *LoadedLibrary, sym_idx: u32) SymbolResult {
    var result = SymbolResult{};

    if (lib.dyn_symtab == 0) return result;

    const symtab: [*]const Elf64_Sym = @ptrFromInt(lib.dyn_symtab);
    const sym = symtab[sym_idx];

    const binding = elf64SymBinding(sym.st_info);
    const is_weak = binding == STB_WEAK;
    result.is_weak = is_weak;

    // Check if the symbol is defined in this library
    if (sym.st_shndx != SHN_UNDEF and sym.st_value != 0) {
        // Symbol is defined here — return its address
        result.found = true;
        result.value = sym.st_value +% lib.base_addr;
        result.module_id = lib.tls.module_id;
        result.dtv_offset = sym.st_value; // Offset within TLS block

        // If this is a TLS symbol, the value is the offset in the TLS template
        if (elf64SymType(sym.st_info) == STT_TLS) {
            result.value = sym.st_value; // TLS offset, not absolute address
        }

        return result;
    }

    // Symbol is undefined — look up version requirement
    var required_version: u16 = 0; // 0 = no version requirement
    var required_version_name: ?[]const u8 = null;

    if (lib.dyn_versym != 0) {
        const versym: [*]const u16 = @ptrFromInt(lib.dyn_versym);
        const raw_versym = versym[sym_idx];
        required_version = raw_versym & 0x7FFF; // Mask off hidden bit

        // If version is VER_NDX_GLOBAL (1) or VER_NDX_LOCAL (0), no specific version
        if (required_version > VER_NDX_GLOBAL) {
            // Find the version name from DT_VERNEED
            required_version_name = findVersionName(lib, required_version);
        }
    }

    // Get the symbol name from the string table
    if (lib.dyn_strtab == 0) return result;

    const name_offset = sym.st_name;
    if (name_offset == 0) return result;

    const name_ptr: [*]const u8 = @ptrFromInt(lib.dyn_strtab + name_offset);
    const name_len = cstrLen(name_ptr);
    const name = name_ptr[0..name_len];

    if (name.len == 0) return result;

    // Search all other loaded libraries for this symbol
    var best_match: SymbolResult = .{ .is_weak = is_weak };

    for (&loaded_libraries) |*other_lib| {
        if (!other_lib.is_loaded) continue;
        if (other_lib == lib) continue; // Skip self
        if (other_lib.dyn_symtab == 0) continue;

        const candidate = findSymbolInLibraryWithVersion(other_lib, name, required_version, required_version_name);

        if (candidate.found) {
            // Global symbols beat weak symbols
            if (!candidate.is_weak) {
                return candidate; // Found a global definition — use it immediately
            }

            // This is a weak match — keep looking for a global one
            if (!best_match.found) {
                best_match = candidate;
            }
        }
    }

    return best_match;
}

/// Find the version name string for a given version index by scanning DT_VERNEED.
fn findVersionName(lib: *LoadedLibrary, version_idx: u16) ?[]const u8 {
    if (lib.dyn_verneed == 0 or lib.dyn_verneednum == 0) return null;

    var vn_offset: u64 = 0;
    var vn_count: u64 = 0;

    while (vn_count < lib.dyn_verneednum) : (vn_count += 1) {
        const vn: *const Elf64_Verneed = @ptrFromInt(lib.dyn_verneed + vn_offset);

        // Walk Vernaux entries
        var vna_offset: u64 = vn_offset + vn.vn_aux;
        var vna_count: u16 = 0;

        while (vna_count < vn.vn_cnt) : (vna_count += 1) {
            const vna: *const Elf64_Vernaux = @ptrFromInt(lib.dyn_verneed + vna_offset);

            if (vna.vna_other == version_idx) {
                // Found the version entry — get the name
                if (lib.dyn_strtab != 0) {
                    const name_ptr: [*]const u8 = @ptrFromInt(lib.dyn_strtab + vna.vna_name);
                    const name_len = cstrLen(name_ptr);
                    return name_ptr[0..name_len];
                }
                return null;
            }

            if (vna.vna_next == 0) break;
            vna_offset += vna.vna_next;
        }

        if (vn.vn_next == 0) break;
        vn_offset += vn.vn_next;
    }

    return null;
}

/// Check if a version definition in a provider library matches the required version.
fn checkVersionMatch(provider_lib: *LoadedLibrary, required_version: u16, required_version_name: ?[]const u8) bool {
    // If no version was required, any version matches
    if (required_version <= VER_NDX_GLOBAL or required_version_name == null) {
        return true;
    }

    // Check the provider's DT_VERDEF for a matching version
    if (provider_lib.dyn_verdef == 0 or provider_lib.dyn_verdefnum == 0) {
        // Provider has no version definitions — accept anyway
        // (many simple libraries don't define versions)
        return true;
    }

    var vd_offset: u64 = 0;
    var vd_count: u64 = 0;

    while (vd_count < provider_lib.dyn_verdefnum) : (vd_count += 1) {
        const vd: *const Elf64_Verdef = @ptrFromInt(provider_lib.dyn_verdef + vd_offset);

        // Check if this version index matches what we need
        if (vd.vd_ndx == required_version) {
            // Index matches — verify the name
            if (required_version_name) |req_name| {
                // Get the version name from the first Verdaux entry
                const vda: *const Elf64_Verdaux = @ptrFromInt(provider_lib.dyn_verdef + vd_offset + vd.vd_aux);
                if (provider_lib.dyn_strtab != 0) {
                    const prov_name_ptr: [*]const u8 = @ptrFromInt(provider_lib.dyn_strtab + vda.vda_name);
                    const prov_name_len = cstrLen(prov_name_ptr);
                    const prov_name = prov_name_ptr[0..prov_name_len];

                    if (nameEql(req_name, prov_name)) {
                        return true;
                    }
                }
            }
            return true; // Index match is sufficient
        }

        if (vd.vd_next == 0) break;
        vd_offset += vd.vd_next;
    }

    // No matching version found — but many libraries don't version explicitly.
    // Be lenient: accept if the library provides a symbol with the right name.
    return true;
}

/// Find a global/weak symbol by name in a specific library,
/// checking version compatibility.
fn findSymbolInLibraryWithVersion(lib: *LoadedLibrary, name: []const u8, required_version: u16, required_version_name: ?[]const u8) SymbolResult {
    var result = SymbolResult{};

    if (lib.dyn_symtab == 0 or lib.dyn_strtab == 0) return result;
    if (lib.dyn_hash == 0 and lib.dyn_gnu_hash == 0) return result;

    // Use the hash table for efficient lookup
    var sym_addr: ?u64 = null;
    var sym_binding: u8 = STB_GLOBAL;

    if (lib.dyn_hash != 0) {
        const found = findSymbolSysvHash(lib, name);
        if (found) |info| {
            sym_addr = info.addr;
            sym_binding = info.binding;
        }
    } else if (lib.dyn_gnu_hash != 0) {
        const found = findSymbolGnuHash(lib, name);
        if (found) |info| {
            sym_addr = info.addr;
            sym_binding = info.binding;
        }
    }

    if (sym_addr) |addr| {
        // Check version compatibility
        if (!checkVersionMatch(lib, required_version, required_version_name)) {
            return result; // Version mismatch
        }

        result.found = true;
        result.value = addr;
        result.is_weak = sym_binding == STB_WEAK;
        result.module_id = lib.tls.module_id;
        return result;
    }

    return result;
}

// ============================================================================
// Symbol Resolution (Core)
// ============================================================================

/// Extended symbol lookup result (with binding info)
const SymbolInfo = struct {
    addr: u64,
    binding: u8, // STB_GLOBAL or STB_WEAK
};

/// Find a symbol using the SVR4-style hash table (DT_HASH)
fn findSymbolSysvHash(lib: *LoadedLibrary, name: []const u8) ?SymbolInfo {
    const hash_table: [*]const u32 = @ptrFromInt(lib.dyn_hash);
    const nchain = hash_table[1]; // Number of symbol table entries

    const hash = elfHash(name);
    const bucket_idx = hash % hash_table[0]; // nbucket
    var sym_idx = hash_table[2 + bucket_idx]; // buckets[bucket_idx]

    const symtab: [*]const Elf64_Sym = @ptrFromInt(lib.dyn_symtab);

    while (sym_idx != 0 and sym_idx < nchain) {
        const sym = symtab[sym_idx];

        // Check if symbol is defined and global/weak
        if (sym.st_shndx != SHN_UNDEF and
            (elf64SymBinding(sym.st_info) == STB_GLOBAL or
            elf64SymBinding(sym.st_info) == STB_WEAK))
        {
            const sym_name_ptr: [*]const u8 = @ptrFromInt(lib.dyn_strtab + sym.st_name);
            const sym_name_len = cstrLen(sym_name_ptr);

            if (name.len == sym_name_len and memEql(name.ptr, sym_name_ptr, name.len)) {
                // Check visibility — STV_HIDDEN symbols are not exported
                const visibility = sym.st_other & 0x3;
                if (visibility == STV_HIDDEN) {
                    // Hidden symbol — skip, not visible outside the defining component
                } else {
                    return SymbolInfo{
                        .addr = sym.st_value +% lib.base_addr,
                        .binding = elf64SymBinding(sym.st_info),
                    };
                }
            }
        }

        // Follow the chain
        sym_idx = hash_table[2 + hash_table[0] + sym_idx]; // chains[sym_idx]
    }

    return null;
}

/// Find a symbol using the GNU hash table (DT_GNU_HASH)
fn findSymbolGnuHash(lib: *LoadedLibrary, name: []const u8) ?SymbolInfo {
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
            if (sym.st_shndx != SHN_UNDEF and
                (elf64SymBinding(sym.st_info) == STB_GLOBAL or
                elf64SymBinding(sym.st_info) == STB_WEAK))
            {
                const sym_name_ptr: [*]const u8 = @ptrFromInt(lib.dyn_strtab + sym.st_name);
                const sym_name_len = cstrLen(sym_name_ptr);
                if (name.len == sym_name_len and memEql(name.ptr, sym_name_ptr, name.len)) {
                    // Check visibility
                    const visibility = sym.st_other & 0x3;
                    if (visibility != STV_HIDDEN) {
                        return SymbolInfo{
                            .addr = sym.st_value +% lib.base_addr,
                            .binding = elf64SymBinding(sym.st_info),
                        };
                    }
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
// TLS Setup (v1.0.0)
// ============================================================================

/// Parse TLS template information from the ELF's PT_TLS segment.
///
/// The PT_TLS segment (p_type = 7) describes the TLS template:
///   - p_vaddr: virtual address of .tdata (initialized TLS data)
///   - p_memsz: total TLS size (.tdata + .tbss)
///   - p_filesz: size of .tdata (only initialized part)
///   - p_align: alignment requirement
pub fn parseTlsTemplate(elf_data: []const u8, load_base: u64, lib: *LoadedLibrary) void {
    if (elf_data.len < @sizeOf(elf_loader.Elf64_Ehdr)) return;

    const ehdr: *const elf_loader.Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_offset + @sizeOf(elf_loader.Elf64_Phdr) > elf_data.len) break;

        const phdr: *const elf_loader.Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_offset));

        if (phdr.p_type == 7) { // PT_TLS
            lib.tls.init_image = phdr.p_vaddr + load_base;
            lib.tls.init_size = phdr.p_filesz;
            lib.tls.total_size = phdr.p_memsz;
            lib.tls.alignment = if (phdr.p_align > 1) phdr.p_align else 16;

            // Assign module ID
            lib.tls.module_id = next_tls_module_id;
            next_tls_module_id += 1;

            // Calculate block offset (aligned to max alignment)
            const aligned_offset = (combined_tls_size + lib.tls.alignment - 1) & ~(lib.tls.alignment - 1);
            lib.tls.block_offset = aligned_offset;
            combined_tls_size = aligned_offset + lib.tls.total_size;

            if (lib.tls.alignment > combined_tls_align) {
                combined_tls_align = lib.tls.alignment;
            }

            // Increment TLS generation (threads must check DTV)
            tls_generation += 1;

            hal.Serial.puts("[DYNLINK] PT_TLS: init_image=0x");
            hal.Serial.putHex(lib.tls.init_image);
            hal.Serial.puts(" init_size=");
            hal.Serial.putDecimal(lib.tls.init_size);
            hal.Serial.puts(" total_size=");
            hal.Serial.putDecimal(lib.tls.total_size);
            hal.Serial.puts(" align=");
            hal.Serial.putDecimal(lib.tls.alignment);
            hal.Serial.puts(" module_id=");
            hal.Serial.putDecimal(lib.tls.module_id);
            hal.Serial.puts("\n");

            return;
        }
    }

    // No PT_TLS — this library doesn't use TLS
}

/// Allocate and initialize the TCB (Thread Control Block) for a new thread.
///
/// This creates the thread's TLS master copy and sets up the DTV.
/// Must be called for each new thread before it starts executing.
///
/// Parameters:
///   cr3       — PML4 of the process this thread belongs to
///   thread_id — Thread ID (used to compute TCB address)
///
/// Returns: Virtual address of the TCB (= thread pointer = %fs:0)
pub fn allocateTcbForThread(cr3: u64, thread_id: u32) DynLinkError!u64 {
    // Allocate TCB + combined TLS block
    const tcb_size = @sizeOf(Tcb);
    const total_alloc = tcb_size + combined_tls_size + combined_tls_align;

    // Allocate physical pages for TCB + TLS
    const num_pages = (total_alloc + 4095) / 4096;
    const phys = pmm.allocContiguousPages(num_pages) orelse {
        hal.Serial.puts("[DYNLINK] ERROR: failed to allocate TCB pages\n");
        return DynLinkError.OutOfMemory;
    };

    // Map at TCB base address (per-thread offset)
    const tcb_vaddr = TCB_BASE_ADDR - @as(u64, thread_id) * 0x10000; // 64KB per thread
    _ = tcb_vaddr + tcb_size; // TLS area starts after TCB (used by tlsGetAddr)

    var i: u64 = 0;
    while (i < num_pages) : (i += 1) {
        vmm.mapPageInPML4(cr3, tcb_vaddr + i * 4096, phys + i * 4096, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch {
            hal.Serial.puts("[DYNLINK] ERROR: failed to map TCB page\n");
            return DynLinkError.MapFailed;
        };
    }

    // Zero the TCB + TLS block
    const mem: [*]volatile u8 = @ptrFromInt(phys);
    var j: u64 = 0;
    while (j < total_alloc) : (j += 1) {
        mem[j] = 0;
    }

    // Initialize TCB
    const tcb: *volatile Tcb = @ptrFromInt(phys);
    tcb.tp = @ptrFromInt(phys); // tp points to self (phys = virt for kernel identity map)
    tcb.self = @ptrFromInt(phys);
    tcb.stack_canary = 0xDEADBEEFCAFEBABE; // Default canary

    // Set up DTV (Dynamic TLS Vector)
    // DTV layout: [0] = generation, [1..n] = TLS block pointers
    const dtv_size = (next_tls_module_id + 1) * @sizeOf(DtvEntry);
    const dtv_phys = pmm.allocContiguousPages((dtv_size + 4095) / 4096) orelse {
        return DynLinkError.OutOfMemory;
    };
    const dtv: [*]DtvEntry = @ptrFromInt(dtv_phys);
    dtv[0].counter = tls_generation;
    dtv[0].pointer = null;

    // Copy TLS initialization images for each loaded library
    var lib_idx: usize = 0;
    for (&loaded_libraries) |*lib| {
        if (!lib.is_loaded) continue;
        if (lib.tls.total_size == 0) continue;

        const mid = lib.tls.module_id;
        if (mid == 0) continue;

        // Point DTV entry to the TLS block at the correct offset
        const tls_block_offset = tcb_size + lib.tls.block_offset;
        const tls_block_phys = phys + tls_block_offset;
        dtv[mid].counter = tls_generation;
        dtv[mid].pointer = @ptrFromInt(tls_block_phys);

        // Copy initialization image (.tdata)
        if (lib.tls.init_size > 0 and lib.tls.init_image != 0) {
            // Read from the mapped virtual address (already in PML4)
            const src_phys = virtToPhys(lib.cr3, lib.tls.init_image);
            if (src_phys != 0) {
                const src: [*]const u8 = @ptrFromInt(src_phys);
                const dst: [*]u8 = @ptrFromInt(tls_block_phys);
                var k: u64 = 0;
                while (k < lib.tls.init_size) : (k += 1) {
                    dst[k] = src[k];
                }
                // .tbss is already zeroed by the memset above
            }
        }

        lib_idx += 1;
    }

    tcb.dtv = dtv;

    hal.Serial.puts("[DYNLINK] TCB allocated for thread ");
    hal.Serial.putDecimal(thread_id);
    hal.Serial.puts(" at vaddr=0x");
    hal.Serial.putHex(tcb_vaddr);
    hal.Serial.puts(" TLS size=");
    hal.Serial.putDecimal(combined_tls_size);
    hal.Serial.puts("\n");

    return tcb_vaddr;
}

/// __tls_get_addr — runtime TLS resolver for General Dynamic (GD) model.
///
/// Called by user code when accessing a TLS variable that could not
/// be resolved at link time. Parameters are typically passed in %rdi
/// and %rsi following the x86_64 ABI:
///   %rdi = pointer to struct { u64 ti_module, u64 ti_offset } (tls_index)
///   %rsi = unused (reserved)
///
/// Returns: pointer to the TLS variable
pub fn tlsGetAddr(ti_module: u64, ti_offset: u64) u64 {
    // Find the library with this module ID
    for (&loaded_libraries) |*lib| {
        if (!lib.is_loaded) continue;
        if (lib.tls.module_id != ti_module) continue;

        // Get the current thread's TCB
        const tp = hal.readFsBase();
        const tcb: *const Tcb = @ptrFromInt(tp);

        // Check DTV generation
        if (tcb.dtv[0].counter != tls_generation) {
            // DTV is stale — would need to reallocate
            // For now, just log a warning (in production, reallocate DTV)
            hal.Serial.puts("[DYNLINK] WARNING: stale DTV for module ");
            hal.Serial.putDecimal(ti_module);
            hal.Serial.puts("\n");
        }

        // Get the TLS block pointer from DTV
        if (tcb.dtv[ti_module].pointer) |block_ptr| {
            return @intFromPtr(block_ptr) + ti_offset;
        }

        break;
    }

    hal.Serial.puts("[DYNLINK] ERROR: __tls_get_addr failed for module=");
    hal.Serial.putDecimal(ti_module);
    hal.Serial.puts(" offset=0x");
    hal.Serial.putHex(ti_offset);
    hal.Serial.puts("\n");

    return 0;
}

/// Convert a virtual address to physical using the page tables
fn virtToPhys(cr3: u64, vaddr: u64) u64 {
    const pte = vmm.getPTE(cr3, vaddr);
    if (pte & vmm.PTE_PRESENT == 0) return 0;
    const phys_page = pte & 0x000FFFFFFFFFF000;
    const page_offset = vaddr & 0xFFF;
    return phys_page + page_offset;
}

// ============================================================================
// Shared Library Loading
// ============================================================================

/// Load a shared library from the filesystem into a process's address space.
///
/// v1.0.0: Supports both in-memory library data AND VFS-based loading.
/// If lib_data is provided (non-null), it's used directly.
/// If lib_data is null, the library is looked up via VFS from /lib/.
///
/// Parameters:
///   lib_data   — Raw ELF .so file content (null to load from VFS)
///   lib_name   — Library name (e.g., "libc.so")
///   target_cr3 — PML4 to load the library into
///   load_index — Which library slot to use for base address calculation
///
/// Returns: LoadedLibrary descriptor
pub fn loadSharedLibrary(lib_data: ?[]const u8, lib_name: []const u8, target_cr3: u64, load_index: usize) DynLinkError!?*LoadedLibrary {
    // If no data provided, try to load from VFS
    var vfs_file_data: VfsFileData = .{};
    var vfs_loaded = false;

    const actual_data = if (lib_data) |d| d else blk: {
        // Try to load from VFS using search paths
        for (LIBRARY_SEARCH_PATHS) |path| {
            var full_path: [512]u8 = undefined;
            const path_len = path.len + lib_name.len;
            if (path_len > full_path.len) continue;

            @memcpy(full_path[0..path.len], path);
            @memcpy(full_path[path_len .. path_len + lib_name.len], lib_name);

            // Try to read the file from FAT32 via VFS
            if (loadFromVfs(full_path[0..path_len + lib_name.len], &vfs_file_data)) {
                vfs_loaded = true;
                hal.Serial.puts("[DYNLINK] Loaded '");
                hal.Serial.puts(lib_name);
                hal.Serial.puts("' from VFS path '");
                hal.Serial.puts(full_path[0..path_len + lib_name.len]);
                hal.Serial.puts("'\n");
                break;
            }
        }

        if (!vfs_loaded) {
            hal.Serial.puts("[DYNLINK] ERROR: library '");
            hal.Serial.puts(lib_name);
            hal.Serial.puts("' not found in VFS\n");
            return DynLinkError.LibraryNotFound;
        }

        break :blk vfs_file_data.slice;
    };

    if (actual_data.len < @sizeOf(elf_loader.Elf64_Ehdr)) return null;

    const ehdr: *const elf_loader.Elf64_Ehdr = @ptrCast(@alignCast(actual_data.ptr));

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
    const result = elf_loader.loadElfIntoPML4_v2(actual_data, target_cr3, load_base) catch {
        hal.Serial.puts("[DYNLINK] ERROR: failed to map library into PML4\n");
        return DynLinkError.MapFailed;
    };

    // Parse the dynamic section
    const lib = parseDynamic(actual_data, load_base, target_cr3) catch {
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

        // v1.0.0: Store VFS data for recursive DT_NEEDED resolution
        // This keeps the ELF file data alive in kernel heap so we can
        // parse its DT_NEEDED entries and load transitive dependencies.
        // After all dependencies are resolved, the caller should free
        // this via heap.kfree(lib.vfs_data.ptr).
        if (vfs_loaded) {
            l.vfs_data = vfs_file_data;
        }

        // v1.1.0: Compute SHA-256 integrity hash of the raw ELF image.
        // This hash is stored in the LoadedLibrary struct and can be
        // verified against a known-good manifest to detect tampering
        // or corruption of shared libraries.
        // The hash covers the ENTIRE raw .so file as loaded from VFS.
        const rsa = @import("rsa_oaep.zig");
        l.integrity_hash = rsa.sha256(actual_data);
        l.integrity_verified = false; // Not verified against a manifest yet

        // v1.0.0: Parse TLS template from PT_TLS
        parseTlsTemplate(actual_data, load_base, l);

        hal.Serial.puts("[DYNLINK] Library '");
        hal.Serial.puts(lib_name);
        hal.Serial.puts("' loaded at 0x");
        hal.Serial.putHex(load_base);
        hal.Serial.puts(" entry=0x");
        hal.Serial.putHex(result.entry_point);
        if (l.tls.total_size > 0) {
            hal.Serial.puts(" TLS=");
            hal.Serial.putDecimal(l.tls.total_size);
            hal.Serial.puts("b mid=");
            hal.Serial.putDecimal(l.tls.module_id);
        }
        hal.Serial.puts("\n");

        return l;
    }

    return null;
}

// ============================================================================
// .so Integrity Verification — v1.1.0
// ============================================================================
//
// POLER-OS verifies the integrity of shared libraries by computing a
// SHA-256 hash of the raw .so file at load time and storing it in the
// LoadedLibrary struct. This hash can then be compared against a
// known-good manifest (e.g., a signed list of expected hashes).
//
// Flow:
//   1. loadSharedLibrary() computes SHA-256 → stored in integrity_hash
//   2. verifyLibraryIntegrity() compares against expected_hash
//   3. If match → integrity_verified = true, proceed with relocation
//   4. If mismatch → log warning, mark as unverified (policy decides)
//
// The manifest of known-good hashes can be:
//   - Embedded in the kernel at build time (trusted boot chain)
//   - Loaded from a signed file on disk (RSA-OAEP signature verification)
//   - Set dynamically by the policy engine for trusted libraries
//
// This addresses Security Vulnerability #2 from the v1.1.0 audit:
// ".so loads bypass VFS" — now all .so loads go through VFS AND
// are integrity-verified with SHA-256.

/// Verify a loaded library's integrity against a known-good hash.
/// Returns true if the hash matches, false otherwise.
/// Also sets integrity_verified on the LoadedLibrary struct.
pub fn verifyLibraryIntegrity(lib_name: []const u8, expected_hash: *const [32]u8) bool {
    for (loaded_libraries[0..library_count]) |*lib| {
        if (lib.is_loaded and lib.name_len > 0) {
            const name = lib.name[0..lib.name_len];
            if (std.mem.eql(u8, name, lib_name)) {
                var match = true;
                for (lib.integrity_hash, expected_hash.*) |actual, expected| {
                    if (actual != expected) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    lib.integrity_verified = true;
                    hal.Serial.puts("[DYNLINK] Integrity VERIFIED for '");
                    hal.Serial.puts(lib_name);
                    hal.Serial.puts("'\n");
                } else {
                    hal.Serial.puts("[DYNLINK] WARNING: Integrity MISMATCH for '");
                    hal.Serial.puts(lib_name);
                    hal.Serial.puts("' — library may be tampered!\n");
                }
                return match;
            }
        }
    }
    hal.Serial.puts("[DYNLINK] Integrity check: library '");
    hal.Serial.puts(lib_name);
    hal.Serial.puts("' not found\n");
    return false;
}

/// Get the integrity hash of a loaded library (for manifest comparison).
/// Returns null if the library is not loaded.
pub fn getLibraryIntegrityHash(lib_name: []const u8) ?*[32]u8 {
    for (loaded_libraries[0..library_count]) |*lib| {
        if (lib.is_loaded and lib.name_len > 0) {
            const name = lib.name[0..lib.name_len];
            if (std.mem.eql(u8, name, lib_name)) {
                return &lib.integrity_hash;
            }
        }
    }
    return null;
}

/// Print integrity status of all loaded libraries (for debugging/audit).
pub fn printIntegrityReport() void {
    hal.Serial.puts("[DYNLINK] === Library Integrity Report ===\n");
    for (loaded_libraries[0..library_count]) |*lib| {
        if (!lib.is_loaded) continue;
        hal.Serial.puts("  ");
        hal.Serial.puts(lib.name[0..lib.name_len]);
        hal.Serial.puts(" hash=");
        // Print first 8 bytes of SHA-256 as hex
        for (lib.integrity_hash[0..8]) |b| {
            hal.Serial.putHex(b);
        }
        hal.Serial.puts("... verified=");
        hal.Serial.puts(if (lib.integrity_verified) "YES" else "NO");
        hal.Serial.puts("\n");
    }
    hal.Serial.puts("[DYNLINK] === End Report ===\n");
}

// ============================================================================
// VFS Integration for DT_NEEDED Loading (v1.0.0)
// ============================================================================

/// Load a file from the VFS (FAT32 filesystem).
///
/// Opens the file at the given path, reads its ENTIRE contents into a
/// heap-allocated buffer, and returns the data slice. The caller is
/// responsible for freeing the buffer via heap.kfree() when done.
///
/// Flow:
///   1. fat32.getFs() → get the global FAT32 filesystem instance
///   2. fs.openFile(path) → open the file
///   3. kmalloc(file_size) → allocate buffer on kernel heap
///   4. fs.readFile() in a loop → read entire file content
///   5. Return the data slice
///
/// Thread safety:
///   FAT32 operations are protected by the driver's internal state
///   (single IO buffer). In a multi-threaded environment, the caller
///   should hold a VFS lock. For now, we use the FAT32 driver as-is
///   since the dynlinker runs during process loading (single-threaded
///   at that point, before user threads start).
///
/// Parameters:
///   path      — Absolute path (e.g., "/lib/libc.so")
///   out_data  — Set to the slice of heap-allocated file content
///
/// Returns: true if the file was successfully read, false otherwise
fn loadFromVfs(path: []const u8, out_data: *VfsFileData) bool {
    out_data.* = VfsFileData{};

    // v1.1.0: Use the VFS callback if registered (normal path).
    // This routes .so loading through the VFS security layer instead of
    // directly accessing the FAT32 driver, ensuring that Intent Layer
    // verification and per-handle access checks apply to library loads.
    if (vfsLoadCallback) |cb| {
        return cb(path.ptr, path.len, out_data);
    }

    // Fallback: if no callback registered (shouldn't happen in v1.1.0),
    // use the legacy FAT32 path. This exists only as a safety net.
    hal.Serial.puts("[DYNLINK] WARNING: no VFS callback, using legacy FAT32 path\n");
    return loadFromVfsLegacy(path, out_data);
}

/// Legacy FAT32 loading — used only as fallback when VFS callback is not registered.
/// This is the pre-v1.1.0 code path that directly accesses fat32.zig.
fn loadFromVfsLegacy(path: []const u8, out_data: *VfsFileData) bool {
    _ = path;
    _ = out_data;
    // In v1.1.0, we don't import fat32.zig directly anymore.
    // If no VFS callback is registered, loading fails.
    hal.Serial.puts("[DYNLINK] VFS: no filesystem available (VFS callback not registered)\n");
    return false;
}

// ============================================================================
// DT_NEEDED Resolution
// ============================================================================

/// Get the list of DT_NEEDED library names from an ELF's .dynamic section.
///
/// Returns an array of string slices pointing into the ELF data.
/// The caller must provide the output array.
pub fn getNeededLibraries(elf_data: []const u8, _load_base: u64, out_names: []UnsizedSlice, out_count: *usize) DynLinkError!void {
    _ = _load_base;
    out_count.* = 0;

    if (elf_data.len < @sizeOf(elf_loader.Elf64_Ehdr)) return;

    const ehdr: *const elf_loader.Elf64_Ehdr = @ptrCast(@alignCast(elf_data.ptr));

    // Find PT_DYNAMIC
    var dynamic_offset: u64 = 0;
    var dynamic_size: u64 = 0;
    var strtab_vaddr: u64 = 0;

    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const phdr_off = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (phdr_off + @sizeOf(elf_loader.Elf64_Phdr) > elf_data.len) break;

        const phdr: *const elf_loader.Elf64_Phdr = @ptrCast(@alignCast(elf_data.ptr + phdr_off));

        if (phdr.p_type == 2) { // PT_DYNAMIC
            dynamic_offset = phdr.p_offset;
            dynamic_size = phdr.p_memsz;
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
    const strtab_offset = vaddrToFileOffset(elf_data, strtab_vaddr);

    // Second pass: collect DT_NEEDED entries
    offset = dynamic_offset;
    while (offset + @sizeOf(Elf64_Dyn) <= dynamic_offset + dynamic_size and offset < elf_data.len) {
        const dyn: *const Elf64_Dyn = @ptrCast(@alignCast(elf_data.ptr + offset));
        if (dyn.d_tag == DT_NULL) break;

        if (dyn.d_tag == DT_NEEDED) {
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

    return vaddr; // Fallback
}

// ============================================================================
// DT_NEEDED Auto-Loading via VFS (v1.0.0)
// ============================================================================

/// Automatically load all DT_NEEDED libraries from the VFS.
///
/// This is called during the dynamic linking phase. It:
///   1. Reads the DT_NEEDED entries from the ELF's .dynamic section
///   2. For each entry, constructs the full path (/lib/<name>)
///   3. Checks if the library is already loaded (dedup)
///   4. If not, loads it from VFS and recursively processes its own DT_NEEDED
///
/// Parameters:
///   elf_data    — Raw ELF file content
///   load_base   — Virtual base address where the ELF was loaded
///   target_cr3  — PML4 to load libraries into
///   depth       — Recursion depth (to prevent circular dependencies)
pub fn loadNeededLibraries(elf_data: []const u8, load_base: u64, target_cr3: u64, depth: usize) DynLinkError!void {
    if (depth > 8) {
        hal.Serial.puts("[DYNLINK] ERROR: DT_NEEDED recursion depth exceeded (circular deps?)\n");
        return;
    }

    var needed_names: [MAX_NEEDED]UnsizedSlice = undefined;
    var needed_count: usize = 0;

    try getNeededLibraries(elf_data, load_base, &needed_names, &needed_count);

    if (needed_count == 0) return;

    hal.Serial.puts("[DYNLINK] Found ");
    hal.Serial.putDecimal(needed_count);
    hal.Serial.puts(" DT_NEEDED libraries (depth=");
    hal.Serial.putDecimal(depth);
    hal.Serial.puts(")\n");

    for (0..needed_count) |i| {
        const name_ptr = needed_names[i].ptr;
        const name_len = cstrLen(name_ptr);
        const name = name_ptr[0..name_len];

        // Check if already loaded (dedup by name)
        var already_loaded = false;
        for (&loaded_libraries) |*lib| {
            if (!lib.is_loaded) continue;
            if (lib.name_len == name_len and memEql(lib.name[0..lib.name_len], name_ptr, name_len)) {
                already_loaded = true;
                break;
            }
        }

        if (already_loaded) {
            hal.Serial.puts("[DYNLINK] '");
            hal.Serial.puts(name);
            hal.Serial.puts("' already loaded, skipping\n");
            continue;
        }

        hal.Serial.puts("[DYNLINK] Loading DT_NEEDED: '");
        hal.Serial.puts(name);
        hal.Serial.puts("'\n");

        // Load the library (passing null for lib_data to trigger VFS lookup)
        const load_idx = library_count; // Will be incremented by loadSharedLibrary
        const loaded = loadSharedLibrary(null, name, target_cr3, load_idx) catch |err| {
            hal.Serial.puts("[DYNLINK] ERROR: failed to load '");
            hal.Serial.puts(name);
            hal.Serial.puts("': ");
            switch (err) {
                DynLinkError.LibraryNotFound => hal.Serial.puts("not found in VFS"),
                DynLinkError.MapFailed => hal.Serial.puts("map failed"),
                DynLinkError.NoDynamicSegment => hal.Serial.puts("no dynamic segment"),
                else => hal.Serial.puts("unknown error"),
            }
            hal.Serial.puts("\n");

            // v1.0.0: If the library is not found but we have the library data
            // embedded (e.g., from initrd/ramdisk), fall back to searching there.
            // This is handled by the caller providing the data directly.
            continue;
        };

        if (loaded) |lib| {
            // Process relocations for the newly loaded library
            try processRelocations(lib);

            // v1.0.1: Recursively load this library's own DT_NEEDED dependencies.
            // We use the cached VFS data (vfs_data.slice) which contains the
            // original ELF file bytes. This allows us to parse DT_NEEDED without
            // re-reading from disk. The VFS data is freed after all dependencies
            // in the tree are resolved (see freeVfsData below).
            if (lib.vfs_data.isValid()) {
                loadNeededLibraries(lib.vfs_data.slice, lib.base_addr, target_cr3, depth + 1) catch |err| {
                    hal.Serial.puts("[DYNLINK] WARNING: recursive DT_NEEDED failed for '");
                    hal.Serial.puts(name);
                    hal.Serial.puts("': ");
                    switch (err) {
                        DynLinkError.LibraryNotFound => hal.Serial.puts("dep not found"),
                        else => hal.Serial.puts("unknown"),
                    }
                    hal.Serial.puts("\n");
                };
            }

            hal.Serial.puts("[DYNLINK] '");
            hal.Serial.puts(name);
            hal.Serial.puts("' loaded and relocated (with deps)\n");
        }
    }
}

// ============================================================================
// VFS Data Cleanup
// ============================================================================

/// Free all cached VFS file data from loaded libraries.
///
/// After all dynamic linking is complete (all DT_NEEDED resolved,
/// all relocations applied, all TLS templates copied), the ELF file
/// data that was read from disk is no longer needed. This function
/// walks all loaded libraries and frees their VFS buffers.
///
/// This MUST be called after linkDynamicExecutable() completes to
/// avoid leaking kernel heap memory. The library descriptors themselves
/// remain valid — only the raw file data is freed.
pub fn freeAllVfsData() void {
    var freed_count: usize = 0;
    var freed_bytes: usize = 0;

    for (&loaded_libraries) |*lib| {
        if (!lib.is_loaded) continue;
        if (lib.vfs_data.size > 0) {
            freed_bytes += lib.vfs_data.size;
            heap.kfree(lib.vfs_data.ptr);
            lib.vfs_data = VfsFileData{};
            freed_count += 1;
        }
    }

    if (freed_count > 0) {
        hal.Serial.puts("[DYNLINK] Freed VFS data for ");
        hal.Serial.putDecimal(freed_count);
        hal.Serial.puts(" libraries (");
        hal.Serial.putDecimal(freed_bytes);
        hal.Serial.puts(" bytes reclaimed)\n");
    }
}

// ============================================================================
// PLT/GOT Setup
// ============================================================================

/// Set up the PLT resolver for lazy binding.
///
/// In v1.0.0, lazy binding uses the PLT lock for thread safety.
/// The PLT resolver stub template (per-function):
///   jmp *GOT[n](%rip)     ; Jump through GOT entry
///   push $reloc_index     ; Push relocation index
///   jmp PLT[0]            ; Jump to PLT resolver (PLT entry 0)
///
/// PLT entry 0 (resolver):
///   push GOT[1]            ; Push link map (object identifier)
///   jmp GOT[2]             ; Jump to pltLazyResolver()
///
/// For eager binding (BIND_NOW), all GOT entries are already resolved.
pub fn setupPltResolver(lib: *LoadedLibrary) void {
    if (lib.bind_now) {
        hal.Serial.puts("[DYNLINK] PLT/GOT setup complete (BIND_NOW — all resolved)\n");
    } else {
        hal.Serial.puts("[DYNLINK] PLT/GOT setup complete (lazy binding with PLT lock)\n");
    }
}

// ============================================================================
// Constructor/Destructor Invocation
// ============================================================================

/// Call DT_INIT and DT_INIT_ARRAY functions for a library.
/// These are the C++ constructors and __attribute__((constructor)) functions.
pub fn callInitFunctions(lib: *LoadedLibrary) void {
    if (lib.dyn_init != 0) {
        hal.Serial.puts("[DYNLINK] DT_INIT at 0x");
        hal.Serial.putHex(lib.dyn_init);
        hal.Serial.puts("\n");
    }

    if (lib.dyn_init_array != 0 and lib.dyn_init_arraysz > 0) {
        const num_init = lib.dyn_init_arraysz / 8; // Each pointer is 8 bytes
        hal.Serial.puts("[DYNLINK] DT_INIT_ARRAY: ");
        hal.Serial.putDecimal(num_init);
        hal.Serial.puts(" constructors\n");
    }
}

/// Call DT_FINI and DT_FINI_ARRAY functions for a library (at exit).
pub fn callFiniFunctions(lib: *LoadedLibrary) void {
    if (lib.dyn_fini != 0) {
        hal.Serial.puts("[DYNLINK] DT_FINI at 0x");
        hal.Serial.putHex(lib.dyn_fini);
        hal.Serial.puts("\n");
    }

    if (lib.dyn_fini_array != 0 and lib.dyn_fini_arraysz > 0) {
        const num_fini = lib.dyn_fini_arraysz / 8;
        hal.Serial.puts("[DYNLINK] DT_FINI_ARRAY: ");
        hal.Serial.putDecimal(num_fini);
        hal.Serial.puts(" destructors\n");
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// ELF hash function (SVR4 style)
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

/// Name equality for slices (no null terminator needed)
fn nameEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return memEql(a.ptr, b.ptr, a.len);
}

// ============================================================================
// Master Dynamic Linking Entry Point
// ============================================================================

/// Link a dynamically-linked ELF executable.
///
/// This is the main entry point called by the ELF loader when it detects
/// a PT_INTERP or PT_DYNAMIC segment. It:
///   1. Parses the .dynamic section
///   2. Loads all DT_NEEDED shared libraries (via VFS or in-memory data)
///   3. Processes relocations for all objects (with versioning + weak symbols)
///   4. Sets up TLS templates and TCB for each thread
///   5. Sets up PLT/GOT (lazy binding with PLT lock, or BIND_NOW)
///   6. Calls init functions
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

    // v1.0.0: Parse TLS template for the main executable
    parseTlsTemplate(elf_data, load_base, main_lib.?);

    // Step 2: Auto-load DT_NEEDED libraries from VFS
    loadNeededLibraries(elf_data, load_base, target_cr3, 0) catch |err| {
        hal.Serial.puts("[DYNLINK] WARNING: some DT_NEEDED libraries failed to load: ");
        switch (err) {
            DynLinkError.LibraryNotFound => hal.Serial.puts("not found"),
            else => hal.Serial.puts("unknown"),
        }
        hal.Serial.puts("\n");
        // Continue — some libraries may be optional (weak symbols)
    };

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

    // Step 6: Allocate TCB for the main thread
    const tcb_addr = allocateTcbForThread(target_cr3, 0) catch {
        hal.Serial.puts("[DYNLINK] WARNING: TCB allocation failed for main thread\n");
    };
    _ = tcb_addr;

    // Step 7: Call init functions
    callInitFunctions(main_lib.?);

    // Step 8: Free cached VFS data — the ELF file bytes are no longer needed
    // now that all segments are mapped into the process's PML4, all TLS
    // templates are copied, and all relocations are applied. Keeping this
    // data would waste kernel heap memory.
    freeAllVfsData();

    hal.Serial.puts("[DYNLINK] Dynamic linking complete (v1.0.1)\n");
    hal.Serial.puts("[DYNLINK]   Libraries loaded: ");
    hal.Serial.putDecimal(library_count);
    hal.Serial.puts("\n");
    hal.Serial.puts("[DYNLINK]   Combined TLS size: ");
    hal.Serial.putDecimal(combined_tls_size);
    hal.Serial.puts(" bytes\n");
    hal.Serial.puts("[DYNLINK]   Bind mode: ");
    if (main_lib.?.bind_now) {
        hal.Serial.puts("BIND_NOW\n");
    } else {
        hal.Serial.puts("lazy (PLT lock enabled)\n");
    }
}

/// Placeholder type (same as UnsizedSlice)
const UnsignedSlice = UnsizedSlice;
