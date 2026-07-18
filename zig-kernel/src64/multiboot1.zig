// ============================================================================
// POLER-OS Multiboot1 Info Structure Parser
// ============================================================================
//
// Multiboot1 (magic 0x2BADB002) is used by QEMU -kernel direct boot
// and older bootloaders. Unlike Multiboot2's tag-based format, MB1 uses
// a fixed-structure with a flags bitmask indicating which fields are valid.
//
// IMPORTANT: MB1 mmap entries have u64 fields at non-8-byte-aligned offsets
// (addr at offset 4 after the 4-byte size field). We cannot use extern struct
// with u64 fields directly — instead we read raw bytes and construct values.
//
// Reference: https://www.gnu.org/software/grub/manual/multiboot/multiboot.html
// ============================================================================

pub const BOOTLOADER_MAGIC: u32 = 0x2BADB002;

/// Multiboot1 Info Header — passed via EBX by the bootloader.
/// All fields are u32 so alignment is fine (4-byte aligned).
pub const InfoHeader = extern struct {
    flags: u32,            // +0x00: Bitmask indicating which fields are valid
    mem_lower: u32,        // +0x04: Lower memory KB (valid if flags bit 0 set)
    mem_upper: u32,        // +0x08: Upper memory KB (valid if flags bit 0 set)
    boot_device: u32,      // +0x0C: Boot device (valid if flags bit 1 set)
    cmdline: u32,          // +0x10: Command line pointer (valid if flags bit 2 set)
    mods_count: u32,       // +0x14: Module count (valid if flags bit 3 set)
    mods_addr: u32,        // +0x18: Module pointer (valid if flags bit 3 set)
    syms: [4]u32,          // +0x1C: Symbol table (aout/elf, flags bits 4-5)
    mmap_length: u32,      // +0x2C: Memory map data length (valid if flags bit 6 set)
    mmap_addr: u32,        // +0x30: Memory map pointer (valid if flags bit 6 set)
    drives_length: u32,    // +0x34: (valid if flags bit 7 set)
    drives_addr: u32,      // +0x38: (valid if flags bit 7 set)
    config_table: u32,     // +0x3C: (valid if flags bit 8 set)
    boot_loader_name: u32, // +0x40: (valid if flags bit 9 set)
    apm_table: u32,        // +0x44: (valid if flags bit 10 set)
    // VBE/framebuffer fields at +0x48..+0x90 (flags bits 11-12)
};

/// Parsed memory map entry — NOT an extern struct because MB1 entries have
/// u64 fields at non-aligned offsets (addr at byte 4, len at byte 12).
/// We read from raw bytes and construct this struct.
pub const MmapEntry = struct {
    size: u32,             // Size of rest of entry (typically 20)
    addr: u64,             // Base address of memory region
    len: u64,              // Length of memory region in bytes
    entry_type: u32,       // 1=Available RAM, 2=Reserved, etc.
};

/// Basic memory info from MB1 (mem_lower and mem_upper fields)
pub const BasicMemInfo = struct {
    mem_lower: u32,        // KB of memory below 640KB
    mem_upper: u32,        // KB of memory above 1MB
};

pub const Parser = struct {
    info_ptr: u64,

    pub fn init(info_ptr: u64) Parser {
        return Parser{ .info_ptr = info_ptr };
    }

    /// Get basic memory info (mem_lower/mem_upper).
    /// Returns null if flags bit 0 is not set.
    pub fn getBasicMemInfo(self: *const Parser) ?BasicMemInfo {
        const header: *align(4) const InfoHeader = @ptrFromInt(self.info_ptr);
        if (header.flags & 0x01 == 0) return null;
        return BasicMemInfo{
            .mem_lower = header.mem_lower,
            .mem_upper = header.mem_upper,
        };
    }

    /// Create an iterator over Multiboot1 memory map entries.
    /// Returns null if flags bit 6 is not set.
    pub fn getMmapIterator(self: *const Parser) ?MmapIterator {
        const header: *align(4) const InfoHeader = @ptrFromInt(self.info_ptr);
        if (header.flags & 0x40 == 0) return null;
        return MmapIterator{
            .current = @as(u64, header.mmap_addr),
            .end = @as(u64, header.mmap_addr) + @as(u64, header.mmap_length),
        };
    }

    /// Check if memory map is available (flags bit 6 set)
    pub fn hasMmap(self: *const Parser) bool {
        const header: *align(4) const InfoHeader = @ptrFromInt(self.info_ptr);
        return (header.flags & 0x40) != 0;
    }

    /// Check if basic mem info is available (flags bit 0 set)
    pub fn hasBasicMemInfo(self: *const Parser) bool {
        const header: *align(4) const InfoHeader = @ptrFromInt(self.info_ptr);
        return (header.flags & 0x01) != 0;
    }

    /// Get the mmap_length and mmap_addr for protection
    pub fn getMmapInfo(self: *const Parser) ?struct { addr: u64, length: u32 } {
        const header: *align(4) const InfoHeader = @ptrFromInt(self.info_ptr);
        if (header.flags & 0x40 == 0) return null;
        return .{ .addr = @as(u64, header.mmap_addr), .length = header.mmap_length };
    }
};

/// Iterator over Multiboot1 memory map entries.
/// MB1 entries have variable size and u64 fields at non-aligned offsets.
/// We read raw bytes to avoid alignment panics.
pub const MmapIterator = struct {
    current: u64,
    end: u64,

    /// Read the next memory map entry.
    /// Returns null if no more entries or if data is invalid.
    pub fn next(self: *MmapIterator) ?MmapEntry {
        if (self.current >= self.end) return null;
        if (self.current + 24 > self.end) return null; // Need at least 24 bytes

        // Read raw bytes — MB1 mmap entry layout:
        //   offset 0:  size      (u32, 4 bytes)
        //   offset 4:  addr      (u64, 8 bytes)  ← NOT 8-byte aligned!
        //   offset 12: len       (u64, 8 bytes)
        //   offset 20: entry_type (u32, 4 bytes)
        //   total: 24 bytes
        const raw: [*]const u8 = @ptrFromInt(self.current);

        const size = readU32(raw, 0);
        const addr = readU64(raw, 4);
        const len = readU64(raw, 12);
        const entry_type = readU32(raw, 20);

        // Sanity check: size should be 16..80 (entry minus the 4-byte size field)
        if (size < 16 or size > 80) return null;

        // Advance: total entry size = size + 4 (the size field itself)
        self.current += @as(u64, size) + 4;

        return MmapEntry{
            .size = size,
            .addr = addr,
            .len = len,
            .entry_type = entry_type,
        };
    }
};

/// Read a u32 from raw bytes at the given offset (little-endian)
fn readU32(raw: [*]const u8, offset: usize) u32 {
    return @as(u32, raw[offset]) |
        (@as(u32, raw[offset + 1]) << 8) |
        (@as(u32, raw[offset + 2]) << 16) |
        (@as(u32, raw[offset + 3]) << 24);
}

/// Read a u64 from raw bytes at the given offset (little-endian)
fn readU64(raw: [*]const u8, offset: usize) u64 {
    return @as(u64, readU32(raw, offset)) |
        (@as(u64, readU32(raw, offset + 4)) << 32);
}
