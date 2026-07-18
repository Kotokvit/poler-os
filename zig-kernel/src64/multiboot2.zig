// ============================================================================
// POLER-OS Multiboot2 Specification Parser — x86_64
// ============================================================================

pub const BOOTLOADER_MAGIC: u32 = 0x36D76289;

pub const Tag = extern struct {
    type: u32,
    size: u32,
};

pub const MmapEntry = extern struct {
    addr: u64,
    len: u64,
    entry_type: u32, // 1 = RAM, 2 = Reserved, 3 = ACPI, 4 = NVS, 5 = Unusable, 6 = ACPI Reclaimable
    zero: u32,
};

pub const MmapTag = extern struct {
    type: u32,
    size: u32,
    entry_size: u32,
    entry_version: u32,
    
    pub fn getEntries(self: *const MmapTag) []const MmapEntry {
        const entries_ptr: [*]const MmapEntry = @ptrFromInt(@intFromPtr(self) + 16);
        const num_entries = (self.size - 16) / self.entry_size;
        return entries_ptr[0..num_entries];
    }
};

pub const BasicMemTag = extern struct {
    type: u32,
    size: u32,
    mem_lower: u32,
    mem_upper: u32,
};

pub const FramebufferTag = extern struct {
    type: u32,
    size: u32,
    fb_addr: u64,
    fb_pitch: u32,
    fb_width: u32,
    fb_height: u32,
    fb_bpp: u8,
    fb_type: u8,
    reserved: u16,
};

pub const CmdlineTag = extern struct {
    type: u32,
    size: u32,
    
    pub fn getCmdline(self: *const CmdlineTag) []const u8 {
        const str_ptr: [*]const u8 = @ptrFromInt(@intFromPtr(self) + 8);
        return str_ptr[0..(self.size - 8 - 1)]; // exclude null terminator
    }
};

pub const ModuleTag = extern struct {
    type: u32,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    
    pub fn getCmdline(self: *const ModuleTag) []const u8 {
        const str_ptr: [*]const u8 = @ptrFromInt(@intFromPtr(self) + 16);
        var len: usize = 0;
        while (str_ptr[len] != 0) : (len += 1) {}
        return str_ptr[0..len];
    }
};



pub const InfoHeader = extern struct {
    total_size: u32,
    reserved: u32,
};

pub const Parser = struct {
    total_size: u32,
    info_ptr: u64,

    pub fn init(info_ptr: u64) Parser {
        // GRUB may place the multiboot2 info at an unaligned address.
        // Read the header fields using volatile byte-level access
        // to avoid Zig's alignment safety checks panicking.
        const ptr: [*]const volatile u8 = @ptrFromInt(info_ptr);
        const total_size: u32 = @as(u32, ptr[0]) |
            (@as(u32, ptr[1]) << 8) |
            (@as(u32, ptr[2]) << 16) |
            (@as(u32, ptr[3]) << 24);
        return Parser{
            .total_size = total_size,
            .info_ptr = info_ptr,
        };
    }

    /// Read a u32 from potentially unaligned address (volatile, byte-level)
    fn readU32(addr: u64) u32 {
        const ptr: [*]const volatile u8 = @ptrFromInt(addr);
        return @as(u32, ptr[0]) |
            (@as(u32, ptr[1]) << 8) |
            (@as(u32, ptr[2]) << 16) |
            (@as(u32, ptr[3]) << 24);
    }

    pub fn findTag(self: *const Parser, tag_type: u32) ?u64 {
        var offset: u64 = 8; // skip InfoHeader
        while (offset < self.total_size) {
            const tag_type_val = readU32(self.info_ptr + offset);
            const tag_size = readU32(self.info_ptr + offset + 4);
            if (tag_type_val == tag_type) {
                return self.info_ptr + offset;
            }
            if (tag_type_val == 0 and tag_size == 8) {
                break; // End tag
            }
            // Align tag size to 8-byte boundary
            offset += (tag_size + 7) & ~@as(u32, 7);
        }
        return null;
    }

    pub fn findModuleTag(self: *const Parser, start_offset: *u64) ?*const ModuleTag {
        var offset = start_offset.*;
        while (offset < self.total_size) {
            const tag_type_val = readU32(self.info_ptr + offset);
            const tag_size = readU32(self.info_ptr + offset + 4);
            if (tag_type_val == 0 and tag_size == 8) {
                break; // End tag
            }
            const next_offset = offset + ((tag_size + 7) & ~@as(u32, 7));
            if (tag_type_val == 3) {
                start_offset.* = next_offset;
                const module_ptr: *const ModuleTag = @ptrFromInt(self.info_ptr + offset);
                return module_ptr;
            }
            offset = next_offset;
        }
        return null;
    }
};
