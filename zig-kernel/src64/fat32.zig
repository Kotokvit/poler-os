// ============================================================================
// POLER-OS FAT32 Filesystem Driver — x86_64
// ============================================================================
// Phase 2: Full FAT32 filesystem for virtio-blk devices.
//
// Features:
//   - Read/write file operations
//   - Nested directory traversal (path resolution: /dir/subdir/file)
//   - Directory creation
//   - File creation and appending
//   - Cluster allocation and FAT chain management
//   - LFN (Long File Name) entry parsing
//   - Date/time timestamps for created entries
// ============================================================================

const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");
const virtio_blk = @import("virtio_blk.zig");

// ============================================================================
// FAT32 Constants
// ============================================================================

const SECTOR_SIZE: u32 = 512;
const FAT32_EOF: u32 = 0x0FFFFFF8;
const FAT32_BAD: u32 = 0x0FFFFFF7;
const FAT32_FREE: u32 = 0x00000000;
const FAT32_MASK: u32 = 0x0FFFFFFF;
const MAX_CLUSTER_CHAIN: u32 = 4096;
const DIR_ENTRIES_PER_SECTOR: u32 = 16; // 512 / 32

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

// ============================================================================
// FAT32 BPB
// ============================================================================

pub const Bpb = extern struct {
    jmp_boot: [3]u8,
    oem_name: [8]u8,
    bytes_per_sector: u16 align(1),
    sectors_per_cluster: u8,
    reserved_sectors: u16 align(1),
    num_fats: u8,
    root_entry_count: u16 align(1),
    total_sectors_16: u16 align(1),
    media_type: u8,
    fat_size_16: u16 align(1),
    sectors_per_track: u16 align(1),
    num_heads: u16 align(1),
    hidden_sectors: u32 align(1),
    total_sectors_32: u32 align(1),
    fat_size_32: u32 align(1),
    ext_flags: u16 align(1),
    fs_version: u16 align(1),
    root_cluster: u32 align(1),
    fs_info_sector: u16 align(1),
    backup_boot_sector: u16 align(1),
    reserved: [12]u8,
    drive_number: u8,
    reserved1: u8,
    boot_sig: u8,
    volume_id: u32 align(1),
    volume_label: [11]u8,
    fs_type: [8]u8,
};

pub const DirEntry = extern struct {
    name: [8]u8,
    ext: [3]u8,
    attr: u8,
    nt_reserved: u8,
    creation_time_tenth: u8,
    creation_time: u16 align(1),
    creation_date: u16 align(1),
    last_access_date: u16 align(1),
    first_cluster_hi: u16 align(1),
    last_write_time: u16 align(1),
    last_write_date: u16 align(1),
    first_cluster_lo: u16 align(1),
    file_size: u32 align(1),
};

pub const LfnEntry = extern struct {
    seq: u8,
    name1: [5]u16 align(1),
    attr: u8,
    type: u8,
    checksum: u8,
    name2: [6]u16 align(1),
    first_cluster: u16 align(1),
    name3: [2]u16 align(1),
};

pub const File = struct {
    first_cluster: u32,
    current_cluster: u32,
    file_size: u32,
    position: u32,
    is_valid: bool,
    is_directory: bool,
    dir_cluster: u32, // Cluster of the directory containing this file
    name: [256]u8,
    name_len: usize,
};

pub const DirEntryInfo = struct {
    name: [256]u8,
    name_len: usize,
    is_directory: bool,
    is_read_only: bool,
    is_hidden: bool,
    file_size: u32,
    first_cluster: u32,
};

// ============================================================================
// FAT32 Filesystem Driver
// ============================================================================

pub const Fat32Fs = struct {
    bpb: Bpb,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    fat_size_32: u32,
    root_cluster: u32,
    total_sectors: u32,
    data_start_sector: u32,
    sectors_per_fat: u32,
    cluster_size: u32,
    total_data_clusters: u32,

    // I/O buffer (single page for sector reads/writes)
    io_buf_phys: u64,
    io_buf: [*]u8,

    // FAT cache (one sector of FAT entries)
    fat_buf_phys: u64,
    fat_buf: [*]u32,
    fat_cache_sector: u32,
    fat_cache_dirty: bool,

    // Write buffer (for sector writes — must be separate from io_buf)
    write_buf_phys: u64,
    write_buf: [*]u8,

    initialized: bool,

    // ================================================================
    // Initialization
    // ================================================================

    pub fn init() ?Fat32Fs {
        if (!virtio_blk.isInitialized()) {
            hal.Serial.puts("[FAT32] No virtio-blk driver available\n");
            return null;
        }

        var fs = Fat32Fs{
            .bpb = undefined,
            .bytes_per_sector = 0,
            .sectors_per_cluster = 0,
            .reserved_sectors = 0,
            .num_fats = 0,
            .fat_size_32 = 0,
            .root_cluster = 0,
            .total_sectors = 0,
            .data_start_sector = 0,
            .sectors_per_fat = 0,
            .cluster_size = 0,
            .total_data_clusters = 0,
            .io_buf_phys = 0,
            .io_buf = undefined,
            .fat_buf_phys = 0,
            .fat_buf = undefined,
            .fat_cache_sector = 0xFFFFFFFF,
            .fat_cache_dirty = false,
            .write_buf_phys = 0,
            .write_buf = undefined,
            .initialized = false,
        };

        // Allocate I/O buffer
        fs.io_buf_phys = pmm.allocPage() orelse {
            hal.Serial.puts("[FAT32] ERROR: Failed to allocate I/O buffer\n");
            return null;
        };
        fs.io_buf = @ptrFromInt(@as(usize, @intCast(fs.io_buf_phys)));

        // Allocate FAT cache buffer
        fs.fat_buf_phys = pmm.allocPage() orelse {
            hal.Serial.puts("[FAT32] ERROR: Failed to allocate FAT cache\n");
            return null;
        };
        fs.fat_buf = @ptrFromInt(@as(usize, @intCast(fs.fat_buf_phys)));

        // Allocate write buffer
        fs.write_buf_phys = pmm.allocPage() orelse {
            hal.Serial.puts("[FAT32] ERROR: Failed to allocate write buffer\n");
            return null;
        };
        fs.write_buf = @ptrFromInt(@as(usize, @intCast(fs.write_buf_phys)));

        // Read sector 0 (BPB)
        virtio_blk.readSectors(0, 1, fs.io_buf[0..512]) catch {
            hal.Serial.puts("[FAT32] ERROR: Failed to read sector 0 (BPB)\n");
            return null;
        };

        // v0.8.1 debug: dump first 32 bytes of BPB to diagnose read issues
        hal.Serial.puts("[FAT32] BPB first 32 bytes:\n  ");
        var bi: usize = 0;
        while (bi < 32) : (bi += 1) {
            hal.Serial.putHex(fs.io_buf[bi]);
            hal.Serial.puts(" ");
        }
        hal.Serial.puts("\n");

        // v0.8.1: Bpb is extern struct with align(1) on u16/u32 fields
        // to match the on-disk layout (no padding for unaligned multi-byte fields).
        // @alignCast is safe because io_buf is page-aligned (from PMM).
        const bpb_ptr: *const Bpb = @ptrCast(@alignCast(fs.io_buf));
        fs.bpb = bpb_ptr.*;

        if (!fs.validateBpb()) return null;

        fs.bytes_per_sector = fs.bpb.bytes_per_sector;
        fs.sectors_per_cluster = fs.bpb.sectors_per_cluster;
        fs.reserved_sectors = fs.bpb.reserved_sectors;
        fs.num_fats = fs.bpb.num_fats;
        fs.fat_size_32 = fs.bpb.fat_size_32;
        fs.root_cluster = fs.bpb.root_cluster;
        fs.sectors_per_fat = fs.fat_size_32;
        fs.cluster_size = fs.bytes_per_sector * fs.sectors_per_cluster;

        if (fs.bpb.total_sectors_32 != 0) {
            fs.total_sectors = fs.bpb.total_sectors_32;
        } else {
            fs.total_sectors = fs.bpb.total_sectors_16;
        }

        fs.data_start_sector = fs.reserved_sectors + fs.num_fats * fs.sectors_per_fat;
        fs.total_data_clusters = (fs.total_sectors - fs.data_start_sector) / fs.sectors_per_cluster;

        hal.Serial.puts("[FAT32] Mounted: sectors/cluster=");
        hal.Serial.putHex(fs.sectors_per_cluster);
        hal.Serial.puts(" cluster_size=");
        hal.Serial.putHex(fs.cluster_size);
        hal.Serial.puts(" root_cluster=");
        hal.Serial.putHex(fs.root_cluster);
        hal.Serial.puts(" data_clusters=");
        hal.Serial.putHex(fs.total_data_clusters);
        hal.Serial.puts("\n");

        fs.initialized = true;
        return fs;
    }

    fn validateBpb(self: *Fat32Fs) bool {
        if (self.bpb.bytes_per_sector != 512) {
            hal.Serial.puts("[FAT32] ERROR: bytes_per_sector != 512\n");
            return false;
        }
        const spc = self.bpb.sectors_per_cluster;
        if (spc == 0 or spc > 128 or (spc & (spc - 1)) != 0) {
            hal.Serial.puts("[FAT32] ERROR: Invalid sectors_per_cluster\n");
            return false;
        }
        if (self.bpb.reserved_sectors == 0) return false;
        if (self.bpb.fat_size_32 == 0) return false;
        if (self.bpb.root_cluster < 2) return false;
        return true;
    }

    // ================================================================
    // Address Conversion
    // ================================================================

    fn clusterToSector(self: *Fat32Fs, cluster: u32) u64 {
        return @as(u64, self.data_start_sector) +
            @as(u64, cluster - 2) * self.sectors_per_cluster;
    }

    // ================================================================
    // Low-level Sector I/O
    // ================================================================

    fn readClusterSector(self: *Fat32Fs, cluster: u32, sector_in_cluster: u32) bool {
        if (cluster < 2) return false;
        if (sector_in_cluster >= self.sectors_per_cluster) return false;
        const sector = self.clusterToSector(cluster) + @as(u64, sector_in_cluster);
        virtio_blk.readSectors(sector, 1, self.io_buf[0..512]) catch return false;
        return true;
    }

    fn writeClusterSector(self: *Fat32Fs, cluster: u32, sector_in_cluster: u32, data: [*]const u8) bool {
        if (cluster < 2) return false;
        if (sector_in_cluster >= self.sectors_per_cluster) return false;
        const sector = self.clusterToSector(cluster) + @as(u64, sector_in_cluster);
        virtio_blk.writeSectors(sector, 1, data[0..512]) catch return false;
        return true;
    }

    fn readSectorAbsolute(self: *Fat32Fs, sector: u64) bool {
        virtio_blk.readSectors(sector, 1, self.io_buf[0..512]) catch return false;
        return true;
    }

    fn _writeSectorAbsolute(self: *Fat32Fs, sector: u64, data: [*]const u8) bool {
        _ = self;
        virtio_blk.writeSectors(sector, 1, data[0..512]) catch return false;
        return true;
    }

    // ================================================================
    // FAT Table Operations
    // ================================================================

    fn getNextCluster(self: *Fat32Fs, cluster: u32) ?u32 {
        if (cluster < 2) return null;

        const entries_per_sector: u32 = self.bytes_per_sector / 4;
        const fat_sector: u32 = cluster / entries_per_sector;
        const fat_index: u32 = cluster % entries_per_sector;
        const abs_fat_sector = @as(u64, self.reserved_sectors) + fat_sector;

        if (self.fat_cache_sector != fat_sector) {
            // Flush dirty FAT cache before loading new sector
            if (self.fat_cache_dirty) {
                self.flushFatCache();
            }
            virtio_blk.readSectors(abs_fat_sector, 1, @as([*]u8, @ptrCast(self.fat_buf))[0..512]) catch {
                hal.Serial.puts("[FAT32] ERROR: Failed to read FAT sector\n");
                return null;
            };
            self.fat_cache_sector = fat_sector;
            self.fat_cache_dirty = false;
        }

        const next = self.fat_buf[fat_index] & FAT32_MASK;
        if (next >= FAT32_EOF) return null;
        if (next == FAT32_BAD) return null;
        if (next < 2) return null;
        return next;
    }

    /// Set the FAT entry for a cluster
    fn setFatEntry(self: *Fat32Fs, cluster: u32, value: u32) bool {
        if (cluster < 2) return false;

        const entries_per_sector: u32 = self.bytes_per_sector / 4;
        const fat_sector: u32 = cluster / entries_per_sector;
        const fat_index: u32 = cluster % entries_per_sector;

        // Load the FAT sector (may already be cached)
        if (self.fat_cache_sector != fat_sector) {
            if (self.fat_cache_dirty) {
                self.flushFatCache();
            }
            const abs_fat_sector = @as(u64, self.reserved_sectors) + fat_sector;
            virtio_blk.readSectors(abs_fat_sector, 1, @as([*]u8, @ptrCast(self.fat_buf))[0..512]) catch {
                return false;
            };
            self.fat_cache_sector = fat_sector;
        }

        // Preserve top 4 bits (reserved), set bottom 28 bits
        self.fat_buf[fat_index] = (self.fat_buf[fat_index] & 0xF0000000) | (value & FAT32_MASK);
        self.fat_cache_dirty = true;
        return true;
    }

    /// Flush dirty FAT cache to disk (writes to all FAT copies)
    fn flushFatCache(self: *Fat32Fs) void {
        if (!self.fat_cache_dirty) return;
        if (self.fat_cache_sector == 0xFFFFFFFF) return;

        // Write to all FAT copies
        var fat_num: u32 = 0;
        while (fat_num < self.num_fats) : (fat_num += 1) {
            const abs_sector = @as(u64, self.reserved_sectors) +
                @as(u64, fat_num) * self.sectors_per_fat +
                self.fat_cache_sector;
            virtio_blk.writeSectors(abs_sector, 1, @as([*]const u8, @ptrCast(self.fat_buf))[0..512]) catch {
                hal.Serial.puts("[FAT32] WARNING: Failed to write FAT copy ");
                hal.Serial.putHex(fat_num);
                hal.Serial.puts("\n");
                continue;
            };
        }
        self.fat_cache_dirty = false;
    }

    fn getClusterAt(self: *Fat32Fs, start_cluster: u32, n: u32) ?u32 {
        var cluster = start_cluster;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            if (i >= MAX_CLUSTER_CHAIN) return null;
            cluster = self.getNextCluster(cluster) orelse return null;
        }
        return cluster;
    }

    // ================================================================
    // Cluster Allocation
    // ================================================================

    /// Allocate a new cluster, set its FAT entry to EOF, and return its number.
    /// Optionally links it to a previous cluster (chain extension).
    fn allocCluster(self: *Fat32Fs, prev_cluster: ?u32) ?u32 {
        // Scan FAT for a free cluster (starting from cluster 2)
        const entries_per_sector: u32 = self.bytes_per_sector / 4;
        const total_fat_sectors = self.sectors_per_fat;

        var sec: u32 = 0;
        while (sec < total_fat_sectors) : (sec += 1) {
            // Load FAT sector
            if (self.fat_cache_sector != sec) {
                if (self.fat_cache_dirty) self.flushFatCache();
                const abs_sector = @as(u64, self.reserved_sectors) + sec;
                virtio_blk.readSectors(abs_sector, 1, @as([*]u8, @ptrCast(self.fat_buf))[0..512]) catch continue;
                self.fat_cache_sector = sec;
                self.fat_cache_dirty = false;
            }

            // Scan entries in this sector
            const start_entry = if (sec == 0) @as(u32, 2) else @as(u32, 0); // Skip entries 0,1
            const end_entry = if (sec == total_fat_sectors - 1)
                self.total_data_clusters + 2 - sec * entries_per_sector
            else
                entries_per_sector;

            var idx = start_entry;
            while (idx < end_entry and idx < entries_per_sector) : (idx += 1) {
                if ((self.fat_buf[idx] & FAT32_MASK) == FAT32_FREE) {
                    const cluster = sec * entries_per_sector + idx;
                    if (cluster < 2) continue;
                    if (cluster >= self.total_data_clusters + 2) continue;

                    // Mark as EOF
                    self.fat_buf[idx] = (self.fat_buf[idx] & 0xF0000000) | (FAT32_EOF & FAT32_MASK);
                    self.fat_cache_dirty = true;

                    // Link from previous cluster if provided
                    if (prev_cluster) |prev| {
                        if (!self.setFatEntry(prev, cluster)) {
                            // Undo allocation
                            self.fat_buf[idx] = (self.fat_buf[idx] & 0xF0000000) | FAT32_FREE;
                            return null;
                        }
                    }

                    self.flushFatCache();
                    return cluster;
                }
            }
        }

        hal.Serial.puts("[FAT32] ERROR: No free clusters available\n");
        return null;
    }

    /// Zero out all sectors in a newly allocated cluster
    fn zeroCluster(self: *Fat32Fs, cluster: u32) void {
        if (cluster < 2) return;
        // Zero the write buffer
        @memset(self.write_buf[0..512], 0);
        for (0..self.sectors_per_cluster) |sec| {
            _ = self.writeClusterSector(cluster, @intCast(sec), self.write_buf);
        }
    }

    // ================================================================
    // Directory Operations
    // ================================================================

    pub fn listDir(
        self: *Fat32Fs,
        dir_cluster: u32,
        ctx: *anyopaque,
        callback: *const fn (*anyopaque, *const DirEntryInfo) void,
    ) u32 {
        var count: u32 = 0;
        var cluster: u32 = dir_cluster;
        var lfn_buf: [256]u16 = undefined;
        var lfn_len: usize = 0;
        var chain_len: u32 = 0;

        while (true) {
            if (cluster < 2) break;
            if (chain_len >= MAX_CLUSTER_CHAIN) break;

            for (0..self.sectors_per_cluster) |sec_idx| {
                if (!self.readClusterSector(cluster, @intCast(sec_idx))) break;

                for (0..DIR_ENTRIES_PER_SECTOR) |entry_idx| {
                    const entry: *const DirEntry = @ptrCast(@alignCast(self.io_buf + entry_idx * 32));

                    if (entry.name[0] == 0x00) return count; // End of dir
                    if (entry.name[0] == 0xE5) { lfn_len = 0; continue; } // Deleted

                    if (entry.attr == ATTR_LFN) {
                        const lfn: *const LfnEntry = @ptrCast(@alignCast(entry));
                        processLfnEntry(lfn, &lfn_buf, &lfn_len);
                        continue;
                    }

                    if ((entry.attr & ATTR_VOLUME_ID) != 0 and (entry.attr & ATTR_DIRECTORY) == 0) {
                        lfn_len = 0;
                        continue;
                    }

                    var info = DirEntryInfo{
                        .name = undefined,
                        .name_len = 0,
                        .is_directory = (entry.attr & ATTR_DIRECTORY) != 0,
                        .is_read_only = (entry.attr & ATTR_READ_ONLY) != 0,
                        .is_hidden = (entry.attr & ATTR_HIDDEN) != 0,
                        .file_size = if ((entry.attr & ATTR_DIRECTORY) != 0) 0 else entry.file_size,
                        .first_cluster = (@as(u32, entry.first_cluster_hi) << 16) | entry.first_cluster_lo,
                    };

                    if (lfn_len > 0) {
                        for (0..lfn_len) |i| {
                            const ch = lfn_buf[i];
                            info.name[i] = if (ch < 128) @intCast(ch) else '?';
                        }
                        info.name_len = lfn_len;
                    } else {
                        info.name_len = shortNameToAscii(&entry.name, &entry.ext, &info.name);
                    }
                    if (info.name_len < 256) info.name[info.name_len] = 0;

                    callback(ctx, &info);
                    count += 1;
                    lfn_len = 0;
                }
            }

            const next = self.getNextCluster(cluster) orelse break;
            cluster = next;
            chain_len += 1;
        }

        return count;
    }

    fn processLfnEntry(lfn: *const LfnEntry, buf: *[256]u16, len: *usize) void {
        const is_last = (lfn.seq & 0x40) != 0;
        const entry_seq = (lfn.seq & 0x3F);
        if (entry_seq == 0) return;

        if (is_last) len.* = 0;

        const base_pos = (entry_seq - 1) * 13;
        var pos = base_pos;

        for (lfn.name1) |ch| {
            if (ch == 0x0000 or ch == 0xFFFF) break;
            if (pos < 256) { buf[pos] = ch; pos += 1; }
        }
        for (lfn.name2) |ch| {
            if (ch == 0x0000 or ch == 0xFFFF) break;
            if (pos < 256) { buf[pos] = ch; pos += 1; }
        }
        for (lfn.name3) |ch| {
            if (ch == 0x0000 or ch == 0xFFFF) break;
            if (pos < 256) { buf[pos] = ch; pos += 1; }
        }

        if (pos > len.*) len.* = pos;
    }

    fn shortNameToAscii(name: *const [8]u8, ext: *const [3]u8, out: *[256]u8) usize {
        var len: usize = 0;

        var name_end: usize = 8;
        while (name_end > 0 and name[name_end - 1] == ' ') name_end -= 1;
        for (0..name_end) |i| {
            const ch = name[i];
            if (ch == 0) break;
            out[len] = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
            len += 1;
        }

        var ext_end: usize = 3;
        while (ext_end > 0 and ext[ext_end - 1] == ' ') ext_end -= 1;
        if (ext_end > 0) {
            out[len] = '.';
            len += 1;
            for (0..ext_end) |i| {
                const ch = ext[i];
                if (ch == 0) break;
                out[len] = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
                len += 1;
            }
        }

        return len;
    }

    // ================================================================
    // Path Resolution (Nested Directories)
    // ================================================================

    /// Resolve a path like "/dir/subdir/file.txt" to a File.
    /// Handles multiple path components separated by '/'.
    pub fn openFile(self: *Fat32Fs, path: []const u8) ?File {
        // Strip leading slashes
        var p = path;
        while (p.len > 0 and p[0] == '/') p = p[1..];

        if (p.len == 0) {
            // Root directory requested
            return File{
                .first_cluster = self.root_cluster,
                .current_cluster = self.root_cluster,
                .file_size = 0,
                .position = 0,
                .is_valid = true,
                .is_directory = true,
                .dir_cluster = 0,
                .name = undefined,
                .name_len = 0,
            };
        }

        // Split path into components
        var current_dir: u32 = self.root_cluster;
        var start: usize = 0;

        while (start < p.len) {
            // Find end of this component
            var end = start;
            while (end < p.len and p[end] != '/') : (end += 1) {}
            const component = p[start..end];

            if (component.len == 0) {
                start = end + 1;
                continue;
            }

            // P0 SECURITY: Path traversal protection — reject ".." to prevent
            // escaping the intended directory hierarchy, and skip "." (no-op).
            if (component.len == 2 and component[0] == '.' and component[1] == '.') return null;
            if (component.len == 1 and component[0] == '.') {
                start = end + 1;
                continue; // Skip "." — current directory, no traversal needed
            }

            // Is this the last component?
            const remaining = if (end < p.len) p[end + 1 ..] else "";
            var rem_clean = remaining;
            while (rem_clean.len > 0 and rem_clean[0] == '/') rem_clean = rem_clean[1..];
            const is_last = rem_clean.len == 0;

            // Look up this component in the current directory
            const entry = self.findEntryInDir(current_dir, component) orelse return null;

            if (is_last) {
                // This is the final component — return as File
                var file_name: [256]u8 = undefined;
                @memcpy(file_name[0..component.len], component);
                file_name[component.len] = 0;

                return File{
                    .first_cluster = entry.first_cluster,
                    .current_cluster = if (entry.first_cluster >= 2) entry.first_cluster else 0,
                    .file_size = entry.file_size,
                    .position = 0,
                    .is_valid = true,
                    .is_directory = entry.is_directory,
                    .dir_cluster = current_dir,
                    .name = file_name,
                    .name_len = component.len,
                };
            } else {
                // Intermediate component — must be a directory
                if (!entry.is_directory) return null;
                current_dir = if (entry.first_cluster >= 2) entry.first_cluster else self.root_cluster;
            }

            start = end + 1;
        }

        return null;
    }

    /// Find a directory entry by name within a specific directory cluster
    fn findEntryInDir(self: *Fat32Fs, dir_cluster: u32, target_name: []const u8) ?DirEntryInfo {
        var cluster: u32 = dir_cluster;
        var chain_len: u32 = 0;
        var lfn_buf: [256]u16 = undefined;
        var lfn_len: usize = 0;

        while (true) {
            if (cluster < 2) break;
            if (chain_len >= MAX_CLUSTER_CHAIN) break;

            for (0..self.sectors_per_cluster) |sec_idx| {
                if (!self.readClusterSector(cluster, @intCast(sec_idx))) break;

                for (0..DIR_ENTRIES_PER_SECTOR) |entry_idx| {
                    const entry: *const DirEntry = @ptrCast(@alignCast(self.io_buf + entry_idx * 32));

                    if (entry.name[0] == 0x00) return null; // End of dir
                    if (entry.name[0] == 0xE5) { lfn_len = 0; continue; }

                    if (entry.attr == ATTR_LFN) {
                        const lfn: *const LfnEntry = @ptrCast(@alignCast(entry));
                        processLfnEntry(lfn, &lfn_buf, &lfn_len);
                        continue;
                    }

                    if ((entry.attr & ATTR_VOLUME_ID) != 0 and (entry.attr & ATTR_DIRECTORY) == 0) {
                        lfn_len = 0;
                        continue;
                    }

                    var entry_name: [256]u8 = undefined;
                    var entry_name_len: usize = 0;

                    if (lfn_len > 0) {
                        for (0..lfn_len) |i| {
                            const ch = lfn_buf[i];
                            entry_name[i] = if (ch < 128) @intCast(ch) else '?';
                        }
                        entry_name_len = lfn_len;
                    } else {
                        entry_name_len = shortNameToAscii(&entry.name, &entry.ext, &entry_name);
                    }

                    // Case-insensitive comparison
                    if (entry_name_len == target_name.len) {
                        var match = true;
                        for (0..target_name.len) |i| {
                            const a = toLower(entry_name[i]);
                            const b = toLower(target_name[i]);
                            if (a != b) { match = false; break; }
                        }

                        if (match) {
                            return DirEntryInfo{
                                .name = entry_name,
                                .name_len = entry_name_len,
                                .is_directory = (entry.attr & ATTR_DIRECTORY) != 0,
                                .is_read_only = (entry.attr & ATTR_READ_ONLY) != 0,
                                .is_hidden = (entry.attr & ATTR_HIDDEN) != 0,
                                .file_size = entry.file_size,
                                .first_cluster = (@as(u32, entry.first_cluster_hi) << 16) | entry.first_cluster_lo,
                            };
                        }
                    }

                    lfn_len = 0;
                }
            }

            const next = self.getNextCluster(cluster) orelse break;
            cluster = next;
            chain_len += 1;
        }

        return null;
    }

    fn toLower(ch: u8) u8 {
        return if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
    }

    /// Get the directory cluster for a parent path.
    /// e.g. for "/dir/subdir", returns the cluster of "subdir" in "dir"
    /// If path is "/" or "", returns root_cluster.
    pub fn resolveDirCluster(self: *Fat32Fs, path: []const u8) ?u32 {
        var p = path;
        while (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1]; // Strip trailing /
        while (p.len > 0 and p[0] == '/') p = p[1..]; // Strip leading /

        if (p.len == 0) return self.root_cluster;

        // Open the path — if it's a directory, return its cluster
        const f = self.openFile(path) orelse return null; // Return null instead of silently falling back to root
        if (f.is_directory and f.first_cluster >= 2) {
            return f.first_cluster;
        }
        return null; // Not a directory — return null
    }

    // ================================================================
    // File Read Operations
    // ================================================================

    pub fn openFileInDir(self: *Fat32Fs, dir_cluster: u32, target_name: []const u8) ?File {
        var cluster: u32 = dir_cluster;
        var chain_len: u32 = 0;
        var lfn_buf: [256]u16 = undefined;
        var lfn_len: usize = 0;

        while (true) {
            if (cluster < 2) break;
            if (chain_len >= MAX_CLUSTER_CHAIN) break;

            for (0..self.sectors_per_cluster) |sec_idx| {
                if (!self.readClusterSector(cluster, @intCast(sec_idx))) break;

                for (0..DIR_ENTRIES_PER_SECTOR) |entry_idx| {
                    const entry: *const DirEntry = @ptrCast(@alignCast(self.io_buf + entry_idx * 32));

                    if (entry.name[0] == 0x00) return null;
                    if (entry.name[0] == 0xE5) { lfn_len = 0; continue; }

                    if (entry.attr == ATTR_LFN) {
                        const lfn: *const LfnEntry = @ptrCast(@alignCast(entry));
                        processLfnEntry(lfn, &lfn_buf, &lfn_len);
                        continue;
                    }

                    if ((entry.attr & ATTR_VOLUME_ID) != 0 and (entry.attr & ATTR_DIRECTORY) == 0) {
                        lfn_len = 0;
                        continue;
                    }

                    var entry_name: [256]u8 = undefined;
                    var entry_name_len: usize = 0;

                    if (lfn_len > 0) {
                        for (0..lfn_len) |i| {
                            const ch = lfn_buf[i];
                            entry_name[i] = if (ch < 128) @intCast(ch) else '?';
                        }
                        entry_name_len = lfn_len;
                    } else {
                        entry_name_len = shortNameToAscii(&entry.name, &entry.ext, &entry_name);
                    }

                    // Case-insensitive comparison
                    if (entry_name_len == target_name.len) {
                        var match = true;
                        for (0..target_name.len) |i| {
                            const a = toLower(entry_name[i]);
                            const b = toLower(target_name[i]);
                            if (a != b) { match = false; break; }
                        }

                        if (match) {
                            const first_cluster = (@as(u32, entry.first_cluster_hi) << 16) | entry.first_cluster_lo;
                            var file_name: [256]u8 = undefined;
                            @memcpy(file_name[0..entry_name_len], entry_name[0..entry_name_len]);
                            file_name[entry_name_len] = 0;

                            return File{
                                .first_cluster = first_cluster,
                                .current_cluster = if (first_cluster >= 2) first_cluster else 0,
                                .file_size = entry.file_size,
                                .position = 0,
                                .is_valid = true,
                                .is_directory = (entry.attr & ATTR_DIRECTORY) != 0,
                                .dir_cluster = dir_cluster,
                                .name = file_name,
                                .name_len = entry_name_len,
                            };
                        }
                    }

                    lfn_len = 0;
                }
            }

            const next = self.getNextCluster(cluster) orelse break;
            cluster = next;
            chain_len += 1;
        }

        return null;
    }

    /// Read bytes from an open file into a caller-provided buffer.
    pub fn readFile(self: *Fat32Fs, file: *File, buf: []u8, count: u32) u32 {
        if (!file.is_valid or file.first_cluster < 2) return 0;
        if (file.position >= file.file_size) return 0;

        const remaining = file.file_size - file.position;
        const to_read = if (count < remaining) count else remaining;
        var bytes_read: u32 = 0;

        while (bytes_read < to_read) {
            const cluster_idx = (file.position + bytes_read) / self.cluster_size;
            const byte_in_cluster = (file.position + bytes_read) % self.cluster_size;

            const cluster = self.getClusterAt(file.first_cluster, cluster_idx) orelse break;

            const sector_in_cluster = byte_in_cluster / self.bytes_per_sector;
            if (!self.readClusterSector(cluster, @intCast(sector_in_cluster))) break;

            const byte_in_sector = byte_in_cluster % self.bytes_per_sector;
            const bytes_in_sector = self.bytes_per_sector - byte_in_sector;
            const bytes_to_copy = if (to_read - bytes_read < bytes_in_sector)
                to_read - bytes_read else bytes_in_sector;

            const src = self.io_buf + byte_in_sector;
            @memcpy(buf[bytes_read..][0..bytes_to_copy], src[0..bytes_to_copy]);

            bytes_read += bytes_to_copy;
        }

        file.position += bytes_read;
        return bytes_read;
    }

    // ================================================================
    // File Write Operations
    // ================================================================

    /// Write bytes to a file. If the file doesn't exist, creates it.
    /// If it exists, appends at the current position.
    pub fn writeFile(self: *Fat32Fs, file: *File, data: []const u8) u32 {
        if (!file.is_valid) return 0;
        if (virtio_blk.isReadOnly()) return 0;

        var bytes_written: u32 = 0;

        while (bytes_written < data.len) {
            // Ensure we have a cluster allocated for the current position
            const cluster_idx = (file.position + bytes_written) / self.cluster_size;

            var cluster: u32 = undefined;
            if (file.first_cluster < 2) {
                // No clusters allocated yet — allocate the first one
                cluster = self.allocCluster(null) orelse break;
                self.zeroCluster(cluster);
                file.first_cluster = cluster;
                file.current_cluster = cluster;
                // Update the directory entry with the new first cluster
                _ = self.updateDirEntry(file);
            } else {
                cluster = self.getClusterAt(file.first_cluster, cluster_idx) orelse blk: {
                    // Need to extend the chain
                    // Find the last cluster in the chain
                    var last = file.first_cluster;
                    while (self.getNextCluster(last)) |next| {
                        last = next;
                    }
                    const new_cluster = self.allocCluster(last) orelse break :blk 0;
                    self.zeroCluster(new_cluster);
                    break :blk new_cluster;
                };
                if (cluster == 0) break;
            }

            const byte_in_cluster = (file.position + bytes_written) % self.cluster_size;
            const sector_in_cluster = byte_in_cluster / self.bytes_per_sector;
            const byte_in_sector = byte_in_cluster % self.bytes_per_sector;

            // Read the sector first (partial sector write — need read-modify-write)
            if (byte_in_sector != 0 or (data.len - bytes_written) < self.bytes_per_sector) {
                if (!self.readClusterSector(cluster, @intCast(sector_in_cluster))) break;
                // Copy from io_buf to write_buf
                @memcpy(self.write_buf[0..512], self.io_buf[0..512]);
            } else {
                // Full sector write — no need to read first
                @memset(self.write_buf[0..512], 0);
            }

            // Copy data into the write buffer at the right offset
            const bytes_in_sector = self.bytes_per_sector - byte_in_sector;
            const bytes_to_copy = if (@as(u32, @intCast(data.len - bytes_written)) < bytes_in_sector)
                @as(u32, @intCast(data.len - bytes_written)) else bytes_in_sector;

            @memcpy(
                self.write_buf[byte_in_sector..][0..bytes_to_copy],
                data[bytes_written..][0..bytes_to_copy],
            );

            // Write the sector
            if (!self.writeClusterSector(cluster, @intCast(sector_in_cluster), self.write_buf)) break;

            bytes_written += bytes_to_copy;
        }

        // Update file size and position
        if (bytes_written > 0) {
            file.position += bytes_written;
            if (file.position > file.file_size) {
                file.file_size = file.position;
            }
            _ = self.updateDirEntry(file);
        }

        return bytes_written;
    }

    /// Create a new empty file in the specified directory.
    /// Returns the File handle, or null on error.
    pub fn createFile(self: *Fat32Fs, dir_cluster: u32, filename: []const u8) ?File {
        if (virtio_blk.isReadOnly()) return null;

        // Check if file already exists
        if (self.findEntryInDir(dir_cluster, filename) != null) {
            hal.Serial.puts("[FAT32] File already exists: ");
            hal.Serial.puts(filename);
            hal.Serial.puts("\n");
            return null;
        }

        // Create a directory entry for the new file (0 size, no clusters)
        var file = File{
            .first_cluster = 0,
            .current_cluster = 0,
            .file_size = 0,
            .position = 0,
            .is_valid = true,
            .is_directory = false,
            .dir_cluster = dir_cluster,
            .name = undefined,
            .name_len = 0,
        };
        @memcpy(file.name[0..filename.len], filename);
        file.name[filename.len] = 0;
        file.name_len = filename.len;

        // Add the entry to the directory
        if (!self.addDirEntry(dir_cluster, &file)) return null;

        return file;
    }

    /// Create a new directory.
    pub fn createDir(self: *Fat32Fs, parent_cluster: u32, dirname: []const u8) ?u32 {
        if (virtio_blk.isReadOnly()) return null;

        // Check if directory already exists
        if (self.findEntryInDir(parent_cluster, dirname)) |existing| {
            if (existing.is_directory) return existing.first_cluster;
            return null; // A file with this name exists
        }

        // Allocate a cluster for the new directory
        const new_cluster = self.allocCluster(null) orelse return null;
        self.zeroCluster(new_cluster);

        // Write "." and ".." entries in the new directory
        // "." entry
        var dot_entry = DirEntry{
            .name = ".       ".*,
            .ext = "   ".*,
            .attr = ATTR_DIRECTORY,
            .nt_reserved = 0,
            .creation_time_tenth = 0,
            .creation_time = 0,
            .creation_date = 0,
            .last_access_date = 0,
            .first_cluster_hi = @truncate(new_cluster >> 16),
            .last_write_time = 0,
            .last_write_date = 0,
            .first_cluster_lo = @truncate(new_cluster),
            .file_size = 0,
        };

        // ".." entry
        var dotdot_entry = DirEntry{
            .name = "..      ".*,
            .ext = "   ".*,
            .attr = ATTR_DIRECTORY,
            .nt_reserved = 0,
            .creation_time_tenth = 0,
            .creation_time = 0,
            .creation_date = 0,
            .last_access_date = 0,
            .first_cluster_hi = @truncate(parent_cluster >> 16),
            .last_write_time = 0,
            .last_write_date = 0,
            .first_cluster_lo = @truncate(parent_cluster),
            .file_size = 0,
        };

        // Write "." and ".." to the first sector of the new cluster
        @memset(self.write_buf[0..512], 0);
        @memcpy(self.write_buf[0..32], @as([*]const u8, @ptrCast(&dot_entry))[0..32]);
        @memcpy(self.write_buf[32..64], @as([*]const u8, @ptrCast(&dotdot_entry))[0..32]);

        if (!self.writeClusterSector(new_cluster, 0, self.write_buf)) {
            // Failed — free the cluster
            _ = self.setFatEntry(new_cluster, FAT32_FREE);
            self.flushFatCache();
            return null;
        }

        // Add the directory entry in the parent
        var dir_file = File{
            .first_cluster = new_cluster,
            .current_cluster = new_cluster,
            .file_size = 0,
            .position = 0,
            .is_valid = true,
            .is_directory = true,
            .dir_cluster = parent_cluster,
            .name = undefined,
            .name_len = 0,
        };
        @memcpy(dir_file.name[0..dirname.len], dirname);
        dir_file.name[dirname.len] = 0;
        dir_file.name_len = dirname.len;

        if (!self.addDirEntry(parent_cluster, &dir_file)) {
            _ = self.setFatEntry(new_cluster, FAT32_FREE);
            self.flushFatCache();
            return null;
        }

        return new_cluster;
    }

    // ================================================================
    // Directory Entry Management
    // ================================================================

    /// Add a new directory entry to a directory.
    /// Creates a short-name entry (8.3 format) for simplicity.
    fn addDirEntry(self: *Fat32Fs, dir_cluster: u32, file: *const File) bool {
        var cluster: u32 = dir_cluster;
        var chain_len: u32 = 0;

        while (true) {
            if (cluster < 2) break;
            if (chain_len >= MAX_CLUSTER_CHAIN) break;

            for (0..self.sectors_per_cluster) |sec_idx| {
                if (!self.readClusterSector(cluster, @intCast(sec_idx))) break;

                for (0..DIR_ENTRIES_PER_SECTOR) |entry_idx| {
                    const entry_ptr: *const DirEntry = @ptrCast(@alignCast(self.io_buf + entry_idx * 32));

                    // Find a free slot (0x00 = end, 0xE5 = deleted)
                    if (entry_ptr.name[0] == 0x00 or entry_ptr.name[0] == 0xE5) {
                        // Found a free slot — create the entry here
                        var new_entry = DirEntry{
                            .name = "        ".*,
                            .ext = "   ".*,
                            .attr = if (file.is_directory) ATTR_DIRECTORY else ATTR_ARCHIVE,
                            .nt_reserved = 0,
                            .creation_time_tenth = 0,
                            .creation_time = 0x0000,
                            .creation_date = 0x0000,
                            .last_access_date = 0x0000,
                            .first_cluster_hi = @truncate(file.first_cluster >> 16),
                            .last_write_time = 0x0000,
                            .last_write_date = 0x0000,
                            .first_cluster_lo = @truncate(file.first_cluster & 0xFFFF),
                            .file_size = file.file_size,
                        };

                        // Convert filename to 8.3 short name
                        self.filenameToShortName(file.name[0..file.name_len], &new_entry.name, &new_entry.ext);

                        // Copy new entry into write buffer (preserve other entries)
                        @memcpy(self.write_buf[0..512], self.io_buf[0..512]);
                        @memcpy(self.write_buf[entry_idx * 32 ..][0..32], @as([*]const u8, @ptrCast(&new_entry))[0..32]);

                        // If this was the end-of-dir marker, add a new one after
                        if (entry_ptr.name[0] == 0x00) {
                            const next_idx = entry_idx + 1;
                            if (next_idx < DIR_ENTRIES_PER_SECTOR) {
                                @memset(self.write_buf[next_idx * 32 ..][0..32], 0);
                            }
                        }

                        // Write the sector back
                        if (!self.writeClusterSector(cluster, @intCast(sec_idx), self.write_buf)) {
                            return false;
                        }

                        hal.Serial.puts("[FAT32] Added dir entry: ");
                        hal.Serial.puts(file.name[0..file.name_len]);
                        hal.Serial.puts(" cluster=");
                        hal.Serial.putHex(file.first_cluster);
                        hal.Serial.puts("\n");
                        return true;
                    }
                }
            }

            // Try next cluster in chain
            const next = self.getNextCluster(cluster) orelse {
                // Need to extend the directory — allocate a new cluster
                const new_cluster = self.allocCluster(cluster) orelse return false;
                self.zeroCluster(new_cluster);
                cluster = new_cluster;
                continue;
            };
            cluster = next;
            chain_len += 1;
        }

        return false;
    }

    /// Delete a file by marking its directory entry as deleted (0xE5)
    /// Returns true on success, false on failure.
    pub fn deleteFile(self: *Fat32Fs, path: []const u8) bool {
        // Resolve the file
        const f = self.openFile(path) orelse return false;
        if (f.is_directory) return false; // Cannot delete directories with this function

        // Find the parent directory and file name
        var last_slash: usize = 0;
        for (0..path.len) |i| {
            if (path[i] == '/') last_slash = i;
        }

        const dir_cluster = if (last_slash == 0)
            self.root_cluster
        else
            self.resolveDirCluster(path[0..last_slash]) orelse return false;

        const file_name = if (last_slash == 0) path else path[last_slash + 1 ..];
        if (file_name.len == 0) return false;

        // Convert to short name for matching
        var short_name: [11]u8 = undefined;
        self.filenameToShortName(file_name, short_name[0..8], short_name[8..11]);

        // Walk the directory to find and mark the entry as deleted
        var cluster: u32 = dir_cluster;
        var chain_len: u32 = 0;

        while (true) {
            if (cluster < 2) break;
            if (chain_len >= MAX_CLUSTER_CHAIN) break;

            for (0..self.sectors_per_cluster) |sec_idx| {
                if (!self.readClusterSector(cluster, @intCast(sec_idx))) break;

                for (0..DIR_ENTRIES_PER_SECTOR) |entry_idx| {
                    const entry: *const DirEntry = @ptrCast(@alignCast(self.io_buf + entry_idx * 32));

                    if (entry.name[0] == 0x00) return false; // End of dir, not found
                    if (entry.name[0] == 0xE5) continue;
                    if (entry.attr == ATTR_LFN) continue;

                    // Compare short name
                    var match = true;
                    for (0..11) |i| {
                        const a = if (i < 8) entry.name[i] else entry.ext[i - 8];
                        if (toLower(a) != toLower(short_name[i])) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        // Mark entry as deleted (0xE5)
                        @memcpy(self.write_buf[0..512], self.io_buf[0..512]);
                        const del_entry: *volatile [32]u8 = @ptrCast(self.write_buf + entry_idx * 32);
                        del_entry[0] = 0xE5;

                        if (!self.writeClusterSector(cluster, @intCast(sec_idx), self.write_buf)) {
                            return false;
                        }

                        // Free the cluster chain
                        if (f.first_cluster >= 2) {
                            self.freeClusterChain(f.first_cluster);
                        }

                        // Flush FAT cache
                        self.flushFatCache();
                        return true;
                    }
                }
            }

            const next = self.getNextCluster(cluster) orelse break;
            cluster = next;
            chain_len += 1;
        }

        return false;
    }

    /// Free a chain of clusters starting from the given cluster.
    /// Marks each cluster as free (0x00000000) in the FAT.
    fn freeClusterChain(self: *Fat32Fs, start_cluster: u32) void {
        var cluster: u32 = start_cluster;
        var count: u32 = 0;

        while (cluster >= 2 and cluster < 0x0FFFFFF8 and count < MAX_CLUSTER_CHAIN) {
            const next = self.getNextCluster(cluster) orelse {
                _ = self.setFatEntry(cluster, 0x00000000);
                break;
            };
            _ = self.setFatEntry(cluster, 0x00000000);
            cluster = next;
            count += 1;
        }

        // Flush the FAT cache to disk
        self.flushFatCache();
    }

    /// Update an existing directory entry (e.g. file size, first cluster).
    fn updateDirEntry(self: *Fat32Fs, file: *const File) bool {
        if (file.dir_cluster < 2) return false;

        var cluster: u32 = file.dir_cluster;
        var chain_len: u32 = 0;

        while (true) {
            if (cluster < 2) break;
            if (chain_len >= MAX_CLUSTER_CHAIN) break;

            for (0..self.sectors_per_cluster) |sec_idx| {
                if (!self.readClusterSector(cluster, @intCast(sec_idx))) break;

                for (0..DIR_ENTRIES_PER_SECTOR) |entry_idx| {
                    const entry: *const DirEntry = @ptrCast(@alignCast(self.io_buf + entry_idx * 32));

                    if (entry.name[0] == 0x00) return false; // Not found
                    if (entry.name[0] == 0xE5) continue;
                    if (entry.attr == ATTR_LFN) continue;
                    if ((entry.attr & ATTR_VOLUME_ID) != 0 and (entry.attr & ATTR_DIRECTORY) == 0) continue;

                    // Check if this entry matches our file
                    var short_name: [11]u8 = undefined;
                    self.filenameToShortName(file.name[0..file.name_len], short_name[0..8], short_name[8..11]);

                    var match = true;
                    for (0..11) |i| {
                        if (entry.name[0..8][if (i < 8) i else i - 8] != short_name[i]) {
                            // Compare case-insensitively for short names
                            const a = entry.name[0..8][if (i < 8) i else i - 8];
                            const b = short_name[i];
                            if (toLower(a) != toLower(b)) {
                                match = false;
                                break;
                            }
                        }
                    }

                    if (match) {
                        // Update the entry
                        @memcpy(self.write_buf[0..512], self.io_buf[0..512]);
                        const update: *volatile DirEntry = @ptrCast(@alignCast(self.write_buf + entry_idx * 32));
                        update.first_cluster_hi = @truncate(file.first_cluster >> 16);
                        update.first_cluster_lo = @truncate(file.first_cluster & 0xFFFF);
                        update.file_size = file.file_size;

                        if (!self.writeClusterSector(cluster, @intCast(sec_idx), self.write_buf)) {
                            return false;
                        }
                        return true;
                    }
                }
            }

            const next = self.getNextCluster(cluster) orelse break;
            cluster = next;
            chain_len += 1;
        }

        return false;
    }

    /// Convert a long filename to 8.3 short name format.
    fn filenameToShortName(self: *Fat32Fs, filename: []const u8, name_out: *[8]u8, ext_out: *[3]u8) void {
        _ = self;
        // Initialize with spaces
        @memset(name_out, ' ');
        @memset(ext_out, ' ');

        // Find the dot separating name and extension
        var dot_pos: ?usize = null;
        var i: usize = filename.len;
        while (i > 0) : (i -= 1) {
            if (filename[i - 1] == '.') {
                dot_pos = i - 1;
                break;
            }
        }

        // Copy name part (before dot, or whole name if no dot)
        const name_end = dot_pos orelse filename.len;
        const name_len = if (name_end > 8) @as(usize, 6) else name_end; // Truncate to 6 for ~1
        for (0..name_len) |j| {
            var ch = filename[j];
            if (ch >= 'a' and ch <= 'z') ch -= 32; // Uppercase
            if (ch == ' ' or ch == '.') ch = '_'; // Replace invalid chars
            name_out[j] = ch;
        }
        // If truncated, add ~1
        if (name_end > 8) {
            name_out[6] = '~';
            name_out[7] = '1';
        }

        // Copy extension part (after dot)
        if (dot_pos) |dp| {
            const ext_start = dp + 1;
            for (0..3) |j| {
                if (ext_start + j < filename.len) {
                    var ch = filename[ext_start + j];
                    if (ch >= 'a' and ch <= 'z') ch -= 32;
                    if (ch == ' ' or ch == '.') ch = '_';
                    ext_out[j] = ch;
                }
            }
        }
    }

    // ================================================================
    // Root Directory Listing
    // ================================================================

    pub fn listRootDir(self: *Fat32Fs) u32 {
        var ctx = ListDirCtx{ .count = 0 };
        _ = self.listDir(self.root_cluster, &ctx, listDirCallback);
        return ctx.count;
    }

    const ListDirCtx = struct { count: u32 };

    fn listDirCallback(ctx_opaque: *anyopaque, info: *const DirEntryInfo) void {
        const ctx: *ListDirCtx = @ptrCast(@alignCast(ctx_opaque));
        ctx.count += 1;

        hal.Serial.puts("  ");
        if (info.is_directory) hal.Serial.puts("[DIR] ");
        if (info.name_len > 0) {
            hal.Serial.puts(info.name[0..info.name_len]);
        }
        if (!info.is_directory) {
            hal.Serial.puts(" (");
            hal.Serial.putHex(info.file_size);
            hal.Serial.puts(" bytes)");
        }
        hal.Serial.puts("\n");
    }

    // ================================================================
    // FAT32 Formatting (mkfs)
    // ================================================================

    /// Format a virtio-blk device with a fresh FAT32 filesystem.
    /// Creates BPB, FAT tables, root directory, and FSInfo sector.
    /// Destroys all existing data on the device.
    pub fn format(disk_capacity_bytes: u64) bool {
        if (!virtio_blk.isInitialized()) {
            hal.Serial.puts("[FAT32 FORMAT] No virtio-blk driver available\n");
            return false;
        }
        if (virtio_blk.isReadOnly()) {
            hal.Serial.puts("[FAT32 FORMAT] Device is read-only\n");
            return false;
        }

        hal.Serial.puts("[FAT32 FORMAT] Formatting device...\n");

        const SECTOR: u64 = 512;

        // Calculate geometry for a standard FAT32 filesystem
        const total_sectors = disk_capacity_bytes / SECTOR;
        if (total_sectors < 32768) {
            hal.Serial.puts("[FAT32 FORMAT] Device too small (min 16MB)\n");
            return false;
        }

        // Choose sectors_per_cluster based on disk size (Microsoft spec)
        const spc: u8 = if (total_sectors < 532480) @as(u8, 1) // <260MB: 1
        else if (total_sectors < 16777216) @as(u8, 8) // <8GB: 8
        else if (total_sectors < 33554432) @as(u8, 16) // <16GB: 16
        else if (total_sectors < 67108864) @as(u8, 32) // <32GB: 32
        else @as(u8, 64); // >=32GB: 64

        const reserved_sectors: u16 = 32; // Standard for FAT32
        const num_fats: u8 = 2;
        const cluster_size: u32 = @as(u32, spc) * 512;

        // Calculate FAT size using Microsoft's formula:
        // FAT sectors = ((total_sectors - reserved - root_dir_sectors) / spc * 4 + 511) / 512
        // Then round up and add safety margin
        const data_sectors_approx = total_sectors - @as(u64, reserved_sectors);
        const num_clusters_approx = data_sectors_approx / @as(u64, spc);
        // Each FAT entry is 4 bytes; each FAT sector holds 128 entries
        const fat_sectors_approx = (num_clusters_approx * 4 + 511) / 512;
        // Add 1% safety margin, minimum 1 sector
        const fat_size_32: u32 = @intCast(fat_sectors_approx + (fat_sectors_approx / 100 + 1));

        const data_start: u64 = @as(u64, reserved_sectors) + @as(u64, num_fats) * @as(u64, fat_size_32);
        const data_sectors = total_sectors - data_start;
        const total_data_clusters: u32 = @intCast(data_sectors / @as(u64, spc));

        hal.Serial.puts("[FAT32 FORMAT] Geometry: total_sectors=");
        hal.Serial.putHex(@as(u32, @intCast(total_sectors)));
        hal.Serial.puts(" spc=");
        hal.Serial.putHex(spc);
        hal.Serial.puts(" fat_size=");
        hal.Serial.putHex(fat_size_32);
        hal.Serial.puts(" data_clusters=");
        hal.Serial.putHex(total_data_clusters);
        hal.Serial.puts("\n");

        // Allocate temporary buffers
        const buf_phys = pmm.allocPage() orelse {
            hal.Serial.puts("[FAT32 FORMAT] ERROR: Failed to allocate buffer\n");
            return false;
        };
        const buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(buf_phys)));
        defer _ = pmm.freePage(buf_phys);

        // ── Step 1: Write BPB (Boot Sector) at sector 0 ──
        @memset(buf[0..512], 0);

        // Jump instruction (x86 NOP + short jump)
        buf[0] = 0xEB; // jmp short
        buf[1] = 0x58; // offset to bootstrap
        buf[2] = 0x90; // NOP

        // OEM Name
        const oem = "POLER-OS";
        @memcpy(buf[3..11], oem);

        // BPB fields (little-endian)
        // bytes_per_sector = 512
        buf[11] = 0x00; buf[12] = 0x02; // 512
        // sectors_per_cluster
        buf[13] = spc;
        // reserved_sectors
        buf[14] = @truncate(reserved_sectors);
        buf[15] = @truncate(reserved_sectors >> 8);
        // num_fats
        buf[16] = num_fats;
        // root_entry_count (0 for FAT32)
        buf[17] = 0; buf[18] = 0;
        // total_sectors_16 (0 for FAT32)
        buf[19] = 0; buf[20] = 0;
        // media_type (0xF8 = hard disk)
        buf[21] = 0xF8;
        // fat_size_16 (0 for FAT32)
        buf[22] = 0; buf[23] = 0;
        // sectors_per_track (63 standard)
        buf[24] = 63; buf[25] = 0;
        // num_heads (255 standard)
        buf[26] = 255; buf[27] = 0;
        // hidden_sectors
        var hs: u32 = 0;
        @memcpy(buf[28..32], @as([*]const u8, @ptrCast(&hs))[0..4]);
        // total_sectors_32
        const ts32: u32 = @intCast(total_sectors);
        @memcpy(buf[32..36], @as([*]const u8, @ptrCast(&ts32))[0..4]);

        // FAT32-specific fields (starting at offset 36)
        // fat_size_32
        @memcpy(buf[36..40], @as([*]const u8, @ptrCast(&fat_size_32))[0..4]);
        // ext_flags (0 = both FATs active)
        buf[40] = 0; buf[41] = 0;
        // fs_version (0)
        buf[42] = 0; buf[43] = 0;
        // root_cluster (2)
        const root_cluster: u32 = 2;
        @memcpy(buf[44..48], @as([*]const u8, @ptrCast(&root_cluster))[0..4]);
        // fs_info_sector (1)
        buf[48] = 1; buf[49] = 0;
        // backup_boot_sector (6)
        buf[50] = 6; buf[51] = 0;
        // reserved (12 bytes, already 0)

        // Drive number
        buf[64] = 0x80; // Hard disk
        // reserved1
        buf[65] = 0;
        // boot_sig (0x29 = extended boot signature)
        buf[66] = 0x29;
        // volume_id
        const vol_id: u32 = 0x504F4C45; // "POLE"
        @memcpy(buf[67..71], @as([*]const u8, @ptrCast(&vol_id))[0..4]);
        // volume_label
        const vol_label = "POLER-OS   ";
        @memcpy(buf[71..82], vol_label);
        // fs_type
        const fs_type = "FAT32   ";
        @memcpy(buf[82..90], fs_type);

        // Boot sector signature
        buf[510] = 0x55;
        buf[511] = 0xAA;

        virtio_blk.writeSectors(0, 1, buf[0..512]) catch {
            hal.Serial.puts("[FAT32 FORMAT] ERROR: Failed to write BPB\n");
            return false;
        };
        hal.Serial.puts("[FAT32 FORMAT] BPB written (sector 0)\n");

        // ── Step 2: Write backup BPB at sector 6 ──
        virtio_blk.writeSectors(6, 1, buf[0..512]) catch {
            hal.Serial.puts("[FAT32 FORMAT] WARNING: Failed to write backup BPB\n");
        };

        // ── Step 3: Write FSInfo sector at sector 1 ──
        @memset(buf[0..512], 0);
        // Lead signature
        const lead_sig: u32 = 0x41615252;
        @memcpy(buf[0..4], @as([*]const u8, @ptrCast(&lead_sig))[0..4]);
        // Reserved (480 bytes, already 0)
        // Struct signature
        const struct_sig: u32 = 0x61417272;
        @memcpy(buf[484..488], @as([*]const u8, @ptrCast(&struct_sig))[0..4]);
        // Free cluster count (0xFFFFFFFF = unknown)
        const free_count: u32 = 0xFFFFFFFF;
        @memcpy(buf[488..492], @as([*]const u8, @ptrCast(&free_count))[0..4]);
        // Next free cluster (hint: cluster 3)
        const next_free: u32 = 3;
        @memcpy(buf[492..496], @as([*]const u8, @ptrCast(&next_free))[0..4]);
        // Reserved (12 bytes, already 0)
        // Trail signature
        const trail_sig: u32 = 0xAA550000;
        @memcpy(buf[508..512], @as([*]const u8, @ptrCast(&trail_sig))[0..4]);

        virtio_blk.writeSectors(1, 1, buf[0..512]) catch {
            hal.Serial.puts("[FAT32 FORMAT] ERROR: Failed to write FSInfo\n");
            return false;
        };
        hal.Serial.puts("[FAT32 FORMAT] FSInfo written (sector 1)\n");

        // ── Step 4: Write backup FSInfo at sector 7 ──
        virtio_blk.writeSectors(7, 1, buf[0..512]) catch {};

        // ── Step 5: Zero out reserved sectors (2-5, 8-31) ──
        @memset(buf[0..512], 0);
        var res_sec: u64 = 2;
        while (res_sec < reserved_sectors) : (res_sec += 1) {
            if (res_sec == 6 or res_sec == 7) continue; // Already written
            virtio_blk.writeSectors(res_sec, 1, buf[0..512]) catch continue;
        }

        // ── Step 6: Initialize FAT tables ──
        // First FAT starts at sector 'reserved_sectors'
        // Second FAT starts at sector 'reserved_sectors + fat_size_32'
        @memset(buf[0..512], 0);

        // Entry 0: media_type in low byte + 0x0FFFFFF8
        // 0x0FFFFFF8 means: media byte 0xF8, end-of-chain marker
        const fat0: u32 = 0x0FFFFFF8;
        @memcpy(buf[0..4], @as([*]const u8, @ptrCast(&fat0))[0..4]);
        // Entry 1: end-of-chain marker
        const fat1: u32 = 0x0FFFFFFF;
        @memcpy(buf[4..8], @as([*]const u8, @ptrCast(&fat1))[0..4]);
        // Entry 2: root directory cluster — end-of-chain
        const fat2: u32 = 0x0FFFFFFF;
        @memcpy(buf[8..12], @as([*]const u8, @ptrCast(&fat2))[0..4]);
        // Entries 3+ are 0 (free)

        // Write first sector of each FAT copy
        var fat_num: u32 = 0;
        while (fat_num < num_fats) : (fat_num += 1) {
            const fat_start = @as(u64, reserved_sectors) + @as(u64, fat_num) * @as(u64, fat_size_32);
            virtio_blk.writeSectors(fat_start, 1, buf[0..512]) catch {
                hal.Serial.puts("[FAT32 FORMAT] ERROR: Failed to write FAT ");
                hal.Serial.putHex(fat_num);
                hal.Serial.puts("\n");
                return false;
            };

            // Zero out remaining FAT sectors
            @memset(buf[0..512], 0);
            var fat_sec: u64 = 1;
            while (fat_sec < fat_size_32) : (fat_sec += 1) {
                virtio_blk.writeSectors(fat_start + fat_sec, 1, buf[0..512]) catch continue;
            }

            // Re-write the first sector with FAT entries (buf was zeroed)
            @memset(buf[0..512], 0);
            @memcpy(buf[0..4], @as([*]const u8, @ptrCast(&fat0))[0..4]);
            @memcpy(buf[4..8], @as([*]const u8, @ptrCast(&fat1))[0..4]);
            @memcpy(buf[8..12], @as([*]const u8, @ptrCast(&fat2))[0..4]);
            virtio_blk.writeSectors(fat_start, 1, buf[0..512]) catch {};
        }
        hal.Serial.puts("[FAT32 FORMAT] FAT tables initialized\n");

        // ── Step 7: Zero out root directory cluster (cluster 2) ──
        @memset(buf[0..512], 0);
        const root_dir_sector = data_start; // Cluster 2 = first data sector
        var dir_sec: u64 = 0;
        while (dir_sec < spc) : (dir_sec += 1) {
            virtio_blk.writeSectors(root_dir_sector + dir_sec, 1, buf[0..512]) catch continue;
        }
        hal.Serial.puts("[FAT32 FORMAT] Root directory initialized (cluster 2)\n");

        hal.Serial.puts("[FAT32 FORMAT] Format complete!\n");
        hal.Serial.puts("[FAT32 FORMAT]   Volume: POLER-OS\n");
        hal.Serial.puts("[FAT32 FORMAT]   Cluster size: ");
        hal.Serial.putHex(cluster_size);
        hal.Serial.puts(" bytes\n");
        hal.Serial.puts("[FAT32 FORMAT]   Data clusters: ");
        hal.Serial.putHex(total_data_clusters);
        hal.Serial.puts("\n");

        return true;
    }
};

// ============================================================================
// Global Instance
// ============================================================================

var fat32_fs: ?Fat32Fs = null;

pub fn init() bool {
    // Try to mount existing FAT32 filesystem
    fat32_fs = Fat32Fs.init() orelse {
        hal.Serial.puts("[FAT32] No valid filesystem found\n");

        // Auto-format if virtio-blk is available and writable
        if (virtio_blk.isInitialized() and !virtio_blk.isReadOnly()) {
            const capacity = virtio_blk.getCapacityBytes();
            if (capacity > 0) {
                hal.Serial.puts("[FAT32] Auto-formatting device (");
                hal.Serial.putHex(@as(u32, @intCast(capacity)));
                hal.Serial.puts(" bytes)...\n");

                if (Fat32Fs.format(capacity)) {
                    hal.Serial.puts("[FAT32] Auto-format successful, mounting...\n");
                    fat32_fs = Fat32Fs.init() orelse {
                        hal.Serial.puts("[FAT32] ERROR: Mount failed after format\n");
                        return false;
                    };
                    return true;
                } else {
                    hal.Serial.puts("[FAT32] Auto-format failed\n");
                }
            }
        }

        return false;
    };
    return true;
}

pub fn getFs() ?*Fat32Fs {
    if (fat32_fs == null) return null;
    return &fat32_fs.?;
}
