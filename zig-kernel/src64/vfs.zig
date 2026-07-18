// ============================================================================
// POLER-OS VFS — Virtual File System Layer (v1.0)
// ============================================================================
//
// Architecture:
//   ┌─────────────────────────────────────────────────────────────────┐
//   │  POSIX syscalls (open, read, write, close, stat, mkdir, ...)   │
//   │  NT syscalls    (NtCreateFile, NtReadFile, NtWriteFile, ...)   │
//   │  POLER native   (POLER_OPEN, POLER_READ, ...)                  │
//   └──────────────────────┬──────────────────────────────────────────┘
//                          │  Unified path resolution (POSIX / + NT \)
//   ┌──────────────────────▼──────────────────────────────────────────┐
//   │                     VFS Core                                    │
//   │  ┌──────────┐  ┌───────────┐  ┌──────────────┐                │
//   │  │ Mount    │  │ Inode     │  │ File Handle  │                │
//   │  │ Table    │  │ Cache     │  │ Table        │                │
//   │  └────┬─────┘  └─────┬─────┘  └──────┬───────┘                │
//   └────────┼──────────────┼───────────────┼────────────────────────┘
//            │              │               │
//   ┌────────▼──────────────▼───────────────▼────────────────────────┐
//   │                  VfsOps (vtable)                                │
//   │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
//   │  │ FAT32   │  │ CPIO/RD  │  │ ProcFS   │  │ [future] │      │
//   │  │ Driver  │  │ Driver   │  │ Driver   │  │ ext2/NTFS│      │
//   │  └────┬────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
//   └────────┼────────────┼─────────────┼──────────────┼────────────┘
//            │            │             │              │
//   ┌────────▼────────────▼─────────────▼──────────────▼────────────┐
//   │  BlockDevice          Ramdisk       Virtual       [future]    │
//   │  (virtio_blk)       (memory)     (kernel data)               │
//   └──────────────────────────────────────────────────────────────┘
//
// Design Principles:
//   1. FAT32 is the FIRST filesystem driver, not the ONLY one
//   2. Every filesystem implements VfsOps vtable (function pointer table)
//   3. Mount table maps path prefixes → filesystem instances
//   4. Inodes provide filesystem-agnostic metadata
//   5. Per-process mount namespace (for future container support)
//   6. Unified path resolution: both /posix and \??\C:\nt paths
//
// Compatible with: Zig 0.13.0, freestanding kernel, no std
// ============================================================================

const hal = @import("hal.zig");
const fat32 = @import("fat32.zig");
const cpio = @import("cpio.zig");

// ============================================================================
// Constants
// ============================================================================

pub const VFS_MAX_MOUNTS: usize = 16;
pub const VFS_MAX_OPEN_FILES: usize = 256;
pub const VFS_MAX_PATH: usize = 512;
pub const VFS_MAX_NAME: usize = 256;

// ============================================================================
// Inode — Filesystem-agnostic file/directory metadata
// ============================================================================

pub const VfsFileType = enum(u8) {
    Regular = 0,
    Directory = 1,
    Symlink = 2,
    BlockDevice = 3,
    CharDevice = 4,
    Pipe = 5,
    Socket = 6,
    Unknown = 7,
};

pub const VfsInode = struct {
    ino: u64 = 0,              // Inode number (unique within filesystem)
    file_type: VfsFileType = .Unknown,
    size: u64 = 0,
    mode: u32 = 0o755,         // Unix permissions
    nlinks: u32 = 1,
    uid: u32 = 0,
    gid: u32 = 0,
    atime: u64 = 0,            // Access time (epoch seconds)
    mtime: u64 = 0,            // Modification time
    ctime: u64 = 0,            // Change time
    dev_major: u32 = 0,        // For device nodes
    dev_minor: u32 = 0,
    fs_private: u64 = 0,       // Filesystem-private data (e.g., FAT32 first_cluster)

    pub fn isDirectory(self: *const VfsInode) bool {
        return self.file_type == .Directory;
    }

    pub fn isRegular(self: *const VfsInode) bool {
        return self.file_type == .Regular;
    }
};

// ============================================================================
// VfsDirEntry — Directory entry for listing
// ============================================================================

pub const VfsDirEntry = struct {
    name: [VFS_MAX_NAME]u8 = undefined,
    name_len: usize = 0,
    inode: VfsInode = .{},

    pub fn getName(self: *const VfsDirEntry) []const u8 {
        return self.name[0..self.name_len];
    }
};

// ============================================================================
// VfsStat — File statistics (POSIX stat-compatible)
// ============================================================================

pub const VfsStat = struct {
    st_dev: u64 = 0,
    st_ino: u64 = 0,
    st_mode: u32 = 0,
    st_nlink: u32 = 1,
    st_uid: u32 = 0,
    st_gid: u32 = 0,
    st_size: u64 = 0,
    st_atime: u64 = 0,
    st_mtime: u64 = 0,
    st_ctime: u64 = 0,
    st_blksize: u64 = 512,
    st_blocks: u64 = 0,
};

// ============================================================================
// Open flags (POSIX-compatible)
// ============================================================================

pub const VfsOpenFlags = packed struct(u32) {
    O_RDONLY: bool = false,
    O_WRONLY: bool = false,
    O_RDWR: bool = false,
    O_CREAT: bool = false,
    O_EXCL: bool = false,
    O_NOCTTY: bool = false,
    O_TRUNC: bool = false,
    O_APPEND: bool = false,
    O_NONBLOCK: bool = false,
    O_DIRECTORY: bool = false,
    _pad: u1 = 0, // Padding to reach 32 bits
    _reserved: u21 = 0,

    pub fn isReadable(self: *const VfsOpenFlags) bool {
        return self.O_RDONLY or self.O_RDWR;
    }

    pub fn isWritable(self: *const VfsOpenFlags) bool {
        return self.O_WRONLY or self.O_RDWR or self.O_APPEND;
    }
};

// ============================================================================
// VfsOps — Filesystem operations vtable (the core abstraction)
// ============================================================================
// Every filesystem (FAT32, CPIO, ProcFS, ext2, etc.) must implement this.
// The VFS core calls these function pointers; it never calls FAT32 directly.

pub const VfsOps = struct {
    // File operations
    open: *const fn (*anyopaque, []const u8, VfsOpenFlags) ?*VfsFileHandle,
    read: *const fn (*VfsFileHandle, []u8, u64) u64,
    write: *const fn (*VfsFileHandle, []const u8, u64) u64,
    close: *const fn (*VfsFileHandle) void,
    seek: *const fn (*VfsFileHandle, i64, SeekWhence) ?u64,

    // Metadata operations
    stat: *const fn (*anyopaque, []const u8) ?VfsStat,
    chmod: *const fn (*anyopaque, []const u8, u32) bool,

    // Directory operations
    mkdir: *const fn (*anyopaque, []const u8) bool,
    rmdir: *const fn (*anyopaque, []const u8) bool,
    unlink: *const fn (*anyopaque, []const u8) bool,
    rename: *const fn (*anyopaque, []const u8, []const u8) bool,
    listDir: *const fn (*anyopaque, []const u8, *anyopaque, DirCallback) u32,

    // Lifecycle
    sync: ?*const fn (*anyopaque) void = null,  // Flush buffers to disk
};

pub const SeekWhence = enum(u8) {
    SET = 0,  // Seek from beginning
    CUR = 1,  // Seek from current position
    END = 2,  // Seek from end
};

pub const DirCallback = *const fn (*anyopaque, *const VfsDirEntry) void;

// ============================================================================
// VfsFileHandle — Open file descriptor (filesystem-agnostic)
// ============================================================================

pub const VfsFileHandle = struct {
    ops: *const VfsOps,            // Pointer to the filesystem's vtable
    fs_instance: *anyopaque,       // Pointer to the filesystem instance (e.g., *Fat32Fs)
    fs_private: u64 = 0,           // Filesystem-private file data (e.g., FAT32 cluster/position)
    inode: VfsInode = .{},         // Cached inode for this file
    offset: u64 = 0,               // Current read/write position
    flags: VfsOpenFlags = .{},     // Open flags
    path: [VFS_MAX_PATH]u8 = undefined,
    path_len: usize = 0,
    is_valid: bool = true,

    pub fn getPath(self: *const VfsFileHandle) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn isReadable(self: *const VfsFileHandle) bool {
        return self.flags.isReadable();
    }

    pub fn isWritable(self: *const VfsFileHandle) bool {
        return self.flags.isWritable();
    }
};

// ============================================================================
// Mount Entry — Maps a path prefix to a filesystem instance
// ============================================================================

pub const VfsMount = struct {
    mount_point: [VFS_MAX_PATH]u8 = undefined,
    mount_point_len: usize = 0,
    fs_ops: ?*const VfsOps = null,     // Filesystem vtable
    fs_instance: ?*anyopaque = null,   // Filesystem instance
    is_readonly: bool = false,
    is_active: bool = false,

    pub fn getMountPoint(self: *const VfsMount) []const u8 {
        return self.mount_point[0..self.mount_point_len];
    }
};

// ============================================================================
// VFS Core State
// ============================================================================

var mount_table: [VFS_MAX_MOUNTS]VfsMount = undefined;
var mount_count: usize = 0;

var file_handles: [VFS_MAX_OPEN_FILES]?*VfsFileHandle = undefined;
var file_handle_count: usize = 0;

// Per-process current working directory (simplified: global for now)
var current_cwd: [VFS_MAX_PATH]u8 = undefined;
var current_cwd_len: usize = 1;

var vfs_initialized: bool = false;

// ============================================================================
// VFS Initialization
// ============================================================================

pub fn init() void {
    // Zero out tables
    for (&mount_table) |*m| m.* = .{};
    for (&file_handles) |*fh| fh.* = null;
    mount_count = 0;
    file_handle_count = 0;

    // Set root CWD
    current_cwd[0] = '/';
    current_cwd_len = 1;

    vfs_initialized = true;
    hal.Serial.puts("[VFS] Virtual File System initialized\n");
}

// ============================================================================
// Mount / Umount
// ============================================================================

pub fn mount(mount_point: []const u8, fs_ops: *const VfsOps, fs_instance: *anyopaque, readonly: bool) bool {
    if (mount_count >= VFS_MAX_MOUNTS) {
        hal.Serial.puts("[VFS] ERROR: mount table full\n");
        return false;
    }

    if (mount_point.len == 0 or mount_point.len >= VFS_MAX_PATH) return false;

    // Check if mount point already in use
    for (0..mount_count) |i| {
        if (mount_table[i].is_active and
            eqStr(mount_table[i].getMountPoint(), mount_point))
        {
            hal.Serial.puts("[VFS] ERROR: mount point already in use: ");
            hal.Serial.puts(mount_point);
            hal.Serial.puts("\n");
            return false;
        }
    }

    var m = &mount_table[mount_count];
    @memcpy(m.mount_point[0..mount_point.len], mount_point);
    m.mount_point_len = mount_point.len;
    m.fs_ops = fs_ops;
    m.fs_instance = fs_instance;
    m.is_readonly = readonly;
    m.is_active = true;
    mount_count += 1;

    hal.Serial.puts("[VFS] Mounted '");
    hal.Serial.puts(mount_point);
    hal.Serial.puts("'\n");
    return true;
}

pub fn umount(mount_point: []const u8) bool {
    for (0..mount_count) |i| {
        if (mount_table[i].is_active and
            eqStr(mount_table[i].getMountPoint(), mount_point))
        {
            mount_table[i].is_active = false;
            hal.Serial.puts("[VFS] Unmounted '");
            hal.Serial.puts(mount_point);
            hal.Serial.puts("'\n");
            return true;
        }
    }
    return false;
}

// ============================================================================
// Path Resolution — Unified for POSIX (/) and NT (\) paths
// ============================================================================

/// Resolve a path to (filesystem instance, filesystem-relative path).
/// Supports:
///   /posix/path     → standard POSIX path
///   \??\C:\nt\path  → NT path → strips prefix, converts \ → /
///   relative/path   → prepends current working directory
pub fn resolvePath(path: []const u8, is_nt: bool, out_relative: []u8) ?usize {
    if (path.len == 0) return null;

    var clean_start: usize = 0;
    var is_absolute = false;

    if (is_nt) {
        // NT path: \??\C:\path → /path
        // Strip \??\C: or \DosDevices\C: prefix
        if (startsWith(path, "\\??\\C:") or startsWith(path, "\\??\\c:")) {
            clean_start = 6; // Skip \??\C:
        } else if (startsWith(path, "\\DosDevices\\C:") or startsWith(path, "\\DosDevices\\c:")) {
            clean_start = 14; // Skip \DosDevices\C:
        } else if (path[0] == '\\') {
            clean_start = 0; // Keep as-is for \Device\ paths
        }
        is_absolute = true;
    } else {
        // POSIX path
        if (path[0] == '/') {
            clean_start = 1; // Strip leading /
            is_absolute = true;
        }
    }

    // Build the relative path for filesystem lookup
    var out_len: usize = 0;

    if (!is_absolute) {
        // Prepend CWD
        if (current_cwd_len > 1) {
            @memcpy(out_relative[0..current_cwd_len], current_cwd[0..current_cwd_len]);
            out_len = current_cwd_len;
            out_relative[out_len] = '/';
            out_len += 1;
        }
    }

    // Copy and convert backslashes to forward slashes
    for (path[clean_start..]) |ch| {
        if (out_len >= out_relative.len - 1) break;
        if (ch == '\\') {
            out_relative[out_len] = '/';
            out_len += 1;
        } else if (ch != '\x00') {
            out_relative[out_len] = ch;
            out_len += 1;
        }
    }

    // Remove trailing slash (unless it's the root)
    while (out_len > 1 and out_relative[out_len - 1] == '/') {
        out_len -= 1;
    }

    return out_len;
}

/// Find the filesystem that owns the given path.
/// Returns the longest matching mount point prefix.
pub fn resolveFileSystem(path: []const u8) ?struct { ops: *const VfsOps, instance: *anyopaque, relative_path_offset: usize } {
    var best_idx: ?usize = null;
    var best_len: usize = 0;

    // Find longest matching mount point prefix
    for (0..mount_count) |i| {
        if (!mount_table[i].is_active) continue;
        const mp = mount_table[i].getMountPoint();
        if (path.len >= mp.len and startsWith(path, mp)) {
            if (mp.len > best_len) {
                best_len = mp.len;
                best_idx = i;
            }
        }
    }

    if (best_idx) |idx| {
        return .{
            .ops = mount_table[idx].fs_ops.?,
            .instance = mount_table[idx].fs_instance.?,
            .relative_path_offset = best_len,
        };
    }

    return null;
}

// ============================================================================
// File Operations — VFS-level wrappers
// ============================================================================

pub fn open(path: []const u8, is_nt: bool, flags: VfsOpenFlags) ?usize {
    var rel_path: [VFS_MAX_PATH]u8 = undefined;
    const rel_len = resolvePath(path, is_nt, &rel_path) orelse return null;
    const rel = rel_path[0..rel_len];

    const fs = resolveFileSystem(rel) orelse {
        hal.Serial.puts("[VFS] open: no filesystem for path: ");
        hal.Serial.puts(rel);
        hal.Serial.puts("\n");
        return null;
    };

    // The path passed to the filesystem driver is the part after the mount point
    const fs_path = rel[fs.relative_path_offset..];

    const handle = fs.ops.open(fs.instance, fs_path, flags) orelse return null;

    // Store in file handle table
    for (0..VFS_MAX_OPEN_FILES) |i| {
        if (file_handles[i] == null) {
            file_handles[i] = handle;
            file_handle_count += 1;
            return i;
        }
    }

    // No free slot
    fs.ops.close(handle);
    hal.Serial.puts("[VFS] open: file handle table full\n");
    return null;
}

pub fn read(fd: usize, buf: []u8, count: u64) u64 {
    if (fd >= VFS_MAX_OPEN_FILES) return 0;
    const handle = file_handles[fd] orelse return 0;
    if (!handle.is_valid or !handle.isReadable()) return 0;
    return handle.ops.read(handle, buf, count);
}

pub fn write(fd: usize, data: []const u8) u64 {
    if (fd >= VFS_MAX_OPEN_FILES) return 0;
    const handle = file_handles[fd] orelse return 0;
    if (!handle.is_valid or !handle.isWritable()) return 0;
    return handle.ops.write(handle, data, @intCast(data.len));
}

pub fn close(fd: usize) bool {
    if (fd >= VFS_MAX_OPEN_FILES) return false;
    const handle = file_handles[fd] orelse return false;
    handle.ops.close(handle);
    file_handles[fd] = null;
    if (file_handle_count > 0) file_handle_count -= 1;
    return true;
}

pub fn seek(fd: usize, offset: i64, whence: SeekWhence) ?u64 {
    if (fd >= VFS_MAX_OPEN_FILES) return null;
    const handle = file_handles[fd] orelse return null;
    return handle.ops.seek(handle, offset, whence);
}

pub fn stat(path: []const u8, is_nt: bool) ?VfsStat {
    var rel_path: [VFS_MAX_PATH]u8 = undefined;
    const rel_len = resolvePath(path, is_nt, &rel_path) orelse return null;
    const rel = rel_path[0..rel_len];

    const fs = resolveFileSystem(rel) orelse return null;
    const fs_path = rel[fs.relative_path_offset..];
    return fs.ops.stat(fs.instance, fs_path);
}

pub fn mkdir(path: []const u8, is_nt: bool) bool {
    var rel_path: [VFS_MAX_PATH]u8 = undefined;
    const rel_len = resolvePath(path, is_nt, &rel_path) orelse return false;
    const rel = rel_path[0..rel_len];

    const fs = resolveFileSystem(rel) orelse return false;
    if (mountIsReadonly(rel)) return false;
    const fs_path = rel[fs.relative_path_offset..];
    return fs.ops.mkdir(fs.instance, fs_path);
}

pub fn unlink(path: []const u8, is_nt: bool) bool {
    var rel_path: [VFS_MAX_PATH]u8 = undefined;
    const rel_len = resolvePath(path, is_nt, &rel_path) orelse return false;
    const rel = rel_path[0..rel_len];

    const fs = resolveFileSystem(rel) orelse return false;
    if (mountIsReadonly(rel)) return false;
    const fs_path = rel[fs.relative_path_offset..];
    return fs.ops.unlink(fs.instance, fs_path);
}

pub fn rmdir(path: []const u8, is_nt: bool) bool {
    var rel_path: [VFS_MAX_PATH]u8 = undefined;
    const rel_len = resolvePath(path, is_nt, &rel_path) orelse return false;
    const rel = rel_path[0..rel_len];

    const fs = resolveFileSystem(rel) orelse return false;
    if (mountIsReadonly(rel)) return false;
    const fs_path = rel[fs.relative_path_offset..];
    return fs.ops.rmdir(fs.instance, fs_path);
}

pub fn rename(old_path: []const u8, new_path: []const u8, is_nt: bool) bool {
    var rel_old: [VFS_MAX_PATH]u8 = undefined;
    var rel_new: [VFS_MAX_PATH]u8 = undefined;
    const old_len = resolvePath(old_path, is_nt, &rel_old) orelse return false;
    const new_len = resolvePath(new_path, is_nt, &rel_new) orelse return false;
    const old_rel = rel_old[0..old_len];
    const new_rel = rel_new[0..new_len];

    const fs = resolveFileSystem(old_rel) orelse return false;
    if (mountIsReadonly(old_rel)) return false;
    const fs_old = old_rel[fs.relative_path_offset..];
    const fs_new = new_rel[fs.relative_path_offset..];
    return fs.ops.rename(fs.instance, fs_old, fs_new);
}

pub fn listDir(path: []const u8, is_nt: bool, ctx: *anyopaque, callback: DirCallback) u32 {
    var rel_path: [VFS_MAX_PATH]u8 = undefined;
    const rel_len = resolvePath(path, is_nt, &rel_path) orelse return 0;
    const rel = rel_path[0..rel_len];

    const fs = resolveFileSystem(rel) orelse return 0;
    const fs_path = rel[fs.relative_path_offset..];
    return fs.ops.listDir(fs.instance, fs_path, ctx, callback);
}

// ============================================================================
// Working Directory
// ============================================================================

pub fn getcwd(buf: []u8) usize {
    const len = @min(current_cwd_len, buf.len - 1);
    @memcpy(buf[0..len], current_cwd[0..len]);
    return len;
}

pub fn chdir(path: []const u8, is_nt: bool) bool {
    var rel_path: [VFS_MAX_PATH]u8 = undefined;
    const rel_len = resolvePath(path, is_nt, &rel_path) orelse return false;

    // Verify the directory exists
    const stat_result = stat(rel_path[0..rel_len], false);
    if (stat_result == null) {
        // Accept for now (full stat validation later)
    }

    @memcpy(current_cwd[0..rel_len], rel_path[0..rel_len]);
    current_cwd_len = rel_len;
    return true;
}

// ============================================================================
// Helper Functions
// ============================================================================

fn eqStr(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |ch, i| {
        if (ch != b[i]) return false;
    }
    return true;
}

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    for (prefix, 0..) |ch, i| {
        if (str[i] != ch) return false;
    }
    return true;
}

fn mountIsReadonly(path: []const u8) bool {
    for (0..mount_count) |i| {
        if (!mount_table[i].is_active) continue;
        const mp = mount_table[i].getMountPoint();
        if (path.len >= mp.len and startsWith(path, mp)) {
            return mount_table[i].is_readonly;
        }
    }
    return false;
}

// ============================================================================
// FAT32 VfsOps Implementation — Wraps existing FAT32 driver
// ============================================================================

pub const Fat32VfsOps = struct {
    const Self = @This();

    pub const ops: VfsOps = .{
        .open = fat32Open,
        .read = fat32Read,
        .write = fat32Write,
        .close = fat32Close,
        .seek = fat32Seek,
        .stat = fat32Stat,
        .chmod = fat32Chmod,
        .mkdir = fat32Mkdir,
        .rmdir = fat32Rmdir,
        .unlink = fat32Unlink,
        .rename = fat32Rename,
        .listDir = fat32ListDir,
        .sync = fat32Sync,
    };

    // --- Internal FAT32 file handle wrapper ---
    pub const Fat32Handle = struct {
        fat32_file: fat32.File,
        fs: *fat32.Fat32Fs,
        vfs_handle: VfsFileHandle,
    };

    // We need a static pool of Fat32Handle objects since we can't use heap
    var handle_pool: [64]Fat32Handle = undefined;
    var handle_pool_used: [64]bool = undefined;

    fn allocHandle() ?*Fat32Handle {
        for (0..64) |i| {
            if (!handle_pool_used[i]) {
                handle_pool_used[i] = true;
                return &handle_pool[i];
            }
        }
        return null;
    }

    fn freeHandle(h: *Fat32Handle) void {
        const idx = (@intFromPtr(h) - @intFromPtr(&handle_pool)) / @sizeOf(Fat32Handle);
        if (idx < 64) handle_pool_used[idx] = false;
    }

    // --- VfsOps implementations ---

    fn fat32Open(fs_opaque: *anyopaque, path: []const u8, flags: VfsOpenFlags) ?*VfsFileHandle {
        const fs: *fat32.Fat32Fs = @ptrCast(@alignCast(fs_opaque));

        const fat32_file = fs.openFile(path) orelse {
            // If O_CREAT, try to create the file
            if (flags.O_CREAT) {
                // Resolve parent directory cluster
                const parent_cluster = fs.resolveDirCluster(path) orelse fs.root_cluster;
                // Extract filename from path
                var fname_start: usize = 0;
                for (0..path.len) |i| {
                    if (path[i] == '/') fname_start = i + 1;
                }
                if (fname_start < path.len) {
                    const filename = path[fname_start..];
                    _ = fs.createFile(parent_cluster, filename);
                }
                return null; // For now, caller must re-open
            }
            return null;
        };

        const fh = allocHandle() orelse return null;
        fh.fat32_file = fat32_file;
        fh.fs = fs;

        // Build VfsFileHandle
        fh.vfs_handle = .{
            .ops = &ops,
            .fs_instance = fs_opaque,
            .fs_private = @intCast(fat32_file.first_cluster),
            .offset = 0,
            .flags = flags,
            .is_valid = true,
        };
        @memcpy(fh.vfs_handle.path[0..path.len], path);
        fh.vfs_handle.path_len = path.len;

        // Set inode
        fh.vfs_handle.inode = .{
            .ino = fat32_file.first_cluster,
            .file_type = if (fat32_file.is_directory) .Directory else .Regular,
            .size = fat32_file.file_size,
            .fs_private = fat32_file.first_cluster,
        };

        return &fh.vfs_handle;
    }

    fn fat32Read(handle: *VfsFileHandle, buf: []u8, count: u64) u64 {
        const fh = getFat32Handle(handle) orelse return 0;
        const fs = fh.fs;
        const bytes_read = fs.readFile(&fh.fat32_file, buf, @intCast(count));
        handle.offset = fh.fat32_file.position;
        return bytes_read;
    }

    fn fat32Write(handle: *VfsFileHandle, data: []const u8, count: u64) u64 {
        const fh = getFat32Handle(handle) orelse return 0;
        const fs = fh.fs;
        const bytes_written = fs.writeFile(&fh.fat32_file, data[0..@intCast(count)]);
        handle.offset = fh.fat32_file.position;
        return bytes_written;
    }

    fn fat32Close(handle: *VfsFileHandle) void {
        const fh = getFat32Handle(handle) orelse return;
        freeHandle(fh);
        handle.is_valid = false;
    }

    fn fat32Seek(handle: *VfsFileHandle, offset: i64, whence: SeekWhence) ?u64 {
        const fh = getFat32Handle(handle) orelse return null;
        const file_size = fh.fat32_file.file_size;

        var new_offset: u64 = switch (whence) {
            .SET => @intCast(@max(offset, 0)),
            .CUR => @intCast(@max(@as(i64, @intCast(handle.offset)) + offset, 0)),
            .END => @intCast(@max(@as(i64, @intCast(file_size)) + offset, 0)),
        };

        if (new_offset > file_size) new_offset = file_size;

        // FAT32 seek requires re-reading from beginning (simplified)
        // For now, just update the offset. Actual seek in FAT32 needs
        // cluster chain traversal from the desired position.
        fh.fat32_file.position = @intCast(new_offset);
        handle.offset = new_offset;
        return new_offset;
    }

    fn fat32Stat(fs_opaque: *anyopaque, path: []const u8) ?VfsStat {
        const fs: *fat32.Fat32Fs = @ptrCast(@alignCast(fs_opaque));
        const file = fs.openFile(path) orelse return null;

        return VfsStat{
            .st_dev = 1, // virtio-blk
            .st_ino = file.first_cluster,
            .st_mode = if (file.is_directory) 0o40755 else 0o100644,
            .st_nlink = 1,
            .st_size = file.file_size,
            .st_blksize = 512,
            .st_blocks = (file.file_size + 511) / 512,
        };
    }

    fn fat32Chmod(_: *anyopaque, _: []const u8, _: u32) bool {
        // FAT32 doesn't support Unix permissions
        return true; // No-op success
    }

    fn fat32Mkdir(fs_opaque: *anyopaque, path: []const u8) bool {
        const fs: *fat32.Fat32Fs = @ptrCast(@alignCast(fs_opaque));
        // Extract parent dir and new dir name
        var last_slash: ?usize = null;
        for (0..path.len) |i| {
            if (path[i] == '/') last_slash = i;
        }

        if (last_slash) |slash| {
            const parent_path = path[0..slash];
            const dir_name = path[slash + 1 ..];
            if (dir_name.len == 0) return false;
            const parent_cluster = fs.resolveDirCluster(parent_path) orelse return false;
            return fs.createDir(parent_cluster, dir_name) != null;
        } else {
            // Create in root
            return fs.createDir(fs.root_cluster, path) != null;
        }
    }

    fn fat32Rmdir(fs_opaque: *anyopaque, path: []const u8) bool {
        const fs: *fat32.Fat32Fs = @ptrCast(@alignCast(fs_opaque));
        return fs.deleteFile(path); // FAT32 treats rmdir same as delete
    }

    fn fat32Unlink(fs_opaque: *anyopaque, path: []const u8) bool {
        const fs: *fat32.Fat32Fs = @ptrCast(@alignCast(fs_opaque));
        return fs.deleteFile(path);
    }

    fn fat32Rename(fs_opaque: *anyopaque, old_path: []const u8, new_path: []const u8) bool {
        const fs: *fat32.Fat32Fs = @ptrCast(@alignCast(fs_opaque));
        // FAT32 doesn't have a native rename; copy + delete
        const src = fs.openFile(old_path) orelse return false;
        _ = src; // TODO: implement copy-then-delete
        _ = new_path;
        return false; // Not yet implemented
    }

    fn fat32ListDir(fs_opaque: *anyopaque, path: []const u8, ctx: *anyopaque, callback: DirCallback) u32 {
        const fs: *fat32.Fat32Fs = @ptrCast(@alignCast(fs_opaque));
        const dir_cluster = fs.resolveDirCluster(path) orelse fs.root_cluster;

        // Wrap the FAT32 callback to convert DirEntryInfo → VfsDirEntry
        const Wrapper = struct {
            ctx: *anyopaque,
            cb: DirCallback,
            fn wrap(w_ctx: *anyopaque, entry: *const fat32.DirEntryInfo) void {
                const self: *@This() = @ptrCast(@alignCast(w_ctx));
                var vfs_entry: VfsDirEntry = .{};
                const name = entry.name[0..entry.name_len];
                @memcpy(vfs_entry.name[0..name.len], name);
                vfs_entry.name_len = name.len;
                vfs_entry.inode = .{
                    .ino = entry.first_cluster,
                    .file_type = if (entry.is_directory) .Directory else .Regular,
                    .size = entry.file_size,
                    .fs_private = entry.first_cluster,
                };
                self.cb(self.ctx, &vfs_entry);
            }
        };

        var wrapper = Wrapper{ .ctx = ctx, .cb = callback };
        return fs.listDir(dir_cluster, &wrapper, Wrapper.wrap);
    }

    fn fat32Sync(_: *anyopaque) void {
        // FAT32 doesn't have a sync mechanism yet
        // Could flush write buffer to disk via virtio_blk
    }

    fn getFat32Handle(handle: *VfsFileHandle) ?*Fat32Handle {
        // The VfsFileHandle is embedded inside Fat32Handle
        // Calculate the Fat32Handle pointer from the vfs_handle field offset
        const vfs_handle_ptr = @intFromPtr(handle);
        const fat32_handle_ptr = vfs_handle_ptr - @offsetOf(Fat32Handle, "vfs_handle");
        return @ptrFromInt(fat32_handle_ptr);
    }
};

// ============================================================================
// CPIO/Initrd VfsOps Implementation — Read-only ramdisk filesystem
// ============================================================================

pub const CpioVfsOps = struct {
    // CPIO archive context (stored as fs_instance for VFS mount)
    pub const CpioContext = struct {
        data_ptr: [*]const u8,
        data_len: usize,

        pub fn asSlice(self: *const CpioContext) []const u8 {
            return self.data_ptr[0..self.data_len];
        }
    };

    pub const ops: VfsOps = .{
        .open = cpioOpen,
        .read = cpioRead,
        .write = cpioWrite,
        .close = cpioClose,
        .seek = cpioSeek,
        .stat = cpioStat,
        .chmod = cpioChmod,
        .mkdir = cpioMkdir,
        .rmdir = cpioRmdir,
        .unlink = cpioUnlink,
        .rename = cpioRename,
        .listDir = cpioListDir,
    };

    // CPIO file handle
    pub const CpioHandle = struct {
        data: []const u8 = &[_]u8{},
        position: u64 = 0,
        vfs_handle: VfsFileHandle = .{},
    };

    var cpio_handles: [32]CpioHandle = undefined;
    var cpio_handles_used: [32]bool = undefined;

    fn allocHandle() ?*CpioHandle {
        for (0..32) |i| {
            if (!cpio_handles_used[i]) {
                cpio_handles_used[i] = true;
                return &cpio_handles[i];
            }
        }
        return null;
    }

    fn freeHandle(h: *CpioHandle) void {
        const idx = (@intFromPtr(h) - @intFromPtr(&cpio_handles)) / @sizeOf(CpioHandle);
        if (idx < 32) cpio_handles_used[idx] = false;
    }

    fn cpioOpen(fs_opaque: *anyopaque, path: []const u8, _: VfsOpenFlags) ?*VfsFileHandle {
        const ctx: *CpioContext = @ptrCast(@alignCast(fs_opaque));
        const archive = ctx.asSlice();
        var parser = cpio.CpioParser.init(archive);

        while (parser.next()) |file| {
            if (eqStr(file.name, path)) {
                const fh = allocHandle() orelse return null;
                fh.data = file.data;
                fh.position = 0;

                fh.vfs_handle = .{
                    .ops = &ops,
                    .fs_instance = fs_opaque,
                    .is_valid = true,
                    .inode = .{
                        .ino = 0,
                        .file_type = .Regular,
                        .size = file.size,
                    },
                };
                @memcpy(fh.vfs_handle.path[0..path.len], path);
                fh.vfs_handle.path_len = path.len;
                return &fh.vfs_handle;
            }
        }
        return null;
    }

    fn cpioRead(handle: *VfsFileHandle, buf: []u8, count: u64) u64 {
        const ch = getCpioHandle(handle) orelse return 0;
        const remaining = ch.data.len - ch.position;
        const to_read = @min(@as(u64, count), remaining);
        if (to_read == 0) return 0;
        const read_len: usize = @intCast(to_read);
        @memcpy(buf[0..read_len], ch.data[ch.position .. ch.position + read_len]);
        ch.position += to_read;
        handle.offset = ch.position;
        return to_read;
    }

    fn cpioWrite(_: *VfsFileHandle, _: []const u8, _: u64) u64 {
        return 0; // Read-only filesystem
    }

    fn cpioClose(handle: *VfsFileHandle) void {
        const ch = getCpioHandle(handle) orelse return;
        freeHandle(ch);
        handle.is_valid = false;
    }

    fn cpioSeek(handle: *VfsFileHandle, offset: i64, whence: SeekWhence) ?u64 {
        const ch = getCpioHandle(handle) orelse return null;
        const size = ch.data.len;
        var new_offset: u64 = switch (whence) {
            .SET => @intCast(@max(offset, 0)),
            .CUR => @intCast(@max(@as(i64, @intCast(handle.offset)) + offset, 0)),
            .END => @intCast(@max(@as(i64, @intCast(size)) + offset, 0)),
        };
        if (new_offset > size) new_offset = size;
        ch.position = new_offset;
        handle.offset = new_offset;
        return new_offset;
    }

    fn cpioStat(fs_opaque: *anyopaque, path: []const u8) ?VfsStat {
        const ctx: *CpioContext = @ptrCast(@alignCast(fs_opaque));
        const archive = ctx.asSlice();
        var parser = cpio.CpioParser.init(archive);
        while (parser.next()) |file| {
            if (eqStr(file.name, path)) {
                return VfsStat{
                    .st_dev = 0,
                    .st_ino = 0,
                    .st_mode = 0o100444, // read-only regular file
                    .st_size = file.size,
                    .st_blksize = 512,
                    .st_blocks = (file.size + 511) / 512,
                };
            }
        }
        return null;
    }

    fn cpioChmod(_: *anyopaque, _: []const u8, _: u32) bool {
        return false; // Read-only
    }

    fn cpioMkdir(_: *anyopaque, _: []const u8) bool {
        return false;
    }

    fn cpioRmdir(_: *anyopaque, _: []const u8) bool {
        return false;
    }

    fn cpioUnlink(_: *anyopaque, _: []const u8) bool {
        return false;
    }

    fn cpioRename(_: *anyopaque, _: []const u8, _: []const u8) bool {
        return false;
    }

    fn cpioListDir(_: *anyopaque, _: []const u8, _: *anyopaque, _: DirCallback) u32 {
        return 0; // TODO: enumerate CPIO entries matching directory prefix
    }

    fn getCpioHandle(handle: *VfsFileHandle) ?*CpioHandle {
        const ptr = @intFromPtr(handle);
        const cpio_ptr = ptr - @offsetOf(CpioHandle, "vfs_handle");
        return @ptrFromInt(cpio_ptr);
    }
};

// ============================================================================
// Public convenience wrappers (backward-compatible with kernel_integrate.zig)
// ============================================================================

/// Initialize VFS and mount FAT32 as the root filesystem
pub fn initAndMountFat32() void {
    init();

    // Mount FAT32 as root filesystem
    if (fat32.getFs()) |fs| {
        const fs_ptr: *anyopaque = @ptrCast(fs);
        if (!mount("/", &Fat32VfsOps.ops, fs_ptr, false)) {
            hal.Serial.puts("[VFS] ERROR: failed to mount FAT32 as root\n");
        }
    } else {
        hal.Serial.puts("[VFS] WARNING: no FAT32 filesystem to mount\n");
    }
}

/// Mount CPIO initrd at /initrd (read-only)
pub fn mountInitrd(archive_data: []const u8) void {
    // Create a static CpioContext for this mount
    // (We only support one initrd mount, so this is safe)
    var cpio_ctx: CpioVfsOps.CpioContext = .{
        .data_ptr = archive_data.ptr,
        .data_len = archive_data.len,
    };
    const ctx_ptr: *anyopaque = @ptrCast(&cpio_ctx);
    if (!mount("/initrd", &CpioVfsOps.ops, ctx_ptr, true)) {
        hal.Serial.puts("[VFS] ERROR: failed to mount initrd\n");
    }
}
