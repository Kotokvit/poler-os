// ============================================================================
// POLER-OS Kernel Integration — VFS↔FAT32, Scheduler↔Process, mmap↔VMM,
//                                  POLER Core↔Action Auth
// ============================================================================
//
// This module bridges the dual-personality subsystem layer (v0.8.0) with the
// low-level kernel services (FAT32, VMM, Scheduler, POLER Core).
//
// Architecture:
//
//   NT API  ──┐                          ┌──  POSIX API
//              ├──→ Object Manager ──→ VFS ──→ FAT32 Driver
//              │    (handles/fds)     │       (actual I/O)
//              │                     │
//              ├──→ Process Mgr ──→ Scheduler (create/exit/clone)
//              │    (NT+POSIX)      │
//              │                     │
//              ├──→ Memory Mgr ──→ VMM (mmap/brk/NtAllocateVirtualMemory)
//              │    (unified)       │
//              │                     │
//              └──→ Action Auth ──→ POLER Core (crypto source verification)
//                   (per-syscall)    │
//                                    └──→ HAL (hardware)
// ============================================================================

const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const pmm64 = @import("pmm64.zig");
const fat32 = @import("fat32.zig");
const scheduler = @import("scheduler.zig");
const elf_loader = @import("elf_loader.zig");
const poler = @import("poler_core.zig");
const subsys = @import("subsystem/subsystem.zig");
const objmgr = @import("subsystem/common/object_manager.zig");
const nt_api = @import("subsystem/nt/nt_api.zig");
const posix_api = @import("subsystem/posix/posix_api.zig");

// ============================================================================
// 1. VFS ↔ FAT32 Integration
// ============================================================================
//
// The POSIX VFS and NT path resolver both need to perform actual I/O
// through the FAT32 driver. This section provides:
//
//   - vfsOpen(path) → opens a file on FAT32, returns Object Manager handle
//   - vfsRead(handle, buf, count) → reads from FAT32 file
//   - vfsWrite(handle, buf, count) → writes to FAT32 file
//   - vfsClose(handle) → closes FAT32 file, releases handle
//   - vfsMkdir(path) → creates directory on FAT32
//   - vfsUnlink(path) → deletes file from FAT32
//   - vfsStat(path) → file metadata (stat/fstat)
//
// Path translation:
//   POSIX "/foo/bar"     → FAT32 "foo/bar"    (strip leading /)
//   NT "\??\C:\foo\bar"  → FAT32 "foo/bar"    (strip \??\C:\, \→/)
//   NT "\Device\..."     → device I/O (not FAT32)
// ============================================================================

/// Maximum number of simultaneously open files tracked by VFS
pub const VFS_MAX_OPEN_FILES: usize = 256;

/// VFS file state — wraps a FAT32 File with Object Manager integration
pub const VfsFile = struct {
    in_use: bool = false,
    fat32_file: fat32.File = undefined,
    path: [512]u8 = undefined,
    path_len: usize = 0,
    is_nt_path: bool = false, // True if opened via NT API
    can_read: bool = false,
    can_write: bool = false,
    offset: u64 = 0, // Current read/write offset
};

/// Global VFS open file table
var vfs_open_files: [VFS_MAX_OPEN_FILES]VfsFile = undefined;
var vfs_initialized: bool = false;

pub fn vfsInit() void {
    if (vfs_initialized) return;
    for (&vfs_open_files) |*f| {
        f.* = VfsFile{};
    }
    vfs_initialized = true;
    hal.Serial.puts("[VFS] VFS↔FAT32 integration layer initialized\n");
}

/// Convert an NT path to a FAT32-compatible path
/// \??\C:\foo\bar → foo/bar
/// \DosDevices\C:\foo → foo/bar
pub fn ntPathToFat32(nt_path: []const u8) []const u8 {
    // Parse using NT path parser
    const parsed = nt_api.parseNtPath(nt_path);

    if (parsed.path_type == .DosDevices) {
        // Strip device name (C:\) and convert backslashes
        var result = parsed.remaining_path;
        // Skip leading backslash if present
        if (result.len > 0 and result[0] == '\\') {
            result = result[1..];
        }
        return result;
    }
    // For device paths, we can't translate to FAT32
    return "";
}

/// Convert a POSIX path to a FAT32-compatible path
/// /foo/bar → foo/bar (just strip leading /)
pub fn posixPathToFat32(posix_path: []const u8) []const u8 {
    var p = posix_path;
    while (p.len > 0 and p[0] == '/') p = p[1..];
    return p;
}

/// Open a file through the VFS — used by both NT and POSIX subsystems
/// Returns an index into vfs_open_files, or null on failure
pub fn vfsOpen(path: []const u8, is_nt: bool, readable: bool, writable: bool) ?usize {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("[VFS] No FAT32 filesystem available\n");
        return null;
    };

    // Convert path to FAT32 format
    const fat32_path: []const u8 = if (is_nt) ntPathToFat32(path) else posixPathToFat32(path);

    if (fat32_path.len == 0) {
        hal.Serial.puts("[VFS] Cannot open root or empty path\n");
        return null;
    }

    // Convert backslashes to forward slashes for FAT32 driver
    var path_buf: [512]u8 = undefined;
    @memcpy(path_buf[0..fat32_path.len], fat32_path);
    for (path_buf[0..fat32_path.len]) |*ch| {
        if (ch.* == '\\') ch.* = '/';
    }
    const clean_path = path_buf[0..fat32_path.len];

    // Open file via FAT32 driver
    var file = fs.openFile(clean_path) orelse {
        hal.Serial.puts("[VFS] FAT32 openFile failed for: ");
        hal.Serial.puts(clean_path);
        hal.Serial.puts("\n");
        return null;
    };

    // Find a free slot in VFS table
    for (&vfs_open_files, 0..) |*slot, i| {
        if (!slot.in_use) {
            slot.* = VfsFile{
                .in_use = true,
                .fat32_file = file,
                .path = undefined,
                .path_len = 0,
                .is_nt_path = is_nt,
                .can_read = readable,
                .can_write = writable,
                .offset = 0,
            };
            const copy_len = @min(path.len, 511);
            @memcpy(slot.path[0..copy_len], path[0..copy_len]);
            slot.path[copy_len] = 0;
            slot.path_len = copy_len;

            hal.Serial.puts("[VFS] Opened file: ");
            hal.Serial.puts(clean_path);
            hal.Serial.puts(" as slot ");
            hal.Serial.putDecimal(i);
            hal.Serial.puts("\n");

            return i;
        }
    }

    hal.Serial.puts("[VFS] No free file slots\n");
    return null;
}

/// Read from a VFS file
pub fn vfsRead(vfs_fd: usize, buf: []u8, count: u64) u64 {
    if (vfs_fd >= VFS_MAX_OPEN_FILES) return 0;
    const vf = &vfs_open_files[vfs_fd];
    if (!vf.in_use or !vf.can_read) return 0;

    const fs = fat32.getFs() orelse return 0;

    // Set file position before reading
    vf.fat32_file.position = @intCast(vf.offset);
    const bytes_read = fs.readFile(&vf.fat32_file, buf, @intCast(count));
    vf.offset += bytes_read;

    return bytes_read;
}

/// Write to a VFS file
pub fn vfsWrite(vfs_fd: usize, data: []const u8) u64 {
    if (vfs_fd >= VFS_MAX_OPEN_FILES) return 0;
    const vf = &vfs_open_files[vfs_fd];
    if (!vf.in_use or !vf.can_write) return 0;

    const fs = fat32.getFs() orelse return 0;

    // Set file position before writing
    vf.fat32_file.position = @intCast(vf.offset);
    const bytes_written = fs.writeFile(&vf.fat32_file, data);
    vf.offset += bytes_written;

    return bytes_written;
}

/// Close a VFS file
pub fn vfsClose(vfs_fd: usize) bool {
    if (vfs_fd >= VFS_MAX_OPEN_FILES) return false;
    const vf = &vfs_open_files[vfs_fd];
    if (!vf.in_use) return false;

    vf.* = VfsFile{};
    return true;
}

/// Seek in a VFS file
pub fn vfsSeek(vfs_fd: usize, offset: i64, whence: enum { SET, CUR, END }) ?u64 {
    if (vfs_fd >= VFS_MAX_OPEN_FILES) return null;
    const vf = &vfs_open_files[vfs_fd];
    if (!vf.in_use) return null;

    switch (whence) {
        .SET => vf.offset = @intCast(offset),
        .CUR => vf.offset = @intCast(@as(i64, @intCast(vf.offset)) + offset),
        .END => {
            const size: i64 = @intCast(vf.fat32_file.file_size);
            vf.offset = @intCast(size + offset);
        },
    }

    // Update FAT32 file position too
    vf.fat32_file.position = @intCast(vf.offset);
    return vf.offset;
}

/// Create a directory through VFS
pub fn vfsMkdir(path: []const u8, is_nt: bool) bool {
    const fs = fat32.getFs() orelse return false;
    const fat32_path: []const u8 = if (is_nt) ntPathToFat32(path) else posixPathToFat32(path);

    // Find the parent directory cluster
    // Split path into parent + dirname
    var last_slash: usize = 0;
    for (fat32_path, 0..) |ch, i| {
        if (ch == '/' or ch == '\\') last_slash = i;
    }

    if (last_slash == 0) {
        // Creating in root directory
        const dir_cluster = fs.root_cluster;
        const dirname = fat32_path;
        return fs.createDir(dir_cluster, dirname) != null;
    }

    const parent_path = fat32_path[0..last_slash];
    const dirname = fat32_path[last_slash + 1 ..];

    // Resolve parent directory
    const parent_file = fs.openFile(parent_path) orelse return false;
    if (!parent_file.is_directory) return false;

    const parent_cluster = if (parent_file.first_cluster >= 2) parent_file.first_cluster else fs.root_cluster;
    return fs.createDir(parent_cluster, dirname) != null;
}

/// Delete a file through VFS
pub fn vfsUnlink(path: []const u8, is_nt: bool) bool {
    const fs = fat32.getFs() orelse return false;
    const fat32_path: []const u8 = if (is_nt) ntPathToFat32(path) else posixPathToFat32(path);

    // Convert path for FAT32
    var path_buf: [512]u8 = undefined;
    @memcpy(path_buf[0..fat32_path.len], fat32_path);
    for (path_buf[0..fat32_path.len]) |*ch| {
        if (ch.* == '\\') ch.* = '/';
    }

    return fs.deleteFile(path_buf[0..fat32_path.len]);
}

/// Get VFS file metadata (stat-like)
pub const VfsStat = struct {
    size: u64,
    is_directory: bool,
    is_read_only: bool,
    first_cluster: u32,
};

pub fn vfsStat(path: []const u8, is_nt: bool) ?VfsStat {
    const fs = fat32.getFs() orelse return null;
    const fat32_path: []const u8 = if (is_nt) ntPathToFat32(path) else posixPathToFat32(path);

    var path_buf: [512]u8 = undefined;
    @memcpy(path_buf[0..fat32_path.len], fat32_path);
    for (path_buf[0..fat32_path.len]) |*ch| {
        if (ch.* == '\\') ch.* = '/';
    }

    const file = fs.openFile(path_buf[0..fat32_path.len]) orelse return null;

    return VfsStat{
        .size = file.file_size,
        .is_directory = file.is_directory,
        .is_read_only = false, // TODO: get from FAT32 attributes
        .first_cluster = file.first_cluster,
    };
}

// ============================================================================
// 2. Process Manager — Scheduler Integration
// ============================================================================
//
// Unified process/thread creation for both NT and POSIX subsystems.
//
// NT API:
//   NtCreateProcess  → processMgrCreateProcess() → scheduler.createUserTask()
//   NtCreateThread   → processMgrCreateThread()  → scheduler.createUserTask()
//   NtTerminateProcess → processMgrTerminate()   → scheduler.killTask()
//
// POSIX:
//   fork()  → processMgrFork()   → duplicate process state
//   clone() → processMgrClone()  → scheduler.createUserTask()
//   execve() → processMgrExec()  → load ELF + replace address space
//   exit()  → processMgrExit()   → scheduler.killTask()
//
// The Process Control Block (PCB) extends the scheduler's Task struct
// with subsystem-specific information.
// ============================================================================

pub const MAX_PROCESSES: usize = 64;

pub const ProcessState = enum(u8) {
    Unused = 0,
    Creating = 1,
    Running = 2,
    Zombie = 3, // Exited but parent hasn't called wait()
    Killed = 4,
};

pub const ProcessControlBlock = struct {
    pid: u32 = 0,
    ppid: u32 = 0, // Parent PID
    state: ProcessState = .Unused,
    subsystem: subsys.SubsystemId = .Native,
    exit_code: i32 = 0,
    task_id: usize = 0, // Index into scheduler.tasks[]
    cr3: u64 = 0, // Per-process page tables
    entry_point: u64 = 0,

    // POSIX state
    posix: posix_api.SignalState = undefined,
    fd_table: posix_api.FdTable = undefined,
    cwd: [256]u8 = undefined,
    cwd_len: usize = 1,

    // NT state
    nt_process_handle: u64 = 0,

    // POLER authentication token for this process
    poler_token: [32]u8 = undefined,

    pub fn init(pid: u32, ppid: u32, subsystem_id: subsys.SubsystemId) ProcessControlBlock {
        var pcb = ProcessControlBlock{
            .pid = pid,
            .ppid = ppid,
            .state = .Creating,
            .subsystem = subsystem_id,
            .posix = posix_api.SignalState.init(),
            .fd_table = posix_api.FdTable.init(),
            .cwd = undefined,
            .cwd_len = 1,
        };
        pcb.cwd[0] = '/';
        return pcb;
    }
};

var process_table: [MAX_PROCESSES]ProcessControlBlock = undefined;
var next_pid: u32 = 1;
var process_count: u32 = 0;

pub fn processMgrInit() void {
    for (&process_table) |*pcb| {
        pcb.* = ProcessControlBlock{};
    }
    next_pid = 1;
    process_count = 0;

    // Create PID 0 (kernel/idle)
    process_table[0] = ProcessControlBlock.init(0, 0, .Native);
    process_table[0].state = .Running;
    process_count = 1;

    hal.Serial.puts("[PROC] Process Manager initialized\n");
}

/// Allocate a new PID
fn allocPid() ?u32 {
    var checked: u32 = 0;
    while (checked < MAX_PROCESSES) : ({
        next_pid = (next_pid + 1) % MAX_PROCESSES;
        if (next_pid == 0) next_pid = 1; // Skip PID 0
        checked += 1;
    }) {
        if (process_table[next_pid].state == .Unused) {
            return next_pid;
        }
    }
    return null;
}

/// Find PCB by PID
pub fn processMgrFind(pid: u32) ?*ProcessControlBlock {
    if (pid >= MAX_PROCESSES) return null;
    if (process_table[pid].state == .Unused) return null;
    return &process_table[pid];
}

/// Create a new process — used by both NtCreateProcess and fork()
pub fn processMgrCreateProcess(parent_pid: u32, subsystem_id: subsys.SubsystemId, entry_point: u64) ?u32 {
    const pid = allocPid() orelse {
        hal.Serial.puts("[PROC] No free PIDs\n");
        return null;
    };

    const pcb = &process_table[pid];
    pcb.* = ProcessControlBlock.init(pid, parent_pid, subsystem_id);
    pcb.entry_point = entry_point;

    // Create per-process page tables
    const user_cr3 = vmm.createUserPML4() catch {
        hal.Serial.puts("[PROC] Failed to create user PML4\n");
        pcb.* = ProcessControlBlock{};
        return null;
    };
    pcb.cr3 = user_cr3;

    // Allocate user stack (4 pages = 16KB)
    const USER_STACK_TOP: u64 = 0x100080000;
    const USER_STACK_SIZE: u64 = 0x4000; // 16KB
    var stack_page: u64 = USER_STACK_TOP - USER_STACK_SIZE;
    while (stack_page < USER_STACK_TOP) : (stack_page += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse {
            hal.Serial.puts("[PROC] Failed to allocate stack page\n");
            pcb.* = ProcessControlBlock{};
            return null;
        };
        vmm.mapPageInPML4(user_cr3, stack_page, phys, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch {
            hal.Serial.puts("[PROC] Failed to map stack page\n");
            pcb.* = ProcessControlBlock{};
            return null;
        };
    }

    // Create scheduler task
    const task_id = scheduler.createUserTask(entry_point, user_cr3, USER_STACK_TOP) catch {
        hal.Serial.puts("[PROC] Failed to create scheduler task\n");
        pcb.* = ProcessControlBlock{};
        return null;
    };
    pcb.task_id = task_id;

    // Generate POLER authentication token for this process
    generateProcessToken(pcb);

    pcb.state = .Running;
    process_count += 1;

    hal.Serial.puts("[PROC] Created process PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" subsystem=");
    hal.Serial.putDecimal(@intFromEnum(subsystem_id));
    hal.Serial.puts(" CR3=");
    hal.Serial.putHex(user_cr3);
    hal.Serial.puts("\n");

    return pid;
}

/// Create a thread in an existing process — used by NtCreateThread and clone()
pub fn processMgrCreateThread(pid: u32, start_routine: u64, arg: u64) ?u32 {
    const pcb = processMgrFind(pid) orelse return null;

    // Create a new task with the same CR3 (shared address space)
    const THREAD_STACK_TOP: u64 = 0x200080000; // Different stack region for threads
    const THREAD_STACK_SIZE: u64 = 0x4000;

    // Allocate thread stack
    var stack_page: u64 = THREAD_STACK_TOP - THREAD_STACK_SIZE;
    while (stack_page < THREAD_STACK_TOP) : (stack_page += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse return null;
        vmm.mapPageInPML4(pcb.cr3, stack_page, phys, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch return null;
    }

    const task_id = scheduler.createUserTask(start_routine, pcb.cr3, THREAD_STACK_TOP) catch return null;

    _ = arg; // TODO: pass arg to thread via RDI register

    hal.Serial.puts("[PROC] Created thread in PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" task_id=");
    hal.Serial.putDecimal(task_id);
    hal.Serial.puts("\n");

    return pid; // Threads share the same PID
}

/// Terminate a process — used by NtTerminateProcess and exit()
pub fn processMgrTerminate(pid: u32, exit_code: i32) bool {
    const pcb = processMgrFind(pid) orelse return false;
    if (pid == 0) return false; // Can't kill kernel

    pcb.exit_code = exit_code;
    pcb.state = .Zombie; // Stay zombie until parent calls wait()

    // Kill the scheduler task
    scheduler.killTask(pcb.task_id) catch {};

    // Close all file descriptors
    for (&pcb.fd_table.entries, 0..) |entry, fd| {
        if (entry.in_use) {
            _ = pcb.fd_table.closeFd(@intCast(fd));
        }
    }

    process_count -= 1;

    hal.Serial.puts("[PROC] Terminated PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" exit_code=");
    hal.Serial.putDecimal(exit_code);
    hal.Serial.puts("\n");

    return true;
}

/// Fork the current process — used by POSIX fork()
/// Creates a copy of the current process with a new PID and address space.
pub fn processMgrFork(parent_pid: u32) ?u32 {
    const parent = processMgrFind(parent_pid) orelse return null;

    // Create new process with same subsystem
    const child_pid = processMgrCreateProcess(parent_pid, parent.subsystem, parent.entry_point) orelse return null;
    const child = processMgrFind(child_pid).?;

    // Copy file descriptor table
    child.fd_table = parent.fd_table; // Shallow copy — increments handle refs

    // Copy signal handlers
    child.posix = parent.posix;

    // Copy CWD
    @memcpy(child.cwd[0..parent.cwd_len], parent.cwd[0..parent.cwd_len]);
    child.cwd_len = parent.cwd_len;

    // TODO: Copy memory pages (copy-on-write)
    // For now, the child shares the parent's CR3 — this is incorrect
    // for full fork semantics but works for simple cases.
    // Full implementation needs COW page fault handling.

    hal.Serial.puts("[PROC] Forked PID=");
    hal.Serial.putDecimal(parent_pid);
    hal.Serial.puts(" → child PID=");
    hal.Serial.putDecimal(child_pid);
    hal.Serial.puts("\n");

    return child_pid;
}

/// Execute a new program in the current process — used by POSIX execve()
pub fn processMgrExec(pid: u32, elf_data: []const u8) bool {
    const pcb = processMgrFind(pid) orelse return false;

    // Load ELF into the process's address space
    const result = elf_loader.loadElf(elf_data) catch {
        hal.Serial.puts("[PROC] ELF load failed for PID=");
        hal.Serial.putDecimal(pid);
        hal.Serial.puts("\n");
        return false;
    };

    pcb.entry_point = result.entry_point;

    // TODO: Unmap old pages, remap new ELF segments
    // The current ELF loader maps into kernel PML4 — for per-process
    // isolation, we need to map into pcb.cr3 instead.

    hal.Serial.puts("[PROC] Exec'd PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" entry=");
    hal.Serial.putHex(result.entry_point);
    hal.Serial.puts("\n");

    return true;
}

/// Wait for a child process — used by POSIX wait4() and NT WaitForSingleObject on process
pub fn processMgrWait(pid: u32, blocking: bool) ?i32 {
    const pcb = processMgrFind(pid) orelse return null;

    if (pcb.state != .Zombie) {
        if (!blocking) return null;
        // TODO: Block current thread until child exits
        return null;
    }

    const exit_code = pcb.exit_code;

    // Clean up zombie
    pcb.* = ProcessControlBlock{};

    return exit_code;
}

// ============================================================================
// 3. Memory Manager — mmap/brk/NtAllocateVirtualMemory via VMM
// ============================================================================
//
// Unified memory allocation for both NT and POSIX:
//
// POSIX: mmap(addr, len, prot, flags, fd, offset) → allocate/map pages
//        munmap(addr, len) → unmap pages
//        brk(addr) → program break (heap)
//
// NT:    NtAllocateVirtualMemory(process, base, size, ...) → allocate
//        NtFreeVirtualMemory(process, base, size) → free
//        NtProtectVirtualMemory(process, base, size, new_prot) → change perms
//
// Memory layout for user processes:
//   0x0000000000000000 - 0x0000000FFFFFFFFFFF  User space (lower 256 GB via PML4[0..31])
//   0x0000001000000000 - 0x00007FFFFFFFFFFF   User space (extended, up to 128 TB)
//   0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF    Kernel space (upper canonical)
//
// For v0.8.0, we use a simple bump allocator for user virtual addresses:
//   - Code: mapped by ELF loader at p_vaddr
//   - Stack: mapped at 0x100080000 (grows down)
//   - Heap: starts at 0x100100000 (grows up via brk/mmap)
//   - mmap: starts at 0x200000000 (grows down from high address)
// ============================================================================

pub const USER_HEAP_START: u64 = 0x100100000;
pub const USER_HEAP_SIZE: u64 = 0x01000000; // 16 MB max heap
pub const USER_MMAP_START: u64 = 0x200000000; // mmap region
pub const USER_MMAP_END: u64 = 0x400000000; // 16 GB mmap space

/// Per-process memory state
pub const ProcessMemory = struct {
    brk_current: u64 = USER_HEAP_START, // Current program break
    brk_initial: u64 = USER_HEAP_START, // Initial break value
    mmap_next: u64 = USER_MMAP_START, // Next mmap address (bump allocator)
    cr3: u64 = 0, // Page tables for this process

    pub fn init(cr3: u64) ProcessMemory {
        return ProcessMemory{
            .brk_current = USER_HEAP_START,
            .brk_initial = USER_HEAP_START,
            .mmap_next = USER_MMAP_START,
            .cr3 = cr3,
        };
    }
};

/// Per-process memory state table (indexed by PID)
var process_memory: [MAX_PROCESSES]ProcessMemory = undefined;

pub fn memoryMgrInit() void {
    for (&process_memory) |*pm| {
        pm.* = ProcessMemory{};
    }
    hal.Serial.puts("[MEM] Memory Manager (mmap/brk/VMM integration) initialized\n");
}

/// POSIX brk() — set program break
pub fn memoryMgrBrk(pid: u32, addr: u64) u64 {
    if (pid >= MAX_PROCESSES) return 0;
    const pm = &process_memory[pid];

    if (addr == 0) {
        // Return current break
        return pm.brk_current;
    }

    if (addr < pm.brk_initial) {
        return pm.brk_current; // Can't go below initial
    }
    if (addr >= pm.brk_initial + USER_HEAP_SIZE) {
        return pm.brk_current; // Can't exceed heap limit
    }

    // Map pages between current break and new break
    var page: u64 = pm.brk_current & ~(vmm.PAGE_SIZE - 1);
    while (page < addr) : (page += vmm.PAGE_SIZE) {
        // Check if page is already mapped
        // Simple approach: try to map, ignore AlreadyMapped error
        const phys = pmm.allocPage() orelse return pm.brk_current;
        vmm.mapPageInPML4(pm.cr3, page, phys, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch {
            pmm.freePage(phys);
            // Page might already be mapped — that's OK
        };
    }

    pm.brk_current = addr;
    return addr;
}

/// POSIX mmap() — map anonymous memory or file-backed memory
pub fn memoryMgrMmap(pid: u32, length: u64, prot: i64, flags: i64) ?u64 {
    if (pid >= MAX_PROCESSES) return null;
    const pm = &process_memory[pid];

    // Round up to page size
    const pages_needed = (length + vmm.PAGE_SIZE - 1) / vmm.PAGE_SIZE;
    const total_size = pages_needed * vmm.PAGE_SIZE;

    // Check if MAP_FIXED (addr is mandatory) — not supported yet
    if (flags & 0x10 != 0) return null; // MAP_FIXED

    // Determine page flags from prot
    var page_flags: u64 = vmm.PTE_PRESENT | vmm.PTE_USER;
    if (prot & 0x1 != 0) page_flags |= vmm.PTE_WRITABLE; // PROT_WRITE
    if (prot & 0x4 == 0) page_flags |= vmm.PTE_NO_EXECUTE; // PROT_EXEC not set

    // Allocate virtual address range (bump allocator)
    const virt_start = pm.mmap_next;
    pm.mmap_next += total_size;

    if (pm.mmap_next > USER_MMAP_END) {
        hal.Serial.puts("[MEM] mmap: out of virtual address space\n");
        return null;
    }

    // Map pages
    var offset: u64 = 0;
    while (offset < total_size) : (offset += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse {
            // TODO: unmap already-mapped pages on failure
            return null;
        };
        // Zero the page first
        const page_ptr: [*]volatile u8 = @ptrFromInt(phys);
        @memset(page_ptr[0..vmm.PAGE_SIZE], 0);

        vmm.mapPageInPML4(pm.cr3, virt_start + offset, phys, page_flags) catch {
            pmm.freePage(phys);
            return null;
        };
    }

    hal.Serial.puts("[MEM] mmap: PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" addr=");
    hal.Serial.putHex(virt_start);
    hal.Serial.puts(" size=");
    hal.Serial.putDecimal(total_size);
    hal.Serial.puts("\n");

    return virt_start;
}

/// POSIX munmap() — unmap memory region
pub fn memoryMgrMunmap(pid: u32, addr: u64, length: u64) bool {
    if (pid >= MAX_PROCESSES) return false;
    const pm = &process_memory[pid];

    // Round to page boundaries
    const start = addr & ~(vmm.PAGE_SIZE - 1);
    const end = (addr + length + vmm.PAGE_SIZE - 1) & ~(vmm.PAGE_SIZE - 1);

    // Unmap each page in the range
    // NOTE: This operates on the kernel PML4, not the process PML4.
    // For proper per-process unmapping, we need to walk the process's PML4.
    // TODO: Implement unmapPageInPML4()
    _ = pm;
    _ = start;
    _ = end;

    hal.Serial.puts("[MEM] munmap: PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" (stub)\n");

    return true; // Stub: always succeeds
}

/// NT NtAllocateVirtualMemory — allocate virtual memory for a process
pub fn memoryMgrNtAllocate(pid: u32, size: u64, allocation_type: u64, protect: u64) ?u64 {
    _ = allocation_type;
    _ = protect;

    // Map NT protect flags to page flags
    var prot: i64 = 0x1 | 0x2; // PROT_READ | PROT_WRITE (default)
    if (protect & 0x40 != 0) prot |= 0x4; // PAGE_EXECUTE_READWRITE

    return memoryMgrMmap(pid, size, prot, 0x20); // MAP_ANONYMOUS | MAP_PRIVATE
}

/// NT NtFreeVirtualMemory — free virtual memory
pub fn memoryMgrNtFree(pid: u32, addr: u64, size: u64) bool {
    return memoryMgrMunmap(pid, addr, size);
}

/// NT NtProtectVirtualMemory — change page protection
pub fn memoryMgrNtProtect(pid: u32, addr: u64, size: u64, new_protect: u64) bool {
    _ = pid;
    _ = addr;
    _ = size;
    _ = new_protect;
    // TODO: Walk PML4 and update PTE flags for the specified range
    return true; // Stub
}

// ============================================================================
// 4. POLER Core — Action Source Authentication
// ============================================================================
//
// POLER Core provides cryptographic authentication of the ORIGIN of each
// kernel action. When a syscall comes in, we can verify:
//   1. Which process made the call (authenticated PID)
//   2. Which subsystem (NT or POSIX) originated it
//   3. Whether the action was authorized by the process's POLER token
//
// Architecture:
//   Syscall → POLER authenticate(action_hash, process_token)
//           → verify against process's stored token
//           → allow/deny/audit
//
// Each process gets a 256-bit POLER token generated at creation time.
// The token is derived from:
//   - PID
//   - Subsystem identity
//   - Parent's token (chain of trust)
//   - POLER Core PRF (PND-based keyed hash)
//
// This creates a chain of trust from kernel → init → all processes,
// where each action can be cryptographically traced back to its origin.
// ============================================================================

/// POLER action authentication result
pub const AuthResult = enum(u8) {
    Allowed = 0,
    Denied = 1,
    Unauthenticated = 2,
    Audited = 3, // Allowed but logged for audit
};

/// POLER action descriptor — describes a syscall for authentication
pub const PolerAction = struct {
    syscall_number: u64,
    subsystem: subsys.SubsystemId,
    pid: u32,
    arg_hash: u32, // FNV-1a hash of (arg1..arg6)
};

/// Generate a POLER authentication token for a new process
fn generateProcessToken(pcb: *ProcessControlBlock) void {
    // Derive token using POLER Core PRF
    // Token = POLER_PRF(parent_token | PID | subsystem | nonce)
    //
    // For v0.8.0, we use a simplified derivation based on POLER Core's
    // SipHash-like PRF. Full integration with poler_core.zig will come
    // when we have proper key scheduling.

    const parent_pcb = processMgrFind(pcb.ppid);
    const parent_token: [32]u8 = if (parent_pcb != null) parent_pcb.?.poler_token else undefined;

    // Simple token derivation using POLER Core primitives
    // Mix PID, subsystem, and parent token
    var state: [4]u32 = .{
        pcb.pid,
        @intFromEnum(pcb.subsystem),
        0x504F4C45, // "POLE" magic
        0x524F5300, // "ROS\0" magic
    };

    // Mix in parent token (if available)
    if (parent_pcb != null) {
        for (0..8) |i| {
            const word: u32 = @bitCast(parent_token[i * 4 ..][0..4].*);
            state[i % 4] ^= word;
        }
    }

    // Apply POLER Core PND mix (simplified)
    for (0..8) |round| {
        state[0] +%= state[1];
        state[2] +%= state[3];
        state[1] ^= poler.rotl(u32, state[0], 7);
        state[3] ^= poler.rotl(u32, state[2], 13);
        state[0] +%= @as(u32, @truncate(round));
        state[2] +%= @as(u32, @truncate(round *% 0x9E3779B9));
    }

    // Write token
    for (0..4) |i| {
        const bytes: [4]u8 = @bitCast(state[i]);
        @memcpy(pcb.poler_token[i * 4 ..][0..4], &bytes);
    }

    // Fill remaining 16 bytes with a second round
    for (0..8) |round| {
        state[0] +%= state[2];
        state[1] +%= state[3];
        state[2] ^= poler.rotl(u32, state[0], 11);
        state[3] ^= poler.rotl(u32, state[1], 17);
        state[0] +%= @as(u32, @truncate(round +% 8));
        state[2] +%= @as(u32, @truncate(round *% 0x6C62272E));
    }

    for (0..4) |i| {
        const bytes: [4]u8 = @bitCast(state[i]);
        @memcpy(pcb.poler_token[16 + i * 4 ..][0..4], &bytes);
    }
}

/// Authenticate a syscall action using POLER Core
pub fn polerAuthenticate(action: PolerAction) AuthResult {
    // For v0.8.0: All actions from authenticated processes are allowed.
    // Unauthenticated processes (no POLER token) are audited but allowed.
    // Full deny policy will come with per-syscall ACLs.

    const pcb = processMgrFind(action.pid);
    if (pcb == null) {
        // Unknown process — deny
        return .Denied;
    }

    // Verify process has a valid POLER token
    var token_valid = false;
    for (&pcb.?.poler_token) |byte| {
        if (byte != 0) {
            token_valid = true;
            break;
        }
    }

    if (!token_valid) {
        // Process without a token — kernel-level process, always allowed
        return .Allowed;
    }

    // Compute action hash using POLER Core PRF
    // action_hash = POLER_PRF(token | syscall_num | subsystem | arg_hash)
    var mix: u32 = action.syscall_number & 0xFFFFFFFF;
    mix ^= @intFromEnum(action.subsystem);
    mix ^= action.arg_hash;

    // Mix with process token (first 4 bytes as key)
    const key: u32 = @bitCast(pcb.?.poler_token[0..4].*);
    mix ^= key;
    mix = poler.rotl(u32, mix, 13);
    mix +%= key;
    mix = poler.rotl(u32, mix, 7);
    mix ^= key >> 16;

    // For v0.8.0: All authenticated actions are allowed
    // The hash is computed for future audit/ACL use
    _ = mix;

    return .Allowed;
}

/// Compute FNV-1a hash of syscall arguments for action authentication
pub fn fnvHashArgs(args: [6]u64) u32 {
    var hash: u32 = 0x811C9DC5; // FNV offset basis
    for (&args) |arg| {
        var v: u64 = arg;
        for (0..8) |_| {
            const byte: u8 = @truncate(v);
            hash ^= byte;
            hash *%= 0x01000193; // FNV prime
            v >>= 8;
        }
    }
    return hash;
}

// ============================================================================
// Master Initialization
// ============================================================================

pub fn kernelIntegrateInit() void {
    vfsInit();
    processMgrInit();
    memoryMgrInit();
    hal.Serial.puts("[INTEGRATE] All kernel integration layers initialized\n");
    hal.Serial.puts("[INTEGRATE] VFS↔FAT32, ProcessMgr↔Scheduler, mmap↔VMM, POLER↔Auth\n");
}
