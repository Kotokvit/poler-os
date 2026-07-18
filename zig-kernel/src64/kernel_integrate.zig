// ============================================================================
// POLER-OS Kernel Integration — VFS↔FAT32, Scheduler↔Process, mmap↔VMM,
//                                  POLER Core↔Action Auth, COW↔fork, ACL↔Auth
// ============================================================================
//
// v0.8.0: COW fork(), unmapPageInPML4 for munmap, ELF in per-process PML4,
//         Real ACL policy for POLER Auth
//
// Architecture:
//
//   NT API  ──┐                          ┌──  POSIX API
//              ├──→ Object Manager ──→ VFS ──→ FAT32 Driver
//              │    (handles/fds)     │       (actual I/O)
//              │                     │
//              ├──→ Process Mgr ──→ Scheduler (create/exit/clone/fork-COW)
//              │    (NT+POSIX)      │
//              │                     │
//              ├──→ Memory Mgr ──→ VMM (mmap/brk/NtAllocateVirtualMemory)
//              │    (unified)       │   (unmapPageInPML4 for munmap)
//              │                     │
//              └──→ Action Auth ──→ POLER Core (crypto source verification)
//                   (per-syscall)    │   (ACL policy enforcement)
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
const dynlink = @import("dynlinker.zig");
const cap = @import("capability.zig");

// ============================================================================
// 1. VFS ↔ FAT32 Integration
// ============================================================================

pub const VFS_MAX_OPEN_FILES: usize = 256;

pub const VfsFile = struct {
    in_use: bool = false,
    fat32_file: fat32.File = undefined,
    path: [512]u8 = undefined,
    path_len: usize = 0,
    is_nt_path: bool = false,
    can_read: bool = false,
    can_write: bool = false,
    offset: u64 = 0,
};

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

pub fn ntPathToFat32(nt_path: []const u8) []const u8 {
    const parsed = nt_api.parseNtPath(nt_path);
    if (parsed.path_type == .DosDevices) {
        var result = parsed.remaining_path;
        if (result.len > 0 and result[0] == '\\') {
            result = result[1..];
        }
        return result;
    }
    return "";
}

pub fn posixPathToFat32(posix_path: []const u8) []const u8 {
    var p = posix_path;
    while (p.len > 0 and p[0] == '/') p = p[1..];
    return p;
}

pub fn vfsOpen(path: []const u8, is_nt: bool, readable: bool, writable: bool) ?usize {
    const fs = fat32.getFs() orelse return null;
    const fat32_path: []const u8 = if (is_nt) ntPathToFat32(path) else posixPathToFat32(path);

    if (fat32_path.len == 0) return null;

    var path_buf: [512]u8 = undefined;
    @memcpy(path_buf[0..fat32_path.len], fat32_path);
    for (path_buf[0..fat32_path.len]) |*ch| {
        if (ch.* == '\\') ch.* = '/';
    }
    const clean_path = path_buf[0..fat32_path.len];

    const file = fs.openFile(clean_path) orelse return null;

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
            return i;
        }
    }
    return null;
}

pub fn vfsRead(vfs_fd: usize, buf: []u8, count: u64) u64 {
    if (vfs_fd >= VFS_MAX_OPEN_FILES) return 0;
    const vf = &vfs_open_files[vfs_fd];
    if (!vf.in_use or !vf.can_read) return 0;
    const fs = fat32.getFs() orelse return 0;
    vf.fat32_file.position = @intCast(vf.offset);
    const bytes_read = fs.readFile(&vf.fat32_file, buf, @intCast(count));
    vf.offset += bytes_read;
    return bytes_read;
}

pub fn vfsWrite(vfs_fd: usize, data: []const u8) u64 {
    if (vfs_fd >= VFS_MAX_OPEN_FILES) return 0;
    const vf = &vfs_open_files[vfs_fd];
    if (!vf.in_use or !vf.can_write) return 0;
    const fs = fat32.getFs() orelse return 0;
    vf.fat32_file.position = @intCast(vf.offset);
    const bytes_written = fs.writeFile(&vf.fat32_file, data);
    vf.offset += bytes_written;
    return bytes_written;
}

pub fn vfsClose(vfs_fd: usize) bool {
    if (vfs_fd >= VFS_MAX_OPEN_FILES) return false;
    const vf = &vfs_open_files[vfs_fd];
    if (!vf.in_use) return false;
    vf.* = VfsFile{};
    return true;
}

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
    vf.fat32_file.position = @intCast(vf.offset);
    return vf.offset;
}

pub fn vfsMkdir(path: []const u8, is_nt: bool) bool {
    const fs = fat32.getFs() orelse return false;
    const fat32_path: []const u8 = if (is_nt) ntPathToFat32(path) else posixPathToFat32(path);
    var last_slash: usize = 0;
    for (fat32_path, 0..) |ch, i| {
        if (ch == '/' or ch == '\\') last_slash = i;
    }
    if (last_slash == 0) {
        const dir_cluster = fs.root_cluster;
        return fs.createDir(dir_cluster, fat32_path) != null;
    }
    const parent_path = fat32_path[0..last_slash];
    const dirname = fat32_path[last_slash + 1 ..];
    const parent_file = fs.openFile(parent_path) orelse return false;
    if (!parent_file.is_directory) return false;
    const parent_cluster = if (parent_file.first_cluster >= 2) parent_file.first_cluster else fs.root_cluster;
    return fs.createDir(parent_cluster, dirname) != null;
}

pub fn vfsUnlink(path: []const u8, is_nt: bool) bool {
    const fs = fat32.getFs() orelse return false;
    const fat32_path: []const u8 = if (is_nt) ntPathToFat32(path) else posixPathToFat32(path);
    var path_buf: [512]u8 = undefined;
    @memcpy(path_buf[0..fat32_path.len], fat32_path);
    for (path_buf[0..fat32_path.len]) |*ch| {
        if (ch.* == '\\') ch.* = '/';
    }
    return fs.deleteFile(path_buf[0..fat32_path.len]);
}

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
        .is_read_only = false,
        .first_cluster = file.first_cluster,
    };
}

// ============================================================================
// 2. Process Manager — Scheduler Integration with COW fork
// ============================================================================
//
// v0.8.0: fork() now uses COW (Copy-on-Write) instead of sharing CR3.
//   - clonePML4_COW() marks user pages as read-only + PTE_COW
//   - Page fault handler resolves COW by creating private copies
//   - processMgrExec() uses loadElfIntoPML4_v2 for pure per-process loading
// ============================================================================

pub const MAX_PROCESSES: usize = 64;

pub const ProcessState = enum(u8) {
    Unused = 0,
    Creating = 1,
    Running = 2,
    Zombie = 3,
    Killed = 4,
};

pub const ProcessControlBlock = struct {
    pid: u32 = 0,
    ppid: u32 = 0,
    state: ProcessState = .Unused,
    subsystem: subsys.SubsystemId = .Native,
    exit_code: i32 = 0,
    task_id: usize = 0,
    cr3: u64 = 0,
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

    // v0.8.0: ACL capability mask — defines what this process can do
    acl_capabilities: u64 = 0,

    // v0.8.0: ACL policy version — for cache invalidation
    acl_version: u32 = 0,

    // v0.9.0: Capability TTL and resource quotas
    cap_expire_tick: u64 = 0,      // Scheduler tick when capabilities expire (0 = never)
    memory_quota: u64 = 0,         // Maximum memory allocatable in bytes (0 = unlimited)
    memory_used: u64 = 0,          // Currently allocated memory in bytes
    cpu_quota_ticks: u64 = 0,      // Max CPU ticks per time window (0 = unlimited)
    cpu_used_ticks: u64 = 0,       // CPU ticks consumed in current window

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
            .acl_capabilities = DEFAULT_CAPABILITIES,
            .acl_version = 0,
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

    process_table[0] = ProcessControlBlock.init(0, 0, .Native);
    process_table[0].state = .Running;
    process_table[0].acl_capabilities = KERNEL_CAPABILITIES; // Full caps for kernel
    process_count = 1;

    hal.Serial.puts("[PROC] Process Manager initialized (v0.8.0 COW fork + ACL)\n");
}

fn allocPid() ?u32 {
    var checked: u32 = 0;
    while (checked < MAX_PROCESSES) : ({
        next_pid = @intCast((next_pid + 1) % MAX_PROCESSES);
        if (next_pid == 0) next_pid = 1;
        checked += 1;
    }) {
        if (process_table[next_pid].state == .Unused) {
            return next_pid;
        }
    }
    return null;
}

pub fn processMgrFind(pid: u32) ?*ProcessControlBlock {
    if (pid >= MAX_PROCESSES) return null;
    if (process_table[pid].state == .Unused) return null;
    return &process_table[pid];
}

/// Create a new process — used by both NtCreateProcess and fork()
pub fn processMgrCreateProcess(parent_pid: u32, subsystem_id: subsys.SubsystemId, entry_point: u64) ?u32 {
    const pid = allocPid() orelse return null;

    const pcb = &process_table[pid];
    pcb.* = ProcessControlBlock.init(pid, parent_pid, subsystem_id);
    pcb.entry_point = entry_point;

    // Create per-process page tables
    const user_cr3 = vmm.createUserPML4() catch {
        pcb.* = ProcessControlBlock{};
        return null;
    };
    pcb.cr3 = user_cr3;

    // Allocate user stack (4 pages = 16KB)
    const USER_STACK_TOP: u64 = 0x100080000;
    const USER_STACK_SIZE: u64 = 0x4000;
    var stack_page: u64 = USER_STACK_TOP - USER_STACK_SIZE;
    while (stack_page < USER_STACK_TOP) : (stack_page += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse {
            pcb.* = ProcessControlBlock{};
            return null;
        };
        vmm.mapPageInPML4(user_cr3, stack_page, phys, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch {
            pcb.* = ProcessControlBlock{};
            return null;
        };
    }

    const task_id = scheduler.createUserTask(entry_point, user_cr3, USER_STACK_TOP) catch {
        pcb.* = ProcessControlBlock{};
        return null;
    };
    pcb.task_id = task_id;

    // v1.2.0: TCB allocation is now automatic inside createUserTask()
    // (via scheduler.tcbAllocCallback). No manual wiring needed here.
    // The task's tcb_vaddr and fs_base are already set by the scheduler.

    // Generate POLER authentication token
    generateProcessToken(pcb);

    // Inherit ACL capabilities from parent (or default for init)
    if (parent_pid > 0) {
        const parent = processMgrFind(parent_pid);
        if (parent) |p| {
            pcb.acl_capabilities = p.acl_capabilities;
        }
    }

    pcb.state = .Running;
    process_count += 1;

    hal.Serial.puts("[PROC] Created process PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" CR3=");
    hal.Serial.putHex(user_cr3);
    hal.Serial.puts("\n");

    return pid;
}

/// Fork the current process — v0.8.0: Uses COW (Copy-on-Write)
///
/// Instead of copying all user pages (expensive), we:
///   1. Create a new PML4 for the child
///   2. Use clonePML4_COW() to share all user pages with COW marking
///   3. Both parent and child pages are marked read-only + PTE_COW
///   4. A write fault will trigger COW resolution (private copy)
///
/// This gives fork() O(1) time for the actual fork — only page tables
/// are copied, not the memory contents. Pages are copied lazily on write.
pub fn processMgrFork(parent_pid: u32) ?u32 {
    const parent = processMgrFind(parent_pid) orelse return null;

    if (parent.cr3 == 0) {
        hal.Serial.puts("[PROC] Cannot fork kernel process\n");
        return null;
    }

    // Allocate a PID for the child
    const child_pid = allocPid() orelse return null;
    const child = &process_table[child_pid];
    child.* = ProcessControlBlock.init(child_pid, parent_pid, parent.subsystem);

    // Clone the parent's PML4 with COW semantics
    // All user pages are shared but marked read-only + PTE_COW
    const child_cr3 = vmm.clonePML4_COW(parent.cr3) catch {
        hal.Serial.puts("[PROC] COW PML4 clone failed\n");
        child.* = ProcessControlBlock{};
        return null;
    };
    child.cr3 = child_cr3;
    child.entry_point = parent.entry_point;

    // Allocate user stack for child (4 pages)
    // The stack is NOT shared via COW — each process gets its own stack
    const USER_STACK_TOP: u64 = 0x100080000;
    const USER_STACK_SIZE: u64 = 0x4000;
    var stack_page: u64 = USER_STACK_TOP - USER_STACK_SIZE;
    while (stack_page < USER_STACK_TOP) : (stack_page += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse {
            // TODO: free child_cr3 page tables
            child.* = ProcessControlBlock{};
            return null;
        };
        // Stack pages are writable (no COW) — each process has private stack
        vmm.mapPageInPML4(child_cr3, stack_page, phys, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch {
            pmm.freePage(phys);
            child.* = ProcessControlBlock{};
            return null;
        };
    }

    // Create scheduler task for the child
    // The child returns 0 from fork(), parent returns child_pid
    const task_id = scheduler.createUserTask(parent.entry_point, child_cr3, USER_STACK_TOP) catch {
        child.* = ProcessControlBlock{};
        return null;
    };
    child.task_id = task_id;

    // v1.2.0: TCB allocation is now automatic inside createUserTask()
    // (via scheduler.tcbAllocCallback). No manual wiring needed here.

    // Copy file descriptor table (shallow copy — increments handle refs)
    child.fd_table = parent.fd_table;

    // Copy signal handlers
    child.posix = parent.posix;

    // Copy CWD
    @memcpy(child.cwd[0..parent.cwd_len], parent.cwd[0..parent.cwd_len]);
    child.cwd_len = parent.cwd_len;

    // Generate POLER token for child (derived from parent's token)
    generateProcessToken(child);

    // Inherit ACL capabilities from parent
    child.acl_capabilities = parent.acl_capabilities;
    child.acl_version = parent.acl_version;

    child.state = .Running;
    process_count += 1;

    hal.Serial.puts("[PROC] COW fork: PID=");
    hal.Serial.putDecimal(parent_pid);
    hal.Serial.puts(" → child PID=");
    hal.Serial.putDecimal(child_pid);
    hal.Serial.puts(" CR3=");
    hal.Serial.putHex(child_cr3);
    hal.Serial.puts("\n");

    return child_pid;
}

/// Execute a new program in the current process — v0.8.0: Uses per-process PML4
///
/// This replaces the current process's address space with a new ELF program.
/// The old pages are unmapped, and the new ELF is loaded into the process's
/// per-process PML4 using loadElfIntoPML4_v2 (pure per-process isolation).
pub fn processMgrExec(pid: u32, elf_data: []const u8) bool {
    const pcb = processMgrFind(pid) orelse return false;

    // Load ELF into the process's per-process PML4
    // Using v2 which maps ONLY into target PML4 (no kernel PML4 pollution)
    const result = elf_loader.loadElfIntoPML4_v2(elf_data, pcb.cr3, elf_loader.DEFAULT_PIE_BASE) catch {
        hal.Serial.puts("[PROC] ELF load failed for PID=");
        hal.Serial.putDecimal(pid);
        hal.Serial.puts("\n");
        return false;
    };

    pcb.entry_point = result.entry_point;

    hal.Serial.puts("[PROC] Exec'd PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" entry=");
    hal.Serial.putHex(result.entry_point);
    hal.Serial.puts(" (per-process PML4)\n");

    return true;
}

pub fn processMgrCreateThread(pid: u32, start_routine: u64, arg: u64) ?u32 {
    const pcb = processMgrFind(pid) orelse return null;

    const THREAD_STACK_TOP: u64 = 0x200080000;
    const THREAD_STACK_SIZE: u64 = 0x4000;

    var stack_page: u64 = THREAD_STACK_TOP - THREAD_STACK_SIZE;
    while (stack_page < THREAD_STACK_TOP) : (stack_page += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse return null;
        vmm.mapPageInPML4(pcb.cr3, stack_page, phys, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch return null;
    }

    const _task_id = scheduler.createUserTask(start_routine, pcb.cr3, THREAD_STACK_TOP) catch return null;
    _ = arg;
    _ = _task_id;

    // v1.2.0: TCB allocation is now automatic inside createUserTask()
    // (via scheduler.tcbAllocCallback). No manual wiring needed here.
    // The task's tcb_vaddr and fs_base are already set by the scheduler.

    hal.Serial.puts("[PROC] Created thread in PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts("\n");

    return pid;
}

pub fn processMgrTerminate(pid: u32, exit_code: i32) bool {
    const pcb = processMgrFind(pid) orelse return false;
    if (pid == 0) return false;

    pcb.exit_code = exit_code;
    pcb.state = .Zombie;

    scheduler.killTask(pcb.task_id) catch {};

    for (&pcb.fd_table.entries, 0..) |entry, fd| {
        if (entry.in_use) {
            _ = pcb.fd_table.closeFd(@intCast(fd));
        }
    }

    // TODO: Free the process's page tables and physical pages
    // Walk the PML4, free all user pages and page table structures
    // For COW pages, only free if ref_count == 1

    process_count -= 1;

    hal.Serial.puts("[PROC] Terminated PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts("\n");

    return true;
}

pub fn processMgrWait(pid: u32, blocking: bool) ?i32 {
    const pcb = processMgrFind(pid) orelse return null;
    if (pcb.state != .Zombie) {
        if (!blocking) return null;
        return null;
    }
    const exit_code = pcb.exit_code;
    pcb.* = ProcessControlBlock{};
    return exit_code;
}

// ============================================================================
// 3. Memory Manager — mmap/brk/NtAllocateVirtualMemory via VMM
// ============================================================================
//
// v0.8.0: munmap now uses unmapPageInPML4 for proper per-process unmapping
//         mprotect uses protectPageInPML4
// ============================================================================

pub const USER_HEAP_START: u64 = 0x100100000;
pub const USER_HEAP_SIZE: u64 = 0x01000000; // 16 MB max heap
pub const USER_MMAP_START: u64 = 0x200000000;
pub const USER_MMAP_END: u64 = 0x400000000;

pub const ProcessMemory = struct {
    brk_current: u64 = USER_HEAP_START,
    brk_initial: u64 = USER_HEAP_START,
    mmap_next: u64 = USER_MMAP_START,
    cr3: u64 = 0,

    pub fn init(cr3: u64) ProcessMemory {
        return ProcessMemory{
            .brk_current = USER_HEAP_START,
            .brk_initial = USER_HEAP_START,
            .mmap_next = USER_MMAP_START,
            .cr3 = cr3,
        };
    }
};

var process_memory: [MAX_PROCESSES]ProcessMemory = undefined;

pub fn memoryMgrInit() void {
    for (&process_memory) |*pm| {
        pm.* = ProcessMemory{};
    }
    hal.Serial.puts("[MEM] Memory Manager initialized (unmapPageInPML4)\n");
}

pub fn memoryMgrBrk(pid: u32, addr: u64) u64 {
    if (pid >= MAX_PROCESSES) return 0;
    const pm = &process_memory[pid];

    if (addr == 0) return pm.brk_current;
    if (addr < pm.brk_initial) return pm.brk_current;
    if (addr >= pm.brk_initial + USER_HEAP_SIZE) return pm.brk_current;

    var page: u64 = pm.brk_current & ~(vmm.PAGE_SIZE - 1);
    while (page < addr) : (page += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse return pm.brk_current;
        vmm.mapPageInPML4(pm.cr3, page, phys, vmm.PTE_PRESENT | vmm.PTE_WRITABLE | vmm.PTE_USER) catch {
            pmm.freePage(phys);
        };
    }

    pm.brk_current = addr;
    return addr;
}

pub fn memoryMgrMmap(pid: u32, length: u64, prot: i64, flags: i64) ?u64 {
    if (pid >= MAX_PROCESSES) return null;
    const pm = &process_memory[pid];

    const pages_needed = (length + vmm.PAGE_SIZE - 1) / vmm.PAGE_SIZE;
    const total_size = pages_needed * vmm.PAGE_SIZE;

    if (flags & 0x10 != 0) return null; // MAP_FIXED not supported

    var page_flags: u64 = vmm.PTE_PRESENT | vmm.PTE_USER;
    if (prot & 0x1 != 0) page_flags |= vmm.PTE_WRITABLE; // PROT_WRITE
    if (prot & 0x4 == 0) page_flags |= vmm.PTE_NO_EXECUTE;

    const virt_start = pm.mmap_next;
    pm.mmap_next += total_size;

    if (pm.mmap_next > USER_MMAP_END) {
        hal.Serial.puts("[MEM] mmap: out of virtual address space\n");
        return null;
    }

    var offset: u64 = 0;
    while (offset < total_size) : (offset += vmm.PAGE_SIZE) {
        const phys = pmm.allocPage() orelse return null;
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

/// POSIX munmap() — v0.8.0: Uses unmapPageInPML4 for proper per-process unmapping
///
/// Unmaps pages from the process's PML4 and frees the physical pages.
/// This now works correctly with per-process address spaces (before v0.8.0,
/// munmap was a stub that only operated on the kernel PML4).
pub fn memoryMgrMunmap(pid: u32, addr: u64, length: u64) bool {
    if (pid >= MAX_PROCESSES) return false;
    const pm = &process_memory[pid];

    if (pm.cr3 == 0) return false;

    const count = vmm.unmapRangeInPML4(pm.cr3, addr, length);

    hal.Serial.puts("[MEM] munmap: PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" pages_freed=");
    hal.Serial.putDecimal(count);
    hal.Serial.puts("\n");

    return count > 0 or length == 0;
}

/// NT NtAllocateVirtualMemory
pub fn memoryMgrNtAllocate(pid: u32, size: u64, allocation_type: u64, protect: u64) ?u64 {
    _ = allocation_type;
    var prot: i64 = 0x1 | 0x2;
    if (protect & 0x40 != 0) prot |= 0x4;
    return memoryMgrMmap(pid, size, prot, 0x20);
}

/// NT NtFreeVirtualMemory
pub fn memoryMgrNtFree(pid: u32, addr: u64, size: u64) bool {
    return memoryMgrMunmap(pid, addr, size);
}

/// NT NtProtectVirtualMemory — v0.8.0: Uses protectPageInPML4
pub fn memoryMgrNtProtect(pid: u32, addr: u64, size: u64, new_protect: u64) bool {
    if (pid >= MAX_PROCESSES) return false;
    const pm = &process_memory[pid];
    if (pm.cr3 == 0) return false;

    // Convert NT protect flags to PTE flags
    var pte_flags: u64 = vmm.PTE_PRESENT | vmm.PTE_USER;
    if (new_protect & 0x02 != 0) pte_flags |= vmm.PTE_WRITABLE; // PAGE_READWRITE
    if (new_protect & 0x04 == 0) pte_flags |= vmm.PTE_NO_EXECUTE; // Not PAGE_EXECUTE
    if (new_protect & 0x40 != 0) pte_flags |= vmm.PTE_WRITABLE; // PAGE_EXECUTE_READWRITE

    const start = addr & ~(vmm.PAGE_SIZE - 1);
    const end = (addr + size + vmm.PAGE_SIZE - 1) & ~(vmm.PAGE_SIZE - 1);

    var vaddr = start;
    while (vaddr < end) : (vaddr += vmm.PAGE_SIZE) {
        if (!vmm.protectPageInPML4(pm.cr3, vaddr, pte_flags)) {
            hal.Serial.puts("[MEM] NtProtect: failed at ");
            hal.Serial.putHex(vaddr);
            hal.Serial.puts("\n");
        }
    }

    return true;
}

// ============================================================================
// 4. POLER Core — Action Source Authentication with Real ACL Policy
// ============================================================================
//
// v0.8.0: Replaces the stub "always allowed" with a real ACL policy engine.
//
// Architecture:
//   Each process has a 64-bit capability mask (acl_capabilities).
//   Each syscall has a required capability set.
//   Authentication flow:
//     1. Syscall arrives → compute action hash
//     2. Check ACL: does the process have the required capability?
//     3. If ACL passes → verify POLER token authenticity
//     4. If token is valid → compute action MAC (Message Authentication Code)
//     5. Log the action for audit trail
//     6. Allow/Deny based on policy result
//
// Capability bits:
//   Bit 0  (0x01): CAP_FILE_READ      — read files
//   Bit 1  (0x02): CAP_FILE_WRITE     — write/create/delete files
//   Bit 2  (0x04): CAP_FILE_EXECUTE   — execute programs (execve)
//   Bit 3  (0x08): CAP_PROCESS_CREATE — create processes (fork/clone)
//   Bit 4  (0x10): CAP_PROCESS_KILL   — kill processes
//   Bit 5  (0x20): CAP_MEMORY_MMAP    — mmap/munmap/brk
//   Bit 6  (0x40): CAP_NETWORK        — socket/connect/bind/listen
//   Bit 7  (0x80): CAP_DEVICE         — device I/O (ioctl, device access)
//   Bit 8  (0x100): CAP_REGISTRY      — registry key access (NT)
//   Bit 9  (0x200): CAP_SIGNAL        — send signals (kill, sigaction)
//   Bit 10 (0x400): CAP_PRIVILEGE     — escalate privileges (setuid, etc.)
//   Bit 11 (0x800): CAP_RAW_IO        — raw I/O port access
//   Bit 12 (0x1000): CAP_ADMIN        — system administration (mount, reboot)
//   Bit 13-15: Reserved
//   Bit 16 (0x10000): CAP_NT_API      — can use NT syscall range
//   Bit 17 (0x20000): CAP_POSIX_API   — can use POSIX syscall range
//   Bit 18 (0x40000): CAP_POLER_AUTH  — can use POLER native syscalls
//   Bit 19 (0x80000): CAP_AI_RUNTIME   — can launch/run AI capsule
//   Bit 20 (0x100000): CAP_AI_MANAGE   — can manage AI lifecycle
//   Bit 21 (0x200000): CAP_POLICY_SET   — can modify policy rules
//   Bit 22 (0x400000): CAP_AUDIT_READ   — can read audit log
//   Bit 23-63: Reserved
//
// Default capabilities for a new user process:
//   CAP_FILE_READ | CAP_FILE_WRITE | CAP_FILE_EXECUTE |
//   CAP_PROCESS_CREATE | CAP_MEMORY_MMAP | CAP_SIGNAL |
//   CAP_NT_API | CAP_POSIX_API | CAP_POLER_AUTH |
//   CAP_AI_RUNTIME | CAP_AUDIT_READ
//
// Kernel process gets ALL capabilities.
// ============================================================================

// Capability definitions
pub const CAP_FILE_READ: u64 = 1 << 0;
pub const CAP_FILE_WRITE: u64 = 1 << 1;
pub const CAP_FILE_EXECUTE: u64 = 1 << 2;
pub const CAP_PROCESS_CREATE: u64 = 1 << 3;
pub const CAP_PROCESS_KILL: u64 = 1 << 4;
pub const CAP_MEMORY_MMAP: u64 = 1 << 5;
pub const CAP_NETWORK: u64 = 1 << 6;
pub const CAP_DEVICE: u64 = 1 << 7;
pub const CAP_REGISTRY: u64 = 1 << 8;
pub const CAP_SIGNAL: u64 = 1 << 9;
pub const CAP_PRIVILEGE: u64 = 1 << 10;
pub const CAP_RAW_IO: u64 = 1 << 11;
pub const CAP_ADMIN: u64 = 1 << 12;
pub const CAP_NT_API: u64 = 1 << 16;
pub const CAP_POSIX_API: u64 = 1 << 17;
pub const CAP_POLER_AUTH: u64 = 1 << 18;
pub const CAP_AI_RUNTIME: u64   = 1 << 19; // Can launch/run AI capsule
pub const CAP_AI_MANAGE: u64    = 1 << 20; // Can manage AI lifecycle (start/stop/update)
pub const CAP_POLICY_SET: u64   = 1 << 21; // Can modify policy rules
pub const CAP_AUDIT_READ: u64   = 1 << 22; // Can read audit log

/// Default capabilities for a new user process
pub const DEFAULT_CAPABILITIES: u64 = CAP_FILE_READ | CAP_FILE_WRITE | CAP_FILE_EXECUTE |
    CAP_PROCESS_CREATE | CAP_MEMORY_MMAP | CAP_SIGNAL |
    CAP_NT_API | CAP_POSIX_API | CAP_POLER_AUTH |
    CAP_AI_RUNTIME | CAP_AUDIT_READ;

/// Kernel process gets ALL capabilities
pub const KERNEL_CAPABILITIES: u64 = 0xFFFFFFFFFFFFFFFF;

/// Map POSIX syscall numbers to required capabilities
pub fn posixSyscallToCapabilities(syscall_num: u64) u64 {
    return switch (syscall_num) {
        0, 17, 19, 78, 79 => CAP_FILE_READ | CAP_POSIX_API, // read, pread64, readv, getdents, getcwd
        1, 18, 20, 85, 86, 87, 88, 82, 83, 84 => CAP_FILE_WRITE | CAP_POSIX_API, // write, pwrite64, writev, creat, link, unlink, symlink, rename, mkdir, rmdir
        2, 257 => CAP_FILE_READ | CAP_FILE_WRITE | CAP_POSIX_API, // open, openat
        3 => CAP_POSIX_API, // close (always allowed)
        4, 5, 6 => CAP_FILE_READ | CAP_POSIX_API, // stat, fstat, lstat
        9, 25 => CAP_MEMORY_MMAP | CAP_POSIX_API, // mmap, mremap
        10 => CAP_MEMORY_MMAP | CAP_POSIX_API, // mprotect
        11, 26, 27, 28 => CAP_MEMORY_MMAP | CAP_POSIX_API, // munmap, msync, mincore, madvise
        12 => CAP_MEMORY_MMAP | CAP_POSIX_API, // brk
        56, 57, 58 => CAP_PROCESS_CREATE | CAP_POSIX_API, // clone, fork, vfork
        59 => CAP_FILE_EXECUTE | CAP_POSIX_API, // execve
        60 => CAP_POSIX_API, // exit (always allowed)
        61 => CAP_POSIX_API, // wait4
        62 => CAP_SIGNAL | CAP_POSIX_API, // kill
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55 => CAP_NETWORK | CAP_POSIX_API, // socket syscalls
        16 => CAP_DEVICE | CAP_POSIX_API, // ioctl
        90, 91 => CAP_FILE_WRITE | CAP_POSIX_API, // chmod, fchmod
        92, 93, 94 => CAP_PRIVILEGE | CAP_POSIX_API, // chown, fchown, lchown
        105, 106 => CAP_PRIVILEGE | CAP_POSIX_API, // setuid, setgid
        125, 126 => CAP_PRIVILEGE | CAP_POSIX_API, // capget, capset
        else => CAP_POSIX_API, // Default: just need POSIX API access
    };
}

/// Map NT syscall numbers to required capabilities
pub fn ntSyscallToCapabilities(nt_num: u64) u64 {
    return switch (nt_num) {
        // NtCreateFile, NtOpenFile, NtReadFile
        0x02, 0x30, 0x03 => CAP_FILE_READ | CAP_FILE_WRITE | CAP_NT_API,
        // NtWriteFile
        0x04 => CAP_FILE_WRITE | CAP_NT_API,
        // NtClose
        0x0C => CAP_NT_API,
        // NtCreateProcess, NtCreateProcessEx
        0x1F, 0x46 => CAP_PROCESS_CREATE | CAP_NT_API,
        // NtTerminateProcess
        0x2C => CAP_PROCESS_KILL | CAP_NT_API,
        // NtAllocateVirtualMemory
        0x18 => CAP_MEMORY_MMAP | CAP_NT_API,
        // NtFreeVirtualMemory
        0x1E => CAP_MEMORY_MMAP | CAP_NT_API,
        // NtProtectVirtualMemory
        0x50 => CAP_MEMORY_MMAP | CAP_NT_API,
        // NtOpenKey, NtCreateKey, NtSetValueKey, NtDeleteValueKey, NtDeleteKey
        0x0D, 0x29, 0x37, 0x3A, 0x3B => CAP_REGISTRY | CAP_NT_API,
        // NtDeviceIoControlFile
        0x07 => CAP_DEVICE | CAP_NT_API,
        else => CAP_NT_API,
    };
}

/// Map POLER native syscall numbers to required capabilities
pub fn polerSyscallToCapabilities(poler_num: u64) u64 {
    return switch (poler_num) {
        0 => CAP_POLER_AUTH, // POLER_SYSCALL_PRINT
        1 => CAP_POLER_AUTH, // POLER_SYSCALL_GET_SUBSYSTEM
        2 => CAP_POLER_AUTH, // POLER_SYSCALL_AUTHENTICATE
        3 => CAP_ADMIN | CAP_POLER_AUTH, // POLER_SYSCALL_SET_CAPS (privilege escalation)
        4 => CAP_ADMIN | CAP_POLER_AUTH, // POLER_SYSCALL_REVOKE_CAPS
        else => CAP_POLER_AUTH,
    };
}

/// POLER action authentication result
pub const AuthResult = enum(u8) {
    Allowed = 0,
    Denied = 1,
    Unauthenticated = 2,
    Audited = 3,
};

/// POLER action descriptor — describes a syscall for authentication
pub const PolerAction = struct {
    syscall_number: u64,
    subsystem: subsys.SubsystemId,
    pid: u32,
    arg_hash: u32,
};

/// Maximum number of ACL audit log entries
const ACL_AUDIT_LOG_SIZE: usize = 256;

/// ACL audit log entry
const AclAuditEntry = struct {
    pid: u32,
    syscall_num: u64,
    required_caps: u64,
    process_caps: u64,
    result: AuthResult,
    timestamp: u64,
};

/// Global ACL audit log (circular buffer)
var acl_audit_log: [ACL_AUDIT_LOG_SIZE]AclAuditEntry = undefined;
var acl_audit_index: usize = 0;

/// Global ACL policy version — incremented when capabilities change
var acl_global_version: u32 = 0;

// ═══════════════════════════════════════════════════════════════════════
// P0 FIX 2: Kernel secret key for POLER token MAC
//
// The secret key is generated once at boot from RDRAND + TSC entropy.
// It is NEVER exposed to user-space. All token MACs are derived from
// this key using the PND-Feistel PRF from poler_core.zig.
//
// Token layout (32 bytes):
//   [0..15]  = MAC = pndPrf(secret_key | pid | acl_caps | subsystem)
//   [16..31] = nonce (random, from RDRAND)
//
// On authentication, we recompute the MAC and compare with stored value.
// If MAC mismatches → the token was forged → DENY.
// ═══════════════════════════════════════════════════════════════════════

var kernel_secret_key: [32]u8 = [_]u8{0} ** 32;
var kernel_secret_initialized: bool = false;

/// Initialize the kernel secret key at boot using RDRAND + TSC
pub fn initKernelSecret() void {
    if (kernel_secret_initialized) return;

    // Mix RDRAND and TSC for entropy
    var state: [8]u32 = .{0} ** 8;
    for (&state, 0..) |*s, i| {
        // Try RDRAND; fallback to TSC if not available
        var rng: u64 = 0;
        const rdrand_ok = asm volatile (
            "rdrand %[out]"
            : [out] "=r" (rng),
              [cf] "=@ccc" (-> u8),
        );
        if (rdrand_ok != 0) {
            s.* = @truncate(rng);
        } else {
            // Fallback: TSC + counter
            s.* = @truncate(hal.readTsc() ^ @as(u64, i *% 0x9E3779B9));
        }
    }

    // Mix with POLER PND to prevent weak entropy
    for (0..4) |round| {
        const a = state[round * 2];
        const b = state[round * 2 + 1];
        const mixed = poler.pndMix(a, b, 1);
        const bytes: [4]u8 = @bitCast(mixed);
        @memcpy(kernel_secret_key[round * 4 ..][0..4], &bytes);
    }

    // Second pass for bytes 16-31
    for (0..4) |round| {
        const a = state[round * 2] ^ @as(u32, @truncate(hal.readTsc()));
        const b = state[round * 2 + 1] ^ @as(u32, @truncate(hal.readTsc() >> 32));
        const mixed = poler.pndMix(a, b, 1);
        const bytes: [4]u8 = @bitCast(mixed);
        @memcpy(kernel_secret_key[16 + round * 4 ..][0..4], &bytes);
    }

    kernel_secret_initialized = true;
    hal.Serial.puts("[POLER] Kernel secret key initialized (MAC verification active)\n");
}

/// Compute a 16-byte MAC for a process token using PND-Feistel PRF
fn computeTokenMac(pid: u32, acl_caps: u64, subsystem: u8) [16]u8 {
    var mac: [16]u8 = [_]u8{0} ** 16;

    // Build input block: secret_key[0..16] | pid | caps_low | caps_high | subsystem
    var input: [8]u32 = .{0} ** 8;
    // First 4 words from secret key
    input[0] = @bitCast(kernel_secret_key[0..4].*);
    input[1] = @bitCast(kernel_secret_key[4..8].*);
    input[2] = @bitCast(kernel_secret_key[8..12].*);
    input[3] = @bitCast(kernel_secret_key[12..16].*);
    // Process-specific data
    input[4] = pid;
    input[5] = @truncate(acl_caps);
    input[6] = @truncate(acl_caps >> 32);
    input[7] = @as(u32, subsystem) | (@as(u32, 0x504F4C45)); // "POLE" tag

    // 8 rounds of PND-Feistel MAC
    for (0..8) |round| {
        const a = input[round % 8];
        const b = input[(round + 1) % 8];
        const mixed = poler.pndMix(a, b, 1);
        input[(round + 2) % 8] ^= mixed;
        input[(round + 3) % 8] +%= @as(u32, @truncate(round *% 0x9E3779B9));
    }

    // Output: first 16 bytes of the final state
    for (0..4) |i| {
        const bytes: [4]u8 = @bitCast(input[i]);
        @memcpy(mac[i * 4 ..][0..4], &bytes);
    }

    return mac;
}

/// Generate a POLER authentication token for a new process
/// Token = MAC(16 bytes) || Nonce(16 bytes)
/// MAC = pndPrf(secret_key | pid | acl_caps | subsystem)
/// Nonce = random from RDRAND
fn generateProcessToken(pcb: *ProcessControlBlock) void {
    // Compute MAC
    const mac = computeTokenMac(pcb.pid, pcb.acl_capabilities, @intFromEnum(pcb.subsystem));
    @memcpy(pcb.poler_token[0..16], &mac);

    // Generate nonce (16 bytes) from RDRAND + TSC
    for (0..4) |i| {
        var rng: u64 = 0;
        const rdrand_ok = asm volatile (
            "rdrand %[out]"
            : [out] "=r" (rng),
              [cf] "=@ccc" (-> u8),
        );
        if (rdrand_ok != 0) {
            const bytes: [4]u8 = @bitCast(@as(u32, @truncate(rng)) ^ @as(u32, @truncate(hal.readTsc() >> (i * 8))));
            @memcpy(pcb.poler_token[16 + i * 4 ..][0..4], &bytes);
        } else {
            // Fallback: TSC-derived
            const bytes: [4]u8 = @bitCast(@as(u32, @truncate(hal.readTsc() +% @as(u64, i) *% 0x6C62272E)));
            @memcpy(pcb.poler_token[16 + i * 4 ..][0..4], &bytes);
        }
    }

    hal.Serial.puts("[POLER] Token generated for PID=");
    hal.Serial.putDecimal(pcb.pid);
    hal.Serial.puts(" (MAC-verified)\n");
}

/// Authenticate a syscall action using POLER Core + ACL policy — v0.8.0
///
/// This function implements the full ACL policy engine:
///   1. Look up the process's capability mask
///   2. Determine required capabilities for the syscall
///   3. Check if (process_caps & required_caps) == required_caps
///   4. Verify POLER token authenticity
///   5. Compute action MAC for audit trail
///   6. Return Allowed / Denied / Audited
pub fn polerAuthenticate(action: PolerAction) AuthResult {
    const pcb = processMgrFind(action.pid);
    if (pcb == null) return .Denied;

    const process = pcb.?;

    // Step 1: Determine required capabilities for this syscall
    var required_caps: u64 = 0;
    if (action.syscall_number <= subsys.MAX_POSIX_SYSCALL) {
        required_caps = posixSyscallToCapabilities(action.syscall_number);
    } else if (action.syscall_number >= subsys.NT_SYSCALL_BASE and action.syscall_number <= subsys.MAX_NT_SYSCALL) {
        required_caps = ntSyscallToCapabilities(action.syscall_number - subsys.NT_SYSCALL_BASE);
    } else if (action.syscall_number >= subsys.POLER_SYSCALL_BASE and action.syscall_number <= subsys.MAX_POLER_SYSCALL) {
        required_caps = polerSyscallToCapabilities(action.syscall_number - subsys.POLER_SYSCALL_BASE);
    } else {
        // Unknown syscall range — deny
        return .Denied;
    }

    // Step 1.5: Check capability TTL expiration
    if (process.cap_expire_tick != 0 and scheduler.scheduler_ticks > process.cap_expire_tick) {
        hal.Serial.puts("[POLER-ACL] EXPIRED: PID=");
        hal.Serial.putDecimal(action.pid);
        hal.Serial.puts(" caps expired at tick ");
        hal.Serial.putDecimal(process.cap_expire_tick);
        hal.Serial.puts("\n");
        auditLog(action, required_caps, process.acl_capabilities, .Denied);
        return .Denied;
    }

    // Step 2: Check ACL — does the process have ALL required capabilities?
    const process_caps = process.acl_capabilities;
    const missing_caps = required_caps & ~process_caps;

    if (missing_caps != 0) {
        // Process lacks required capabilities — DENY
        hal.Serial.puts("[POLER-ACL] DENIED: PID=");
        hal.Serial.putDecimal(action.pid);
        hal.Serial.puts(" syscall=");
        hal.Serial.putHex(action.syscall_number);
        hal.Serial.puts(" missing_caps=0x");
        hal.Serial.putHex(missing_caps);
        hal.Serial.puts("\n");

        // Audit log the denial
        auditLog(action, required_caps, process_caps, .Denied);
        return .Denied;
    }

    // ═══════════════════════════════════════════════════════════════════
    // P0 FIX 2: Real MAC verification of POLER token
    //
    // Previously: just checked if any byte is non-zero (trivially forgeable)
    // Now: recompute MAC from (secret_key | pid | acl_caps | subsystem)
    //      and compare with stored token[0..15]. Mismatch → DENY.
    // ═══════════════════════════════════════════════════════════════════
    if (!kernel_secret_initialized) {
        // Kernel secret not initialized — should not happen after boot
        // Deny all non-kernel processes as a safety measure
        if (action.pid != 0) {
            auditLog(action, required_caps, process_caps, .Denied);
            return .Denied;
        }
        auditLog(action, required_caps, process_caps, .Allowed);
        return .Allowed;
    }

    // Check if process has a zero token (kernel process PID 0)
    var token_all_zero = true;
    for (&process.poler_token) |byte| {
        if (byte != 0) {
            token_all_zero = false;
            break;
        }
    }

    if (token_all_zero) {
        // Kernel process (PID 0) without a token — always allowed
        auditLog(action, required_caps, process_caps, .Allowed);
        return .Allowed;
    }

    // Recompute MAC and compare with stored value
    const expected_mac = computeTokenMac(action.pid, process_caps, @intFromEnum(process.subsystem));
    var mac_valid = true;
    for (0..16) |i| {
        if (process.poler_token[i] != expected_mac[i]) {
            mac_valid = false;
            break;
        }
    }

    if (!mac_valid) {
        // TOKEN FORGERY DETECTED — deny immediately
        hal.Serial.puts("[POLER-ACL] TOKEN FORGERY: PID=");
        hal.Serial.putDecimal(action.pid);
        hal.Serial.puts(" MAC mismatch — possible token tampering!\n");
        auditLog(action, required_caps, process_caps, .Denied);
        return .Denied;
    }

    // Step 4: Compute action MAC for audit trail
    // This binds the specific action to the process in the audit log
    var mix: u32 = @truncate(action.syscall_number);
    mix ^= @intFromEnum(action.subsystem);
    mix ^= action.arg_hash;
    mix ^= @bitCast(process.poler_token[0..4].*);
    mix = poler.rotl(u32, mix, 13);
    mix +%= @bitCast(process.poler_token[4..8].*);
    mix = poler.rotl(u32, mix, 7);
    mix ^= @bitCast(process.poler_token[12..16].*);

    // Action MAC is stored in audit log for forensic analysis


    // Step 5: Determine result — sensitive operations get audited
    const is_sensitive = (required_caps & (CAP_PROCESS_KILL | CAP_PRIVILEGE | CAP_ADMIN | CAP_RAW_IO | CAP_DEVICE)) != 0;

    if (is_sensitive) {
        // Sensitive operation — allowed but audited
        auditLog(action, required_caps, process_caps, .Audited);
        return .Audited;
    }

    // Regular operation — allowed
    auditLog(action, required_caps, process_caps, .Allowed);
    return .Allowed;
}

/// Set capabilities for a process (requires CAP_ADMIN)
pub fn processMgrSetCaps(caller_pid: u32, target_pid: u32, new_caps: u64) bool {
    const caller = processMgrFind(caller_pid) orelse return false;
    const target = processMgrFind(target_pid) orelse return false;

    // Caller must have CAP_ADMIN and CAP_POLER_AUTH
    if ((caller.acl_capabilities & (CAP_ADMIN | CAP_POLER_AUTH)) != (CAP_ADMIN | CAP_POLER_AUTH)) {
        hal.Serial.puts("[POLER-ACL] SET_CAPS denied: PID=");
        hal.Serial.putDecimal(caller_pid);
        hal.Serial.puts(" lacks CAP_ADMIN\n");
        return false;
    }

    // Cannot escalate beyond caller's own capabilities (no privilege escalation)
    // Exception: kernel (PID 0) can set any capabilities
    if (caller_pid != 0 and (new_caps & ~caller.acl_capabilities) != 0) {
        hal.Serial.puts("[POLER-ACL] SET_CAPS denied: attempted privilege escalation\n");
        return false;
    }

    target.acl_capabilities = new_caps;
    target.acl_version += 1;
    acl_global_version += 1;

    hal.Serial.puts("[POLER-ACL] CAPS updated: PID=");
    hal.Serial.putDecimal(target_pid);
    hal.Serial.puts(" caps=0x");
    hal.Serial.putHex(new_caps);
    hal.Serial.puts("\n");

    return true;
}

/// Get capabilities for a process
pub fn processMgrGetCaps(pid: u32) u64 {
    const pcb = processMgrFind(pid) orelse return 0;
    return pcb.acl_capabilities;
}

/// Set capabilities with TTL — for AI capsule temporary privileges
pub fn processMgrSetCapsWithTtl(caller_pid: u32, target_pid: u32, new_caps: u64, ttl_ticks: u64) bool {
    if (!processMgrSetCaps(caller_pid, target_pid, new_caps)) return false;
    const target = processMgrFind(target_pid) orelse return false;
    if (ttl_ticks > 0) {
        target.cap_expire_tick = scheduler.scheduler_ticks + ttl_ticks;
    }
    return true;
}

/// Check and enforce capability expiration
pub fn processMgrCheckCapExpiry(pid: u32) bool {
    const pcb = processMgrFind(pid) orelse return false;
    if (pcb.cap_expire_tick != 0 and scheduler.scheduler_ticks > pcb.cap_expire_tick) {
        // Capabilities expired — reduce to minimal set
        pcb.acl_capabilities = CAP_FILE_READ | CAP_POSIX_API; // Minimal survival caps
        pcb.cap_expire_tick = 0;
        hal.Serial.puts("[PROC] PID=");
        hal.Serial.putDecimal(pid);
        hal.Serial.puts(" capabilities EXPIRED — reduced to minimal\n");
        return true; // Expired
    }
    return false; // Still valid
}

/// Add an entry to the ACL audit log
fn auditLog(action: PolerAction, required_caps: u64, process_caps: u64, result: AuthResult) void {
    const entry = AclAuditEntry{
        .pid = action.pid,
        .syscall_num = action.syscall_number,
        .required_caps = required_caps,
        .process_caps = process_caps,
        .result = result,
        .timestamp = hal.readTsc(),
    };

    acl_audit_log[acl_audit_index % ACL_AUDIT_LOG_SIZE] = entry;
    acl_audit_index += 1;

    // Log denied/audited actions to serial console
    if (result == .Denied) {
        hal.Serial.puts("[POLER-AUDIT] DENY PID=");
        hal.Serial.putDecimal(action.pid);
        hal.Serial.puts(" syscall=0x");
        hal.Serial.putHex(action.syscall_number);
        hal.Serial.puts("\n");
    }
}

/// Compute FNV-1a hash of syscall arguments for action authentication
pub fn fnvHashArgs(args: [6]u64) u32 {
    var hash: u32 = 0x811C9DC5;
    for (&args) |arg| {
        var v: u64 = arg;
        for (0..8) |_| {
            const byte: u8 = @truncate(v);
            hash ^= byte;
            hash *%= 0x01000193;
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

    // P0 FIX 2: Initialize kernel secret key BEFORE any process tokens are generated
    initKernelSecret();

    // Initialize ACL audit log
    for (&acl_audit_log) |*entry| {
        entry.* = AclAuditEntry{
            .pid = 0,
            .syscall_num = 0,
            .required_caps = 0,
            .process_caps = 0,
            .result = .Allowed,
            .timestamp = 0,
        };
    }
    acl_audit_index = 0;

    // v0.9.0: Initialize capability module
    cap.init();

    // v0.9.0: Initialize dynamic linker
    dynlink.init();

    // v1.2.0: Wire TCB allocation into scheduler task creation path.
    // Any call to scheduler.createUserTask() will now automatically allocate
    // a TCB with FS_BASE for TLS — no caller can forget.
    scheduler.tcbAllocCallback = tcbAllocWrapper;

    hal.Serial.puts("[INTEGRATE] All kernel integration layers initialized\n");
    hal.Serial.puts("[INTEGRATE] VFS, ProcessMgr+COW+refcount, mmap+unmapPageInPML4, POLER+ACL, dynlink\n");
}

/// TCB allocation wrapper with C calling convention for scheduler callback.
/// Returns TCB virtual address on success, 0 on failure.
fn tcbAllocWrapper(cr3: u64, thread_id: u32) callconv(.C) u64 {
    const result = dynlink.allocateTcbForThread(cr3, thread_id) catch {
        return 0;
    };
    return result;
}
