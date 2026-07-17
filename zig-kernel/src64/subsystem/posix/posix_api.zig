// ============================================================================
// POLER-OS POSIX Subsystem — Native Linux/POSIX Compatibility
// ============================================================================
//
// This is NOT a Linux compatibility layer or an emulation. This is a native
// POSIX syscall implementation where Linux syscall numbers are first-class.
//
// Architecture overview:
//   User Mode:  libc → syscall instruction → kernel
//   Kernel:     POSIX dispatcher → Object Manager → HAL
//
// Key components:
//   - Linux-compatible syscall numbers (0-335 for x86_64)
//   - VFS (Virtual File System) with mount points
//   - Signal framework (POSIX signals)
//   - File descriptor table (shared with NT Handle Table)
//   - Process groups, sessions, controlling terminal
//   - poll/select/epoll stubs
//   - mmap/munmap → VMM integration
//
// The POSIX subsystem and NT subsystem share the same Object Manager,
// so a file opened via NtCreateFile can be accessed via POSIX read()
// if the process has both subsystem personalities.
// ============================================================================

const hal = @import("../../hal.zig");
const subsys = @import("../subsystem.zig");
const objmgr = @import("../common/object_manager.zig");

// ============================================================================
// POSIX Syscall Numbers — Linux x86_64 ABI
// ============================================================================
// Source: Linux kernel arch/x86/entry/syscalls/syscall_64.tbl
// Convention: RAX=syscall#, RDI=arg1, RSI=arg2, RDX=arg3, R10=arg4, R8=arg5, R9=arg6
// ============================================================================

pub const SYS_read: u64 = 0;
pub const SYS_write: u64 = 1;
pub const SYS_open: u64 = 2;
pub const SYS_close: u64 = 3;
pub const SYS_stat: u64 = 4;
pub const SYS_fstat: u64 = 5;
pub const SYS_lstat: u64 = 6;
pub const SYS_poll: u64 = 7;
pub const SYS_lseek: u64 = 8;
pub const SYS_mmap: u64 = 9;
pub const SYS_mprotect: u64 = 10;
pub const SYS_munmap: u64 = 11;
pub const SYS_brk: u64 = 12;
pub const SYS_rt_sigaction: u64 = 13;
pub const SYS_rt_sigprocmask: u64 = 14;
pub const SYS_rt_sigreturn: u64 = 15;
pub const SYS_ioctl: u64 = 16;
pub const SYS_pread64: u64 = 17;
pub const SYS_pwrite64: u64 = 18;
pub const SYS_readv: u64 = 19;
pub const SYS_writev: u64 = 20;
pub const SYS_access: u64 = 21;
pub const SYS_pipe: u64 = 22;
pub const SYS_select: u64 = 23;
pub const SYS_sched_yield: u64 = 24;
pub const SYS_mremap: u64 = 25;
pub const SYS_msync: u64 = 26;
pub const SYS_mincore: u64 = 27;
pub const SYS_madvise: u64 = 28;
pub const SYS_shmget: u64 = 29;
pub const SYS_shmat: u64 = 30;
pub const SYS_shmctl: u64 = 31;
pub const SYS_dup: u64 = 32;
pub const SYS_dup2: u64 = 33;
pub const SYS_pause: u64 = 34;
pub const SYS_nanosleep: u64 = 35;
pub const SYS_getitimer: u64 = 36;
pub const SYS_alarm: u64 = 37;
pub const SYS_setitimer: u64 = 38;
pub const SYS_getpid: u64 = 39;
pub const SYS_sendfile: u64 = 40;
pub const SYS_socket: u64 = 41;
pub const SYS_connect: u64 = 42;
pub const SYS_accept: u64 = 43;
pub const SYS_sendto: u64 = 44;
pub const SYS_recvfrom: u64 = 45;
pub const SYS_sendmsg: u64 = 46;
pub const SYS_recvmsg: u64 = 47;
pub const SYS_shutdown: u64 = 48;
pub const SYS_bind: u64 = 49;
pub const SYS_listen: u64 = 50;
pub const SYS_getsockname: u64 = 51;
pub const SYS_getpeername: u64 = 52;
pub const SYS_socketpair: u64 = 53;
pub const SYS_setsockopt: u64 = 54;
pub const SYS_getsockopt: u64 = 55;
pub const SYS_clone: u64 = 56;
pub const SYS_fork: u64 = 57;
pub const SYS_vfork: u64 = 58;
pub const SYS_execve: u64 = 59;
pub const SYS_exit: u64 = 60;
pub const SYS_wait4: u64 = 61;
pub const SYS_kill: u64 = 62;
pub const SYS_uname: u64 = 63;
pub const SYS_semget: u64 = 64;
pub const SYS_semop: u64 = 65;
pub const SYS_semctl: u64 = 66;
pub const SYS_shmdt: u64 = 67;
pub const SYS_msgget: u64 = 68;
pub const SYS_msgsnd: u64 = 69;
pub const SYS_msgrcv: u64 = 70;
pub const SYS_msgctl: u64 = 71;
pub const SYS_fcntl: u64 = 72;
pub const SYS_flock: u64 = 73;
pub const SYS_fsync: u64 = 74;
pub const SYS_fdatasync: u64 = 75;
pub const SYS_truncate: u64 = 76;
pub const SYS_ftruncate: u64 = 77;
pub const SYS_getdents: u64 = 78;
pub const SYS_getcwd: u64 = 79;
pub const SYS_chdir: u64 = 80;
pub const SYS_fchdir: u64 = 81;
pub const SYS_rename: u64 = 82;
pub const SYS_mkdir: u64 = 83;
pub const SYS_rmdir: u64 = 84;
pub const SYS_creat: u64 = 85;
pub const SYS_link: u64 = 86;
pub const SYS_unlink: u64 = 87;
pub const SYS_symlink: u64 = 88;
pub const SYS_readlink: u64 = 89;
pub const SYS_chmod: u64 = 90;
pub const SYS_fchmod: u64 = 91;
pub const SYS_chown: u64 = 92;
pub const SYS_fchown: u64 = 93;
pub const SYS_lchown: u64 = 94;
pub const SYS_umask: u64 = 95;
pub const SYS_gettimeofday: u64 = 96;
pub const SYS_getrlimit: u64 = 97;
pub const SYS_getrusage: u64 = 98;
pub const SYS_sysinfo: u64 = 99;
pub const SYS_times: u64 = 100;
pub const SYS_ptrace: u64 = 101;
pub const SYS_getuid: u64 = 102;
pub const SYS_syslog: u64 = 103;
pub const SYS_getgid: u64 = 104;
pub const SYS_setuid: u64 = 105;
pub const SYS_setgid: u64 = 106;
pub const SYS_geteuid: u64 = 107;
pub const SYS_getegid: u64 = 108;
pub const SYS_setpgid: u64 = 109;
pub const SYS_getppid: u64 = 110;
pub const SYS_getpgrp: u64 = 111;
pub const SYS_setsid: u64 = 112;
pub const SYS_setreuid: u64 = 113;
pub const SYS_setregid: u64 = 114;
pub const SYS_getgroups: u64 = 115;
pub const SYS_setgroups: u64 = 116;
pub const SYS_setresuid: u64 = 117;
pub const SYS_getresuid: u64 = 118;
pub const SYS_setresgid: u64 = 119;
pub const SYS_getresgid: u64 = 120;
pub const SYS_getpgid: u64 = 121;
pub const SYS_setfsuid: u64 = 122;
pub const SYS_setfsgid: u64 = 123;
pub const SYS_getsid: u64 = 124;
pub const SYS_capget: u64 = 125;
pub const SYS_capset: u64 = 126;

// File I/O extended
pub const SYS_openat: u64 = 257;
pub const SYS_mkdirat: u64 = 258;
pub const SYS_unlinkat: u64 = 259;
pub const SYS_futimesat: u64 = 261;
pub const SYS_newfstatat: u64 = 262;
pub const SYS_uname2: u64 = 263; // renameat2 in Linux
pub const SYS_linkat: u64 = 265;
pub const SYS_symlinkat: u64 = 266;
pub const SYS_readlinkat: u64 = 267;
pub const SYS_fchmodat: u64 = 268;
pub const SYS_faccessat: u64 = 269;
pub const SYS_pselect6: u64 = 270;
pub const SYS_ppoll: u64 = 271;
pub const SYS_splice: u64 = 272;
pub const SYS_tee: u64 = 276;
pub const SYS_sync_file_range: u64 = 277;
pub const SYS_utimensat: u64 = 280;
pub const SYS_epoll_create1: u64 = 291;
pub const SYS_epoll_ctl: u64 = 292;
pub const SYS_epoll_pwait: u64 = 293;
pub const SYS_timerfd_create: u64 = 283;
pub const SYS_eventfd2: u64 = 290;
pub const SYS_signalfd4: u64 = 289;
pub const SYS_pipe2: u64 = 293;
pub const SYS_dup3: u64 = 292;
pub const SYS_inotify_init1: u64 = 294;
pub const SYS_epoll_pwait2: u64 = 441;

// Process/thread
pub const SYS_clone3: u64 = 435;
pub const SYS_pidfd_open: u64 = 434;
pub const SYS_pidfd_send_signal: u64 = 424;

// ============================================================================
// POSIX Open Flags
// ============================================================================

pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_CLOEXEC: u32 = 0o2000000;

// ============================================================================
// POSIX Signal Numbers
// ============================================================================

pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGSEGV: u8 = 11;
pub const SIGUSR2: u8 = 12;
pub const SIGPIPE: u8 = 13;
pub const SIGALRM: u8 = 14;
pub const SIGTERM: u8 = 15;
pub const SIGSTKFLT: u8 = 16;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGTTIN: u8 = 21;
pub const SIGTTOU: u8 = 22;
pub const SIGURG: u8 = 23;
pub const SIGXCPU: u8 = 24;
pub const SIGXFSZ: u8 = 25;
pub const SIGVTALRM: u8 = 26;
pub const SIGPROF: u8 = 27;
pub const SIGWINCH: u8 = 28;
pub const SIGIO: u8 = 29;
pub const SIGSYS: u8 = 31;

pub const SIG_DFL: u64 = 0; // Default signal handler
pub const SIG_IGN: u64 = 1; // Ignore signal
pub const SIG_ERR: u64 = 0xFFFFFFFFFFFFFFFF;

pub const MAX_SIGNAL: usize = 32;

/// Signal action structure (matches Linux sigaction)
pub const SigAction = extern struct {
    sa_handler: u64, // void (*)(int) or SIG_DFL/SIG_IGN
    sa_flags: u64,
    sa_mask: [1]u64, // sigset_t (1024 bits, but 1 u64 for now)
};

/// Per-process signal state
pub const SignalState = struct {
    handlers: [MAX_SIGNAL]SigAction,
    pending: u64, // Bitmask of pending signals
    blocked: u64, // Bitmask of blocked signals

    pub fn init() SignalState {
        var state = SignalState{
            .handlers = undefined,
            .pending = 0,
            .blocked = 0,
        };
        // Default: all signals use default handler
        for (&state.handlers) |*h| {
            h.* = SigAction{
                .sa_handler = SIG_DFL,
                .sa_flags = 0,
                .sa_mask = .{0},
            };
        }
        // SIGKILL and SIGSTOP cannot be caught/blocked
        state.handlers[SIGKILL - 1].sa_handler = SIG_DFL;
        state.handlers[SIGSTOP - 1].sa_handler = SIG_DFL;
        return state;
    }
};

// ============================================================================
// POSIX File Descriptor Table
// ============================================================================
//
// File descriptors are indices into a per-process table.
// Each fd maps to an Object Manager handle internally.
// This allows NT and POSIX to share the same underlying objects.
//
// Convention:
//   fd 0 = stdin  (NT: \Device\ConDrv\Input)
//   fd 1 = stdout (NT: \Device\ConDrv\Output)
//   fd 2 = stderr (NT: \Device\ConDrv\Error)
// ============================================================================

pub const MAX_FDS: usize = 1024;

pub const FdEntry = struct {
    in_use: bool = false,
    obj_handle: u64 = 0, // Object Manager handle
    flags: u32 = 0, // O_RDONLY/O_WRONLY/O_RDWR | O_CLOEXEC | etc.
    offset: u64 = 0, // Current file offset
};

pub const FdTable = struct {
    entries: [MAX_FDS]FdEntry,

    pub fn init() FdTable {
        var table = FdTable{
            .entries = undefined,
        };
        for (&table.entries) |*e| {
            e.* = FdEntry{};
        }
        // Reserve stdin/stdout/stderr
        table.entries[0] = FdEntry{ .in_use = true, .obj_handle = 0, .flags = O_RDONLY, .offset = 0 };
        table.entries[1] = FdEntry{ .in_use = true, .obj_handle = 0, .flags = O_WRONLY, .offset = 0 };
        table.entries[2] = FdEntry{ .in_use = true, .obj_handle = 0, .flags = O_WRONLY, .offset = 0 };
        return table;
    }

    pub fn allocFd(self: *FdTable) ?i32 {
        for (&self.entries, 0..) |*entry, i| {
            if (!entry.in_use) {
                entry.in_use = true;
                return @intCast(i);
            }
        }
        return null; // EMFILE
    }

    pub fn getFd(self: *FdTable, fd: i32) ?*FdEntry {
        if (fd < 0 or fd >= MAX_FDS) return null;
        if (!self.entries[@intCast(fd)].in_use) return null;
        return &self.entries[@intCast(fd)];
    }

    pub fn closeFd(self: *FdTable, fd: i32) bool {
        if (fd < 0 or fd >= MAX_FDS) return false;
        if (!self.entries[@intCast(fd)].in_use) return false;
        self.entries[@intCast(fd)] = FdEntry{};
        return true;
    }
};

// ============================================================================
// POSIX VFS — Virtual File System
// ============================================================================
//
// The VFS provides a unified view of the file system namespace.
// Mount points map NT paths and POSIX paths to the same underlying files:
//
//   /          → root filesystem
//   /mnt/c/    → \??\C:\  (NT DosDevices C:)
//   /dev/      → \Device\  (NT device namespace)
//   /proc/     → virtual filesystem (process info)
//   /sys/      → virtual filesystem (kernel info)
//
// This is the core of the dual-personality design: both subsystems
// reference the SAME files through different naming conventions.
// ============================================================================

pub const VfsNodeType = enum {
    Directory,
    File,
    Device,
    Symlink,
    MountPoint,
    Pipe,
    Socket,
};

pub const VfsNode = struct {
    name: [256]u8,
    name_len: usize,
    node_type: VfsNodeType,
    parent: ?*VfsNode,
    first_child: ?*VfsNode,
    next_sibling: ?*VfsNode,
    mount_target: ?*VfsNode, // For mount points
    size: u64,
    permissions: u32, // Unix permissions (0755 etc.)
    obj_handle: u64, // Object Manager handle (if backed by a real object)

    pub fn init(name: []const u8, node_type: VfsNodeType) VfsNode {
        var node = VfsNode{
            .name = undefined,
            .name_len = 0,
            .node_type = node_type,
            .parent = null,
            .first_child = null,
            .next_sibling = null,
            .mount_target = null,
            .size = 0,
            .permissions = 0o755,
            .obj_handle = 0,
        };
        const copy_len = @min(name.len, 255);
        @memcpy(node.name[0..copy_len], name[0..copy_len]);
        node.name[copy_len] = 0;
        node.name_len = copy_len;
        return node;
    }

    pub fn getName(self: *const VfsNode) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const VfsRoot = struct {
    root: VfsNode,
    mnt_c: VfsNode, // /mnt/c → NT C:
    dev: VfsNode, // /dev → device namespace
    proc_fs: VfsNode, // /proc → process info
    sys_fs: VfsNode, // /sys → kernel info

    pub fn init() VfsRoot {
        var vfs = VfsRoot{
            .root = VfsNode.init("/", .Directory),
            .mnt_c = VfsNode.init("mnt", .Directory),
            .dev = VfsNode.init("dev", .Directory),
            .proc_fs = VfsNode.init("proc", .Directory),
            .sys_fs = VfsNode.init("sys", .Directory),
        };

        // Build tree: root → {mnt, dev, proc, sys}
        vfs.root.first_child = &vfs.mnt_c;
        vfs.mnt_c.parent = &vfs.root;
        vfs.mnt_c.next_sibling = &vfs.dev;
        vfs.dev.parent = &vfs.root;
        vfs.dev.next_sibling = &vfs.proc_fs;
        vfs.proc_fs.parent = &vfs.root;
        vfs.proc_fs.next_sibling = &vfs.sys_fs;
        vfs.sys_fs.parent = &vfs.root;

        // /mnt/c → Windows C: drive
        var mnt_c_child = VfsNode.init("c", .MountPoint);
        mnt_c_child.parent = &vfs.mnt_c;
        vfs.mnt_c.first_child = &mnt_c_child;

        // /dev/null, /dev/zero, /dev/console
        var dev_null = VfsNode.init("null", .Device);
        var dev_zero = VfsNode.init("zero", .Device);
        var dev_console = VfsNode.init("console", .Device);
        dev_null.parent = &vfs.dev;
        dev_null.next_sibling = &dev_zero;
        dev_zero.parent = &vfs.dev;
        dev_zero.next_sibling = &dev_console;
        dev_console.parent = &vfs.dev;
        vfs.dev.first_child = &dev_null;

        return vfs;
    }

    /// Resolve a POSIX path to a VFS node
    pub fn resolve(self: *VfsRoot, path: []const u8) ?*VfsNode {
        if (path.len == 0 or path[0] != '/') return null;
        if (path.len == 1) return &self.root; // "/"

        var current: *VfsNode = &self.root;
        var start: usize = 1; // Skip leading '/'

        while (start < path.len) {
            // Find end of component
            var end: usize = start;
            while (end < path.len and path[end] != '/') : (end += 1) {}
            const component = path[start..end];

            if (component.len == 0 or (component.len == 1 and component[0] == '.')) {
                start = end + 1;
                continue;
            }
            if (component.len == 2 and component[0] == '.' and component[1] == '.') {
                // Parent directory
                if (current.parent) |p| current = p;
                start = end + 1;
                continue;
            }

            // Search children for matching name
            var child = current.first_child;
            var found = false;
            while (child) |c| : (child = c.next_sibling) {
                if (c.getName().len == component.len and stdMemEqual(u8, c.getName(), component)) {
                    current = c;
                    found = true;
                    break;
                }
            }
            if (!found) return null;

            // If mount point, follow it
            if (current.mount_target) |target| {
                current = target;
            }

            start = end + 1;
        }

        return current;
    }

    /// Convert a POSIX path to an NT path
    /// /mnt/c/foo/bar → \??\C:\foo\bar
    /// /dev/sda1      → \Device\Harddisk0\Partition1
    pub fn posixToNtPath(self: *VfsRoot, posix_path: []const u8, nt_buf: []u8) ?usize {
        _ = self;

        if (posix_path.len >= 6 and posix_path[0] == '/' and posix_path[1] == 'm' and posix_path[2] == 'n' and posix_path[3] == 't' and posix_path[4] == '/' and posix_path[5] >= 'a' and posix_path[5] <= 'z') {
            // /mnt/X/... → \??\X:\...
            const drive_letter: u8 = posix_path[5] - 0x20; // lowercase → uppercase
            if (nt_buf.len < 8) return null;
            nt_buf[0] = '\\';
            nt_buf[1] = '?';
            nt_buf[2] = '?';
            nt_buf[3] = '\\';
            nt_buf[4] = drive_letter;
            nt_buf[5] = ':';
            if (posix_path.len > 6) {
                const rest = posix_path[6..];
                if (nt_buf.len < 6 + rest.len) return null;
                @memcpy(nt_buf[6..6 + rest.len], rest);
                // Convert forward slashes to backslashes
                for (nt_buf[6..6 + rest.len]) |*ch| {
                    if (ch.* == '/') ch.* = '\\';
                }
                return 6 + rest.len;
            }
            nt_buf[6] = '\\';
            return 7;
        }

        if (posix_path.len >= 5 and posix_path[0] == '/' and posix_path[1] == 'd' and posix_path[2] == 'e' and posix_path[3] == 'v' and posix_path[4] == '/') {
            // /dev/... → \Device\...
            if (nt_buf.len < 8 + posix_path.len - 5) return null;
            const prefix = "\\Device\\";
            @memcpy(nt_buf[0..8], prefix);
            const rest = posix_path[5..];
            @memcpy(nt_buf[8..8 + rest.len], rest);
            return 8 + rest.len;
        }

        return null;
    }
};

fn stdMemEqual(comptime T: type, a: []const T, b: []const T) bool {
    if (a.len != b.len) return false;
    for (a, b) |aa, bb| {
        if (aa != bb) return false;
    }
    return true;
}

// ============================================================================
// POSIX Subsystem State
// ============================================================================

var objmgr_ref: ?*objmgr.ObjectManager = null;
var fd_table: FdTable = undefined;
var signal_state: SignalState = undefined;
var vfs: VfsRoot = undefined;

pub fn init(om: *objmgr.ObjectManager) void {
    objmgr_ref = om;
    fd_table = FdTable.init();
    signal_state = SignalState.init();
    vfs = VfsRoot.init();

    hal.Serial.puts("[POSIX] POSIX API subsystem initialized\n");
    hal.Serial.puts("[POSIX] Linux syscalls: 0x0000-0x0FFF, VFS root ready\n");
    hal.Serial.puts("[POSIX] /mnt/c → \\??\\C:, /dev → \\Device\\\n");
}

// ============================================================================
// POSIX Syscall Handler
// ============================================================================

pub fn handleSyscall(syscall_num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) i64 {
    switch (syscall_num) {
        SYS_read => return posixRead(@intCast(arg1), arg2, arg3),
        SYS_write => return posixWrite(@intCast(arg1), arg2, arg3),
        SYS_open => return posixOpen(arg1, @intCast(arg2), @intCast(arg3)),
        SYS_close => return posixClose(@intCast(arg1)),
        SYS_stat => return posixStat(arg1, arg2),
        SYS_fstat => return posixFstat(@intCast(arg1), arg2),
        SYS_lseek => return posixLseek(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_mmap => return posixMmap(arg1, @intCast(arg2), @intCast(arg3), @intCast(arg4), @intCast(arg5), @intCast(arg6)),
        SYS_munmap => return posixMunmap(arg1, @intCast(arg2)),
        SYS_brk => return posixBrk(arg1),
        SYS_ioctl => return posixIoctl(@intCast(arg1), @intCast(arg2), arg3),
        SYS_getpid => return posixGetpid(),
        SYS_getppid => return posixGetppid(),
        SYS_exit => return posixExit(@intCast(arg1)),
        SYS_fork => return posixFork(),
        SYS_clone => return posixClone(@intCast(arg1), arg2, arg3, arg4, arg5),
        SYS_execve => return posixExecve(arg1, arg2, arg3),
        SYS_wait4 => return posixWait4(@intCast(arg1), arg2, @intCast(arg3), arg4),
        SYS_kill => return posixKill(@intCast(arg1), @intCast(arg2)),
        SYS_rt_sigaction => return posixSigaction(@intCast(arg1), arg2, arg3),
        SYS_rt_sigprocmask => return posixSigprocmask(@intCast(arg1), arg2, arg3),
        SYS_getcwd => return posixGetcwd(arg1, @intCast(arg2)),
        SYS_chdir => return posixChdir(arg1),
        SYS_dup => return posixDup(@intCast(arg1)),
        SYS_dup2 => return posixDup2(@intCast(arg1), @intCast(arg2)),
        SYS_pipe => return posixPipe(arg1),
        SYS_socket => return posixSocket(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_connect => return posixConnect(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_uname => return posixUname(arg1),
        SYS_openat => return posixOpenat(@intCast(arg1), arg2, @intCast(arg3), @intCast(arg4)),
        SYS_mkdir => return posixMkdir(arg1, @intCast(arg2)),
        SYS_rmdir => return posixRmdir(arg1),
        SYS_unlink => return posixUnlink(arg1),
        SYS_rename => return posixRename(arg1, arg2),
        SYS_chmod => return posixChmod(arg1, @intCast(arg2)),
        SYS_getuid => return 0, // root
        SYS_getgid => return 0, // root
        SYS_geteuid => return 0, // root
        SYS_getegid => return 0, // root
        SYS_setuid => return 0, // Stub: always succeeds
        SYS_setgid => return 0, // Stub: always succeeds
        SYS_sched_yield => return posixYield(),
        SYS_nanosleep => return posixNanosleep(arg1, arg2),
        SYS_sysinfo => return posixSysinfo(arg1),
        else => {
            hal.Serial.puts("[POSIX] Unimplemented syscall: ");
            hal.Serial.putDecimal(syscall_num);
            hal.Serial.puts("\n");
            return -@as(i64, subsys.ENOSYS);
        },
    }
}

// ============================================================================
// POSIX Syscall Implementations
// ============================================================================

fn posixRead(fd: i32, buf_addr: u64, count: u64) i64 {
    _ = buf_addr;
    _ = count;

    const entry = fd_table.getFd(fd) orelse return -@as(i64, subsys.EBADF);
    if (entry.flags & 3 == O_WRONLY) return -@as(i64, subsys.EBADF); // Not open for reading

    // TODO: Read from VFS via Object Manager handle
    hal.Serial.puts("[POSIX] read(fd=");
    hal.Serial.putDecimal(fd);
    hal.Serial.puts(", count=");
    hal.Serial.putDecimal(count);
    hal.Serial.puts(")\n");

    return -@as(i64, subsys.ENOSYS);
}

fn posixWrite(fd: i32, buf_addr: u64, count: u64) i64 {
    if (fd == 1 or fd == 2) {
        // stdout/stderr → serial output
        const ptr: [*]const u8 = @ptrFromInt(buf_addr);
        hal.Serial.puts(ptr[0..@intCast(count)]);
        return @intCast(count);
    }

    const entry = fd_table.getFd(fd) orelse return -@as(i64, subsys.EBADF);
    if (entry.flags & 3 == O_RDONLY) return -@as(i64, subsys.EBADF); // Not open for writing

    // TODO: Write to VFS via Object Manager handle
    return -@as(i64, subsys.ENOSYS);
}

fn posixOpen(path_addr: u64, flags: i32, _mode: i32) i64 {
    _ = _mode;

    const path: [*]const u8 = @ptrFromInt(path_addr);
    const path_len = strLen(path);
    const path_slice = path[0..path_len];

    hal.Serial.puts("[POSIX] open(\"");
    hal.Serial.puts(path_slice);
    hal.Serial.puts("\", flags=0x");
    hal.Serial.putHex(@intCast(flags));
    hal.Serial.puts(")\n");

    // Allocate a file descriptor
    const fd = fd_table.allocFd() orelse return -@as(i64, subsys.EMFILE);

    // Create an Object Manager handle for this file
    if (objmgr_ref) |om| {
        const access: u64 = if (flags & 3 == O_RDONLY) 0x80000000 else if (flags & 3 == O_WRONLY) 0x40000000 else 0xC0000000;
        const handle = om.createHandle(.File, access);
        if (handle != objmgr.INVALID_HANDLE) {
            if (fd_table.getFd(fd)) |entry| {
                entry.obj_handle = handle;
                entry.flags = @intCast(flags & 0xFFFFFFFF);
            }
        }
    }

    return fd;
}

fn posixClose(fd: i32) i64 {
    if (fd < 3) return 0; // Can't close stdin/stdout/stderr (stub)

    const entry = fd_table.getFd(fd) orelse return -@as(i64, subsys.EBADF);

    // Close Object Manager handle
    if (objmgr_ref) |om| {
        _ = om.closeHandle(entry.obj_handle);
    }

    if (!fd_table.closeFd(fd)) return -@as(i64, subsys.EBADF);
    return 0;
}

fn posixStat(_path: u64, _buf: u64) i64 {
    _ = _path;
    _ = _buf;
    return -@as(i64, subsys.ENOSYS);
}

fn posixFstat(fd: i32, _buf: u64) i64 {
    _ = fd;
    _ = _buf;
    return -@as(i64, subsys.ENOSYS);
}

fn posixLseek(fd: i32, offset: i64, whence: i32) i64 {
    const entry = fd_table.getFd(fd) orelse return -@as(i64, subsys.EBADF);

    switch (whence) {
        0 => { // SEEK_SET
            entry.offset = @intCast(offset);
        },
        1 => { // SEEK_CUR
            entry.offset = @intCast(@as(i64, @intCast(entry.offset)) + offset);
        },
        2 => { // SEEK_END
            // TODO: Get file size from Object Manager
            return -@as(i64, subsys.ENOSYS);
        },
        else => return -@as(i64, subsys.EINVAL),
    }

    return @intCast(entry.offset);
}

fn posixMmap(addr: u64, length: i64, prot: i64, flags: i64, fd: i64, offset: i64) i64 {
    _ = addr;
    _ = prot;
    _ = flags;
    _ = fd;
    _ = offset;

    if (length <= 0) return -@as(i64, subsys.EINVAL);

    // TODO: Allocate virtual memory via VMM
    // For now, return a stub address
    hal.Serial.puts("[POSIX] mmap(length=");
    hal.Serial.putDecimal(@intCast(length));
    hal.Serial.puts(")\n");

    return -@as(i64, subsys.ENOSYS);
}

fn posixMunmap(addr: u64, length: i64) i64 {
    _ = addr;
    _ = length;
    return -@as(i64, subsys.ENOSYS);
}

fn posixBrk(addr: u64) i64 {
    _ = addr;
    // TODO: Implement program break management
    return 0;
}

fn posixIoctl(fd: i32, request: i64, arg: u64) i64 {
    _ = request;
    _ = arg;
    if (fd < 0 or fd >= MAX_FDS) return -@as(i64, subsys.EBADF);
    return -@as(i64, subsys.ENOTTY);
}

fn posixGetpid() i64 {
    return 1; // Stub: PID 1 (init)
}

fn posixGetppid() i64 {
    return 0; // Stub: PID 0 (kernel)
}

fn posixExit(exit_code: i32) i64 {
    hal.Serial.puts("[POSIX] exit(");
    hal.Serial.putDecimal(exit_code);
    hal.Serial.puts(")\n");
    // TODO: Kill current process via scheduler
    while (true) {
        asm volatile ("pause");
    }
}

fn posixFork() i64 {
    hal.Serial.puts("[POSIX] fork()\n");
    // TODO: Clone current process via scheduler
    return -@as(i64, subsys.ENOSYS);
}

fn posixClone(flags: i64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) i64 {
    _ = flags;
    _ = stack;
    _ = parent_tid;
    _ = child_tid;
    _ = tls;
    hal.Serial.puts("[POSIX] clone()\n");
    return -@as(i64, subsys.ENOSYS);
}

fn posixExecve(path: u64, argv: u64, envp: u64) i64 {
    _ = path;
    _ = argv;
    _ = envp;
    hal.Serial.puts("[POSIX] execve()\n");
    return -@as(i64, subsys.ENOSYS);
}

fn posixWait4(pid: i32, status: u64, options: i32, rusage: u64) i64 {
    _ = pid;
    _ = status;
    _ = options;
    _ = rusage;
    return -@as(i64, subsys.ECHILD); // No children
}

fn posixKill(pid: i32, sig: i32) i64 {
    _ = pid;
    _ = sig;
    hal.Serial.puts("[POSIX] kill(pid=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(", sig=");
    hal.Serial.putDecimal(sig);
    hal.Serial.puts(")\n");
    return 0;
}

fn posixSigaction(signum: i32, act: u64, oldact: u64) i64 {
    if (signum < 1 or signum > MAX_SIGNAL) return -@as(i64, subsys.EINVAL);
    if (signum == SIGKILL or signum == SIGSTOP) return -@as(i64, subsys.EINVAL);

    const idx: usize = @intCast(signum - 1);

    if (oldact != 0) {
        const old: *SigAction = @ptrFromInt(oldact);
        old.* = signal_state.handlers[idx];
    }

    if (act != 0) {
        const new_act: *SigAction = @ptrFromInt(act);
        signal_state.handlers[idx] = new_act.*;
    }

    return 0;
}

fn posixSigprocmask(how: i32, set: u64, oldset: u64) i64 {
    if (oldset != 0) {
        const old: *u64 = @ptrFromInt(oldset);
        old.* = signal_state.blocked;
    }

    if (set != 0) {
        const new_set: *u64 = @ptrFromInt(set);
        switch (how) {
            0 => { // SIG_BLOCK
                signal_state.blocked |= new_set.*;
            },
            1 => { // SIG_UNBLOCK
                signal_state.blocked &= ~new_set.*;
            },
            2 => { // SIG_SETMASK
                signal_state.blocked = new_set.*;
            },
            else => return -@as(i64, subsys.EINVAL),
        }
        // SIGKILL and SIGSTOP cannot be blocked
        signal_state.blocked &= ~(@as(u64, 1) << (SIGKILL - 1));
        signal_state.blocked &= ~(@as(u64, 1) << (SIGSTOP - 1));
    }

    return 0;
}

fn posixGetcwd(buf: u64, size: i64) i64 {
    if (size < 2) return -@as(i64, subsys.ERANGE);

    const out: [*]u8 = @ptrFromInt(buf);
    out[0] = '/';
    out[1] = 0;
    return 1; // Length of "/"
}

fn posixChdir(path: u64) i64 {
    _ = path;
    return 0; // Stub: always succeeds
}

fn posixDup(fd: i32) i64 {
    const entry = fd_table.getFd(fd) orelse return -@as(i64, subsys.EBADF);
    const new_fd = fd_table.allocFd() orelse return -@as(i64, subsys.EMFILE);

    if (fd_table.getFd(new_fd)) |new_entry| {
        new_entry.obj_handle = entry.obj_handle;
        new_entry.flags = entry.flags;
        new_entry.offset = entry.offset;
    }

    return new_fd;
}

fn posixDup2(oldfd: i32, newfd: i32) i64 {
    const entry = fd_table.getFd(oldfd) orelse return -@as(i64, subsys.EBADF);
    if (newfd < 0 or newfd >= MAX_FDS) return -@as(i64, subsys.EBADF);

    // Close newfd if it's open
    if (fd_table.getFd(newfd)) |new_entry| {
        if (new_entry.in_use) {
            _ = fd_table.closeFd(newfd);
        }
        new_entry.in_use = true;
        new_entry.obj_handle = entry.obj_handle;
        new_entry.flags = entry.flags;
        new_entry.offset = entry.offset;
    }

    return newfd;
}

fn posixPipe(pipefd: u64) i64 {
    const fds: [*]i32 = @ptrFromInt(pipefd);

    if (objmgr_ref) |om| {
        const read_handle = om.createHandle(.File, 0x80000000); // GENERIC_READ
        const write_handle = om.createHandle(.File, 0x40000000); // GENERIC_WRITE

        const read_fd = fd_table.allocFd() orelse return -@as(i64, subsys.EMFILE);
        const write_fd = fd_table.allocFd() orelse return -@as(i64, subsys.EMFILE);

        if (fd_table.getFd(read_fd)) |entry| {
            entry.obj_handle = read_handle;
            entry.flags = O_RDONLY;
        }
        if (fd_table.getFd(write_fd)) |entry| {
            entry.obj_handle = write_handle;
            entry.flags = O_WRONLY;
        }

        fds[0] = read_fd;
        fds[1] = write_fd;
        return 0;
    }

    return -@as(i64, subsys.ENOSYS);
}

fn posixSocket(domain: i32, socket_type: i32, protocol: i32) i64 {
    _ = domain;
    _ = socket_type;
    _ = protocol;
    hal.Serial.puts("[POSIX] socket()\n");
    return -@as(i64, subsys.ENOSYS); // No networking yet
}

fn posixConnect(fd: i32, addr: u64, addrlen: i32) i64 {
    _ = addr;
    _ = addrlen;
    if (fd < 0 or fd >= MAX_FDS) return -@as(i64, subsys.EBADF);
    return -@as(i64, subsys.ENOSYS);
}

fn posixUname(buf: u64) i64 {
    const utsname: [*]u8 = @ptrFromInt(buf);

    // Fill in utsname structure (each field is 65 bytes)
    const sysname = "POLER-OS";
    const nodename = "poleros";
    const release = "0.8.0-dual";
    const version = "POLER-OS v0.8.0 Dual-Personality (NT+POSIX)";
    const machine = "x86_64";

    writeUtsnameField(utsname, 0, sysname);
    writeUtsnameField(utsname, 65, nodename);
    writeUtsnameField(utsname, 130, release);
    writeUtsnameField(utsname, 195, version);
    writeUtsnameField(utsname, 260, machine);

    return 0;
}

fn writeUtsnameField(buf: [*]u8, offset: usize, value: []const u8) void {
    const copy_len = @min(value.len, 64);
    @memcpy(buf[offset..offset + copy_len], value[0..copy_len]);
    buf[offset + copy_len] = 0;
}

fn posixOpenat(dirfd: i32, path: u64, flags: i32, mode: i32) i64 {
    _ = dirfd;
    _ = mode;
    // openat is similar to open but with a directory fd
    return posixOpen(path, flags, mode);
}

fn posixMkdir(path: u64, mode: i32) i64 {
    _ = path;
    _ = mode;
    return -@as(i64, subsys.ENOSYS);
}

fn posixRmdir(path: u64) i64 {
    _ = path;
    return -@as(i64, subsys.ENOSYS);
}

fn posixUnlink(path: u64) i64 {
    _ = path;
    return -@as(i64, subsys.ENOSYS);
}

fn posixRename(oldpath: u64, newpath: u64) i64 {
    _ = oldpath;
    _ = newpath;
    return -@as(i64, subsys.ENOSYS);
}

fn posixChmod(path: u64, mode: i32) i64 {
    _ = path;
    _ = mode;
    return 0; // Stub: always succeeds
}

fn posixYield() i64 {
    // TODO: Trigger scheduler reschedule
    return 0;
}

fn posixNanosleep(req: u64, rem: u64) i64 {
    _ = req;
    _ = rem;
    // TODO: Sleep current thread
    return 0;
}

fn posixSysinfo(info: u64) i64 {
    _ = info;
    return -@as(i64, subsys.ENOSYS);
}

// ============================================================================
// Helpers
// ============================================================================

fn strLen(s: [*]const u8) usize {
    var len: usize = 0;
    while (s[len] != 0) : (len += 1) {}
    return len;
}
