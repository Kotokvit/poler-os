// ============================================================================
// POLER-OS Subsystem Dispatcher — Dual-Personality Kernel
// ============================================================================
//
// Architecture: NT + POSIX simultaneously, neither is a crutch.
//
//   User Process → Syscall → Dispatcher → { NT Handler | POSIX Handler }
//                                       ↘ Common HAL / VMM / PMM / Scheduler
//
// The kernel exposes TWO syscall interfaces:
//   1. NT API:  syscall numbers 0x1000+ (NtCreateFile, NtWriteFile, ...)
//   2. POSIX:   syscall numbers 0x0000+ (read=0, write=1, open=2, ...)
//
// Both converge on the same kernel objects (files, processes, memory, handles).
// The Object Manager provides a unified namespace where:
//   \??\C:\foo     → NT path
//   /mnt/c/foo     → POSIX path
// refer to THE SAME file through different naming conventions.
//
// This is NOT Wine (translation layer) and NOT ReactOS (Windows-only).
// This is a native dual-personality kernel where both APIs are first-class.
// ============================================================================
//
// Conventions:
//   - NTSTATUS (u32) for NT calls, errno (i32) for POSIX calls
//   - HANDLE (u64) for NT, fd (i32) for POSIX — both index into the same
//     Handle Table with different views
//   - Object Manager owns all kernel objects; both subsystems reference them
//   - Security: POLER crypto authenticates the subsystem origin of each action
// ============================================================================

const hal = @import("../hal.zig");
const nt = @import("nt/nt_api.zig");
const posix = @import("posix/posix_api.zig");
const objmgr = @import("common/object_manager.zig");
const ki = @import("../kernel_integrate.zig");
const cap = @import("../capability.zig");

// ============================================================================
// Subsystem Identity — which API personality a process uses
// ============================================================================

pub const SubsystemId = enum(u8) {
    Native = 0, // Kernel / boot-time (neither NT nor POSIX)
    NT = 1, // Windows NT API personality
    POSIX = 2, // Linux/POSIX API personality
    Hybrid = 3, // Can call both (e.g., WSL-like interop)
    AI = 4, // AI runtime capsule (restricted capability set)
};

// ============================================================================
// Syscall number ranges
// ============================================================================

pub const POSIX_SYSCALL_BASE: u64 = 0x0000; // 0x0000..0x0FFF: Linux-compatible
pub const NT_SYSCALL_BASE: u64 = 0x1000; // 0x1000..0x1FFF: NT NtXxx calls
pub const POLER_SYSCALL_BASE: u64 = 0x2000; // 0x2000..0x2FFF: POLER-OS native

pub const MAX_POSIX_SYSCALL: u64 = 0x0FFF;
pub const MAX_NT_SYSCALL: u64 = 0x1FFF;
pub const MAX_POLER_SYSCALL: u64 = 0x2FFF;
pub const AI_SYSCALL_BASE: u64 = 0x3000; // 0x3000..0x3FFF: AI capsule syscalls
pub const MAX_AI_SYSCALL: u64 = 0x3FFF;

// ============================================================================
// NTSTATUS codes — mirrors Windows NT status values
// ============================================================================

pub const NTSTATUS = u32;

pub const STATUS_SUCCESS: NTSTATUS = 0x00000000;
pub const STATUS_INVALID_HANDLE: NTSTATUS = 0xC0000008;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000D;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC0000034;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS = 0xC000003A;
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC0000002;
pub const STATUS_NO_MEMORY: NTSTATUS = 0xC0000017;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023;
pub const STATUS_PENDING: NTSTATUS = 0x00000103;
pub const STATUS_TIMEOUT: NTSTATUS = 0x00000102;

/// Check if NTSTATUS indicates success (bit 31 clear, bit 30 clear or set)
pub fn NT_SUCCESS(status: NTSTATUS) bool {
    return status >= 0x00000000 and status < 0x80000000;
}

/// Check if NTSTATUS is an error (bit 31 set)
pub fn NT_ERROR(status: NTSTATUS) bool {
    return status & 0x80000000 != 0;
}

// ============================================================================
// POSIX errno values — mirrors Linux errno.h
// ============================================================================

pub const errno_t = i32;

pub const EPERM: errno_t = 1;
pub const ENOENT: errno_t = 2;
pub const ESRCH: errno_t = 3;
pub const EINTR: errno_t = 4;
pub const EIO: errno_t = 5;
pub const ENXIO: errno_t = 6;
pub const E2BIG: errno_t = 7;
pub const ENOEXEC: errno_t = 8;
pub const EBADF: errno_t = 9;
pub const ECHILD: errno_t = 10;
pub const EAGAIN: errno_t = 11;
pub const ENOMEM: errno_t = 12;
pub const EACCES: errno_t = 13;
pub const EFAULT: errno_t = 14;
pub const ENOTBLK: errno_t = 15;
pub const EBUSY: errno_t = 16;
pub const EEXIST: errno_t = 17;
pub const EXDEV: errno_t = 18;
pub const ENODEV: errno_t = 19;
pub const ENOTDIR: errno_t = 20;
pub const EISDIR: errno_t = 21;
pub const EINVAL: errno_t = 22;
pub const ENFILE: errno_t = 23;
pub const EMFILE: errno_t = 24;
pub const ENOTTY: errno_t = 25;
pub const ETXTBSY: errno_t = 26;
pub const EFBIG: errno_t = 27;
pub const ENOSPC: errno_t = 28;
pub const ESPIPE: errno_t = 29;
pub const EROFS: errno_t = 30;
pub const EMLINK: errno_t = 31;
pub const EPIPE: errno_t = 32;
pub const EDOM: errno_t = 33;
pub const ERANGE: errno_t = 34;
pub const ENOSYS: errno_t = 38; // Function not implemented
pub const ENOTEMPTY: errno_t = 39; // Directory not empty
pub const ELOOP: errno_t = 40; // Too many symbolic links
pub const EWOULDBLOCK: errno_t = 11; // Same as EAGAIN
pub const ENOMSG: errno_t = 42; // No message of desired type
pub const EIDRM: errno_t = 43; // Identifier removed
pub const ECHRNG: errno_t = 44; // Channel number out of range
pub const EL2NSYNC: errno_t = 45; // Level 2 not synchronized
pub const EL3HLT: errno_t = 46; // Level 3 halted
pub const EL3RST: errno_t = 47; // Level 3 reset
pub const ENOLCK: errno_t = 77; // No locks available
pub const ENOSTR: errno_t = 60; // Device not a stream
pub const ENODATA: errno_t = 61; // No data available
pub const ETIME: errno_t = 62; // Timer expired
pub const ENOSR: errno_t = 63; // Out of streams resources
pub const EPROTO: errno_t = 71; // Protocol error
pub const EBADMSG: errno_t = 74; // Bad message
pub const EOVERFLOW: errno_t = 75; // Value too large
pub const EILSEQ: errno_t = 84; // Illegal byte sequence
pub const ECANCELED: errno_t = 125; // Operation canceled
pub const EOWNERDEAD: errno_t = 130; // Owner died
pub const ENOTRECOVERABLE: errno_t = 131; // State not recoverable
pub const ERFKILL: errno_t = 132; // Operation not possible due to RF-kill
pub const EHWPOISON: errno_t = 133; // Memory page has hardware error

// ============================================================================
// Dispatch result — unified return from syscall handler
// ============================================================================

pub const SyscallResult = union(enum) {
    NtStatus: NTSTATUS,
    PosixReturn: i64, // >= 0 on success, negative errno on error (-errno)
    PollerNative: u64,
};

// ============================================================================
// Per-process subsystem state
// ============================================================================

pub const ProcessSubsystemInfo = struct {
    id: SubsystemId = .Native,
    nt_api_set: ?*nt.ApiSetTable = null, // Per-process API set bindings
    posix_cwd: [256]u8 = undefined, // POSIX current working directory
    posix_cwd_len: usize = 1, // Length of CWD string
    nt_curdir_handle: ?u64 = null, // NT handle to current directory
    env_block: ?[]u8 = null, // Environment block (shared format)
    pid: u32 = 0, // Process ID

    pub fn init(id: SubsystemId, pid: u32) ProcessSubsystemInfo {
        var info = ProcessSubsystemInfo{
            .id = id,
            .pid = pid,
        };
        info.posix_cwd[0] = '/';
        info.posix_cwd_len = 1;
        return info;
    }
};

// ============================================================================
// Global subsystem state
// ============================================================================

var initialized: bool = false;
var global_objmgr: objmgr.ObjectManager = undefined;

pub fn init() void {
    if (initialized) return;

    hal.Serial.puts("[SUBSYSTEM] Initializing dual-personality subsystem dispatcher\n");

    // Initialize Object Manager (shared between NT and POSIX)
    global_objmgr.init();
    hal.Serial.puts("[SUBSYSTEM] Object Manager initialized\n");

    // Initialize NT subsystem
    nt.init(&global_objmgr);
    hal.Serial.puts("[SUBSYSTEM] NT API subsystem initialized\n");

    // Initialize POSIX subsystem
    posix.init(&global_objmgr);
    hal.Serial.puts("[SUBSYSTEM] POSIX API subsystem initialized\n");

    initialized = true;
    hal.Serial.puts("[SUBSYSTEM] Dual-personality kernel ready (NT + POSIX)\n");
}

// ============================================================================
// Capability mapping — determine required capabilities for a syscall
// ============================================================================

/// Determine required capabilities for a syscall number.
/// Routes to the appropriate subsystem's capability mapping.
pub fn requiredCapsForSyscall(syscall_num: u64) u64 {
    if (syscall_num <= MAX_POSIX_SYSCALL) {
        return ki.posixSyscallToCapabilities(syscall_num);
    } else if (syscall_num >= NT_SYSCALL_BASE and syscall_num <= MAX_NT_SYSCALL) {
        return ki.ntSyscallToCapabilities(syscall_num - NT_SYSCALL_BASE);
    } else if (syscall_num >= POLER_SYSCALL_BASE and syscall_num <= MAX_POLER_SYSCALL) {
        return ki.polerSyscallToCapabilities(syscall_num - POLER_SYSCALL_BASE);
    } else if (syscall_num >= AI_SYSCALL_BASE and syscall_num <= MAX_AI_SYSCALL) {
        // AI syscalls require CAP_AI_RUNTIME | CAP_POLER_AUTH
        return ki.CAP_AI_RUNTIME | ki.CAP_POLER_AUTH;
    }
    return 0; // Unknown — no capabilities required (will be denied by policy)
}

// ============================================================================
// Master Syscall Dispatcher
// ============================================================================
//
// This is the main entry point from the SYSCALL instruction.
// It routes to NT or POSIX handlers based on syscall number range.
//
// Convention:
//   RAX = syscall number
//   RCX = return address (saved by SYSCALL)
//   R11 = saved RFLAGS
//   RDI = arg1, RSI = arg2, RDX = arg3, R10 = arg4, R8 = arg5, R9 = arg6
//
// Return: RAX = result (NTSTATUS, or i64 with -errno, or native u64)
// ============================================================================

pub fn dispatch(syscall_num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) SyscallResult {
    // v0.8.0: ACL policy enforcement — authenticate before dispatching
    const action = ki.PolerAction{
        .syscall_number = syscall_num,
        .subsystem = if (syscall_num <= MAX_POSIX_SYSCALL) .POSIX else if (syscall_num >= NT_SYSCALL_BASE and syscall_num <= MAX_NT_SYSCALL) .NT else .Hybrid,
        .pid = getCurrentPid(),
        .arg_hash = ki.fnvHashArgs(.{ arg1, arg2, arg3, arg4, arg5, arg6 }),
    };

    const auth_result = ki.polerAuthenticate(action);
    switch (auth_result) {
        .Denied => {
            hal.Serial.puts("[SUBSYSTEM] ACL DENIED: syscall=0x");
            hal.Serial.putHex(syscall_num);
            hal.Serial.puts(" pid=");
            hal.Serial.putDecimal(action.pid);
            hal.Serial.puts("\n");
            // Return appropriate error based on subsystem
            if (syscall_num >= NT_SYSCALL_BASE) {
                return .{ .NtStatus = STATUS_ACCESS_DENIED };
            } else {
                return .{ .PosixReturn = -@as(i64, EACCES) };
            }
        },
        .Allowed, .Audited => {
            // Proceed with the syscall
        },
        .Unauthenticated => {
            return .{ .NtStatus = STATUS_ACCESS_DENIED };
        },
    }

    if (syscall_num <= MAX_POSIX_SYSCALL) {
        return .{ .PosixReturn = posix.handleSyscall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6) };
    } else if (syscall_num >= NT_SYSCALL_BASE and syscall_num <= MAX_NT_SYSCALL) {
        const nt_num = syscall_num - NT_SYSCALL_BASE;
        return .{ .NtStatus = nt.handleSyscall(nt_num, arg1, arg2, arg3, arg4, arg5, arg6) };
    } else if (syscall_num >= POLER_SYSCALL_BASE and syscall_num <= MAX_POLER_SYSCALL) {
        const poler_num = syscall_num - POLER_SYSCALL_BASE;
        return .{ .PollerNative = handlePolerNative(poler_num, arg1, arg2, arg3, arg4, arg5, arg6) };
    } else {
        hal.Serial.puts("[SUBSYSTEM] Unknown syscall range: ");
        hal.Serial.putHex(syscall_num);
        hal.Serial.puts("\n");
        return .{ .PosixReturn = -@as(i64, EINVAL) };
    }
}

/// Get current process PID — simple helper
fn getCurrentPid() u32 {
    // v0.8.0: For now, use scheduler's current_task_id + 1
    // (task 0 is kernel, PIDs start at 1 for user processes)
    const sched = @import("../scheduler.zig");
    if (sched.current_task_id == 0) return 0;
    // Look up PID from process table
    const pid = ki.processMgrFind(@intCast(sched.current_task_id));
    if (pid) |pcb| return pcb.pid;
    return 0;
}

// ============================================================================
// POLER-OS Native syscalls (0x2000+)
// ============================================================================

fn handlePolerNative(num: u64, arg1: u64, arg2: u64, _: u64, _: u64, _: u64, _: u64) u64 {

    switch (num) {
        0 => {
            // POLER_SYSCALL_PRINT — debug print (same as old syscall 1)
            const ptr: [*]const u8 = @ptrFromInt(arg1);
            const len: usize = @intCast(arg2);
            hal.Serial.puts(ptr[0..len]);
            return 0;
        },
        1 => {
            // POLER_SYSCALL_GET_SUBSYSTEM — query process subsystem identity
            return @intFromEnum(SubsystemId.Hybrid); // Both available
        },
        2 => {
            // POLER_SYSCALL_AUTHENTICATE — POLER crypto action authentication
            // arg1 = action hash, arg2 = POLER token pointer
            // Returns: authenticated status
            hal.Serial.puts("[POLER] Action authentication requested\n");
            return 1; // Authenticated (stub)
        },
        3 => {
            // POLER_SYSCALL_SET_CAPS — set capabilities for a target process
            // arg1 = target PID, arg2 = new capability mask
            // Requires CAP_ADMIN on the caller
            const target_pid: u32 = @intCast(arg1);
            const new_caps: u64 = arg2;
            const caller_pid = getCurrentPid();
            if (ki.processMgrSetCaps(caller_pid, target_pid, new_caps)) {
                return 0; // Success
            }
            return @bitCast(@as(i64, -EACCES)); // Denied
        },
        4 => {
            // POLER_SYSCALL_GET_CAPS — get capabilities for a process
            // arg1 = target PID (0 = current process)
            // Returns: capability mask (u64)
            var target_pid: u32 = @intCast(arg1);
            if (target_pid == 0) target_pid = getCurrentPid();
            return ki.processMgrGetCaps(target_pid);
        },
        5 => {
            // POLER_SYSCALL_COW_FORK — explicit COW fork (like SYS_fork but
            // with POLER authentication). This is the POLER-native way to
            // create a new process.
            const parent_pid = getCurrentPid();
            const child_pid = ki.processMgrFork(parent_pid);
            if (child_pid) |pid| {
                return pid;
            }
            return @bitCast(@as(i64, -ENOMEM));
        },
        else => {
            hal.Serial.puts("[SUBSYSTEM] Unknown POLER native syscall: ");
            hal.Serial.putDecimal(num);
            hal.Serial.puts("\n");
            return @bitCast(@as(i64, -EINVAL));
        },
    }
}

// ============================================================================
// NTSTATUS ↔ errno conversion
// ============================================================================

/// Convert NTSTATUS to POSIX errno (for hybrid processes)
pub fn ntstatusToErrno(status: NTSTATUS) errno_t {
    if (NT_SUCCESS(status)) return 0;
    return switch (status) {
        STATUS_INVALID_HANDLE => EBADF,
        STATUS_INVALID_PARAMETER => EINVAL,
        STATUS_ACCESS_DENIED => EACCES,
        STATUS_OBJECT_NAME_NOT_FOUND => ENOENT,
        STATUS_OBJECT_PATH_NOT_FOUND => ENOENT,
        STATUS_NO_MEMORY => ENOMEM,
        STATUS_BUFFER_TOO_SMALL => EINVAL,
        STATUS_PENDING => EAGAIN,
        STATUS_TIMEOUT => EAGAIN,
        else => EIO, // Generic I/O error for unmapped statuses
    };
}

/// Convert POSIX errno to NTSTATUS (for hybrid processes)
pub fn errnoToNtstatus(err: errno_t) NTSTATUS {
    if (err == 0) return STATUS_SUCCESS;
    return switch (err) {
        EPERM => STATUS_ACCESS_DENIED,
        ENOENT => STATUS_OBJECT_NAME_NOT_FOUND,
        ESRCH => STATUS_INVALID_PARAMETER,
        EINTR => STATUS_PENDING,
        EIO => STATUS_NOT_IMPLEMENTED,
        EBADF => STATUS_INVALID_HANDLE,
        ENOMEM => STATUS_NO_MEMORY,
        EACCES => STATUS_ACCESS_DENIED,
        EFAULT => STATUS_INVALID_PARAMETER,
        EEXIST => STATUS_OBJECT_NAME_NOT_FOUND, // Closest match
        EINVAL => STATUS_INVALID_PARAMETER,
        ENOSPC => STATUS_NO_MEMORY, // Disk full
        else => STATUS_NOT_IMPLEMENTED,
    };
}
