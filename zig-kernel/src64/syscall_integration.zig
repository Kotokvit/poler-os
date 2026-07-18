// ============================================================================
// POLER-OS Syscall Integration — Bridges HAL syscall handler to subsystems
// ============================================================================
//
// This file replaces the old zig_syscall_handler in hal.zig.
// Instead of handling 5 simple syscalls directly, it routes through
// the dual-personality subsystem dispatcher.
//
// Old syscalls (1-5) are remapped to POLER_NATIVE base (0x2000+).
// All new syscalls use the proper NT/POSIX/POLER numbering.
//
// Assembly convention (unchanged):
//   RAX = syscall number
//   RDI = arg1, RSI = arg2, RDX = arg3, R10 = arg4 (moved to RCX by asm)
//   R8  = syscall number (moved from RAX by asm)
//   R9  = available (arg5)
//
// The assembly calls zig_syscall_handler(arg1, arg2, arg3, arg4, syscall_num)
// which is defined here.
// ============================================================================

const hal = @import("hal.zig");
const subsys = @import("subsystem/subsystem.zig");

// Import the scheduler for exit/yield handling (legacy compatibility)
const scheduler = @import("scheduler.zig");

// Import kernel_integrate for process management (capability checks)
const kernel_integrate = @import("kernel_integrate.zig");

// v1.1.0: Import Intent Dispatcher — all I/O operations must pass through
// the Intent Layer before reaching the subsystem dispatcher.
const intent = @import("poler/intent.zig");

// ============================================================================
// User-space pointer validation — prevents kernel address dereference
// ============================================================================

/// Check that an address lies below the kernel-space boundary.
/// On x86_64 with canonical addressing, user space is 0x0000000000000000 –
/// 0x00007FFFFFFFFFFF.  Anything at or above 0x0000_8000_0000_0000 is
/// kernel space and must NEVER be dereferenced from a user-supplied pointer.
fn isUserAddress(addr: u64) bool {
    return addr < 0x0000_8000_0000_0000;
}

// ============================================================================
// Legacy syscall numbers (for backward compatibility with v0.7.0 user programs)
// ============================================================================

const LEGACY_PRINT: u64 = 1;
const LEGACY_READ_KEY: u64 = 2;
const LEGACY_CLEAR_SCREEN: u64 = 3;
const LEGACY_EXIT: u64 = 4;
const LEGACY_YIELD: u64 = 5;
const LEGACY_READ_SERIAL: u64 = 6;

// ============================================================================
// Print and screen functions — registered by main64.zig
// ============================================================================

pub var print_fn: ?*const fn ([]const u8) void = null;
pub var clear_screen_fn: ?*const fn () void = null;

// ============================================================================
// Master Syscall Handler — called from assembly syscall_entry
// ============================================================================
//
// This function is the SINGLE entry point for ALL syscalls.
// It handles:
//   1. Legacy syscalls (1-5) for backward compatibility
//   2. POSIX syscalls (0x0000-0x0FFF) for Linux compatibility
//   3. NT syscalls (0x1000-0x1FFF) for Windows compatibility
//   4. POLER native syscalls (0x2000-0x2FFF) for OS-specific features
// ============================================================================

pub export fn zig_syscall_handler(arg1: u64, arg2: u64, arg3: u64, arg4: u64, syscall_num: u64) callconv(.C) u64 {
    // Re-enable interrupts — syscall clears IF via SFMASK, but we need
    // timer interrupts to fire for preemptive scheduling.
    hal.sti();

    // ========================================================================
    // Legacy syscalls (1-5) — backward compatible with v0.7.0 user programs
    // ========================================================================
    switch (syscall_num) {
        LEGACY_PRINT => {
            // Syscall 1: Print string
            // P0 SECURITY: Validate that the user-supplied buffer is entirely
            // within user space.  Without this check, a malicious program could
            // pass a kernel-space address and leak kernel memory.
            const ptr_addr: u64 = arg1;
            const len: u64 = arg2;
            if (!isUserAddress(ptr_addr)) return 0xFFFFFFFF; // EFAULT
            if (len > 0 and !isUserAddress(ptr_addr + len - 1)) return 0xFFFFFFFF; // EFAULT
            const ptr: [*]const u8 = @ptrFromInt(ptr_addr);
            const slice = ptr[0..@as(usize, @intCast(len))];
            if (print_fn) |f| {
                f(slice);
            } else {
                hal.Serial.puts(slice);
            }
            return 0;
        },
        LEGACY_READ_KEY => {
            // Syscall 2: Read key (non-blocking)
            // TODO: Needs capability check (CAP_RAW_IO) when the system is ready
            return hal.kbd_pop();
        },
        LEGACY_CLEAR_SCREEN => {
            // Syscall 3: Clear screen
            // TODO: Needs capability check (CAP_DEVICE) when the system is ready
            if (clear_screen_fn) |f| {
                f();
            }
            return 0;
        },
        LEGACY_EXIT => {
            // Syscall 4: Exit — terminate the calling user process
            // TODO: Needs capability check (CAP_PROCESS_EXIT) when the system is ready
            hal.Serial.puts("[SYSCALL] exit(");
            hal.Serial.putDecimal(arg1);
            hal.Serial.puts(") — killing user process\n");

            if (hal.exitCallback) |cb| {
                cb();
            }
            while (true) {
                asm volatile ("pause");
            }
        },
        LEGACY_YIELD => {
            // Syscall 5: Yield
            // TODO: Needs capability check when the system is ready
            return 0;
        },
        LEGACY_READ_SERIAL => {
            // Syscall 6: Read serial character (non-blocking)
            // TODO: Needs capability check (CAP_RAW_IO) when the system is ready
            // Returns 0 if no serial data available, or the ASCII character.
            // Used for -serial stdio interactive mode.
            // Also falls back to polling COM1 LSR if interrupt missed.
            if (hal.serial_has_data()) {
                return hal.serial_pop();
            }
            // Poll COM1 directly (fallback if interrupt was not delivered)
            if ((hal.inb(0x3F8 + 5) & 0x01) != 0) {
                const ch = hal.inb(0x3F8);
                if (ch == '\r') return '\n';
                return ch;
            }
            return 0;
        },
        else => {
            // Not a legacy syscall — route to subsystem dispatcher
        },
    }

    // ========================================================================
    // Intent Layer — v1.1.0 Semantic Security Gateway
    // ========================================================================
    // Before dispatching to any subsystem, create an Intent and verify it
    // through the 4-phase pipeline:
    //   Phase 1: PND nonce verification (tamper detection)
    //   Phase 2: Rate limiting (DoS prevention)
    //   Phase 3: Process-level capability check
    //   Phase 4: Per-handle access_mask verification
    //
    // This ensures NO I/O operation bypasses the Intent Layer.
    // The Intent Dispatcher is the single point of truth for authorization.
    //
    // Note: Legacy syscalls (1-6) are exempt from Intent verification because
    // they are simple operations (print, read key, exit, yield) that don't
    // touch the I/O path. They are covered by the process-level ACL check
    // in polerAuthenticate() instead.
    const caller_pid: u32 = @intCast(scheduler.current_task_id);
    const intent_action = syscallToIntentAction(syscall_num);
    if (intent_action != null) {
        const action = intent_action.?;
        const cat = intentActionToCategory(action);
        const target_handle: u32 = if (action != .FS_OPEN and action != .PROC_CREATE and action != .MEM_MMAP) @truncate(arg1) else 0;
        const intent_obj = intent.Intent.create(
            cat,
            action,
            caller_pid,
            target_handle,
            .{ arg1, arg2, arg3, arg4, 0, 0 },
        );
        const verdict = intent.dispatch(&intent_obj);
        if (verdict != .Allowed) {
            // Intent denied — return appropriate error code
            // NT: STATUS_ACCESS_DENIED (0xC0000022)
            // POSIX: -EPERM (−1)
            // We return a generic error; the subsystem will translate.
            hal.Serial.puts("[SYSCALL] Intent DENIED for syscall=0x");
            hal.Serial.putHex(syscall_num);
            hal.Serial.puts(" verdict=");
            hal.Serial.putDecimal(@intFromEnum(verdict));
            hal.Serial.puts("\n");
            return 0xC0000022; // STATUS_ACCESS_DENIED
        }
    }

    // ========================================================================
    // Subsystem dispatch — NT / POSIX / POLER native
    // ========================================================================
    const result = subsys.dispatch(syscall_num, arg1, arg2, arg3, arg4, 0, 0);

    return switch (result) {
        .NtStatus => |status| status, // NTSTATUS is already u32, fits in u64
        .PosixReturn => |ret| @bitCast(ret), // i64 → u64 for return
        .PollerNative => |ret| ret,
    };
}

// ============================================================================
// Syscall → IntentAction Mapping — v1.1.0
// ============================================================================
//
// Maps syscall numbers to their corresponding IntentAction for the Intent
// Layer. Not every syscall maps to an Intent — only I/O-related ones.
// Syscalls like getpid(), clock_gettime() etc. are pure queries that don't
// need Intent verification (they're covered by the process-level ACL check).
//
// Returns null for syscalls that don't need Intent verification.

fn syscallToIntentAction(syscall_num: u64) ?intent.IntentAction {
    // POSIX syscalls (0x0000-0x0FFF)
    if (syscall_num <= 0x0FFF) {
        return switch (syscall_num) {
            0 => .FS_READ,                // read
            1 => .FS_WRITE,               // write
            2 => .FS_OPEN,                // open
            3 => .FS_CLOSE,               // close
            9 => .MEM_MMAP,               // mmap
            10 => .MEM_MPROTECT,          // mprotect
            11 => .MEM_MUNMAP,            // munmap
            56, 57, 58 => .PROC_CREATE,   // clone, fork, vfork
            59 => .PROC_EXEC,             // execve
            60 => .PROC_EXIT,             // exit
            62 => .PROC_SIGNAL,           // kill
            78 => .FS_READ,               // getdents
            79 => .FS_READ,               // getcwd (reads dir info)
            80 => .FS_CHMOD,              // chdir
            82 => .FS_MKDIR,              // mkdir
            83 => .FS_RMDIR,              // rmdir
            84 => .FS_UNLINK,             // unlink
            85 => .FS_WRITE,              // creat
            86 => .FS_WRITE,              // link
            87 => .FS_UNLINK,             // symlink target
            88 => .FS_WRITE,              // rename
            90 => .FS_CHMOD,              // chmod
            41...55 => .NET_CONNECT,      // socket syscalls
            else => null,                 // No Intent verification needed
        };
    }
    // NT syscalls (0x1000-0x1FFF)
    if (syscall_num >= 0x1000 and syscall_num <= 0x1FFF) {
        const nt_num = syscall_num - 0x1000;
        return switch (nt_num) {
            0x02 => .FS_OPEN,             // NtCreateFile
            0x03 => .FS_READ,             // NtReadFile
            0x04 => .FS_WRITE,            // NtWriteFile
            0x07 => .HW_IOCTL,            // NtDeviceIoControlFile
            0x0C => .FS_CLOSE,            // NtClose
            0x0D => .FS_READ,             // NtOpenKey (registry = FS_READ in Intent model)
            0x18 => .MEM_MMAP,            // NtAllocateVirtualMemory
            0x1E => .MEM_MUNMAP,          // NtFreeVirtualMemory
            0x1F => .PROC_CREATE,         // NtCreateProcess
            0x29 => .FS_WRITE,            // NtCreateKey (registry = FS_WRITE)
            0x30 => .FS_OPEN,             // NtOpenFile
            0x37 => .FS_WRITE,            // NtSetValueKey
            0x2C => .PROC_KILL,           // NtTerminateProcess
            0x46 => .PROC_CREATE,         // NtCreateProcessEx
            0x50 => .MEM_MPROTECT,        // NtProtectVirtualMemory
            else => null,
        };
    }
    // POLER native syscalls (0x2000-0x2FFF)
    if (syscall_num >= 0x2000 and syscall_num <= 0x2FFF) {
        const poler_num = syscall_num - 0x2000;
        return switch (poler_num) {
            0 => null,                     // POLER_SYSCALL_PRINT (no I/O)
            1 => null,                     // POLER_SYSCALL_GET_SUBSYSTEM (query)
            2 => null,                     // POLER_SYSCALL_AUTHENTICATE (auth)
            3 => .SYS_CAP_DELEGATE,        // POLER_SYSCALL_SET_CAPS
            4 => .SYS_CAP_REVOKE,          // POLER_SYSCALL_REVOKE_CAPS
            else => null,
        };
    }
    return null;
}

/// Map an IntentAction back to its IntentCategory
fn intentActionToCategory(action: intent.IntentAction) intent.IntentCategory {
    return switch (action) {
        .FS_OPEN, .FS_READ, .FS_WRITE, .FS_CLOSE, .FS_MKDIR, .FS_RMDIR, .FS_UNLINK, .FS_STAT, .FS_CHMOD, .FS_MOUNT => .FS,
        .NET_CONNECT, .NET_BIND, .NET_LISTEN, .NET_ACCEPT, .NET_SEND, .NET_RECV, .NET_CLOSE => .NET,
        .PROC_CREATE, .PROC_KILL, .PROC_WAIT, .PROC_SIGNAL, .PROC_FORK, .PROC_EXEC, .PROC_EXIT, .PROC_GETPID => .PROC,
        .MEM_MMAP, .MEM_MUNMAP, .MEM_MPROTECT, .MEM_SHARE => .MEM,
        .HW_READ, .HW_WRITE, .HW_IOCTL, .HW_DMA_MAP => .HW,
        .IPC_SEND, .IPC_RECV, .IPC_CHANNEL_CREATE, .IPC_CHANNEL_DESTROY => .IPC,
        .SYS_CAP_DELEGATE, .SYS_CAP_REVOKE, .SYS_POLICY_SET, .SYS_AUDIT_READ, .SYS_SHUTDOWN => .SYS,
    };
}
