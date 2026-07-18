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
    // Subsystem dispatch — NT / POSIX / POLER native
    // ========================================================================
    const result = subsys.dispatch(syscall_num, arg1, arg2, arg3, arg4, 0, 0);

    return switch (result) {
        .NtStatus => |status| status, // NTSTATUS is already u32, fits in u64
        .PosixReturn => |ret| @bitCast(ret), // i64 → u64 for return
        .PollerNative => |ret| ret,
    };
}
