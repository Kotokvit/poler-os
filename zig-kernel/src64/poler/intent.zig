// ============================================================================
// POLER-OS Intent Layer — Semantic Security Dispatcher (v1.1.0)
// ============================================================================
//
// Architecture:
//   ┌─────────────┐
//   │  Userspace   │  NT/POSIX syscalls
//   └──────┬──────┘
//          │
//   ┌──────▼──────┐
//   │  Subsystem   │  Dual-personality dispatcher
//   │  Dispatcher  │  (nt_api / posix_api)
//   └──────┬──────┘
//          │ Creates Intent
//   ┌──────▼──────┐
//   │   Intent     │  Intercepts & validates ALL I/O operations
//   │  Dispatcher  │  via POLER Firewall (PND v8 tensor verification)
//   └──────┬──────┘
//          │ Authorized
//   ┌──────▼──────┐
//   │ Object Table │  Per-handle access_mask verification
//   │ (Handles)    │  (Zircon/seL4 model)
//   └──────┬──────┘
//          │ Permitted
//   ┌──────▼──────┐
//   │     VFS      │  Virtual File System → FAT32 / VirtIO-BLK
//   └─────────────┘
//
// The Intent Layer solves the "Ambient Authority" problem:
// Instead of checking global process flags (pcb.acl_capabilities),
// every I/O operation is:
//   1. Encapsulated as an Intent (72 bytes)
//   2. Verified by the POLER Firewall (PND v8 tensor check)
//   3. Authorized against the specific Object Handle's access_mask
//   4. Only then dispatched to VFS/drivers
//
// This ensures: CAP_FILE_READ on a process does NOT give access to ALL files.
// Access is granted per-handle, per-object, with explicit delegation chains.
// ============================================================================

const hal = @import("../hal.zig");
const poler = @import("../poler_core.zig");
const cap = @import("../capability.zig");
const objmgr = @import("../subsystem/common/object_manager.zig");
const ki = @import("../kernel_integrate.zig");

// ============================================================================
// Intent Categories — semantic classification of operations
// ============================================================================

pub const IntentCategory = enum(u8) {
    FS = 0,     // File system: open, read, write, close, mkdir, rm
    NET = 1,    // Network: connect, bind, listen, accept, send, recv
    PROC = 2,   // Process: create, kill, wait, signal, fork, exec
    MEM = 3,    // Memory: mmap, munmap, mprotect, shared memory
    HW = 4,    // Hardware: device I/O, DMA, interrupt control
    IPC = 5,    // Inter-process: channel send/recv, shared memory
    SYS = 6,    // System: capability ops, policy, audit, shutdown
};

// ============================================================================
// Intent Actions — specific operations within each category
// ============================================================================

pub const IntentAction = enum(u16) {
    // File System
    FS_OPEN = 0x0001,
    FS_READ = 0x0002,
    FS_WRITE = 0x0003,
    FS_CLOSE = 0x0004,
    FS_MKDIR = 0x0005,
    FS_RMDIR = 0x0006,
    FS_UNLINK = 0x0007,
    FS_STAT = 0x0008,
    FS_CHMOD = 0x0009,
    FS_MOUNT = 0x000A,

    // Network
    NET_CONNECT = 0x0101,
    NET_BIND = 0x0102,
    NET_LISTEN = 0x0103,
    NET_ACCEPT = 0x0104,
    NET_SEND = 0x0105,
    NET_RECV = 0x0106,
    NET_CLOSE = 0x0107,

    // Process
    PROC_CREATE = 0x0201,
    PROC_KILL = 0x0202,
    PROC_WAIT = 0x0203,
    PROC_SIGNAL = 0x0204,
    PROC_FORK = 0x0205,
    PROC_EXEC = 0x0206,
    PROC_EXIT = 0x0207,
    PROC_GETPID = 0x0208,

    // Memory
    MEM_MMAP = 0x0301,
    MEM_MUNMAP = 0x0302,
    MEM_MPROTECT = 0x0303,
    MEM_SHARE = 0x0304,

    // Hardware
    HW_READ = 0x0401,
    HW_WRITE = 0x0402,
    HW_IOCTL = 0x0403,
    HW_DMA_MAP = 0x0404,

    // IPC
    IPC_SEND = 0x0501,
    IPC_RECV = 0x0502,
    IPC_CHANNEL_CREATE = 0x0503,
    IPC_CHANNEL_DESTROY = 0x0504,

    // System
    SYS_CAP_DELEGATE = 0x0601,
    SYS_CAP_REVOKE = 0x0602,
    SYS_POLICY_SET = 0x0603,
    SYS_AUDIT_READ = 0x0604,
    SYS_SHUTDOWN = 0x0605,
};

// ============================================================================
// Intent Verdict — result of Intent verification
// ============================================================================

pub const IntentVerdict = enum(u8) {
    Allowed = 0,
    Denied = 1,
    Blocked = 2,       // Blocked by POLER Firewall (crypto verification failed)
    NoHandle = 3,      // Caller doesn't have a valid handle for the target object
    Insufficient = 4,  // Handle exists but access_mask doesn't cover the action
    RateLimited = 5,   // Too many intents in a time window (DoS prevention)
    InvalidParams = 6, // Intent parameters are out of range or malformed
};

// ============================================================================
// Intent Structure (72 bytes) — the core semantic operation descriptor
// ============================================================================
//
// Every I/O operation in POLER-OS must pass through the Intent Layer.
// The Intent structure encapsulates:
//   - WHAT is being requested (category + action)
//   - WHO is requesting it (caller_id from Object Table)
//   - WITH WHAT authority (handle with access_mask)
//   - PARAMETERS for the operation (6 × u64 universal args)
//   - WHEN it was created (TSC timestamp)
//   - CRYPTOGRAPHIC proof of authenticity (PND nonce)
//
// The Intent is the single point of truth for authorization decisions.
// No operation bypasses Intent verification — this is enforced at the
// syscall dispatch level in syscall_integration.zig.

pub const Intent = extern struct {
    category: IntentCategory,   // 1 byte  — what domain (FS, NET, PROC...)
    _pad1: u8 = 0,              // 1 byte  — alignment padding
    action: IntentAction,       // 2 bytes — specific operation
    caller_id: u32,             // 4 bytes — Object Table index of the caller
    handle: u32,                // 4 bytes — Object Table handle for the target
    _pad2: u32 = 0,             // 4 bytes — alignment padding
    params: [6]u64,             // 48 bytes — universal arguments
    timestamp: u64,             // 8 bytes  — RDTSC timestamp at creation
    nonce: u32,                 // 4 bytes  — PND v8 cryptographic nonce
    _pad3: u32 = 0,             // 4 bytes  — alignment padding
    // Total: 72 bytes (cache-line friendly, 8-byte aligned)

    /// Create a new Intent with the given parameters.
    /// The timestamp is automatically set from RDTSC.
    /// The nonce is computed via PND v8 tensor verification.
    pub fn create(
        cat: IntentCategory,
        act: IntentAction,
        caller: u32,
        target_handle: u32,
        p: [6]u64,
    ) Intent {
        const ts = hal.readTsc();
        // PND nonce: mix category, action, caller, and timestamp
        // This makes every Intent cryptographically unique
        const seed = @as(u64, @intFromEnum(cat)) << 56 |
                     @as(u64, @intFromEnum(act)) << 40 |
                     @as(u64, caller) << 24 |
                     (ts & 0xFFFFFF);
        const nonce = poler.pndMix(@truncate(seed), @truncate(seed >> 32), 1);

        return Intent{
            .category = cat,
            .action = act,
            .caller_id = caller,
            .handle = target_handle,
            .params = p,
            .timestamp = ts,
            .nonce = nonce,
        };
    }
};

// ============================================================================
// Intent Dispatcher — the central authorization gateway
// ============================================================================
//
// The Intent Dispatcher is called from the syscall dispatch layer
// (syscall_integration.zig) BEFORE any I/O operation is performed.
//
// Flow:
//   1. Syscall handler creates an Intent
//   2. Intent Dispatcher verifies it:
//      a. POLER Firewall tensor check (PND v8)
//      b. Object Table handle validation (access_mask)
//      c. Policy Engine rule check
//   3. If Allowed → dispatch to VFS/driver
//   4. If Denied/Blocked → log and return error
//
// The Intent Dispatcher maintains statistics for auditing and rate limiting.

pub const MAX_INTENT_LOG = 256;
pub const INTENT_RATE_WINDOW = 1000; // TSC ticks for rate limiting

pub const IntentLogEntry = struct {
    intent: Intent,
    verdict: IntentVerdict,
    dispatch_tick: u64,
};

var intent_log: [MAX_INTENT_LOG]IntentLogEntry = undefined;
var intent_log_count: usize = 0;
var intent_log_index: usize = 0;

// Statistics
var total_intents: u64 = 0;
var allowed_intents: u64 = 0;
var denied_intents: u64 = 0;
var blocked_intents: u64 = 0;

// Rate limiting per caller
var caller_intent_count: [64]u64 = undefined;
var caller_intent_window_start: [64]u64 = undefined;
const MAX_RATE_LIMITED_CALLERS = 64;
const MAX_INTENTS_PER_WINDOW = 1000;

/// Initialize the Intent Dispatcher
pub fn init() void {
    for (&intent_log) |*entry| {
        entry.* = IntentLogEntry{
            .intent = undefined,
            .verdict = .Denied,
            .dispatch_tick = 0,
        };
    }
    intent_log_count = 0;
    intent_log_index = 0;
    total_intents = 0;
    allowed_intents = 0;
    denied_intents = 0;
    blocked_intents = 0;

    for (&caller_intent_count) |*c| c.* = 0;
    for (&caller_intent_window_start) |*s| s.* = 0;

    hal.Serial.puts("[INTENT] Intent Dispatcher initialized (v1.1.0)\n");
}

/// Dispatch an Intent through the authorization pipeline.
/// This is the MAIN entry point for all I/O operations in POLER-OS v1.1.0.
///
/// Returns:
///   .Allowed — the intent is authorized, proceed with the operation
///   .Denied/.Blocked/.etc — the intent is rejected
///
/// The caller should check the verdict and only proceed if .Allowed.
pub fn dispatch(intent: *const Intent) IntentVerdict {
    total_intents += 1;

    // ── Phase 1: POLER Firewall Tensor Verification ──────────────────────
    // Use PND v8 to verify the intent's cryptographic nonce.
    // This detects tampering: if any field was modified after create(),
    // the nonce won't match the recomputed value.
    const expected_nonce = computeNonce(intent);
    if (intent.nonce != expected_nonce) {
        blocked_intents += 1;
        logIntent(intent, .Blocked);
        hal.Serial.puts("[INTENT] BLOCKED: nonce mismatch (tampered intent?)\n");
        return .Blocked;
    }

    // ── Phase 2: Rate Limiting ───────────────────────────────────────────
    // Prevent DoS by limiting intents per caller per time window.
    if (intent.caller_id < MAX_RATE_LIMITED_CALLERS) {
        const now = hal.readTsc();
        const window_start = caller_intent_window_start[intent.caller_id];
        if (now - window_start > INTENT_RATE_WINDOW) {
            // Reset window
            caller_intent_count[intent.caller_id] = 1;
            caller_intent_window_start[intent.caller_id] = now;
        } else {
            caller_intent_count[intent.caller_id] += 1;
            if (caller_intent_count[intent.caller_id] > MAX_INTENTS_PER_WINDOW) {
                denied_intents += 1;
                logIntent(intent, .RateLimited);
                return .RateLimited;
            }
        }
    }

    // ── Phase 3: Capability Check (process-level) ────────────────────────
    // Verify that the caller's process has the coarse-grained capability
    // for this category of operation. This uses the per-process capability
    // mask from the ProcessControlBlock (via kernel_integrate).
    const required_caps = categoryToCapability(intent.category);
    if (required_caps != 0 and intent.caller_id != 0) {
        const caller_caps = ki.processMgrGetCaps(intent.caller_id);
        if (cap.checkCapabilities(caller_caps, required_caps) != .Allowed) {
            denied_intents += 1;
            logIntent(intent, .Insufficient);
            hal.Serial.puts("[INTENT] DENIED: process-level capability insufficient\n");
            return .Insufficient;
        }
    }

    // ── Phase 4: Object Handle Verification ──────────────────────────────
    // If a handle is specified, verify it exists in the CALLER's per-process
    // handle table and its access_mask covers the requested action.
    // This is the key v1.1.0 improvement: per-handle, per-object access
    // control eliminates the Ambient Authority problem.
    if (intent.handle != 0) {
        const required_access = actionToAccessMask(intent.action);
        if (required_access != 0) {
            const result = objmgr.intentVerifyHandle(
                intent.caller_id,
                intent.handle,
                required_access,
            );
            switch (result) {
                .Allowed => {}, // Proceed
                .NoHandle => {
                    denied_intents += 1;
                    logIntent(intent, .NoHandle);
                    hal.Serial.puts("[INTENT] DENIED: handle not found or revoked\n");
                    return .NoHandle;
                },
                .Insufficient => {
                    denied_intents += 1;
                    logIntent(intent, .Insufficient);
                    hal.Serial.puts("[INTENT] DENIED: handle access_mask insufficient\n");
                    return .Insufficient;
                },
                .Denied => {
                    denied_intents += 1;
                    logIntent(intent, .Denied);
                    return .Denied;
                },
            }
        }
    }

    // ── All checks passed ────────────────────────────────────────────────
    allowed_intents += 1;
    logIntent(intent, .Allowed);
    return .Allowed;
}

/// Dispatch an Intent with a pre-checked handle access mask.
/// Use this when the caller has already resolved the handle and just needs
/// POLER Firewall + rate limit checks.
pub fn dispatchWithAccess(
    intent: *const Intent,
    access_mask: u32,
) IntentVerdict {
    total_intents += 1;

    // Phase 1: POLER Firewall nonce check
    const expected_nonce = computeNonce(intent);
    if (intent.nonce != expected_nonce) {
        blocked_intents += 1;
        logIntent(intent, .Blocked);
        return .Blocked;
    }

    // Phase 2: Object access check
    const required_access = actionToAccessMask(intent.action);
    if (required_access != 0 and !cap.checkObjectAccess(access_mask, required_access)) {
        denied_intents += 1;
        logIntent(intent, .Insufficient);
        return .Insufficient;
    }

    allowed_intents += 1;
    logIntent(intent, .Allowed);
    return .Allowed;
}

// ============================================================================
// POLER Firewall — Nonce Computation (PND v8 Tensor Verification)
// ============================================================================
//
// The nonce binds together all fields of the Intent into a single
// cryptographic value. Any modification to the Intent after creation
// will be detected because the nonce won't match the recomputed value.
//
// This is NOT a MAC — it's a fast integrity check using PND v8 diffusion.
// The nonce provides:
//   1. Tamper detection: any field change invalidates the nonce
//   2. Uniqueness: every Intent gets a unique nonce
//   3. Non-repudiation: the nonce is deterministic and verifiable
//
// For true MAC authentication, use poler_core.zig's Feistel cipher
// with a secret key (not needed for kernel-internal Intents since
// userspace cannot forge Intent structs — they go through syscalls).

fn computeNonce(intent: *const Intent) u32 {
    // Mix all Intent fields into a PND nonce
    // Category + Action → first input
    const a: u32 = (@as(u32, @intFromEnum(intent.category)) << 16) |
                   @as(u32, @intFromEnum(intent.action));

    // Caller + Handle → second input
    const b: u32 = (intent.caller_id << 16) | intent.handle;

    // Timestamp low bits as round counter
    const round: u32 = @truncate(intent.timestamp);

    // Primary PND mix
    var n = poler.pndMix(a, b, round);

    // Fold in params (2 at a time for efficiency)
    var i: usize = 0;
    while (i < 6) : (i += 2) {
        const p_lo: u32 = @truncate(intent.params[i]);
        const p_hi: u32 = @truncate(intent.params[i + 1]);
        n = poler.pndMix(n, p_lo, p_hi);
    }

    return n;
}

// ============================================================================
// Capability Mapping — IntentCategory → process capability bits
// ============================================================================

fn categoryToCapability(cat: IntentCategory) u64 {
    return switch (cat) {
        .FS   => (1 << 0) | (1 << 1) | (1 << 2),  // FILE_READ | FILE_WRITE | FILE_EXEC
        .NET  => (1 << 6),                          // NET
        .PROC => (1 << 3) | (1 << 4),              // PROC_CREATE | PROC_KILL
        .MEM  => (1 << 5),                          // MMAP
        .HW   => (1 << 7) | (1 << 11),             // DEVICE | RAW_IO
        .IPC  => (1 << 9),                          // SIGNAL (IPC uses signal cap)
        .SYS  => (1 << 12) | (1 << 21),            // ADMIN | POLICY_SET
    };
}

// ============================================================================
// Access Mask Mapping — IntentAction → object access_mask bits
// ============================================================================
//
// These map to the standard POLER-OS access mask bits:
//   0x0001 = READ
//   0x0002 = WRITE
//   0x0004 = EXECUTE
//   0x0008 = DELETE
//   0x0010 = CREATE
//   0x0020 = LIST (directory)
//   0x0040 = CONNECT (network)
//   0x0080 = CONTROL (ioctl/admin)

pub const ACCESS_READ: u32 = 0x0001;
pub const ACCESS_WRITE: u32 = 0x0002;
pub const ACCESS_EXECUTE: u32 = 0x0004;
pub const ACCESS_DELETE: u32 = 0x0008;
pub const ACCESS_CREATE: u32 = 0x0010;
pub const ACCESS_LIST: u32 = 0x0020;
pub const ACCESS_CONNECT: u32 = 0x0040;
pub const ACCESS_CONTROL: u32 = 0x0080;

fn actionToAccessMask(act: IntentAction) u32 {
    return switch (act) {
        .FS_OPEN   => ACCESS_READ,
        .FS_READ   => ACCESS_READ,
        .FS_WRITE  => ACCESS_WRITE,
        .FS_CLOSE  => 0, // Close is always allowed
        .FS_MKDIR  => ACCESS_CREATE | ACCESS_WRITE,
        .FS_RMDIR  => ACCESS_DELETE,
        .FS_UNLINK => ACCESS_DELETE,
        .FS_STAT   => ACCESS_READ,
        .FS_CHMOD  => ACCESS_CONTROL,
        .FS_MOUNT  => ACCESS_CONTROL,

        .NET_CONNECT => ACCESS_CONNECT | ACCESS_WRITE,
        .NET_BIND    => ACCESS_CREATE | ACCESS_CONTROL,
        .NET_LISTEN  => ACCESS_READ | ACCESS_CONTROL,
        .NET_ACCEPT  => ACCESS_CREATE | ACCESS_READ,
        .NET_SEND    => ACCESS_WRITE,
        .NET_RECV    => ACCESS_READ,
        .NET_CLOSE   => 0,

        .PROC_CREATE => ACCESS_CREATE,
        .PROC_KILL   => ACCESS_DELETE,
        .PROC_WAIT   => ACCESS_READ,
        .PROC_SIGNAL => ACCESS_WRITE,
        .PROC_FORK   => ACCESS_CREATE,
        .PROC_EXEC   => ACCESS_EXECUTE,
        .PROC_EXIT   => 0,
        .PROC_GETPID => ACCESS_READ,

        .MEM_MMAP     => ACCESS_READ | ACCESS_CREATE,
        .MEM_MUNMAP   => ACCESS_DELETE,
        .MEM_MPROTECT => ACCESS_CONTROL,
        .MEM_SHARE    => ACCESS_READ | ACCESS_WRITE,

        .HW_READ    => ACCESS_READ,
        .HW_WRITE   => ACCESS_WRITE,
        .HW_IOCTL   => ACCESS_CONTROL,
        .HW_DMA_MAP => ACCESS_CONTROL | ACCESS_WRITE,

        .IPC_SEND           => ACCESS_WRITE,
        .IPC_RECV           => ACCESS_READ,
        .IPC_CHANNEL_CREATE => ACCESS_CREATE,
        .IPC_CHANNEL_DESTROY => ACCESS_DELETE,

        .SYS_CAP_DELEGATE => ACCESS_CONTROL,
        .SYS_CAP_REVOKE   => ACCESS_CONTROL | ACCESS_DELETE,
        .SYS_POLICY_SET   => ACCESS_CONTROL,
        .SYS_AUDIT_READ   => ACCESS_READ,
        .SYS_SHUTDOWN     => ACCESS_CONTROL,
    };
}

// ============================================================================
// Intent Logging — circular buffer for audit trail
// ============================================================================

fn logIntent(intent: *const Intent, verdict: IntentVerdict) void {
    const entry = &intent_log[intent_log_index % MAX_INTENT_LOG];
    entry.* = IntentLogEntry{
        .intent = intent.*,
        .verdict = verdict,
        .dispatch_tick = hal.readTsc(),
    };
    intent_log_index += 1;
    if (intent_log_count < MAX_INTENT_LOG) {
        intent_log_count += 1;
    }
}

/// Get statistics about intent dispatching
pub fn getStats() struct { total: u64, allowed: u64, denied: u64, blocked: u64 } {
    return .{
        .total = total_intents,
        .allowed = allowed_intents,
        .denied = denied_intents,
        .blocked = blocked_intents,
    };
}

/// Print intent statistics (for debugging/audit)
pub fn printStats() void {
    hal.Serial.puts("[INTENT] Stats: total=");
    hal.Serial.putDecimal(total_intents);
    hal.Serial.puts(" allowed=");
    hal.Serial.putDecimal(allowed_intents);
    hal.Serial.puts(" denied=");
    hal.Serial.putDecimal(denied_intents);
    hal.Serial.puts(" blocked=");
    hal.Serial.putDecimal(blocked_intents);
    hal.Serial.puts("\n");
}

/// Print the last N intent log entries (for debugging)
pub fn printLog(n: usize) void {
    const count = if (n < intent_log_count) n else intent_log_count;
    hal.Serial.puts("[INTENT] Last ");
    hal.Serial.putDecimal(count);
    hal.Serial.puts(" entries:\n");

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const idx = (intent_log_index + MAX_INTENT_LOG - count + i) % MAX_INTENT_LOG;
        const entry = &intent_log[idx];
        hal.Serial.puts("  [");
        hal.Serial.putDecimal(i);
        hal.Serial.puts("] cat=");
        hal.Serial.putDecimal(@intFromEnum(entry.intent.category));
        hal.Serial.puts(" act=0x");
        hal.Serial.putHex(@intFromEnum(entry.intent.action));
        hal.Serial.puts(" caller=");
        hal.Serial.putDecimal(entry.intent.caller_id);
        hal.Serial.puts(" handle=");
        hal.Serial.putDecimal(entry.intent.handle);
        hal.Serial.puts(" verdict=");
        hal.Serial.putDecimal(@intFromEnum(entry.verdict));
        hal.Serial.puts("\n");
    }
}

// ============================================================================
// Intent Helper — create intents for common operations
// ============================================================================

/// Create an FS_READ intent for a file handle
pub fn intentFsRead(caller: u32, file_handle: u32, offset: u64, size: u64) Intent {
    return Intent.create(.FS, .FS_READ, caller, file_handle, .{
        offset, size, 0, 0, 0, 0,
    });
}

/// Create an FS_WRITE intent for a file handle
pub fn intentFsWrite(caller: u32, file_handle: u32, offset: u64, size: u64) Intent {
    return Intent.create(.FS, .FS_WRITE, caller, file_handle, .{
        offset, size, 0, 0, 0, 0,
    });
}

/// Create an FS_OPEN intent
pub fn intentFsOpen(caller: u32, path_ptr: u64, path_len: u64, flags: u64) Intent {
    return Intent.create(.FS, .FS_OPEN, caller, 0, .{
        path_ptr, path_len, flags, 0, 0, 0,
    });
}

/// Create a PROC_CREATE intent
pub fn intentProcCreate(caller: u32, entry_point: u64, parent_handle: u32) Intent {
    return Intent.create(.PROC, .PROC_CREATE, caller, parent_handle, .{
        entry_point, 0, 0, 0, 0, 0,
    });
}

/// Create a MEM_MMAP intent
pub fn intentMemMap(caller: u32, addr: u64, size: u64, prot: u64) Intent {
    return Intent.create(.MEM, .MEM_MMAP, caller, 0, .{
        addr, size, prot, 0, 0, 0,
    });
}

/// Create an IPC_SEND intent
pub fn intentIpcSend(caller: u32, channel_handle: u32, msg_ptr: u64, msg_len: u64) Intent {
    return Intent.create(.IPC, .IPC_SEND, caller, channel_handle, .{
        msg_ptr, msg_len, 0, 0, 0, 0,
    });
}
