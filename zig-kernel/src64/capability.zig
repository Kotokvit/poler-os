// ============================================================================
// POLER-OS Capability Module — Derivation, Check, Revocation
// ============================================================================
//
// Evolution of the existing 64-bit bitmask ACL system.
// Dual-mode capability model:
//   Process-level: u64 bitmask (coarse-grain, stored in PCB)
//   Object-level: u32 access_mask (per-handle, stored in HandleEntry)
//
// No cryptography in runtime capabilities. Kernel memory protection is
// sufficient — capabilities live in kernel-only PCB and HandleTable.
// ============================================================================

const hal = @import("hal.zig");
const scheduler = @import("scheduler.zig");

// Re-export capability constants from kernel_integrate.zig for convenience
// (They are defined there; this module provides the LOGIC, not the constants)

// ============================================================================
// Capability Result Types
// ============================================================================

pub const CapCheckResult = enum(u8) {
    Allowed = 0,
    Denied = 1,
    Expired = 2,
    Revoked = 3,
    Insufficient = 4,
};

// ============================================================================
// Capability Derivation
// ============================================================================

/// Derive a child capability from a parent capability.
/// STRICT RULE: child_caps ⊆ parent_caps (subset only, no expansion).
/// Returns null if the child requests capabilities the parent doesn't have.
pub fn deriveCapability(parent_caps: u64, requested_child_caps: u64) ?u64 {
    // If child requests ANY capability that parent doesn't have → deny
    if (requested_child_caps & ~parent_caps != 0) {
        hal.Serial.puts("[CAP] Derive DENIED: child requests caps beyond parent\n");
        return null;
    }
    return requested_child_caps;
}

/// Derive with a mask — intersect parent caps with a restriction mask.
/// Useful for creating a restricted capability from an existing one.
pub fn deriveWithMask(parent_caps: u64, restriction_mask: u64) u64 {
    return parent_caps & restriction_mask;
}

// ============================================================================
// Capability Checking
// ============================================================================

/// Check if a process has ALL required capabilities.
/// This is the core check called from syscall dispatch.
pub fn checkCapabilities(process_caps: u64, required_caps: u64) CapCheckResult {
    // If no capabilities required → always allowed
    if (required_caps == 0) return .Allowed;
    
    // If process has no capabilities → denied
    if (process_caps == 0 and required_caps != 0) return .Insufficient;
    
    // Check: (process_caps & required_caps) == required_caps
    const missing = required_caps & ~process_caps;
    if (missing != 0) {
        return .Insufficient;
    }
    
    return .Allowed;
}

/// Check capabilities with TTL (expiration).
/// `expire_tick` is the scheduler tick at which capabilities expire (0 = never).
pub fn checkCapabilitiesWithTtl(
    process_caps: u64, 
    required_caps: u64, 
    expire_tick: u64,
    current_tick: u64
) CapCheckResult {
    // Check TTL first
    if (expire_tick != 0 and current_tick > expire_tick) {
        return .Expired;
    }
    
    return checkCapabilities(process_caps, required_caps);
}

/// Check object-level access mask.
/// Maps to HandleEntry.access_mask in Object Manager.
pub fn checkObjectAccess(access_mask: u32, required_access: u32) bool {
    return (access_mask & required_access) == required_access;
}

// ============================================================================
// Capability Revocation
// ============================================================================

/// Soft-revoke a capability set by removing specific bits from a process's
/// capability mask. This is immediate — no delayed revocation.
pub fn revokeCaps(process_caps: *u64, caps_to_revoke: u64) void {
    process_caps.* &= ~caps_to_revoke;
}

/// Grant additional capabilities to a process.
/// SECURITY: Caller must verify that the granter has CAP_ADMIN.
/// This function does NOT check — the caller must enforce.
/// Returns true if granted, false if would exceed granter's caps.
pub fn grantCaps(granter_caps: u64, target_caps: *u64, caps_to_grant: u64) bool {
    // Cannot grant caps that granter doesn't have
    if (caps_to_grant & ~granter_caps != 0) {
        return false;
    }
    target_caps.* |= caps_to_grant;
    return true;
}

// ============================================================================
// Capability Description (for debugging/audit)
// ============================================================================

/// Get human-readable description of capability bits.
/// Returns a static string — NOT thread-safe, for debug only.
pub fn describeCaps(caps: u64) void {
    hal.Serial.puts("capabilities=0x");
    hal.Serial.putHex(caps);
    hal.Serial.puts(" [");
    
    if (caps & (1 << 0) != 0) hal.Serial.puts("FILE_READ,");
    if (caps & (1 << 1) != 0) hal.Serial.puts("FILE_WRITE,");
    if (caps & (1 << 2) != 0) hal.Serial.puts("FILE_EXEC,");
    if (caps & (1 << 3) != 0) hal.Serial.puts("PROC_CREATE,");
    if (caps & (1 << 4) != 0) hal.Serial.puts("PROC_KILL,");
    if (caps & (1 << 5) != 0) hal.Serial.puts("MMAP,");
    if (caps & (1 << 6) != 0) hal.Serial.puts("NET,");
    if (caps & (1 << 7) != 0) hal.Serial.puts("DEVICE,");
    if (caps & (1 << 8) != 0) hal.Serial.puts("REGISTRY,");
    if (caps & (1 << 9) != 0) hal.Serial.puts("SIGNAL,");
    if (caps & (1 << 10) != 0) hal.Serial.puts("PRIVILEGE,");
    if (caps & (1 << 11) != 0) hal.Serial.puts("RAW_IO,");
    if (caps & (1 << 12) != 0) hal.Serial.puts("ADMIN,");
    if (caps & (1 << 16) != 0) hal.Serial.puts("NT_API,");
    if (caps & (1 << 17) != 0) hal.Serial.puts("POSIX_API,");
    if (caps & (1 << 18) != 0) hal.Serial.puts("POLER_AUTH,");
    if (caps & (1 << 19) != 0) hal.Serial.puts("AI_RUNTIME,");
    if (caps & (1 << 20) != 0) hal.Serial.puts("AI_MANAGE,");
    if (caps & (1 << 21) != 0) hal.Serial.puts("POLICY_SET,");
    if (caps & (1 << 22) != 0) hal.Serial.puts("AUDIT_READ,");
    
    hal.Serial.puts("]\n");
}

// ============================================================================
// Capability Store — for AI capsule migration
// ============================================================================

/// Maximum number of capability snapshots for rollback
pub const CAP_STORE_SIZE: usize = 16;

pub const CapSnapshot = struct {
    pid: u32,
    caps: u64,
    acl_version: u32,
    expire_tick: u64,
    valid: bool,
};

var cap_store: [CAP_STORE_SIZE]CapSnapshot = undefined;
var cap_store_index: usize = 0;

/// Save a capability snapshot (for AI capsule rollback)
pub fn saveCapSnapshot(pid: u32, caps: u64, acl_version: u32, expire_tick: u64) bool {
    const slot = &cap_store[cap_store_index % CAP_STORE_SIZE];
    slot.* = CapSnapshot{
        .pid = pid,
        .caps = caps,
        .acl_version = acl_version,
        .expire_tick = expire_tick,
        .valid = true,
    };
    cap_store_index += 1;
    return true;
}

/// Restore a capability snapshot (for AI capsule rollback)
pub fn restoreCapSnapshot(pid: u32) ?CapSnapshot {
    // Search backwards for the most recent snapshot for this PID
    var i: usize = cap_store_index;
    while (i > 0) {
        i -= 1;
        const slot = &cap_store[i % CAP_STORE_SIZE];
        if (slot.valid and slot.pid == pid) {
            return slot.*;
        }
    }
    return null;
}

/// Initialize capability store
pub fn init() void {
    for (&cap_store) |*slot| {
        slot.* = CapSnapshot{
            .pid = 0,
            .caps = 0,
            .acl_version = 0,
            .expire_tick = 0,
            .valid = false,
        };
    }
    cap_store_index = 0;
    hal.Serial.puts("[CAP] Capability module initialized\n");
}
