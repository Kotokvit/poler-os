// ============================================================================
// POLER-OS Capability Module — Delegation, Derivation, Check, Revocation
// ============================================================================
//
// v2.0: Capability-based delegation model
//
// Three-layer capability architecture:
//   Layer 1: Capability Kernel (this file) — derivation tree, delegation chains
//   Layer 2: Policy Engine — per-syscall policy rules (policy_engine.zig)
//   Layer 3: AI Capsule — constrained runtime with rollback (ai_capsule.zig)
//
// Delegation model:
//   - Every capability has a derivation chain (parent → child)
//   - STRICT RULE: child_caps ⊆ parent_caps (monotonic decrease)
//   - Delegation depth is bounded (MAX_DELEGATION_DEPTH = 8)
//   - Revocation cascades: revoking parent revokes ALL children
//   - Ambient authority is removed: no implicit caps, all explicit
//
// Dual-mode capability model:
//   Process-level: u64 bitmask (coarse-grain, stored in PCB)
//   Object-level: u32 access_mask (per-handle, stored in HandleEntry)
//
// No cryptography in runtime capabilities. Kernel memory protection is
// sufficient — capabilities live in kernel-only PCB and HandleTable.
// ============================================================================

const hal = @import("hal.zig");
const scheduler = @import("scheduler.zig");

// Capability constants — must match kernel_integrate.zig definitions
const CAP_ADMIN: u64 = 1 << 12;
const CAP_FILE_EXECUTE: u64 = 1 << 2;

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
/// SECURITY: Now enforces CAP_ADMIN internally — defense in depth.
/// Returns true if granted, false if would exceed granter's caps or granter lacks ADMIN.
pub fn grantCaps(granter_caps: u64, target_caps: *u64, caps_to_grant: u64) bool {
    // Defense in depth: granter MUST have CAP_ADMIN
    if ((granter_caps & CAP_ADMIN) == 0) {
        hal.Serial.puts("[CAP] Grant DENIED: granter lacks CAP_ADMIN\n");
        return false;
    }
    // Cannot grant caps that granter doesn't have
    if (caps_to_grant & ~granter_caps != 0) {
        return false;
    }
    target_caps.* |= caps_to_grant;
    return true;
}

// ============================================================================
// Capability Delegation Tree — v2.0
// ============================================================================
//
// The delegation tree tracks parent→child relationships between processes.
// This enables:
//   1. Cascading revocation: when a parent loses a cap, all children lose it too
//   2. Delegation depth limiting: prevents deep chains that obscure authority
//   3. Audit trail: who delegated what to whom
//
// Each DelegationNode records:
//   - parent_pid: who delegated
//   - child_pid: who received
//   - delegated_caps: what was delegated (subset of parent's caps)
//   - depth: how many hops from the root (PID 1)
//   - active: whether this delegation is still in effect
// ============================================================================

pub const MAX_DELEGATION_DEPTH: u8 = 8;
pub const MAX_DELEGATION_NODES: usize = 128;

pub const DelegationNode = struct {
    parent_pid: u32,
    child_pid: u32,
    delegated_caps: u64,
    depth: u8,
    active: bool,
    tick_created: u64,
};

var delegation_tree: [MAX_DELEGATION_NODES]DelegationNode = undefined;
var delegation_count: usize = 0;

/// Delegate capabilities from a parent process to a child process.
/// This is the core of the capability-based delegation model.
///
/// Rules:
///   1. delegated_caps must be a subset of parent_caps (no expansion)
///   2. Delegation depth must not exceed MAX_DELEGATION_DEPTH
///   3. A DelegationNode is recorded for cascading revocation
///
/// Returns true if delegation succeeded, false otherwise.
pub fn delegateCapabilities(
    parent_pid: u32,
    child_pid: u32,
    parent_caps: u64,
    requested_caps: u64,
    parent_depth: u8
) ?u64 {
    // Rule 1: Subset enforcement — child cannot get more than parent
    const effective_caps = deriveCapability(parent_caps, requested_caps) orelse {
        hal.Serial.puts("[CAP] Delegate DENIED: child requests beyond parent\n");
        return null;
    };

    // Rule 2: Depth limit
    if (parent_depth >= MAX_DELEGATION_DEPTH) {
        hal.Serial.puts("[CAP] Delegate DENIED: max delegation depth exceeded\n");
        return null;
    }

    // Rule 3: Record the delegation
    if (delegation_count < MAX_DELEGATION_NODES) {
        delegation_tree[delegation_count] = DelegationNode{
            .parent_pid = parent_pid,
            .child_pid = child_pid,
            .delegated_caps = effective_caps,
            .depth = parent_depth + 1,
            .active = true,
            .tick_created = scheduler.scheduler_ticks,
        };
        delegation_count += 1;
    } else {
        hal.Serial.puts("[CAP] WARNING: delegation tree full, delegation not tracked\n");
    }

    hal.Serial.puts("[CAP] Delegated 0x");
    hal.Serial.putHex(effective_caps);
    hal.Serial.puts(" from PID=");
    hal.Serial.putDecimal(parent_pid);
    hal.Serial.puts(" to PID=");
    hal.Serial.putDecimal(child_pid);
    hal.Serial.puts(" depth=");
    hal.Serial.putDecimal(parent_depth + 1);
    hal.Serial.puts("\n");

    return effective_caps;
}

/// Get the delegation depth for a process (0 = root/init process).
/// Searches the delegation tree for the most recent delegation to this PID.
pub fn getDelegationDepth(pid: u32) u8 {
    var i: usize = delegation_count;
    while (i > 0) {
        i -= 1;
        if (delegation_tree[i].active and delegation_tree[i].child_pid == pid) {
            return delegation_tree[i].depth;
        }
    }
    return 0; // Root process or no delegation found
}

/// Cascading revocation: revoke a capability from a process and ALL its
/// transitive children in the delegation tree.
///
/// Returns the number of processes affected (including the target).
pub fn cascadeRevoke(target_pid: u32, caps_to_revoke: u64, get_caps_fn: *const fn (u32) ?*u64) usize {
    var affected: usize = 0;

    // First, revoke from the target
    if (get_caps_fn(target_pid)) |caps_ptr| {
        revokeCaps(caps_ptr, caps_to_revoke);
        affected += 1;
    }

    // Then, find all direct children and recurse
    var i: usize = 0;
    while (i < delegation_count) : (i += 1) {
        const node = &delegation_tree[i];
        if (!node.active) continue;
        if (node.parent_pid != target_pid) continue;

        // Only cascade if the delegated caps include the revoked bits
        if (node.delegated_caps & caps_to_revoke != 0) {
            // The child may have caps_to_revoke through this delegation
            // Revoke from child (and its subtree)
            affected += cascadeRevoke(node.child_pid, caps_to_revoke, get_caps_fn);

            // Update the delegation node to reflect reduced caps
            node.delegated_caps &= ~caps_to_revoke;
            if (node.delegated_caps == 0) {
                node.active = false; // Empty delegation → deactivate
            }
        }
    }

    return affected;
}

/// Check if a process's capabilities are still consistent with its
/// delegation chain. This detects if a process somehow gained capabilities
/// beyond what its parent delegated (indicates a bug or exploitation).
///
/// Returns true if consistent, false if anomaly detected.
pub fn validateDelegationChain(pid: u32, current_caps: u64) bool {
    // Find the delegation that created this process
    var i: usize = delegation_count;
    while (i > 0) {
        i -= 1;
        if (delegation_tree[i].active and delegation_tree[i].child_pid == pid) {
            // The process's current caps must be a subset of what was delegated
            if (current_caps & ~delegation_tree[i].delegated_caps != 0) {
                hal.Serial.puts("[CAP] ANOMALY: PID=");
                hal.Serial.putDecimal(pid);
                hal.Serial.puts(" has caps beyond delegation!\n");
                return false;
            }
            return true;
        }
    }
    // No delegation found — root/init process, always consistent
    return true;
}

/// Delegation-aware capability check.
/// Combines the basic capability check with delegation chain validation.
/// This is the RECOMMENDED check for all security-sensitive operations.
pub fn checkCapabilitiesDelegated(
    process_caps: u64,
    required_caps: u64,
    pid: u32
) CapCheckResult {
    // First, do the basic check
    const result = checkCapabilities(process_caps, required_caps);
    if (result != .Allowed) return result;

    // Then, validate the delegation chain (detects cap escalation)
    if (!validateDelegationChain(pid, process_caps)) {
        return .Denied;
    }

    return .Allowed;
}

/// Get all children of a process in the delegation tree.
/// Returns a slice of PIDs (borrowed from a static buffer — not thread-safe).
pub const MAX_CHILDREN = 32;
var children_buf: [MAX_CHILDREN]u32 = undefined;

pub fn getChildren(parent_pid: u32) []u32 {
    var count: usize = 0;
    for (delegation_tree[0..delegation_count]) |node| {
        if (node.active and node.parent_pid == parent_pid) {
            if (count < MAX_CHILDREN) {
                children_buf[count] = node.child_pid;
                count += 1;
            }
        }
    }
    return children_buf[0..count];
}

/// Print the full delegation tree (for debugging/audit)
pub fn printDelegationTree() void {
    hal.Serial.puts("[CAP] === Delegation Tree ===\n");
    for (delegation_tree[0..delegation_count]) |node| {
        if (!node.active) continue;
        hal.Serial.puts("  PID=");
        hal.Serial.putDecimal(node.parent_pid);
        hal.Serial.puts(" → PID=");
        hal.Serial.putDecimal(node.child_pid);
        hal.Serial.puts(" caps=0x");
        hal.Serial.putHex(node.delegated_caps);
        hal.Serial.puts(" depth=");
        hal.Serial.putDecimal(node.depth);
        hal.Serial.puts("\n");
    }
    hal.Serial.puts("[CAP] === End Tree ===\n");
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

/// Initialize capability store and delegation tree
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

    // Initialize delegation tree
    for (&delegation_tree) |*node| {
        node.* = DelegationNode{
            .parent_pid = 0,
            .child_pid = 0,
            .delegated_caps = 0,
            .depth = 0,
            .active = false,
            .tick_created = 0,
        };
    }
    delegation_count = 0;

    hal.Serial.puts("[CAP] Capability module initialized (v2.0 delegation model)\n");
}
