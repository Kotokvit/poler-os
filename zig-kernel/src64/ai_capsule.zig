// ============================================================================
// POLER-OS AI Capsule Manager — Lifecycle Management for AI Processes
// ============================================================================
//
// An AI capsule is a POLER-OS process with:
//   - SubsystemId.AI (restricted syscall surface)
//   - Reduced capability set (no CAP_ADMIN, no CAP_RAW_IO, etc.)
//   - Memory quota (enforced by VMM)
//   - Optional capability TTL (temporary privileges expire)
//
// Lifecycle:
//   1. createCapsule() — allocate PCB + scheduler task with AI subsystem
//   2. startCapsule() — load Python interpreter ELF into process PML4
//   3. updateCapsule() — exec() new version + migrate capabilities
//   4. rollbackCapsule() — restore previous capability snapshot
//   5. stopCapsule() — terminate process + revoke all capabilities
//
// Security:
//   - AI capsules NEVER get CAP_ADMIN, CAP_RAW_IO, CAP_PRIVILEGE
//   - AI capsules get CAP_AI_RUNTIME by default
//   - AI capsules can be granted temporary capabilities with TTL
// ============================================================================

const hal = @import("hal.zig");
const scheduler = @import("scheduler.zig");
const ki = @import("kernel_integrate.zig");
const cap = @import("capability.zig");
const elf_loader = @import("elf_loader.zig");
const subsys = @import("subsystem/subsystem.zig");

// ============================================================================
// AI Capsule Capability Set — Restricted
// ============================================================================

/// Default capabilities for an AI capsule.
/// Strictly less than a normal user process.
/// NEVER includes: CAP_ADMIN, CAP_RAW_IO, CAP_PRIVILEGE, CAP_DEVICE
pub const AI_DEFAULT_CAPS: u64 = ki.CAP_FILE_READ | ki.CAP_FILE_WRITE |
    ki.CAP_FILE_EXECUTE | ki.CAP_PROCESS_CREATE |
    ki.CAP_MEMORY_MMAP | ki.CAP_SIGNAL |
    ki.CAP_POSIX_API | ki.CAP_POLER_AUTH |
    ki.CAP_AI_RUNTIME | ki.CAP_AUDIT_READ;

/// Extended capabilities for AI with network access
pub const AI_NETWORK_CAPS: u64 = AI_DEFAULT_CAPS | ki.CAP_NETWORK;

/// Maximum capabilities an AI capsule can EVER have (hard limit)
pub const AI_MAX_CAPS: u64 = AI_NETWORK_CAPS; // Never exceeds this

// ============================================================================
// AI Capsule Configuration
// ============================================================================

pub const AiCapsuleConfig = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    memory_quota_mb: u64 = 64,    // Default 64MB memory limit
    cpu_quota_ticks: u64 = 0,     // 0 = unlimited CPU
    capability_ttl_ticks: u64 = 0, // 0 = capabilities don't expire
    extra_caps: u64 = 0,          // Additional capabilities beyond AI_DEFAULT_CAPS
};

// ============================================================================
// AI Capsule State
// ============================================================================

pub const AiCapsuleState = enum(u8) {
    Invalid = 0,
    Created = 1,
    Running = 2,
    Updating = 3,
    Stopped = 4,
    Crashed = 5,
};

pub const AiCapsule = struct {
    pid: u32 = 0,
    state: AiCapsuleState = .Invalid,
    config: AiCapsuleConfig = AiCapsuleConfig{},
    capabilities: u64 = AI_DEFAULT_CAPS,
    version: u32 = 0,           // Capsule version (incremented on update)
    snapshot_id: u32 = 0,       // Capability snapshot ID for rollback
};

// ============================================================================
// Capsule Registry
// ============================================================================

const MAX_CAPSULES: usize = 8;

var capsules: [MAX_CAPSULES]AiCapsule = undefined;
var capsule_count: usize = 0;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    for (&capsules) |*c| {
        c.* = AiCapsule{};
    }
    capsule_count = 0;
    hal.Serial.puts("[AI-CAPSULE] AI Capsule Manager initialized (max ");
    hal.Serial.putDecimal(MAX_CAPSULES);
    hal.Serial.puts(" capsules)\n");
}

// ============================================================================
// Capsule Lifecycle
// ============================================================================

/// Create a new AI capsule (allocates process + scheduler task).
/// The capsule is in Created state — call startCapsule() to begin execution.
pub fn createCapsule(config: AiCapsuleConfig) ?u32 {
    if (capsule_count >= MAX_CAPSULES) {
        hal.Serial.puts("[AI-CAPSULE] Maximum capsules reached\n");
        return null;
    }
    
    // Compute final capabilities: default + extra, but never exceed AI_MAX_CAPS
    var final_caps = AI_DEFAULT_CAPS | config.extra_caps;
    final_caps = final_caps & AI_MAX_CAPS; // Enforce hard limit
    
    // Verify capability derivation is valid (subset of AI_MAX_CAPS)
    if (cap.deriveCapability(AI_MAX_CAPS, final_caps) == null) {
        hal.Serial.puts("[AI-CAPSULE] Invalid capability set requested\n");
        return null;
    }
    
    // Create process with AI subsystem
    const pid = ki.processMgrCreateProcess(0, .AI, 0) orelse {
        hal.Serial.puts("[AI-CAPSULE] Failed to create process\n");
        return null;
    };
    
    // Configure process capabilities
    const pcb = ki.processMgrFind(pid) orelse return null;
    pcb.acl_capabilities = final_caps;
    
    // Set memory quota
    pcb.memory_quota = config.memory_quota_mb * 1024 * 1024;
    
    // Set capability TTL if specified
    if (config.capability_ttl_ticks > 0) {
        pcb.cap_expire_tick = scheduler.scheduler_ticks + config.capability_ttl_ticks;
    }
    
    // Find a free capsule slot
    var slot: ?*AiCapsule = null;
    for (&capsules) |*c| {
        if (c.state == .Invalid) {
            slot = c;
            break;
        }
    }
    
    const capsule = slot orelse {
        hal.Serial.puts("[AI-CAPSULE] No free capsule slot\n");
        return null;
    };
    
    capsule.* = AiCapsule{
        .pid = pid,
        .state = .Created,
        .config = config,
        .capabilities = final_caps,
        .version = 1,
        .snapshot_id = 0,
    };
    capsule_count += 1;
    
    // Save capability snapshot for rollback
    _ = cap.saveCapSnapshot(pid, final_caps, pcb.acl_version, pcb.cap_expire_tick);
    
    hal.Serial.puts("[AI-CAPSULE] Created capsule PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" caps=0x");
    hal.Serial.putHex(final_caps);
    hal.Serial.puts(" quota=");
    hal.Serial.putDecimal(config.memory_quota_mb);
    hal.Serial.puts("MB\n");
    
    return pid;
}

/// Start an AI capsule — loads the Python interpreter ELF.
pub fn startCapsule(pid: u32, elf_data: []const u8) bool {
    const capsule = findCapsule(pid) orelse return false;
    if (capsule.state != .Created) {
        hal.Serial.puts("[AI-CAPSULE] Cannot start: not in Created state\n");
        return false;
    }
    
    // Load ELF into the process's PML4
    if (!ki.processMgrExec(pid, elf_data)) {
        hal.Serial.puts("[AI-CAPSULE] ELF load failed\n");
        return false;
    }
    
    capsule.state = .Running;
    hal.Serial.puts("[AI-CAPSULE] Started PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts("\n");
    
    return true;
}

/// Update an AI capsule — replaces the running ELF with a new version.
/// Capabilities are preserved (migrated from old version).
pub fn updateCapsule(pid: u32, new_elf_data: []const u8) bool {
    const capsule = findCapsule(pid) orelse return false;
    if (capsule.state != .Running) return false;
    
    // Save current capability snapshot before update
    const pcb = ki.processMgrFind(pid) orelse return false;
    _ = cap.saveCapSnapshot(pid, pcb.acl_capabilities, pcb.acl_version, pcb.cap_expire_tick);
    
    // Mark as updating
    capsule.state = .Updating;
    
    // Load new ELF
    if (!ki.processMgrExec(pid, new_elf_data)) {
        capsule.state = .Crashed;
        hal.Serial.puts("[AI-CAPSULE] Update FAILED — ELF load error\n");
        return false;
    }
    
    capsule.version += 1;
    capsule.state = .Running;
    
    hal.Serial.puts("[AI-CAPSULE] Updated PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" to version ");
    hal.Serial.putDecimal(capsule.version);
    hal.Serial.puts("\n");
    
    return true;
}

/// Rollback an AI capsule to the previous version's capabilities.
/// Note: This restores capabilities, NOT the ELF binary.
pub fn rollbackCapsule(pid: u32) bool {
    const capsule = findCapsule(pid) orelse return false;
    const pcb = ki.processMgrFind(pid) orelse return false;
    
    // Find the most recent capability snapshot for this PID
    const snapshot = cap.restoreCapSnapshot(pid) orelse {
        hal.Serial.puts("[AI-CAPSULE] No snapshot found for rollback\n");
        return false;
    };
    
    // Restore capabilities from snapshot
    pcb.acl_capabilities = snapshot.caps;
    pcb.acl_version = snapshot.acl_version;
    pcb.cap_expire_tick = snapshot.expire_tick;
    
    capsule.capabilities = snapshot.caps;
    
    hal.Serial.puts("[AI-CAPSULE] Rolled back PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts(" caps=0x");
    hal.Serial.putHex(snapshot.caps);
    hal.Serial.puts("\n");
    
    return true;
}

/// Stop an AI capsule — terminates the process and revokes capabilities.
pub fn stopCapsule(pid: u32) bool {
    const capsule = findCapsule(pid) orelse return false;
    
    // Revoke all capabilities before termination
    const pcb = ki.processMgrFind(pid) orelse return false;
    cap.revokeCaps(&pcb.acl_capabilities, 0xFFFFFFFFFFFFFFFF); // Revoke all
    
    // Terminate the process
    _ = ki.processMgrTerminate(pid, 0);
    
    capsule.state = .Stopped;
    capsule_count -= 1;
    
    hal.Serial.puts("[AI-CAPSULE] Stopped PID=");
    hal.Serial.putDecimal(pid);
    hal.Serial.puts("\n");
    
    return true;
}

/// Get capsule info by PID
pub fn getCapsuleInfo(pid: u32) ?AiCapsule {
    return findCapsule(pid);
}

// ============================================================================
// Internal
// ============================================================================

fn findCapsule(pid: u32) ?*AiCapsule {
    for (&capsules) |*c| {
        if (c.pid == pid and c.state != .Invalid) {
            return c;
        }
    }
    return null;
}
