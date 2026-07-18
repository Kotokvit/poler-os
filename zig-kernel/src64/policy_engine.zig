// ============================================================================
// POLER-OS Policy Engine — Kernel-Level Access Policy Evaluation
// ============================================================================
//
// The Policy Engine is a kernel module (NOT userspace) that evaluates
// access policy rules. It sits between the capability check and the
// actual syscall execution.
//
// Architecture:
//   Syscall → polerAuthenticate() → PolicyEngine.check() → Execute
//                                  ↑
//                        Policy rules table (in-kernel)
//
// Why kernel-level? Bootstrapping problem: if Policy Engine were a
// userspace process, who grants IT the first capability?
//
// Policy rules format:
//   { subsystem, syscall_range, required_caps, policy: Allow|Deny|Audit }
//
// Default: Deny unless explicitly allowed (whitelist model).
// ============================================================================

const hal = @import("hal.zig");
const scheduler = @import("scheduler.zig");

// ============================================================================
// Policy Decision
// ============================================================================

pub const PolicyDecision = enum(u8) {
    Allow = 0,
    Deny = 1,
    Audit = 2,    // Allow but log (sensitive operation)
    RateLimit = 3, // Allow but with rate limiting
};

// ============================================================================
// Policy Rule
// ============================================================================

pub const PolicySubsystem = enum(u8) {
    Any = 0,
    POSIX = 1,
    NT = 2,
    POLER = 3,
    AI = 4,
};

pub const PolicyRule = struct {
    subsystem: PolicySubsystem,
    syscall_min: u64,       // Minimum syscall number (inclusive)
    syscall_max: u64,       // Maximum syscall number (inclusive)
    required_caps: u64,     // Required capability mask
    min_capability_bits: u64, // Minimum bits that MUST be set
    decision: PolicyDecision,
    description: [32]u8,    // Human-readable description (zero-terminated)
    enabled: bool = true,
};

// ============================================================================
// Policy Rules Table — Default Whitelist
// ============================================================================

const MAX_POLICY_RULES: usize = 64;

var policy_rules: [MAX_POLICY_RULES]PolicyRule = undefined;
var policy_rule_count: usize = 0;
var policy_version: u32 = 0;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    // Clear all rules
    for (&policy_rules) |*rule| {
        rule.* = PolicyRule{
            .subsystem = .Any,
            .syscall_min = 0,
            .syscall_max = 0,
            .required_caps = 0,
            .min_capability_bits = 0,
            .decision = .Deny,
            .description = [_]u8{0} ** 32,
            .enabled = false,
        };
    }
    policy_rule_count = 0;

    // Register default whitelist rules
    // POSIX file I/O
    _ = addRule(PolicyRule{
        .subsystem = .POSIX,
        .syscall_min = 0, .syscall_max = 2,
        .required_caps = 0x10001, // CAP_FILE_READ | CAP_POSIX_API
        .min_capability_bits = 0x20001, // Must have POSIX_API at minimum
        .decision = .Allow,
        .description = makeDesc("POSIX read/write/open"),
        .enabled = true,
    });

    // POSIX process management
    _ = addRule(PolicyRule{
        .subsystem = .POSIX,
        .syscall_min = 56, .syscall_max = 61,
        .required_caps = 0x20008, // CAP_PROCESS_CREATE | CAP_POSIX_API
        .min_capability_bits = 0x20000,
        .decision = .Audit,
        .description = makeDesc("POSIX fork/exec/exit"),
        .enabled = true,
    });

    // POSIX memory
    _ = addRule(PolicyRule{
        .subsystem = .POSIX,
        .syscall_min = 9, .syscall_max = 12,
        .required_caps = 0x20020, // CAP_MEMORY_MMAP | CAP_POSIX_API
        .min_capability_bits = 0x20000,
        .decision = .Allow,
        .description = makeDesc("POSIX mmap/brk"),
        .enabled = true,
    });

    // NT file I/O
    _ = addRule(PolicyRule{
        .subsystem = .NT,
        .syscall_min = 0x02, .syscall_max = 0x04,
        .required_caps = 0x10003, // CAP_FILE_READ|WRITE | CAP_NT_API
        .min_capability_bits = 0x10000,
        .decision = .Allow,
        .description = makeDesc("NT file I/O"),
        .enabled = true,
    });

    // NT process
    _ = addRule(PolicyRule{
        .subsystem = .NT,
        .syscall_min = 0x1F, .syscall_max = 0x2C,
        .required_caps = 0x10008, // CAP_PROCESS_CREATE | CAP_NT_API
        .min_capability_bits = 0x10000,
        .decision = .Audit,
        .description = makeDesc("NT process ops"),
        .enabled = true,
    });

    // POLER native — always audit
    _ = addRule(PolicyRule{
        .subsystem = .POLER,
        .syscall_min = 0x2000, .syscall_max = 0x2FFF,
        .required_caps = 0x40000, // CAP_POLER_AUTH
        .min_capability_bits = 0x40000,
        .decision = .Audit,
        .description = makeDesc("POLER native syscalls"),
        .enabled = true,
    });

    // AI capsule management — require CAP_AI_MANAGE
    _ = addRule(PolicyRule{
        .subsystem = .AI,
        .syscall_min = 0x2010, .syscall_max = 0x201F,
        .required_caps = 0x100000, // CAP_AI_MANAGE
        .min_capability_bits = 0x100000,
        .decision = .Audit,
        .description = makeDesc("AI capsule management"),
        .enabled = true,
    });

    // Capability management — require CAP_ADMIN
    _ = addRule(PolicyRule{
        .subsystem = .POLER,
        .syscall_min = 0x2020, .syscall_max = 0x202F,
        .required_caps = 0x11000, // CAP_ADMIN | CAP_POLER_AUTH
        .min_capability_bits = 0x11000,
        .decision = .Audit,
        .description = makeDesc("Capability management"),
        .enabled = true,
    });

    hal.Serial.puts("[POLICY] Policy Engine initialized with ");
    hal.Serial.putDecimal(policy_rule_count);
    hal.Serial.puts(" default rules\n");
}

fn makeDesc(comptime s: []const u8) [32]u8 {
    var desc: [32]u8 = [_]u8{0} ** 32;
    const len = if (s.len > 31) @as(usize, 31) else s.len;
    @memcpy(desc[0..len], s[0..len]);
    return desc;
}

// ============================================================================
// Rule Management
// ============================================================================

pub fn addRule(rule: PolicyRule) bool {
    if (policy_rule_count >= MAX_POLICY_RULES) return false;
    policy_rules[policy_rule_count] = rule;
    policy_rule_count += 1;
    policy_version += 1;
    return true;
}

pub fn removeRule(index: usize) bool {
    if (index >= policy_rule_count) return false;
    policy_rules[index].enabled = false;
    policy_version += 1;
    return true;
}

// ============================================================================
// Policy Evaluation
// ============================================================================

/// Evaluate policy for a syscall.
/// Returns the policy decision: Allow, Deny, Audit, or RateLimit.
pub fn evaluate(
    syscall_num: u64,
    subsystem: PolicySubsystem,
    process_caps: u64
) PolicyDecision {
    // Check each rule in order — first match wins
    for (policy_rules[0..policy_rule_count]) |rule| {
        if (!rule.enabled) continue;

        // Check subsystem match
        if (rule.subsystem != .Any and rule.subsystem != subsystem) continue;

        // Check syscall range
        if (syscall_num < rule.syscall_min or syscall_num > rule.syscall_max) continue;

        // Check if process has required capabilities
        if ((process_caps & rule.required_caps) != rule.required_caps) {
            // Process doesn't have required caps for this rule → deny
            hal.Serial.puts("[POLICY] DENY: syscall=0x");
            hal.Serial.putHex(syscall_num);
            hal.Serial.puts(" lacks required caps\n");
            return .Deny;
        }

        // Rule matches — return decision
        return rule.decision;
    }

    // No matching rule → default deny
    return .Deny;
}

/// Get policy version (for cache invalidation)
pub fn getVersion() u32 {
    return policy_version;
}
