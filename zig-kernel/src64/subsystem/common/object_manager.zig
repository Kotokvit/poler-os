// ============================================================================
// POLER-OS Object Manager — Unified Kernel Object Namespace
// ============================================================================
//
// The Object Manager is the core of the dual-personality design.
// It provides a SINGLE namespace for kernel objects that BOTH the NT and
// POSIX subsystems access through their own naming conventions.
//
// Object types:
//   File, Directory, Device, Event, Mutant (Mutex), Semaphore, Timer,
//   Section (Shared Memory), Port (LPC), Token, Key (Registry), Process, Thread
//
// Object naming:
//   NT:      \??\C:\foo          → ObjectManager path: /DosDevices/C:/foo
//   POSIX:   /mnt/c/foo          → ObjectManager path: /DosDevices/C:/foo
//   NT:      \BaseNamedObjects\E → ObjectManager path: /NamedObjects/E
//   NT:      \Device\Harddisk0   → ObjectManager path: /Device/Harddisk0
//   POSIX:   /dev/sda            → ObjectManager path: /Device/Harddisk0
//
// Both NT and POSIX see the SAME objects through different naming conventions.
// The Object Manager resolves names to objects; subsystems provide the view.
// ============================================================================

const hal = @import("../../hal.zig");

// ============================================================================
// NT-compatible ACCESS_MASK bits
// ============================================================================

pub const ACCESS_READ: u32 = 0x00000001;
pub const ACCESS_WRITE: u32 = 0x00000002;
pub const ACCESS_EXECUTE: u32 = 0x00000004;
pub const ACCESS_DELETE: u32 = 0x00010000;
pub const ACCESS_READ_ATTRIBUTES: u32 = 0x00000080;
pub const ACCESS_WRITE_ATTRIBUTES: u32 = 0x00000100;
pub const ACCESS_FULL: u32 = 0xFFFFFFFF;
pub const ACCESS_NONE: u32 = 0x00000000;

// NT-compatible GENERIC access rights (used in handle creation + mediation)
pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;
pub const SYNCHRONIZE: u32 = 0x00100000;

// Specific access rights for mediation
pub const FILE_READ_DATA: u32 = 0x00000001;       // Read data from file
pub const FILE_WRITE_DATA: u32 = 0x00000002;      // Write data to file
pub const FILE_APPEND_DATA: u32 = 0x00000004;     // Append data
pub const FILE_EXECUTE: u32 = 0x00000020;         // Execute file
pub const PROCESS_TERMINATE: u32 = 0x00000001;    // Terminate process
pub const PROCESS_VM_READ: u32 = 0x00000010;      // Read process memory
pub const PROCESS_VM_WRITE: u32 = 0x00000020;     // Write process memory
pub const PROCESS_VM_OPERATION: u32 = 0x00000008; // Virtual memory ops

// ============================================================================
// Object Types
// ============================================================================

pub const ObjectType = enum(u8) {
    Free = 0, // Unused handle slot
    File = 1,
    Directory = 2,
    Device = 3,
    Event = 4,
    Mutant = 5, // NT Mutex
    Semaphore = 6,
    Timer = 7,
    Section = 8, // Shared memory / memory-mapped file
    Port = 9, // LPC port
    Token = 10, // Security token
    Key = 11, // Registry key
    Process = 12,
    Thread = 13,
    SymbolicLink = 14,
    WaitablePort = 15,
    IoCompletion = 16,
    Job = 17,
    WmiGuid = 18,
    DebugObject = 19,
    EventPair = 20,
    Callback = 21,
    Adapter = 22,
    Controller = 23,
    Profile = 24,
    Desktop = 25,
    WindowStation = 26,
    Driver = 27,
    Type = 28,
};

// ============================================================================
// Handle Table
// ============================================================================
//
// The Handle Table maps integer handles (NT) / file descriptors (POSIX)
// to kernel objects. NT uses HANDLE (u64), POSIX uses fd (i32).
// Both ultimately index into the same table.
//
// NT processes get handles starting from 0x00000004 (same as Windows).
// POSIX processes get fds starting from 0 (same as Linux).
// The conversion is: fd = handle_index - 4 (for the same underlying object).
// ============================================================================

pub const MAX_HANDLES: usize = 4096;
pub const INVALID_HANDLE: u64 = 0xFFFFFFFFFFFFFFFF;
pub const NT_HANDLE_BASE: u64 = 4; // NT handles start at 4 (like Windows)

pub const HandleEntry = struct {
    in_use: bool = false,
    obj_type: ObjectType = .Free,
    access_mask: u32 = 0,
    ref_count: u32 = 0,
    cap_generation: u32 = 0, // Generation counter for revocation detection
    cap_revoked: bool = false, // Soft-revoke flag
    // Object-specific data follows
    // For files: VFS node pointer, offset, etc.
    // For events: signaled state, auto-reset flag
    // For mutants: owning thread, recursion count
    object_data: u64 = 0, // Generic data field

    // Event-specific
    event_signaled: bool = false,
    event_auto_reset: bool = false,

    // Mutant (mutex) specific
    mutant_owner: u32 = 0, // Thread ID of owner
    mutant_recursion: u32 = 0,

    // Semaphore specific
    semaphore_count: u32 = 0,
    semaphore_max: u32 = 0,
};

pub const ObjectManager = struct {
    handles: [MAX_HANDLES]HandleEntry,
    next_handle: u64,
    lock: u32,

    const Self = @This();

    pub fn init(self: *Self) void {
        self.* = Self{
            .handles = undefined,
            .next_handle = NT_HANDLE_BASE,
            .lock = 0,
        };
        for (&self.handles) |*entry| {
            entry.* = HandleEntry{};
        }

        // Pre-allocate standard handles
        // Handle 0-3: reserved (like Windows, handles 0-3 are invalid)
        // Handle 4+: available for allocation

        self.handles[0] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved
        self.handles[1] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved
        self.handles[2] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved
        self.handles[3] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved
    }

    /// Create a new handle for the given object type
    /// initial_access_mask: optional ACCESS_MASK bits; if null, maps GENERIC bits
    /// to type-specific access rights. If ACCESS_FULL is passed, it stays ACCESS_FULL.
    ///
    /// GENERIC access mapping (NT-compatible):
    ///   GENERIC_READ    → type-specific read rights
    ///   GENERIC_WRITE   → type-specific write rights
    ///   GENERIC_EXECUTE → type-specific execute rights
    ///   GENERIC_ALL     → all rights for this type
    ///
    /// This ensures handles are created with least-privilege by default,
    /// preventing the ambient authority problem where every handle grants
    /// full access regardless of how it was opened.
    pub fn createHandle(self: *Self, obj_type: ObjectType, initial_access_mask: ?u32) u64 {
        const raw_mask = initial_access_mask orelse ACCESS_FULL;
        const mask = mapGenericAccess(obj_type, raw_mask);
        self.spinLock();

        // Find a free handle slot
        var idx: usize = @intCast(self.next_handle);
        var checked: usize = 0;
        while (checked < MAX_HANDLES) : ({
            idx = (idx + 1) % MAX_HANDLES;
            checked += 1;
        }) {
            if (!self.handles[idx].in_use) {
                self.handles[idx] = HandleEntry{
                    .in_use = true,
                    .obj_type = obj_type,
                    .access_mask = mask,
                    .ref_count = 1,
                    .cap_generation = 0,
                    .cap_revoked = false,
                };

                const handle: u64 = @intCast(idx);
                self.next_handle = (idx + 1) % MAX_HANDLES;

                self.spinUnlock();
                return handle;
            }
        }

        self.spinUnlock();
        return INVALID_HANDLE;
    }

    /// Map GENERIC access rights to type-specific rights.
    /// This is the NT-compatible GENERIC_MAPPING pattern that converts
    /// generic access bits (GENERIC_READ/WRITE/EXECUTE/ALL) into
    /// object-type-specific access bits.
    ///
    /// Without this mapping, a file handle opened with GENERIC_READ would
    /// have bit 0x80000000 set but NOT FILE_READ_DATA (0x00000001),
    /// causing mediateFileRead() to deny access incorrectly.
    fn mapGenericAccess(obj_type: ObjectType, access_mask: u32) u32 {
        var result = access_mask;

        // GENERIC_ALL maps to all type-specific rights
        if (access_mask & GENERIC_ALL != 0) {
            result = switch (obj_type) {
                .File, .Directory => result | FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_EXECUTE | ACCESS_DELETE | ACCESS_READ_ATTRIBUTES | ACCESS_WRITE_ATTRIBUTES | SYNCHRONIZE,
                .Process => result | PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | ACCESS_DELETE | SYNCHRONIZE,
                .Device => result | FILE_READ_DATA | FILE_WRITE_DATA | ACCESS_DELETE | SYNCHRONIZE,
                .Key => result | ACCESS_READ | ACCESS_WRITE | ACCESS_DELETE | ACCESS_READ_ATTRIBUTES | ACCESS_WRITE_ATTRIBUTES,
                .Event => result | ACCESS_READ | ACCESS_WRITE | SYNCHRONIZE,
                .Mutant => result | ACCESS_READ | ACCESS_WRITE | SYNCHRONIZE | ACCESS_DELETE,
                .Semaphore => result | ACCESS_READ | ACCESS_WRITE | SYNCHRONIZE,
                .Timer => result | ACCESS_READ | ACCESS_WRITE | SYNCHRONIZE,
                .Section => result | FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE | ACCESS_READ_ATTRIBUTES,
                .Token => result | ACCESS_READ | ACCESS_WRITE | ACCESS_DELETE,
                .Port, .WaitablePort => result | ACCESS_READ | ACCESS_WRITE | SYNCHRONIZE,
                .IoCompletion => result | ACCESS_READ | ACCESS_WRITE | SYNCHRONIZE,
                .Job => result | ACCESS_READ | ACCESS_WRITE | ACCESS_DELETE | PROCESS_TERMINATE,
                .Thread => result | PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_OPERATION | SYNCHRONIZE,
                else => result | ACCESS_READ | ACCESS_WRITE,
            };
        }

        // GENERIC_READ maps to type-specific read rights
        if (access_mask & GENERIC_READ != 0) {
            result = switch (obj_type) {
                .File, .Directory => result | FILE_READ_DATA | ACCESS_READ_ATTRIBUTES | SYNCHRONIZE,
                .Process => result | PROCESS_VM_READ | SYNCHRONIZE,
                .Device => result | FILE_READ_DATA | ACCESS_READ_ATTRIBUTES | SYNCHRONIZE,
                .Key => result | ACCESS_READ | ACCESS_READ_ATTRIBUTES,
                .Event => result | ACCESS_READ | SYNCHRONIZE,
                .Mutant => result | SYNCHRONIZE,
                .Semaphore => result | ACCESS_READ | SYNCHRONIZE,
                .Timer => result | ACCESS_READ | SYNCHRONIZE,
                .Section => result | FILE_READ_DATA | ACCESS_READ_ATTRIBUTES,
                .Token => result | ACCESS_READ,
                .Port, .WaitablePort => result | ACCESS_READ | SYNCHRONIZE,
                .IoCompletion => result | ACCESS_READ,
                .Job => result | ACCESS_READ,
                .Thread => result | PROCESS_VM_READ | SYNCHRONIZE,
                else => result | ACCESS_READ,
            };
        }

        // GENERIC_WRITE maps to type-specific write rights
        if (access_mask & GENERIC_WRITE != 0) {
            result = switch (obj_type) {
                .File, .Directory => result | FILE_WRITE_DATA | FILE_APPEND_DATA | ACCESS_WRITE_ATTRIBUTES | SYNCHRONIZE,
                .Process => result | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | SYNCHRONIZE,
                .Device => result | FILE_WRITE_DATA | ACCESS_WRITE_ATTRIBUTES | SYNCHRONIZE,
                .Key => result | ACCESS_WRITE | ACCESS_WRITE_ATTRIBUTES,
                .Event => result | ACCESS_WRITE,
                .Mutant => result | ACCESS_WRITE,
                .Semaphore => result | ACCESS_WRITE,
                .Timer => result | ACCESS_WRITE,
                .Section => result | FILE_WRITE_DATA,
                .Token => result | ACCESS_WRITE,
                .Port, .WaitablePort => result | ACCESS_WRITE,
                .IoCompletion => result | ACCESS_WRITE,
                .Job => result | ACCESS_WRITE | PROCESS_TERMINATE,
                .Thread => result | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                else => result | ACCESS_WRITE,
            };
        }

        // GENERIC_EXECUTE maps to type-specific execute rights
        if (access_mask & GENERIC_EXECUTE != 0) {
            result = switch (obj_type) {
                .File => result | FILE_EXECUTE | ACCESS_READ_ATTRIBUTES | SYNCHRONIZE,
                .Process => result | PROCESS_TERMINATE | SYNCHRONIZE,
                .Device => result | ACCESS_READ_ATTRIBUTES | SYNCHRONIZE,
                .Key => result | ACCESS_READ,
                .Event => result | SYNCHRONIZE,
                .Mutant => result | SYNCHRONIZE,
                .Semaphore => result | SYNCHRONIZE,
                .Timer => result | SYNCHRONIZE,
                .Section => result | FILE_EXECUTE,
                .Token => result | ACCESS_READ,
                .Port, .WaitablePort => result | SYNCHRONIZE,
                .IoCompletion => result | SYNCHRONIZE,
                .Job => result | PROCESS_TERMINATE,
                .Thread => result | PROCESS_TERMINATE | SYNCHRONIZE,
                else => result | ACCESS_READ | SYNCHRONIZE,
            };
        }

        // Clear the GENERIC bits from result (they have been mapped)
        result &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);

        return result;
    }

    /// Check whether a handle grants the required access rights
    /// Returns true if: handle is in_use, NOT revoked, and access_mask covers required_access
    pub fn checkHandleAccess(self: *Self, handle_index: usize, required_access: u32) bool {
        if (handle_index >= MAX_HANDLES) return false;
        const entry = &self.handles[handle_index];
        if (!entry.in_use) return false;
        if (entry.cap_revoked) return false;
        return (entry.access_mask & required_access) == required_access;
    }

    /// ═══════════════════════════════════════════════════════════════════
    /// Syscall Mediation — access_mask verification layer
    ///
    /// These methods are the MANDATORY mediation points between
    /// syscall handlers and object operations. Every syscall that
    /// operates on a handle MUST call the appropriate mediateXxx()
    /// before performing the operation.
    ///
    /// Mediation flow:
    ///   1. Validate handle exists and is not revoked
    ///   2. Check access_mask covers the requested operation
    ///   3. Check object type matches expected type
    ///   4. Log denied accesses to audit trail
    ///   5. Return the HandleEntry pointer on success, null on denial
    ///
    /// This eliminates the ambient authority problem where any process
    /// with a valid handle could perform ANY operation on it.
    /// ═══════════════════════════════════════════════════════════════════

    /// Mediation result — carries either the validated entry or a denial reason
    pub const MediationResult = enum(u8) {
        Allowed = 0,
        DeniedInvalidHandle = 1,
        DeniedRevoked = 2,
        DeniedAccessMask = 3,
        DeniedWrongType = 4,
    };

    /// Mediate file read access — must have FILE_READ_DATA or GENERIC_READ
    pub fn mediateFileRead(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .File and entry.obj_type != .Device and entry.obj_type != .Directory) return .DeniedWrongType;
        const required = FILE_READ_DATA | GENERIC_READ | ACCESS_READ;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate file write access — must have FILE_WRITE_DATA or GENERIC_WRITE
    pub fn mediateFileWrite(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .File and entry.obj_type != .Device and entry.obj_type != .Directory) return .DeniedWrongType;
        const required = FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | ACCESS_WRITE;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate file execute — must have FILE_EXECUTE or GENERIC_EXECUTE
    pub fn mediateFileExecute(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .File) return .DeniedWrongType;
        const required = FILE_EXECUTE | GENERIC_EXECUTE | ACCESS_EXECUTE;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate process terminate — must have PROCESS_TERMINATE
    pub fn mediateProcessTerminate(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Process) return .DeniedWrongType;
        const required = PROCESS_TERMINATE | GENERIC_ALL;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate process VM read — must have PROCESS_VM_READ
    pub fn mediateProcessVmRead(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Process) return .DeniedWrongType;
        const required = PROCESS_VM_READ | GENERIC_READ | GENERIC_ALL;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate process VM write — must have PROCESS_VM_WRITE
    pub fn mediateProcessVmWrite(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Process) return .DeniedWrongType;
        const required = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | GENERIC_WRITE | GENERIC_ALL;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate device I/O — must have ACCESS_WRITE (device control) or GENERIC_ALL
    pub fn mediateDeviceIo(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Device and entry.obj_type != .File) return .DeniedWrongType;
        const required = ACCESS_WRITE | GENERIC_WRITE | GENERIC_ALL;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate delete access — must have ACCESS_DELETE
    pub fn mediateDelete(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        const required = ACCESS_DELETE | GENERIC_ALL;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate registry key access — must have appropriate read/write
    pub fn mediateRegistryAccess(self: *Self, handle: u64, write: bool) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Key) return .DeniedWrongType;
        if (write) {
            const required = ACCESS_WRITE | GENERIC_WRITE | GENERIC_ALL;
            if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        } else {
            const required = ACCESS_READ | GENERIC_READ | GENERIC_ALL;
            if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        }
        return .Allowed;
    }

    /// Mediate IPC channel send — must have ACCESS_WRITE on a Port handle
    pub fn mediateChannelSend(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Port and entry.obj_type != .WaitablePort) return .DeniedWrongType;
        const required = ACCESS_WRITE | GENERIC_WRITE | GENERIC_ALL;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate IPC channel receive — must have ACCESS_READ on a Port handle
    pub fn mediateChannelReceive(self: *Self, handle: u64) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Port and entry.obj_type != .WaitablePort) return .DeniedWrongType;
        const required = ACCESS_READ | GENERIC_READ | GENERIC_ALL;
        if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        return .Allowed;
    }

    /// Mediate section (shared memory) mapping — must have appropriate access
    pub fn mediateSectionMap(self: *Self, handle: u64, writable: bool) MediationResult {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return .DeniedInvalidHandle;
        const entry = &self.handles[idx];
        if (!entry.in_use) return .DeniedInvalidHandle;
        if (entry.cap_revoked) return .DeniedRevoked;
        if (entry.obj_type != .Section) return .DeniedWrongType;
        if (writable) {
            const required = FILE_WRITE_DATA | GENERIC_WRITE | GENERIC_ALL;
            if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        } else {
            const required = FILE_READ_DATA | GENERIC_READ | GENERIC_ALL;
            if ((entry.access_mask & required) == 0) return .DeniedAccessMask;
        }
        return .Allowed;
    }

    /// Audit log entry for denied access attempts
    pub const AuditEntry = packed struct {
        timestamp: u32,
        handle: u32,
        required_access: u32,
        actual_access: u32,
        result: MediationResult,
        obj_type: ObjectType,
        _pad: u8,
    };

    const MAX_AUDIT_ENTRIES: usize = 64;
    var audit_log: [MAX_AUDIT_ENTRIES]AuditEntry = undefined;
    var audit_index: usize = 0;
    var audit_count: usize = 0;

    /// Log a denied access attempt to the audit trail
    pub fn logDeniedAccess(handle: u64, required_access: u32, actual_access: u32, result: MediationResult, obj_type: ObjectType) void {
        const entry = AuditEntry{
            .timestamp = @truncate(@as(u64, @intFromPtr(&audit_index))), // Approximate timestamp
            .handle = @truncate(handle),
            .required_access = required_access,
            .actual_access = actual_access,
            .result = result,
            .obj_type = obj_type,
            ._pad = 0,
        };
        audit_log[audit_index % MAX_AUDIT_ENTRIES] = entry;
        audit_index += 1;
        if (audit_count < MAX_AUDIT_ENTRIES) audit_count += 1;
    }

    /// Get the number of audit entries
    pub fn getAuditCount() usize {
        return audit_count;
    }

    /// Convert MediationResult to NTSTATUS (for NT syscall returns)
    pub fn mediationToNtstatus(result: MediationResult) u32 {
        // Import from subsystem.zig — we use raw values to avoid circular dep
        const STATUS_SUCCESS: u32 = 0x00000000;
        const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
        const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
        const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC0000024;
        return switch (result) {
            .Allowed => STATUS_SUCCESS,
            .DeniedInvalidHandle => STATUS_INVALID_HANDLE,
            .DeniedRevoked => STATUS_ACCESS_DENIED,
            .DeniedAccessMask => STATUS_ACCESS_DENIED,
            .DeniedWrongType => STATUS_OBJECT_TYPE_MISMATCH,
        };
    }

    /// Convert MediationResult to POSIX errno (for POSIX syscall returns)
    pub fn mediationToErrno(result: MediationResult) i32 {
        const EBADF: i32 = 9;
        const EACCES: i32 = 13;
        const EINVAL: i32 = 22;
        return switch (result) {
            .Allowed => 0,
            .DeniedInvalidHandle => EBADF,
            .DeniedRevoked => EACCES,
            .DeniedAccessMask => EACCES,
            .DeniedWrongType => EINVAL,
        };
    }

    /// Soft-revoke a handle: marks it revoked and bumps the generation counter
    pub fn revokeHandle(self: *Self, handle_index: usize) void {
        self.spinLock();
        defer self.spinUnlock();

        if (handle_index >= MAX_HANDLES) return;
        if (!self.handles[handle_index].in_use) return;

        self.handles[handle_index].cap_revoked = true;
        self.handles[handle_index].cap_generation += 1;
    }

    /// Check whether a handle has been revoked
    pub fn isHandleRevoked(self: *Self, handle_index: usize) bool {
        if (handle_index >= MAX_HANDLES) return false;
        return self.handles[handle_index].cap_revoked;
    }

    /// Look up a handle and return a pointer to the entry
    pub fn lookupHandle(self: *Self, handle: u64) ?*HandleEntry {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return null;
        if (!self.handles[idx].in_use) return null;
        return &self.handles[idx];
    }

    /// Close a handle (decrement ref count, free if zero)
    pub fn closeHandle(self: *Self, handle: u64) bool {
        self.spinLock();
        defer self.spinUnlock();

        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return false;
        if (!self.handles[idx].in_use) return false;

        self.handles[idx].ref_count -= 1;
        if (self.handles[idx].ref_count == 0) {
            self.handles[idx] = HandleEntry{};
        }

        return true;
    }

    /// Duplicate a handle (increment ref count)
    pub fn duplicateHandle(self: *Self, handle: u64) u64 {
        self.spinLock();

        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES or !self.handles[idx].in_use) {
            self.spinUnlock();
            return INVALID_HANDLE;
        }

        self.handles[idx].ref_count += 1;
        self.spinUnlock();

        return handle; // Same handle value, but with incremented ref count
    }

    /// Get object type for a handle
    pub fn getObjectType(self: *Self, handle: u64) ?ObjectType {
        const entry = self.lookupHandle(handle) orelse return null;
        return entry.obj_type;
    }

    /// Convert a POSIX file descriptor to an Object Manager handle
    /// fd 0 → handle for stdin, fd 1 → stdout, fd 2 → stderr
    /// fd N → handle N + NT_HANDLE_BASE (for the same underlying object)
    pub fn fdToHandle(fd: i32) u64 {
        if (fd < 0) return INVALID_HANDLE;
        return @intCast(fd); // For now, fd == handle index directly
    }

    /// Convert an Object Manager handle to a POSIX file descriptor
    pub fn handleToFd(handle: u64) i32 {
        const idx: usize = @intCast(handle);
        if (idx >= MAX_HANDLES) return -1;
        return @intCast(idx);
    }

    /// Set event signaled state
    pub fn setEvent(self: *Self, handle: u64, signaled: bool) bool {
        const entry = self.lookupHandle(handle) orelse return false;
        if (entry.obj_type != .Event) return false;
        entry.event_signaled = signaled;
        return true;
    }

    /// Acquire mutant (mutex)
    pub fn acquireMutant(self: *Self, handle: u64, thread_id: u32) bool {
        const entry = self.lookupHandle(handle) orelse return false;
        if (entry.obj_type != .Mutant) return false;

        if (entry.mutant_owner == 0) {
            // Unowned — acquire
            entry.mutant_owner = thread_id;
            entry.mutant_recursion = 1;
            return true;
        } else if (entry.mutant_owner == thread_id) {
            // Recursive acquire
            entry.mutant_recursion += 1;
            return true;
        }
        // Owned by another thread — would block (not implemented)
        return false;
    }

    /// Release mutant (mutex)
    pub fn releaseMutant(self: *Self, handle: u64, thread_id: u32) bool {
        const entry = self.lookupHandle(handle) orelse return false;
        if (entry.obj_type != .Mutant) return false;

        if (entry.mutant_owner != thread_id) return false; // Not owner
        entry.mutant_recursion -= 1;
        if (entry.mutant_recursion == 0) {
            entry.mutant_owner = 0; // Released
        }
        return true;
    }

    // Simple spinlock for handle table protection
    fn spinLock(self: *Self) void {
        while (@atomicRmw(u32, &self.lock, .Xchg, 1, .acquire) != 0) {
            asm volatile ("pause");
        }
    }

    fn spinUnlock(self: *Self) void {
        @atomicStore(u32, &self.lock, 0, .release);
    }
};

// ============================================================================
// Per-Process Handle Tables — v1.1.0
// ============================================================================
//
// In v1.0.0 the Object Manager used a single global handle table. This meant
// any process with a valid handle index could access any object — the classic
// Ambient Authority problem. An attacker who guesses a handle value can
// operate on objects they should never see.
//
// v1.1.0 introduces per-process handle tables. Each ProcessControlBlock
// references its own ObjectManager instance. A handle is valid ONLY within
// the process that created it. Handle values from different processes are
// isolated even if they happen to share the same integer value.
//
// Architecture:
//   ┌─────────────────────────────────────────────────────┐
//   │ Process A (PID 1)                                   │
//   │   ObjectManager { handle 4 → File A (READ only) }  │
//   └─────────────────────────────────────────────────────┘
//   ┌─────────────────────────────────────────────────────┐
//   │ Process B (PID 2)                                   │
//   │   ObjectManager { handle 4 → File B (READ|WRITE) } │
//   └─────────────────────────────────────────────────────┘
//
//   Handle 4 in Process A → File A with READ only
//   Handle 4 in Process B → File B with READ|WRITE
//   No cross-process handle leakage is possible.
//
// The global ObjectManager is retained for kernel-internal objects that
// are not associated with any process (e.g., IPC channels created by the
// kernel during boot). Process-scoped operations always use the per-process
// table obtained via getProcessOM(pid).
// ============================================================================

const MAX_PROCESS_OMS: usize = 64; // Matches MAX_PROCESSES in kernel_integrate

var process_oms: [MAX_PROCESS_OMS]ObjectManager = undefined;
var process_oms_initialized: [MAX_PROCESS_OMS]bool = [_]bool{false} ** MAX_PROCESS_OMS;

/// Initialize the per-process Object Manager for a given PID
pub fn initProcessOM(pid: u32) void {
    if (pid >= MAX_PROCESS_OMS) return;
    process_oms[pid].init();
    process_oms_initialized[pid] = true;
}

/// Get the ObjectManager for a specific process
pub fn getProcessOM(pid: u32) ?*ObjectManager {
    if (pid >= MAX_PROCESS_OMS) return null;
    if (!process_oms_initialized[pid]) {
        process_oms[pid].init();
        process_oms_initialized[pid] = true;
    }
    return &process_oms[pid];
}

/// Destroy all handles for a process (called on process termination)
pub fn destroyProcessOM(pid: u32) void {
    if (pid >= MAX_PROCESS_OMS) return;
    if (!process_oms_initialized[pid]) return;
    // Zero out the handle table — resources are freed by processMgrTerminate
    for (&process_oms[pid].handles) |*entry| {
        entry.* = HandleEntry{};
    }
    process_oms_initialized[pid] = false;
}

// ============================================================================
// Global Object Manager Singleton + Standalone Wrapper Functions
// ============================================================================
// These wrappers allow modules (like ipc.zig) to call createHandle/closeHandle
// without needing a direct reference to the ObjectManager instance.

var global_om: ObjectManager = undefined;
var global_om_initialized: bool = false;

/// Get the global ObjectManager instance (initializes on first call)
pub fn getGlobal() *ObjectManager {
    if (!global_om_initialized) {
        global_om.init();
        global_om_initialized = true;
    }
    return &global_om;
}

/// Standalone createHandle — uses global ObjectManager
pub fn createHandle(obj_type: ObjectType, access_mask: ?u32) ?u64 {
    const om = getGlobal();
    const handle = om.createHandle(obj_type, access_mask);
    if (handle == INVALID_HANDLE) return null;
    return handle;
}

/// Standalone closeHandle — uses global ObjectManager
pub fn closeHandle(handle: u64) bool {
    return getGlobal().closeHandle(handle);
}

/// Standalone lookupHandle — uses global ObjectManager
pub fn lookupHandle(handle: u64) ?*HandleEntry {
    return getGlobal().lookupHandle(handle);
}

// ============================================================================
// Intent ↔ Object Manager Integration — v1.1.0
// ============================================================================
//
// The Intent Dispatcher (poler/intent.zig) calls these functions during
// Phase 4 (Object Handle Verification) of intent dispatch.
//
// Flow:
//   Intent.dispatch()
//     → Phase 1: PND nonce verification
//     → Phase 2: Rate limiting
//     → Phase 3: Process-level capability check
//     → Phase 4: intentVerifyHandle() ← THIS FUNCTION
//         ├─ Lookup handle in the CALLER's per-process table
//         ├─ Check access_mask covers the requested action
//         └─ Return .Allowed / .NoHandle / .Insufficient
//
// This eliminates the TODO placeholders in intent.zig Phase 3 and Phase 4.
// ============================================================================

/// Verify that a handle exists in the caller's per-process table and that
/// its access_mask covers the requested access for the given IntentAction.
/// Called from Intent Dispatcher Phase 4.
///
/// Returns:
///   .Allowed       — handle exists and access_mask covers the action
///   .NoHandle      — handle doesn't exist in caller's table or is revoked
///   .Insufficient  — handle exists but access_mask doesn't cover the action
///   .Denied        — caller PID is invalid
pub fn intentVerifyHandle(caller_pid: u32, handle: u32, required_access: u32) IntentCheckResult {
    // Get the per-process ObjectManager for the caller
    const om = getProcessOM(caller_pid) orelse {
        // No per-process table — fall back to global (kernel processes)
        const gom = getGlobal();
        const idx: usize = handle;
        if (idx >= MAX_HANDLES) return .NoHandle;
        if (!gom.handles[idx].in_use) return .NoHandle;
        if (gom.handles[idx].cap_revoked) return .NoHandle;
        if ((gom.handles[idx].access_mask & required_access) != required_access) {
            return .Insufficient;
        }
        return .Allowed;
    };

    const idx: usize = handle;
    if (idx >= MAX_HANDLES) return .NoHandle;
    if (!om.handles[idx].in_use) return .NoHandle;
    if (om.handles[idx].cap_revoked) return .NoHandle;
    if ((om.handles[idx].access_mask & required_access) != required_access) {
        return .Insufficient;
    }
    return .Allowed;
}

/// Result of Intent ↔ Object Manager verification
pub const IntentCheckResult = enum(u8) {
    Allowed = 0,
    Denied = 1,
    NoHandle = 2,
    Insufficient = 3,
};

/// Get the access_mask of a handle in a process's per-process table.
/// Returns null if the handle doesn't exist or is revoked.
pub fn getHandleAccessMask(pid: u32, handle: u32) ?u32 {
    const om = getProcessOM(pid) orelse {
        // Fall back to global
        const gom = getGlobal();
        const idx: usize = handle;
        if (idx >= MAX_HANDLES) return null;
        if (!gom.handles[idx].in_use) return null;
        if (gom.handles[idx].cap_revoked) return null;
        return gom.handles[idx].access_mask;
    };
    const idx: usize = handle;
    if (idx >= MAX_HANDLES) return null;
    if (!om.handles[idx].in_use) return null;
    if (om.handles[idx].cap_revoked) return null;
    return om.handles[idx].access_mask;
}

/// Create a handle in a specific process's per-process table.
/// Returns the handle value on success, null on failure.
pub fn createProcessHandle(pid: u32, obj_type: ObjectType, access_mask: ?u32) ?u64 {
    const om = getProcessOM(pid) orelse return null;
    const handle = om.createHandle(obj_type, access_mask);
    if (handle == INVALID_HANDLE) return null;
    return handle;
}

/// Close a handle in a specific process's per-process table.
pub fn closeProcessHandle(pid: u32, handle: u64) bool {
    const om = getProcessOM(pid) orelse return false;
    return om.closeHandle(handle);
}
