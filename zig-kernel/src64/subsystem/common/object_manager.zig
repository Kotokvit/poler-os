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

    pub fn init() Self {
        var om = Self{
            .handles = undefined,
            .next_handle = NT_HANDLE_BASE,
            .lock = 0,
        };
        for (&om.handles) |*entry| {
            entry.* = HandleEntry{};
        }

        // Pre-allocate standard handles
        // Handle 0-3: reserved (like Windows, handles 0-3 are invalid)
        // Handle 4+: available for allocation

        om.handles[0] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved
        om.handles[1] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved
        om.handles[2] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved
        om.handles[3] = HandleEntry{ .in_use = true, .obj_type = .Free }; // Reserved

        return om;
    }

    /// Create a new handle for the given object type
    pub fn createHandle(self: *Self, obj_type: ObjectType, access: u64) u64 {
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
                    .access_mask = @intCast(access & 0xFFFFFFFF),
                    .ref_count = 1,
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
