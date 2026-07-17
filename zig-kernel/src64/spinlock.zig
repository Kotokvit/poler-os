// ============================================================================
// POLER-OS Spinlock — x86_64
// ============================================================================
//
// Thin wrapper around HAL spinlock primitives providing a named Spinlock type.
// Used by SMP, dynlinker, and other subsystems that need structured locks.
// ============================================================================

pub const Spinlock = struct {
    lock: u32 = 0,

    pub fn acquire(self: *@This()) void {
        while (@atomicRmw(u32, &self.lock, .Xchg, 1, .acquire) != 0) {
            asm volatile ("pause");
        }
    }

    pub fn release(self: *@This()) void {
        @atomicStore(u32, &self.lock, 0, .release);
    }

    pub fn isHeld(self: *const @This()) bool {
        return @atomicLoad(u32, &self.lock, .monotonic) != 0;
    }
};
