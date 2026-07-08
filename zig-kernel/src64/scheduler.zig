// ============================================================================
// POLER-OS Task Scheduler — x86_64
// ============================================================================

const hal = @import("hal.zig");

pub const MAX_TASKS = 8;

pub const TaskState = enum {
    Ready,
    Running,
    Killed,
};

pub const Task = struct {
    id: usize,
    state: TaskState,
    rsp: u64, // Saved stack pointer (points to saved InterruptFrame in kernel_stack)
    kernel_stack: [4096]u8 align(16), // Ring 0 stack
    user_stack: [4096]u8 align(16),   // Ring 3 stack
};

pub var tasks: [MAX_TASKS]Task = undefined;
pub var current_task_id: usize = 0;
pub var task_count: usize = 0;

// Exported variables for assembly syscall_entry
pub export var user_rsp: u64 = 0;
pub export var current_kernel_stack: u64 = 0;

pub fn init() void {
    task_count = 0;
    current_task_id = 0;
    
    // Create idle task (Task 0) — maps to the main kernel thread
    tasks[0] = Task{
        .id = 0,
        .state = .Running,
        .rsp = 0,
        .kernel_stack = undefined,
        .user_stack = undefined,
    };
    task_count = 1;
    
    // Set initial kernel stack top (corresponds to stack_top in linker64.ld)
    current_kernel_stack = 0x10b000;
    
    hal.Serial.puts("[SCHED] Scheduler initialized\n");
}

/// Mark a task as Killed. The idle task (id 0) CANNOT be killed —
/// it is the scheduler's safety net and must always remain schedulable.
pub fn killTask(id: usize) !void {
    if (id == 0) return error.InvalidTask;
    if (id >= task_count) return error.InvalidTask;
    tasks[id].state = .Killed;
    hal.Serial.puts("[SCHED] Killed task ");
    hal.Serial.putHex(id);
    hal.Serial.puts("\n");
}

pub fn createTask(entry_point: u64) !usize {
    if (task_count >= MAX_TASKS) return error.OutOfTasks;

    const id = task_count;
    task_count += 1;

    const task = &tasks[id];
    task.id = id;
    task.state = .Ready;

    // Set up the initial stack frame in the kernel stack.
    // The CPU expects this layout when restoring registers to jump to Ring 3.
    const kstack_top = @intFromPtr(&task.kernel_stack) + task.kernel_stack.len;
    const ustack_top = @intFromPtr(&task.user_stack) + task.user_stack.len;
    
    // InterruptFrame is 176 bytes. Place it at the top of kernel stack.
    const frame_ptr: *hal.InterruptFrame = @ptrFromInt(kstack_top - 176);
    
    // Clear the stack frame initial contents
    @memset(@as([*]volatile u8, @ptrCast(frame_ptr))[0..176], 0);

    // Set up segment registers and execution context
    frame_ptr.rip = entry_point;
    frame_ptr.cs = 0x23; // User code segment selector with RPL=3
    frame_ptr.rflags = 0x202; // IF (Interrupt Enable Flag) set
    frame_ptr.rsp = ustack_top - 8; // User stack pointer aligned to 16-bytes - 8 (x86_64 ABI requirement)
    frame_ptr.ss = 0x1B; // User data segment selector with RPL=3
    frame_ptr.vector = 32; // IRQ0 vector (timer)
    
    // Save stack pointer to task control block
    task.rsp = @intFromPtr(frame_ptr);

    hal.Serial.puts("[SCHED] Created task ");
    hal.Serial.putHex(id);
    hal.Serial.puts(" at entry ");
    hal.Serial.putHex(entry_point);
    hal.Serial.puts("\n");

    return id;
}

pub fn schedule(current_rsp: u64) u64 {
    if (task_count <= 1) return current_rsp; // Only idle/kernel task exists

    // Save RSP of the current task
    tasks[current_task_id].rsp = current_rsp;
    if (tasks[current_task_id].state == .Running) {
        tasks[current_task_id].state = .Ready;
    }

    // Select the next task using Round-Robin
    var next_id = (current_task_id + 1) % task_count;
    var checked: usize = 0;
    while (checked < task_count) : ({
        next_id = (next_id + 1) % task_count;
        checked += 1;
    }) {
        if (tasks[next_id].state == .Ready or tasks[next_id].state == .Running) {
            break;
        }
    }

    // Safety: if no Ready/Running task found, stay on current if it's not Killed
    if (tasks[next_id].state == .Killed) {
        // All tasks are killed — spin on idle (task 0)
        next_id = 0;
        if (tasks[0].state == .Killed) {
            // Even idle is killed — shouldn't happen, but prevent resurrection
            tasks[0].state = .Running;
        }
    }

    current_task_id = next_id;
    tasks[current_task_id].state = .Running;

    // Update TSS.rsp0 and current_kernel_stack
    const next_task = &tasks[current_task_id];
    if (next_task.id != 0) {
        const kstack_top = @intFromPtr(&next_task.kernel_stack) + next_task.kernel_stack.len;
        hal.setKernelStack(kstack_top);
        current_kernel_stack = kstack_top;
    } else {
        // Idle/Kernel task uses the main boot stack
        hal.setKernelStack(0x10b000);
        current_kernel_stack = 0x10b000;
    }

    return next_task.rsp;
}
