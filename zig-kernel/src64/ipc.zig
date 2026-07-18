// ============================================================================
// POLER-OS IPC — Channel-Based Inter-Process Communication
// ============================================================================
//
// Zircon-inspired Channel IPC. Each Channel has two endpoints (handles).
// Messages are fixed-size with bounded queues.
//
// Architecture:
//   Process A ←→ Handle end_a ←→ Channel ←→ Handle end_b ←→ Process B
//
// Capability-passing: a message can carry a handle that is transferred
// from sender to receiver. The handle is removed from sender's table
// and added to receiver's table.
//
// This replaces the stub LPC/pipe implementations in nt_api/posix_api.
// ============================================================================

const hal = @import("hal.zig");
const objmgr = @import("subsystem/common/object_manager.zig");
const scheduler = @import("scheduler.zig");

// ============================================================================
// Message Constants
// ============================================================================

pub const MSG_PAYLOAD_SIZE: usize = 56;
pub const MSG_HEADER_SIZE: usize = 8;
pub const MSG_TOTAL_SIZE: usize = MSG_HEADER_SIZE + MSG_PAYLOAD_SIZE; // 64 bytes
pub const CHANNEL_QUEUE_SIZE: usize = 16;

// ============================================================================
// Message Structure
// ============================================================================

pub const IpcMessage = extern struct {
    // Header (8 bytes)
    msg_type: u16,       // Message type identifier
    flags: u16,          // Flags (e.g., carries_handle)
    payload_len: u16,    // Actual payload length (≤ MSG_PAYLOAD_SIZE)
    carries_handle: u16, // If non-zero, this is a handle being transferred
    
    // Payload (56 bytes)
    payload: [MSG_PAYLOAD_SIZE]u8,
};

pub const MSG_TYPE_DATA: u16 = 0x0001;
pub const MSG_TYPE_SIGNAL: u16 = 0x0002;
pub const MSG_TYPE_CAP_TRANSFER: u16 = 0x0003;
pub const MSG_TYPE_SYNC_REQUEST: u16 = 0x0004;
pub const MSG_TYPE_SYNC_REPLY: u16 = 0x0005;

pub const MSG_FLAG_URGENT: u16 = 0x0001;
pub const MSG_FLAG_NONE: u16 = 0x0000;

// ============================================================================
// Channel Structure
// ============================================================================

pub const Channel = struct {
    in_use: bool = false,
    end_a_handle: u64 = 0,  // Object Manager handle for endpoint A
    end_b_handle: u64 = 0,  // Object Manager handle for endpoint B
    
    // Queues: A→B and B→A
    queue_a_to_b: [CHANNEL_QUEUE_SIZE]IpcMessage = undefined,
    queue_a_to_b_head: usize = 0,
    queue_a_to_b_tail: usize = 0,
    queue_a_to_b_count: usize = 0,
    
    queue_b_to_a: [CHANNEL_QUEUE_SIZE]IpcMessage = undefined,
    queue_b_to_a_head: usize = 0,
    queue_b_to_a_tail: usize = 0,
    queue_b_to_a_count: usize = 0,
    
    lock: u32 = 0, // Spinlock
};

// ============================================================================
// Channel Table
// ============================================================================

const MAX_CHANNELS: usize = 32;

var channels: [MAX_CHANNELS]Channel = undefined;
var channel_count: usize = 0;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    for (&channels) |*ch| {
        ch.* = Channel{};
    }
    channel_count = 0;
    hal.Serial.puts("[IPC] Channel IPC initialized (max ");
    hal.Serial.putDecimal(MAX_CHANNELS);
    hal.Serial.puts(" channels)\n");
}

// ============================================================================
// Channel Creation
// ============================================================================

/// Create a new Channel with two endpoint handles.
/// Returns (handle_a, handle_b) or null on failure.
pub fn createChannel() ?struct { handle_a: u64, handle_b: u64 } {
    // Find a free channel slot
    var slot: ?*Channel = null;
    for (&channels) |*ch| {
        if (!ch.in_use) {
            slot = ch;
            break;
        }
    }
    
    const ch = slot orelse {
        hal.Serial.puts("[IPC] No free channel slots\n");
        return null;
    };
    
    // Initialize the channel
    ch.* = Channel{ .in_use = true };
    
    // Create two handles in Object Manager for the endpoints
    // access_mask = 0x00000003 (READ=1 | WRITE=2)
    const handle_a = objmgr.createHandle(objmgr.ObjectType.Port, 0x00000003) orelse {
        ch.in_use = false;
        return null;
    };
    
    const handle_b = objmgr.createHandle(objmgr.ObjectType.Port, 0x00000003) orelse {
        objmgr.closeHandle(handle_a);
        ch.in_use = false;
        return null;
    };
    
    ch.end_a_handle = handle_a;
    ch.end_b_handle = handle_b;
    channel_count += 1;
    
    hal.Serial.puts("[IPC] Created channel: end_a=");
    hal.Serial.putHex(handle_a);
    hal.Serial.puts(" end_b=");
    hal.Serial.putHex(handle_b);
    hal.Serial.puts("\n");
    
    return .{ .handle_a = handle_a, .handle_b = handle_b };
}

// ============================================================================
// Send / Receive
// ============================================================================

/// Send a message through a channel endpoint.
/// `sender_handle` is the handle of the sending endpoint.
/// Returns true on success, false if queue is full or handle invalid.
/// Access mediation: checks ACCESS_WRITE on the Port handle before sending.
pub fn channelSend(sender_handle: u64, msg: *const IpcMessage) bool {
    // Access mediation: verify the handle grants WRITE access
    const om = objmgr.getGlobal();
    const med = om.mediateChannelSend(sender_handle);
    if (med != .Allowed) {
        hal.Serial.puts("[IPC] Send DENIED: access mask violation (");
        hal.Serial.putDecimal(@intFromEnum(med));
        hal.Serial.puts(")\n");
        objmgr.ObjectManager.logDeniedAccess(sender_handle, objmgr.ACCESS_WRITE, 0, med, .Port);
        return false;
    }

    const ch = findChannelByHandle(sender_handle) orelse {
        hal.Serial.puts("[IPC] Send: handle not found\n");
        return false;
    };
    
    // Determine direction: if sender is end_a, queue goes a→b
    const is_end_a = (sender_handle == ch.end_a_handle);
    
    if (is_end_a) {
        return enqueue(&ch.queue_a_to_b, &ch.queue_a_to_b_head, &ch.queue_a_to_b_tail, &ch.queue_a_to_b_count, msg);
    } else {
        return enqueue(&ch.queue_b_to_a, &ch.queue_b_to_a_head, &ch.queue_b_to_a_tail, &ch.queue_b_to_a_count, msg);
    }
}

/// Receive a message from a channel endpoint.
/// `receiver_handle` is the handle of the receiving endpoint.
/// Returns the message, or null if queue is empty.
/// Access mediation: checks ACCESS_READ on the Port handle before receiving.
pub fn channelReceive(receiver_handle: u64) ?IpcMessage {
    // Access mediation: verify the handle grants READ access
    const om = objmgr.getGlobal();
    const med = om.mediateChannelReceive(receiver_handle);
    if (med != .Allowed) {
        hal.Serial.puts("[IPC] Receive DENIED: access mask violation (");
        hal.Serial.putDecimal(@intFromEnum(med));
        hal.Serial.puts(")\n");
        objmgr.ObjectManager.logDeniedAccess(receiver_handle, objmgr.ACCESS_READ, 0, med, .Port);
        return null;
    }

    const ch = findChannelByHandle(receiver_handle) orelse return null;
    
    // If receiver is end_a, messages come from b→a queue
    const is_end_a = (receiver_handle == ch.end_a_handle);
    
    if (is_end_a) {
        return dequeue(&ch.queue_b_to_a, &ch.queue_b_to_a_head, &ch.queue_b_to_a_tail, &ch.queue_b_to_a_count);
    } else {
        return dequeue(&ch.queue_a_to_b, &ch.queue_a_to_b_head, &ch.queue_a_to_b_tail, &ch.queue_a_to_b_count);
    }
}

/// Check if a channel endpoint has pending messages.
pub fn channelHasData(handle: u64) bool {
    const ch = findChannelByHandle(handle) orelse return false;
    const is_end_a = (handle == ch.end_a_handle);
    
    if (is_end_a) {
        return ch.queue_b_to_a_count > 0;
    } else {
        return ch.queue_a_to_b_count > 0;
    }
}

/// Destroy a channel — closes both handles.
pub fn destroyChannel(ch: *Channel) void {
    objmgr.closeHandle(ch.end_a_handle);
    objmgr.closeHandle(ch.end_b_handle);
    ch.in_use = false;
    channel_count -= 1;
    hal.Serial.puts("[IPC] Channel destroyed\n");
}

// ============================================================================
// Internal helpers
// ============================================================================

fn findChannelByHandle(handle: u64) ?*Channel {
    for (&channels) |*ch| {
        if (ch.in_use and (ch.end_a_handle == handle or ch.end_b_handle == handle)) {
            return ch;
        }
    }
    return null;
}

fn enqueue(queue: *[CHANNEL_QUEUE_SIZE]IpcMessage, head: *usize, tail: *usize, count: *usize, msg: *const IpcMessage) bool {
    _ = head;
    if (count.* >= CHANNEL_QUEUE_SIZE) {
        hal.Serial.puts("[IPC] Queue full — message dropped\n");
        return false;
    }
    
    queue[tail.*] = msg.*;
    tail.* = (tail.* + 1) % CHANNEL_QUEUE_SIZE;
    count.* += 1;
    return true;
}

fn dequeue(queue: *[CHANNEL_QUEUE_SIZE]IpcMessage, head: *usize, tail: *usize, count: *usize) ?IpcMessage {
    _ = tail;
    if (count.* == 0) return null;
    
    const msg = queue[head.*];
    head.* = (head.* + 1) % CHANNEL_QUEUE_SIZE;
    count.* -= 1;
    return msg;
}
