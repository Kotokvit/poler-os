// POLER-OS VirtIO Transport Layer
// Shared-memory communication between Zig microkernel and Linux Driver Server
// Implements VirtIO 1.1 specification — split virtqueues

const std = @import("std");

// ─── VirtIO PCI Constants ──────────────────────────────────────────────────

pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_PCI_DEVICE_ID_MIN: u16 = 0x1000; // virtio-net
pub const VIRTIO_PCI_DEVICE_ID_MAX: u16 = 0x103F; // virtio range

// VirtIO Device IDs
pub const VIRTIO_ID_NET: u16 = 1;
pub const VIRTIO_ID_BLOCK: u16 = 2;
pub const VIRTIO_ID_CONSOLE: u16 = 3;
pub const VIRTIO_ID_GPU: u16 = 16;
pub const VIRTIO_ID_INPUT: u16 = 18;

// VirtIO PCI Header offsets
pub const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
pub const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
pub const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
pub const VIRTIO_PCI_QUEUE_NUM: u16 = 0x0C;
pub const VIRTIO_PCI_QUEUE_SEL: u16 = 0x0E;
pub const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
pub const VIRTIO_PCI_STATUS: u16 = 0x12;
pub const VIRTIO_PCI_ISR: u16 = 0x13;
pub const VIRTIO_PCI_CONFIG: u16 = 0x14;

// Status bits
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

// Descriptor flags
pub const VIRTIO_DESC_F_NEXT: u16 = 1;
pub const VIRTIO_DESC_F_WRITE: u16 = 2;
pub const VIRTIO_DESC_F_INDIRECT: u16 = 4;

// ─── VirtIO Data Structures ────────────────────────────────────────────────

/// VirtIO queue descriptor (16 bytes)
pub const VirtQueueDesc = extern struct {
    addr: u64,    // Guest physical address
    len: u32,     // Length of buffer
    flags: u16,   // VIRTIO_DESC_F_*
    next: u16,    // Next descriptor index (if F_NEXT)
};

/// VirtIO available ring
pub const VirtQueueAvail = extern struct {
    flags: u16,
    idx: u16,           // Next free slot
    ring: [0]u16,       // Variable length — indices into descriptor table
    used_event: u16,    // Last used index (for notifications)
};

/// VirtIO used ring entry
pub const VirtQueueUsedElem = extern struct {
    id: u32,    // Head descriptor index
    len: u32,   // Length written
};

/// VirtIO used ring
pub const VirtQueueUsed = extern struct {
    flags: u16,
    idx: u16,               // Next used slot
    ring: [0]VirtQueueUsedElem, // Variable length
    avail_event: u16,       // For notifications
};

/// Complete virtqueue structure
pub const VirtQueue = struct {
    queue_size: u16,
    desc: [*]VirtQueueDesc,
    avail: [*]VirtQueueAvail,
    used: [*]VirtQueueUsed,
    desc_phys: u64,   // Physical addresses for DMA
    avail_phys: u64,
    used_phys: u64,
    last_used_idx: u16,
    last_avail_idx: u16,
    io_base: u16,     // PCI I/O base port
};

// ─── VirtIO Device ─────────────────────────────────────────────────────────

pub const VirtIODevice = struct {
    device_type: u16,
    io_base: u16,
    irq: u8,
    queues: [8]?VirtQueue,
    num_queues: u8,
    features: u32,
    
    pub fn init(io_base: u16, device_type: u16) VirtIODevice {
        return VirtIODevice{
            .device_type = device_type,
            .io_base = io_base,
            .irq = 0,
            .queues = [_]?VirtQueue{null} ** 8,
            .num_queues = 0,
            .features = 0,
        };
    }
    
    /// Read 8-bit from VirtIO register
    pub fn read8(self: *VirtIODevice, offset: u16) u8 {
        return inb(self.io_base + offset);
    }
    
    /// Read 32-bit from VirtIO register
    pub fn read32(self: *VirtIODevice, offset: u16) u32 {
        return inl(self.io_base + offset);
    }
    
    /// Write 8-bit to VirtIO register
    pub fn write8(self: *VirtIODevice, offset: u16, val: u8) void {
        outb(self.io_base + offset, val);
    }
    
    /// Write 32-bit to VirtIO register
    pub fn write32(self: *VirtIODevice, offset: u16, val: u32) void {
        outl(self.io_base + offset, val);
    }
    
    /// Write 16-bit to VirtIO register
    pub fn write16(self: *VirtIODevice, offset: u16, val: u16) void {
        outw(self.io_base + offset, val);
    }
    
    /// Initialize the device following VirtIO 1.1 initialization sequence
    pub fn initialize(self: *VirtIODevice) bool {
        // 1. Reset device
        self.write8(VIRTIO_PCI_STATUS, 0);
        
        // 2. Acknowledge device
        self.write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        
        // 3. We know how to drive this device
        self.write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        
        // 4. Negotiate features
        const host_features = self.read32(VIRTIO_PCI_HOST_FEATURES);
        self.features = host_features; // Accept all for now
        self.write32(VIRTIO_PCI_GUEST_FEATURES, self.features);
        
        // 5. Set FEATURES_OK
        self.write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
        
        // 6. Re-read status to confirm FEATURES_OK
        const status = self.read8(VIRTIO_PCI_STATUS);
        if ((status & VIRTIO_STATUS_FEATURES_OK) == 0) {
            return false; // Feature negotiation failed
        }
        
        // 7. Setup queues (will be done per-device)
        
        // 8. DRIVER_OK
        self.write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
        
        return true;
    }
    
    /// Setup a specific virtqueue
    pub fn setup_queue(self: *VirtIODevice, queue_idx: u16, queue_size: u16, desc_phys: u64, avail_phys: u64, used_phys: u64) void {
        // Select the queue
        self.write16(VIRTIO_PCI_QUEUE_SEL, queue_idx);
        
        // Set size
        self.write16(VIRTIO_PCI_QUEUE_NUM, queue_size);
        
        // Set descriptor table physical address
        self.write32(VIRTIO_PCI_QUEUE_PFN, @truncate(desc_phys >> 12));
        
        // Store queue info
        if (queue_idx < 8) {
            self.queues[queue_idx] = VirtQueue{
                .queue_size = queue_size,
                .desc = @ptrFromInt(@as(usize, @intCast(desc_phys))),
                .avail = @ptrFromInt(@as(usize, @intCast(avail_phys))),
                .used = @ptrFromInt(@as(usize, @intCast(used_phys))),
                .desc_phys = desc_phys,
                .avail_phys = avail_phys,
                .used_phys = used_phys,
                .last_used_idx = 0,
                .last_avail_idx = 0,
                .io_base = self.io_base,
            };
            if (queue_idx >= self.num_queues) {
                self.num_queues = @intCast(queue_idx + 1);
            }
        }
    }
    
    /// Notify the device that a buffer is available
    pub fn notify_queue(self: *VirtIODevice, queue_idx: u16) void {
        self.write16(VIRTIO_PCI_QUEUE_NOTIFY, queue_idx);
    }
};

// ─── VirtIO Block Device (virtio-blk) ──────────────────────────────────────

pub const VIRTIO_BLK_T_IN: u32 = 0;      // Read
pub const VIRTIO_BLK_T_OUT: u32 = 1;      // Write
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;    // Flush
pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Block device request header
pub const VirtBlkReqHeader = extern struct {
    type: u32,     // VIRTIO_BLK_T_*
    reserved: u32,
    sector: u64,   // Sector number (512-byte units)
};

/// Block device configuration (read from PCI config space)
pub const VirtBlkConfig = extern struct {
    capacity: u64,         // Number of 512-byte sectors
    size_max: u32,         // Max segment size
    seg_max: u32,          // Max segments per request
    geometry_cylinders: u16,
    geometry_heads: u8,
    geometry_sectors: u8,
    blk_size: u32,         // Block size (usually 512)
};

/// Block device wrapper
pub const VirtBlkDevice = struct {
    virtio: VirtIODevice,
    config: VirtBlkConfig,
    
    pub fn init(io_base: u16) VirtBlkDevice {
        var dev = VirtBlkDevice{
            .virtio = VirtIODevice.init(io_base, VIRTIO_ID_BLOCK),
            .config = std.mem.zeroes(VirtBlkConfig),
        };
        return dev;
    }
    
    /// Read block device configuration
    pub fn read_config(self: *VirtBlkDevice) void {
        const config_offset = VIRTIO_PCI_CONFIG;
        var buf: [@sizeOf(VirtBlkConfig)]u8 align(4) = undefined;
        
        var i: u16 = 0;
        while (i < @sizeOf(VirtBlkConfig)) : (i += 4) {
            const val = self.virtio.read32(config_offset + i);
            @as(*u32, @ptrCast(@alignCast(&buf[i]))).* = val;
        }
        
        self.config = @as(*VirtBlkConfig, @ptrCast(@alignCast(&buf[0]))).*);
    }
    
    /// Initialize block device
    pub fn initialize(self: *VirtBlkDevice) bool {
        if (!self.virtio.initialize()) return false;
        self.read_config();
        return true;
    }
    
    /// Get capacity in bytes
    pub fn capacity_bytes(self: *VirtBlkDevice) u64 {
        return self.config.capacity * 512;
    }
};

// ─── VirtIO Console (virtio-serial) ────────────────────────────────────────

pub const VirtConsoleDevice = struct {
    virtio: VirtIODevice,
    
    pub fn init(io_base: u16) VirtConsoleDevice {
        return VirtConsoleDevice{
            .virtio = VirtIODevice.init(io_base, VIRTIO_ID_CONSOLE),
        };
    }
    
    pub fn initialize(self: *VirtConsoleDevice) bool {
        return self.virtio.initialize();
    }
    
    /// Send a byte through the console
    pub fn write_byte(self: *VirtConsoleDevice, ch: u8) void {
        // In simplified mode, write directly to the port buffer
        // Full implementation would use a descriptor chain
        _ = ch;
        // TODO: Implement via virtqueue descriptor chain
    }
};

// ─── PCI Configuration Space Access ────────────────────────────────────────

pub const PCI_CONFIG_ADDR: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

pub const PciDevice = extern struct {
    vendor_id: u16,
    device_id: u16,
    command: u16,
    status: u16,
    revision: u8,
    prog_if: u8,
    subclass: u8,
    class_code: u8,
    cache_line_size: u8,
    latency_timer: u8,
    header_type: u8,
    bist: u8,
    bar: [6]u32,
    cardbus_cis: u32,
    subsystem_vendor: u16,
    subsystem_device: u16,
    expansion_rom: u32,
    capabilities: u8,
    reserved: [7]u8,
    interrupt_line: u8,
    interrupt_pin: u8,
    min_grant: u8,
    max_latency: u8,
};

/// Read PCI configuration register
pub fn pci_read32(bus: u8, slot: u8, func: u8, offset: u8) u32 {
    const addr = (@as(u32, 1) << 31) | 
                 (@as(u32, bus) << 16) | 
                 (@as(u32, slot) << 11) | 
                 (@as(u32, func) << 8) | 
                 (@as(u32, offset) & 0xFC);
    outl(PCI_CONFIG_ADDR, addr);
    return inl(PCI_CONFIG_DATA);
}

/// Write PCI configuration register
pub fn pci_write32(bus: u8, slot: u8, func: u8, offset: u8, val: u32) void {
    const addr = (@as(u32, 1) << 31) | 
                 (@as(u32, bus) << 16) | 
                 (@as(u32, slot) << 11) | 
                 (@as(u32, func) << 8) | 
                 (@as(u32, offset) & 0xFC);
    outl(PCI_CONFIG_ADDR, addr);
    outl(PCI_CONFIG_DATA, val);
}

/// Read PCI configuration 16-bit
pub fn pci_read16(bus: u8, slot: u8, func: u8, offset: u8) u16 {
    const val = pci_read32(bus, slot, func, offset);
    return @truncate(val >> (8 * (@as(u32, offset) & 2)));
}

/// Scan PCI bus for VirtIO devices
pub fn scan_virtio_devices() [8]?VirtIODevice {
    var devices: [8]?VirtIODevice = [_]?VirtIODevice{null} ** 8;
    var dev_count: u8 = 0;
    
    var bus: u8 = 0;
    while (bus < 256) : (bus += 1) {
        var slot: u8 = 0;
        while (slot < 32) : (slot += 1) {
            const vendor = pci_read16(bus, slot, 0, 0);
            if (vendor == 0xFFFF) continue;
            
            const device_id = pci_read16(bus, slot, 0, 2);
            
            // Check for VirtIO vendor (Red Hat / QEMU)
            if (vendor == VIRTIO_PCI_VENDOR_ID and 
                device_id >= VIRTIO_PCI_DEVICE_ID_MIN and 
                device_id <= VIRTIO_PCI_DEVICE_ID_MAX) {
                
                // Determine device type from subsystem
                const subsystem = pci_read16(bus, slot, 0, 0x2C);
                
                // Get I/O base from BAR0
                const bar0 = pci_read32(bus, slot, 0, 0x10);
                const io_base: u16 = if ((bar0 & 1) != 0) 
                    @truncate(bar0 & 0xFFFC) 
                else 
                    0;
                
                if (io_base != 0 and dev_count < 8) {
                    devices[dev_count] = VirtIODevice.init(io_base, subsystem);
                    dev_count += 1;
                }
            }
        }
    }
    
    return devices;
}

// ─── I/O Port Helpers ──────────────────────────────────────────────────────

fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "N{dx}" (port),
    );
}

fn outw(port: u16, val: u16) void {
    asm volatile ("outw %[val], %[port]"
        :
        : [val] "{ax}" (val),
          [port] "N{dx}" (port),
    );
}

fn outl(port: u16, val: u32) void {
    asm volatile ("outl %[val], %[port]"
        :
        : [val] "{eax}" (val),
          [port] "N{dx}" (port),
    );
}

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "=al" (-> u8),
        : [port] "N{dx}" (port),
    );
}

fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "=eax" (-> u32),
        : [port] "N{dx}" (port),
    );
}
