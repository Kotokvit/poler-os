// ============================================================================
// POLER-OS ACPI — Advanced Configuration and Power Interface
// ============================================================================
//
// Черновик: Linux drivers/acpi/ (50K+ строк)
// Чистовик: POLER — только RSDP → XSDT → MADT → MCFG (для APIC + PCIe)
//
// Зачем нам ACPI:
//   1. MADT (Multiple APIC Description Table) → сколько CPU, IO-APIC адреса
//   2. MCFG (PCI Configuration Space) → базовый адрес PCIe конфигурации
//   3. HPET (High Precision Event Timer) → альтернатива PIT
//   4. DSDT/SSDT → информация об устройствах (для будущего)
// ============================================================================

const hal = @import("hal.zig");

// ============================================================================
// ACPI Table Header (общий для всех таблиц)
// ============================================================================

pub const TableHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
};

// ============================================================================
// RSDP (Root System Description Pointer)
// Черновик: Linux drivers/acpi/osl.c → acpi_os_get_root_pointer()
// ============================================================================

pub const RSDP = extern struct {
    signature: [8]u8,       // "RSD PTR "
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,           // 0 = ACPI 1.0, 2 = ACPI 2.0+
    rsdt_address: u32,      // RSDT (32-bit, ACPI 1.0)
    length: u32,            // Total length of RSDP (ACPI 2.0+)
    xsdt_address: u64,      // XSDT (64-bit, ACPI 2.0+)
    extended_checksum: u8,
    _reserved: [3]u8,

    pub fn is_valid(self: *const RSDP) bool {
        // Check signature "RSD PTR "
        const expected_sig = "RSD PTR ";
        for (expected_sig, 0..) |ch, i| {
            if (self.signature[i] != ch) return false;
        }
        // Checksum validation (sum of all bytes = 0 mod 256)
        if (!validateChecksum(@ptrCast(self), 20)) return false; // ACPI 1.0 portion
        if (self.revision >= 2) {
            if (!validateChecksum(@ptrCast(self), @intCast(self.length))) return false;
        }
        return true;
    }
};

// ============================================================================
// RSDT / XSDT (Root/Extended System Description Table)
// Черновик: Linux drivers/acpi/tables.c
// ============================================================================

pub const RSDT = extern struct {
    header: TableHeader,
    entries: [0]u32, // Variable length array of 32-bit physical addresses
};

pub const XSDT = extern struct {
    header: TableHeader,
    entries: [0]u64, // Variable length array of 64-bit physical addresses
};

// ============================================================================
// MADT (Multiple APIC Description Table)
// Черновик: Linux arch/x86/kernel/acpi/boot.c → acpi_process_madt()
// Нам нужно: количество CPU, адрес Local APIC, адрес IO-APIC
// ============================================================================

pub const MADT = extern struct {
    header: TableHeader,
    local_apic_address: u32,    // Physical address of Local APIC
    flags: u32,                 // 1 = PCAT_COMPAT (has dual-8259 setup)
    entries: [0]u8,             // Variable length: APIC structures follow
};

pub const MADTEntryType = enum(u8) {
    LocalAPIC = 0,
    IOAPIC = 1,
    InterruptOverride = 2,
    NMI = 3,
    LocalAPICNMI = 4,
    LocalAPICOverride = 5,
    IOSAPIC = 6,
    LocalSAPIC = 7,
    PlatformInterrupt = 8,
    _,
};

pub const MADTLocalAPIC = extern struct {
    type: u8,           // 0
    length: u8,         // 8
    acpi_processor_id: u8,
    apic_id: u8,
    flags: u32,         // Bit 0 = enabled
};

pub const MADTIOAPIC = extern struct {
    type: u8,           // 1
    length: u8,         // 12
    ioapic_id: u8,
    _reserved: u8,
    ioapic_address: u32,
    global_irq_base: u32,
};

pub const MADTInterruptOverride = extern struct {
    type: u8,           // 2
    length: u8,         // 10
    bus: u8,            // 0 = ISA
    source_irq: u8,
    global_irq: u32,
    flags: u16,         // Polarity + Trigger mode
};

// ============================================================================
// MCFG (PCI Configuration Space)
// Черновик: Linux drivers/acpi/pci_mcfg.c
// ============================================================================

pub const MCFG = extern struct {
    header: TableHeader,
    _reserved: u64,
    entries: [0]MCFGEntry,
};

pub const MCFGEntry = extern struct {
    base_address: u64,      // Base address of enhanced config space
    pci_segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    _reserved: u32,
};

// ============================================================================
// ACPI State
// ============================================================================

pub var rsdp: ?*const RSDP = null;
pub var cpu_count: u32 = 0;
pub var local_apic_addr: u64 = 0;
pub var io_apic_addr: u64 = 0;
pub var io_apic_count: u32 = 0;
pub var mcfg_base: u64 = 0;

// IRQ override table (ISA → Global IRQ mapping)
pub const MAX_IRQ_OVERRIDES = 16;
pub var irq_overrides: [MAX_IRQ_OVERRIDES]IRQOverride = undefined;
pub var irq_override_count: u32 = 0;

pub const IRQOverride = struct {
    source_irq: u8,
    global_irq: u32,
    flags: u16,
};

// ============================================================================
// Функции
// ============================================================================

fn validateChecksum(ptr: [*]const u8, len: u32) bool {
    var sum: u8 = 0;
    for (0..len) |i| {
        sum +%= ptr[i];
    }
    return sum == 0;
}

fn memEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn signatureEquals(sig: *const [4]u8, expected: *const [4]u8) bool {
    return sig[0] == expected[0] and sig[1] == expected[1] and sig[2] == expected[2] and sig[3] == expected[3];
}

/// Physical memory read (identity-mapped, so just cast pointer)
fn physToPtr(phys: u64) *anyopaque {
    return @ptrFromInt(@as(usize, phys));
}

/// Поиск RSDP в памяти
/// Черновик: Linux scans BIOS area (0xE0000-0xFFFFF) + EBDA
pub fn findRSDP() ?*const RSDP {
    // Метод 1: Поиск в BIOS ROM area (0xE0000 - 0xFFFFF)
    // Это стандартное расположение для BIOS ACPI tables
    var addr: u64 = 0xE0000;
    while (addr < 0x100000) : (addr += 16) {
        const candidate: *const RSDP = @ptrFromInt(@as(usize, addr));
        if (candidate.is_valid()) {
            return candidate;
        }
    }

    // Метод 2: Через EFI system table (если загружены через EFI)
    // TODO: Multiboot2 может передать EFI_SYSTEM_TABLE

    // Метод 3: Через EBDA (Extended BIOS Data Area)
    // EBDA address хранится по 0x40E
    const ebda_segment: u16 = @as(*const volatile u16, @ptrFromInt(@as(usize, 0x40E))).*;
    const ebda_addr: u64 = @as(u64, ebda_segment) << 4;
    if (ebda_addr >= 0x400 and ebda_addr < 0xA0000) {
        var scan_addr = ebda_addr;
        while (scan_addr < ebda_addr + 1024) : (scan_addr += 16) {
            const candidate: *const RSDP = @ptrFromInt(@as(usize, scan_addr));
            if (candidate.is_valid()) {
                return candidate;
            }
        }
    }

    return null;
}

/// Парсинг ACPI таблиц
pub fn init() void {
    hal.Serial.puts("[ACPI] Searching for RSDP...\n");

    rsdp = findRSDP() orelse {
        hal.Serial.puts("[ACPI] RSDP NOT FOUND! ACPI unavailable\n");
        return;
    };

    hal.Serial.puts("[ACPI] RSDP found at: ");
    hal.Serial.putHex(@intFromPtr(rsdp.?));
    hal.Serial.puts("\n");

    if (rsdp.?.revision >= 2 and rsdp.?.xsdt_address != 0) {
        parseXSDT();
    } else if (rsdp.?.rsdt_address != 0) {
        parseRSDT();
    } else {
        hal.Serial.puts("[ACPI] No RSDT/XSDT found!\n");
    }

    // Вывод результатов
    hal.Serial.puts("[ACPI] CPUs: ");
    hal.Serial.putHex(cpu_count);
    hal.Serial.puts("\n");

    hal.Serial.puts("[ACPI] Local APIC: ");
    hal.Serial.putHex(local_apic_addr);
    hal.Serial.puts("\n");

    if (io_apic_addr != 0) {
        hal.Serial.puts("[ACPI] IO-APIC: ");
        hal.Serial.putHex(io_apic_addr);
        hal.Serial.puts("\n");
    }
}

fn parseXSDT() void {
    const xsdt: *align(1) const XSDT = @ptrCast(physToPtr(rsdp.?.xsdt_address));

    // Validate XSDT
    if (!signatureEquals(&xsdt.header.signature, "XSDT")) {
        hal.Serial.puts("[ACPI] Invalid XSDT signature!\n");
        return;
    }

    const entry_count = (xsdt.header.length - @sizeOf(TableHeader)) / 8;
    hal.Serial.puts("[ACPI] XSDT entries: ");
    hal.Serial.putHex(entry_count);
    hal.Serial.puts("\n");

    // XSDT entries start right after the header
    const entries_ptr: [*]align(1) const u64 = @ptrFromInt(@intFromPtr(xsdt) + @sizeOf(TableHeader));
    for (0..entry_count) |i| {
        const table_addr = entries_ptr[i];
        if (table_addr == 0) continue;
        parseTable(table_addr);
    }
}

fn parseRSDT() void {
    const rsdt: *align(1) const RSDT = @ptrCast(physToPtr(rsdp.?.rsdt_address));

    if (!signatureEquals(&rsdt.header.signature, "RSDT")) {
        hal.Serial.puts("[ACPI] Invalid RSDT signature!\n");
        return;
    }

    const entry_count = (rsdt.header.length - @sizeOf(TableHeader)) / 4;
    hal.Serial.puts("[ACPI] RSDT entries: ");
    hal.Serial.putHex(entry_count);
    hal.Serial.puts("\n");

    // RSDT entries start right after the header
    const entries_ptr: [*]align(1) const u32 = @ptrFromInt(@intFromPtr(rsdt) + @sizeOf(TableHeader));
    for (0..entry_count) |i| {
        const table_addr: u64 = entries_ptr[i];
        if (table_addr == 0) continue;
        parseTable(table_addr);
    }
}

fn parseTable(phys_addr: u64) void {
    const header: *align(1) const TableHeader = @ptrCast(physToPtr(phys_addr));

    // Проверяем какие таблицы нам нужны
    if (signatureEquals(&header.signature, "APIC")) {
        parseMADT(phys_addr);
    } else if (signatureEquals(&header.signature, "MCFG")) {
        parseMCFG(phys_addr);
    } else if (signatureEquals(&header.signature, "HPET")) {
        hal.Serial.puts("[ACPI] HPET table found (not yet used)\n");
    }
    // FACP, DSDT, SSDT — пока не нужны
}

fn parseMADT(phys_addr: u64) void {
    const madt: *align(1) const MADT = @ptrCast(physToPtr(phys_addr));

    local_apic_addr = madt.local_apic_address;
    hal.Serial.puts("[ACPI] MADT: Local APIC at ");
    hal.Serial.putHex(local_apic_addr);
    hal.Serial.puts("\n");

    // Парсим записи MADT
    const entries_start: usize = @intFromPtr(&madt.entries);
    const entries_end: usize = @intFromPtr(madt) + madt.header.length;
    var offset: usize = entries_start;

    while (offset < entries_end) {
        const entry_type: u8 = @as(*const volatile u8, @ptrFromInt(offset)).*;
        const entry_len: u8 = @as(*const volatile u8, @ptrFromInt(offset + 1)).*;

        if (entry_len < 2) break; // Invalid entry

        switch (@as(MADTEntryType, @enumFromInt(entry_type))) {
            .LocalAPIC => {
                const lapic: *align(1) const MADTLocalAPIC = @ptrFromInt(offset);
                if (lapic.flags & 1 != 0) { // Enabled CPU
                    cpu_count += 1;
                }
            },
            .IOAPIC => {
                const ioapic: *align(1) const MADTIOAPIC = @ptrFromInt(offset);
                if (io_apic_count == 0) {
                    io_apic_addr = ioapic.ioapic_address;
                }
                io_apic_count += 1;
            },
            .InterruptOverride => {
                const override_entry: *align(1) const MADTInterruptOverride = @ptrFromInt(offset);
                if (irq_override_count < MAX_IRQ_OVERRIDES) {
                    irq_overrides[irq_override_count] = .{
                        .source_irq = override_entry.source_irq,
                        .global_irq = override_entry.global_irq,
                        .flags = override_entry.flags,
                    };
                    irq_override_count += 1;
                }
            },
            else => {},
        }

        offset += entry_len;
    }

    hal.Serial.puts("[ACPI] MADT parsed: ");
    hal.Serial.putHex(cpu_count);
    hal.Serial.puts(" CPUs, ");
    hal.Serial.putHex(io_apic_count);
    hal.Serial.puts(" IO-APICs\n");
}

fn parseMCFG(phys_addr: u64) void {
    const mcfg: *align(1) const MCFG = @ptrCast(physToPtr(phys_addr));

    const entry_count = (mcfg.header.length - @sizeOf(TableHeader) - 8) / @sizeOf(MCFGEntry);
    if (entry_count > 0) {
        // MCFG entries start after header + 8-byte reserved field
        const entries_ptr: [*]align(1) const MCFGEntry = @ptrFromInt(@intFromPtr(mcfg) + @sizeOf(TableHeader) + 8);
        mcfg_base = entries_ptr[0].base_address;
        hal.Serial.puts("[ACPI] MCFG: PCIe config at ");
        hal.Serial.putHex(mcfg_base);
        hal.Serial.puts("\n");
    }
}
