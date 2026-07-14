// ===========================================================================
// POLER-OS v0.7.0 — 64-bit x86_64 Semantic Runtime Kernel
// ===========================================================================
//
// Эволюция:
//   v0.4.0: 32-bit kernel, POLER Core, shell, PCI scan
//   v0.5.0: 64-bit boot, HAL (GDT/IDT/PIC/APIC), ACPI, interrupts
//   v0.5.1: VirtualBox compatibility, 64-bit Long Mode fix
//   v0.6.1: Bug fixes (CTR brace, Q glyph, circular import hal↔scheduler)
//   v0.7.0: Ring 3 (user mode), ELF64 loader, per-process CR3, TSS IST
// ============================================================================

const hal = @import("hal.zig");
const std = @import("std");
const acpi = @import("acpi.zig");
const poler = @import("poler_core.zig");
const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const heap = @import("heap64.zig");
const cpio = @import("cpio.zig");
const scheduler = @import("scheduler.zig");
const multiboot2 = @import("multiboot2.zig");
const framebuffer = @import("framebuffer.zig");
const elf_loader = @import("elf_loader.zig");



var use_fb: bool = false;

const VGA_COLORS = [16][3]u8{
    .{ 0, 0, 0 },         // 0: Black
    .{ 0, 0, 170 },       // 1: Blue
    .{ 0, 170, 0 },       // 2: Green
    .{ 0, 170, 170 },     // 3: Cyan
    .{ 170, 0, 0 },       // 4: Red
    .{ 170, 0, 170 },     // 5: Magenta
    .{ 170, 85, 0 },      // 6: Brown
    .{ 170, 170, 170 },   // 7: Light Gray
    .{ 85, 85, 85 },      // 8: Dark Gray
    .{ 85, 85, 255 },     // 9: Light Blue
    .{ 85, 255, 85 },     // 10: Light Green
    .{ 85, 255, 255 },    // 11: Light Cyan
    .{ 255, 85, 85 },     // 12: Light Red
    .{ 255, 85, 255 },    // 13: Light Magenta
    .{ 255, 255, 85 },    // 14: Yellow
    .{ 255, 255, 255 },   // 15: White
};

// ============================================================================
// VGA Text Mode (80x25) — перенесено из main32.zig
// ============================================================================

const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_BUFFER: [*]volatile u16 = @ptrFromInt(0xB8000);

var vga_row: usize = 0;
var vga_col: usize = 0;
var vga_color: u8 = 0x07; // Light gray on black

fn vga_init() void {
    vga_row = 0;
    vga_col = 0;
    vga_color = 0x07;
    var i: usize = 0;
    while (i < VGA_WIDTH * VGA_HEIGHT) : (i += 1) {
        VGA_BUFFER[i] = @as(u16, ' ') | (@as(u16, vga_color) << 8);
    }
}

fn vga_puts(str: []const u8) void {
    for (str) |ch| {
        if (ch == '\n') {
            vga_col = 0;
            vga_row += 1;
        } else if (ch == '\x08') {
            if (vga_col > 0) {
                vga_col -= 1;
                VGA_BUFFER[vga_row * VGA_WIDTH + vga_col] = @as(u16, ' ') | (@as(u16, vga_color) << 8);
            }
        } else {
            VGA_BUFFER[vga_row * VGA_WIDTH + vga_col] = @as(u16, ch) | (@as(u16, vga_color) << 8);
            vga_col += 1;
            if (vga_col >= VGA_WIDTH) {
                vga_col = 0;
                vga_row += 1;
            }
        }
        if (vga_row >= VGA_HEIGHT) {
            // Scroll up
            var y: usize = 0;
            while (y < VGA_HEIGHT - 1) : (y += 1) {
                var x: usize = 0;
                while (x < VGA_WIDTH) : (x += 1) {
                    VGA_BUFFER[y * VGA_WIDTH + x] = VGA_BUFFER[(y + 1) * VGA_WIDTH + x];
                }
            }
            var x2: usize = 0;
            while (x2 < VGA_WIDTH) : (x2 += 1) {
                VGA_BUFFER[(VGA_HEIGHT - 1) * VGA_WIDTH + x2] = @as(u16, ' ') | (@as(u16, vga_color) << 8);
            }
            vga_row = VGA_HEIGHT - 1;
        }
    }
}

fn vga_setcolor(c: u8) void {
    vga_color = c;
}

fn puts_vga_or_fb(str: []const u8) void {
    if (use_fb) {
        const fg = VGA_COLORS[vga_color & 0x0F];
        const bg = VGA_COLORS[(vga_color >> 4) & 0x0F];
        const bg_r = if (bg[0] == 0 and bg[1] == 0 and bg[2] == 0) @as(u8, 0x0B) else bg[0];
        const bg_g = if (bg[0] == 0 and bg[1] == 0 and bg[2] == 0) @as(u8, 0x11) else bg[1];
        const bg_b = if (bg[0] == 0 and bg[1] == 0 and bg[2] == 0) @as(u8, 0x20) else bg[2];
        framebuffer.puts_color(str, fg[0], fg[1], fg[2], bg_r, bg_g, bg_b);
    } else {
        vga_puts(str);
    }
}

// ============================================================================
// Memory Dump Utility — dump N bytes at a virtual address via serial
// ============================================================================

fn memDump(virt_addr: u64, num_bytes: usize, label: []const u8) void {
    hal.Serial.puts("[MEMDUMP] ");
    hal.Serial.puts(label);
    hal.Serial.puts(" @ ");
    hal.Serial.putHex(virt_addr);
    hal.Serial.puts(" (");
    hal.Serial.putDecimal(num_bytes);
    hal.Serial.puts(" bytes):\n");

    const ptr: [*]const volatile u8 = @ptrFromInt(virt_addr);
    var offset: usize = 0;
    while (offset < num_bytes) : (offset += 16) {
        hal.Serial.putHex(virt_addr + offset);
        hal.Serial.puts(": ");

        // Print hex bytes
        var j: usize = 0;
        while (j < 16) : (j += 1) {
            if (offset + j < num_bytes) {
                const b = ptr[offset + j];
                const hex = "0123456789ABCDEF";
                hal.Serial.puts(&.{hex[(b >> 4) & 0xF], hex[b & 0xF]});
            } else {
                hal.Serial.puts("  ");
            }
            hal.Serial.puts(" ");
        }

        // Print ASCII
        hal.Serial.puts(" |");
        j = 0;
        while (j < 16) : (j += 1) {
            if (offset + j < num_bytes) {
                const b = ptr[offset + j];
                if (b >= 0x20 and b < 0x7F) {
                    hal.Serial.puts(&.{b});
                } else {
                    hal.Serial.puts(".");
                }
            }
        }
        hal.Serial.puts("|\n");
    }
}

/// Walk the 4-level page tables for a given virtual address in a PML4
/// and print what we find at each level. Useful for debugging mappings.
fn dumpPageTableWalk(pml4_phys: u64, virt_addr: u64, label: []const u8) void {
    hal.Serial.puts("[PTW] ");
    hal.Serial.puts(label);
    hal.Serial.puts(" — walking VA ");
    hal.Serial.putHex(virt_addr);
    hal.Serial.puts(" in PML4 @ ");
    hal.Serial.putHex(pml4_phys);
    hal.Serial.puts("\n");

    const pml4_idx = (virt_addr >> 39) & 0x1FF;
    const pdpt_idx = (virt_addr >> 30) & 0x1FF;
    const pd_idx = (virt_addr >> 21) & 0x1FF;
    const pt_idx = (virt_addr >> 12) & 0x1FF;

    hal.Serial.puts("  Indices: PML4[");
    hal.Serial.putDecimal(pml4_idx);
    hal.Serial.puts("] PDPT[");
    hal.Serial.putDecimal(pdpt_idx);
    hal.Serial.puts("] PD[");
    hal.Serial.putDecimal(pd_idx);
    hal.Serial.puts("] PT[");
    hal.Serial.putDecimal(pt_idx);
    hal.Serial.puts("]\n");

    const pml4: [*]const volatile u64 = @ptrFromInt(pml4_phys);
    const pml4e = pml4[pml4_idx];
    hal.Serial.puts("  PML4[");
    hal.Serial.putDecimal(pml4_idx);
    hal.Serial.puts("] = ");
    hal.Serial.putHex(pml4e);
    if (pml4e & vmm.PTE_PRESENT == 0) {
        hal.Serial.puts(" — NOT PRESENT, abort\n");
        return;
    }
    hal.Serial.puts(" -> phys=");
    hal.Serial.putHex(pml4e & 0x000FFFFFFFFFF000);
    hal.Serial.puts(" flags=");
    hal.Serial.putHex(pml4e & 0xFFF);
    if (pml4e & vmm.PTE_USER != 0) hal.Serial.puts(" USER");
    hal.Serial.puts("\n");

    const pdpt: [*]const volatile u64 = @ptrFromInt(pml4e & 0x000FFFFFFFFFF000);
    const pdpte = pdpt[pdpt_idx];
    hal.Serial.puts("  PDPT[");
    hal.Serial.putDecimal(pdpt_idx);
    hal.Serial.puts("] = ");
    hal.Serial.putHex(pdpte);
    if (pdpte & vmm.PTE_PRESENT == 0) {
        hal.Serial.puts(" — NOT PRESENT, abort\n");
        return;
    }
    if (pdpte & vmm.PTE_HUGE != 0) {
        hal.Serial.puts(" — 1GB HUGE PAGE -> phys=");
        hal.Serial.putHex(pdpte & 0x000FFFFFC0000000);
        hal.Serial.puts("\n");
        return;
    }
    hal.Serial.puts(" -> phys=");
    hal.Serial.putHex(pdpte & 0x000FFFFFFFFFF000);
    hal.Serial.puts(" flags=");
    hal.Serial.putHex(pdpte & 0xFFF);
    if (pdpte & vmm.PTE_USER != 0) hal.Serial.puts(" USER");
    hal.Serial.puts("\n");

    const pd: [*]const volatile u64 = @ptrFromInt(pdpte & 0x000FFFFFFFFFF000);
    const pde = pd[pd_idx];
    hal.Serial.puts("  PD[");
    hal.Serial.putDecimal(pd_idx);
    hal.Serial.puts("] = ");
    hal.Serial.putHex(pde);
    if (pde & vmm.PTE_PRESENT == 0) {
        hal.Serial.puts(" — NOT PRESENT, abort\n");
        return;
    }
    if (pde & vmm.PTE_HUGE != 0) {
        hal.Serial.puts(" — 2MB HUGE PAGE -> phys=");
        hal.Serial.putHex(pde & 0x000FFFFFFFE00000);
        hal.Serial.puts("\n");
        return;
    }
    hal.Serial.puts(" -> phys=");
    hal.Serial.putHex(pde & 0x000FFFFFFFFFF000);
    hal.Serial.puts(" flags=");
    hal.Serial.putHex(pde & 0xFFF);
    if (pde & vmm.PTE_USER != 0) hal.Serial.puts(" USER");
    hal.Serial.puts("\n");

    const pt: [*]const volatile u64 = @ptrFromInt(pde & 0x000FFFFFFFFFF000);
    const pte = pt[pt_idx];
    hal.Serial.puts("  PT[");
    hal.Serial.putDecimal(pt_idx);
    hal.Serial.puts("] = ");
    hal.Serial.putHex(pte);
    if (pte & vmm.PTE_PRESENT == 0) {
        hal.Serial.puts(" — NOT PRESENT, abort\n");
        return;
    }
    hal.Serial.puts(" -> phys=");
    hal.Serial.putHex(pte & 0x000FFFFFFFFFF000);
    hal.Serial.puts(" flags=");
    hal.Serial.putHex(pte & 0xFFF);
    if (pte & vmm.PTE_USER != 0) hal.Serial.puts(" USER");
    if (pte & vmm.PTE_NO_EXECUTE != 0) hal.Serial.puts(" NX");
    hal.Serial.puts("\n");
}

fn puts(str: []const u8) void {
    puts_vga_or_fb(str);
    hal.Serial.puts(str);
}

/// Console print function for syscall 1 — writes to screen AND serial.
/// Safe to call from Ring 3 syscall context: the string is in user VA,
/// but we're in Ring 0 so both user and kernel pages are accessible.
fn console_print_fn(str: []const u8) void {
    puts_vga_or_fb(str);
    hal.Serial.puts(str);
}

fn clear_screen() void {
    if (use_fb) {
        framebuffer.clear();
    } else {
        vga_init();
    }
}

fn putHex(val: u64) void {
    hal.Serial.putHex(val);
    const hex = "0123456789ABCDEF";
    puts_vga_or_fb("0x");
    var i: usize = 60;
    while (true) {
        const nibble = (val >> @intCast(i)) & 0xF;
        puts_vga_or_fb(&.{hex[@intCast(nibble)]});
        if (i == 0) break;
        i -= 4;
    }
}

fn putDecimal(val: u64) void {
    if (val == 0) {
        puts("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 20;
    var temp = val;
    while (temp > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(temp % 10));
        temp /= 10;
    }
    puts(buf[i..20]);
}

// ============================================================================
// Kernel Banner
// ============================================================================

fn print_banner() void {
    vga_setcolor(0x0B); // Cyan
    puts(
        \\╔══════════════════════════════════════════════════════╗
        \\║             POLER-OS v0.7.0 (64-bit)                ║
        \\║          Semantic Runtime Architecture              ║
        \\║                                                      ║
        \\║   Ring 3 · ELF64 Loader · Per-Process CR3 · IST    ║
        \\╚══════════════════════════════════════════════════════╝
        \\
    );
    vga_setcolor(0x07);
}

// ==============================================================================
// CPU Feature Detection
// ============================================================================

const CPUInfo = struct {
    vendor: [13]u8,
    model_name: [49]u8,
    stepping: u32,
    model: u32,
    family: u32,
    features_edx: u32,
    features_ecx: u32,
    has_lapic: bool,
    has_syscall: bool,
    has_nx: bool,
    has_1gb_pages: bool,
};

fn detectCPU() CPUInfo {
    var info = CPUInfo{
        .vendor = undefined,
        .model_name = undefined,
        .stepping = 0,
        .model = 0,
        .family = 0,
        .features_edx = 0,
        .features_ecx = 0,
        .has_lapic = false,
        .has_syscall = false,
        .has_nx = false,
        .has_1gb_pages = false,
    };

    // CPUID leaf 0 — vendor string
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 0)),
    );

    // Vendor string: EBX + EDX + ECX
    @memcpy(info.vendor[0..4], @as(*const [4]u8, @ptrCast(&ebx)));
    @memcpy(info.vendor[4..8], @as(*const [4]u8, @ptrCast(&edx)));
    @memcpy(info.vendor[8..12], @as(*const [4]u8, @ptrCast(&ecx)));
    info.vendor[12] = 0;

    // CPUID leaf 1 — features
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 1)),
    );

    info.stepping = eax & 0xF;
    info.model = (eax >> 4) & 0xF;
    info.family = (eax >> 8) & 0xF;
    info.features_edx = edx;
    info.features_ecx = ecx;

    info.has_lapic = (edx >> 9) & 1 != 0; // APIC
    info.has_syscall = (edx >> 11) & 1 != 0; // SYSENTER/SYSEXIT
    info.has_nx = false; // Check extended features

    // CPUID leaf 0x80000001 — extended features (NX bit)
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 0x80000001)),
    );

    info.has_nx = (edx >> 20) & 1 != 0; // NX bit
    info.has_1gb_pages = (edx >> 26) & 1 != 0; // 1GB pages

    // CPUID leaf 0x80000002-4 — model name
    var model_buf: [48]u8 = undefined;
    inline for (0..3) |leaf_offset| {
        asm volatile ("cpuid"
            : [eax] "={eax}" (eax),
              [ebx] "={ebx}" (ebx),
              [ecx] "={ecx}" (ecx),
              [edx] "={edx}" (edx),
            : [leaf] "{eax}" (@as(u32, 0x80000002) + @as(u32, @intCast(leaf_offset))),
        );
        const base = leaf_offset * 16;
        @memcpy(model_buf[base..][0..4], @as(*const [4]u8, @ptrCast(&eax)));
        @memcpy(model_buf[base + 4..][0..4], @as(*const [4]u8, @ptrCast(&ebx)));
        @memcpy(model_buf[base + 8..][0..4], @as(*const [4]u8, @ptrCast(&ecx)));
        @memcpy(model_buf[base + 12..][0..4], @as(*const [4]u8, @ptrCast(&edx)));
    }
    @memcpy(info.model_name[0..48], &model_buf);
    info.model_name[48] = 0;

    return info;
}

fn printCPUInfo(info: *const CPUInfo) void {
    puts("  CPU: ");
    // Trim model name
    var start: usize = 0;
    while (start < 48 and info.model_name[start] == ' ') start += 1;
    var end: usize = 47;
    while (end > start and info.model_name[end] == ' ') end -= 1;
    if (end > start) {
        puts(info.model_name[start .. end + 1]);
    }
    puts("\n  Vendor: ");
    puts(&info.vendor);
    puts("\n  Features: ");
    if (info.has_lapic) puts("APIC ");
    if (info.has_syscall) puts("SYSCALL ");
    if (info.has_nx) puts("NX ");
    if (info.has_1gb_pages) puts("1GB-PG ");
    puts("\n");
}

// ==============================================================================
// Memory Map — parsed from Multiboot2 tags
// ============================================================================

fn printMemoryInfo(mbi: u64) void {
    // 1. Show register values
    const cr0 = hal.readCr0();
    const cr3 = hal.readCr3();
    const cr4 = hal.readCr4();

    puts("  CR0: "); putHex(cr0); puts("\n");
    puts("  CR3 (PML4): "); putHex(cr3); puts("\n");
    puts("  CR4: "); putHex(cr4); puts("\n");

    const efer = hal.readMsr(hal.MSR.EFER);
    if (efer & hal.EFER.LMA != 0) {
        puts("  Long Mode: ACTIVE\n");
    }
    if (efer & hal.EFER.NXE != 0) {
        puts("  NX-bit: ENABLED\n");
    }

    // 2. Initialize 64-bit physical memory manager
    puts("[PMM] Initializing from Multiboot2 memory maps...\n");
    pmm.init(mbi);

    // 3. Print memory allocations statistics
    const stats = pmm.getStats();
    puts("  Total RAM detected (BasicMem): ");
    putDecimal(stats.total_kb);
    puts(" KB\n");

    puts("  Usable memory pages: ");
    putDecimal(stats.usable_pages);
    puts(" (");
    putDecimal(stats.usable_pages * 4);
    puts(" KB)\n");

    // 4. Dump Multiboot2 Memory Map if available
    const parser = multiboot2.Parser.init(mbi);
    if (parser.findTag(6)) |tag_addr| {
        const mmap_tag: *const multiboot2.MmapTag = @ptrFromInt(tag_addr);
        const entries = mmap_tag.getEntries();
        puts("  Multiboot2 Memory Map:\n");
        for (entries) |entry| {
            puts("    - [");
            putHex(entry.addr);
            puts(" .. ");
            putHex(entry.addr + entry.len);
            puts("] type=");
            putDecimal(entry.entry_type);
            if (entry.entry_type == 1) puts(" (Usable)");
            puts("\n");
        }
    }
}

// ============================================================================
// POLER Core Quick Test
// Runs active cryptographic verification for POLER Core v4
// ============================================================================

fn testPolerCore() void {
    puts("[POLER] Running Core test...\n");
    const a: u32 = 42;
    const b: u32 = 17;
    const eps: u32 = 1;
    const res = poler.pndMix(a, b, eps);
    const res_alt = poler.pndMixAlt(a, b, eps);
    puts("  pndMix(42, 17, 1) = ");
    putHex(res);
    puts("\n");
    puts("  pndMixAlt(42, 17, 1) = ");
    putHex(res_alt);
    puts("\n");
}

// ============================================================================
// Main Kernel Entry Point
// Вызывается из boot64.S после перехода в 64-bit mode
// ============================================================================

export fn poler_kernel_main(multiboot_magic: u32, multiboot_info: u64) callconv(.C) void {
    // 0. Initialize display — VGA text mode (80x25)
    // FIRST: Program VGA registers to switch from any VBE graphical mode
    // to standard 80x25 text mode. This is critical because GRUB may leave
    // the VGA controller in graphical mode, making writes to 0xB8000 invisible.
    hal.vgaSetTextMode();

    // THEN: Clear the text buffer and reset cursor
    vga_init();

    // NOTE: If framebuffer becomes available (UEFI or future re-enable),
    // uncomment the block below and set use_fb = true:
    // const parser = multiboot2.Parser.init(multiboot_info);
    // if (parser.findTag(8)) |tag_addr| {
    //     const fb_tag: *const multiboot2.FramebufferTag = @ptrFromInt(tag_addr);
    //     if (fb_tag.fb_addr != 0 and fb_tag.fb_width > 0 and fb_tag.fb_height > 0) {
    //         framebuffer.init_from_multiboot(
    //             fb_tag.fb_addr, fb_tag.fb_pitch, fb_tag.fb_width,
    //             fb_tag.fb_height, fb_tag.fb_bpp, fb_tag.fb_type,
    //         );
    //         framebuffer.clear();
    //         use_fb = true;
    //     }
    // }

    // 2. Print banner
    print_banner();

    // 3. Verify Multiboot2 magic
    if (multiboot_magic == 0x36D76289) {
        puts("[BOOT] Multiboot2 loaded successfully\n");
    } else {
        vga_setcolor(0x0C);
        puts("[BOOT] WARNING: Unknown bootloader (magic=");
        putHex(multiboot_magic);
        puts(")\n");
        vga_setcolor(0x07);
    }

    // 4. Initialize HAL (GDT, IDT, PIC, APIC)
    puts("[BOOT] Initializing HAL...\n");
    hal.init();

    // 5. Initialize ACPI
    puts("[BOOT] Initializing ACPI...\n");
    acpi.init();

    // 6. CPU detection
    puts("[BOOT] Detecting CPU...\n");
    const cpu = detectCPU();
    printCPUInfo(&cpu);

    // 7. Memory info
    puts("[BOOT] Memory layout:\n");
    printMemoryInfo(multiboot_info);

    // 8. Test POLER Core
    testPolerCore();

    // 8.5. Initialize VMM
    vmm.init();

    // NOTE: VMM test at 0x100000000 disabled — conflicts with user code page.
    // The user ELF binary is loaded at 0x100000000, and the VMM test's
    // map/unmap/free cycle can leave stale page table entries that conflict.
    // VMM functionality is verified through the ELF loader and user task.

    // 8.6. Initialize Kernel Heap Allocator
    heap.init();

    // Test Heap Allocator
    puts("[HEAP] Testing kernel heap...\n");
    if (heap.kmalloc(128)) |ptr1| {
        puts("[HEAP] Allocated 128 bytes at ");
        putHex(@intFromPtr(ptr1));
        puts("\n");

        if (heap.kmalloc(256)) |ptr2| {
            puts("[HEAP] Allocated 256 bytes at ");
            putHex(@intFromPtr(ptr2));
            puts("\n");

            // Print status
            heap.printHeapStatus();

            heap.kfree(ptr1);
            puts("[HEAP] Freed 128-byte block\n");
            
            heap.kfree(ptr2);
            puts("[HEAP] Freed 256-byte block\n");

            // Print status again (should show coalesced block)
            heap.printHeapStatus();
        } else {
            puts("[HEAP] Failed to allocate second block!\n");
        }
    } else {
        puts("[HEAP] Failed to allocate first block!\n");
    }

    // 8.7. Initialize and parse Initrd/CPIO modules
    puts("[BOOT] Checking for initrd modules...\n");
    const mb_parser = multiboot2.Parser.init(multiboot_info);
    var mod_offset: u64 = 8;
    if (mb_parser.findModuleTag(&mod_offset)) |mod| {
        const mod_size = mod.mod_end - mod.mod_start;
        if (mod_size == 0 or mod.mod_start == 0) {
            puts("[INITRD] Empty initrd module, skipping.\n");
        } else {
            puts("[INITRD] Module found: ");
            puts(mod.getCmdline());
            puts("\n");

            puts("[INITRD] Start Phys: ");
            putHex(mod.mod_start);
            puts(", End Phys: ");
            putHex(mod.mod_end);
            puts(", Size: ");
            putDecimal(mod_size);
            puts(" bytes\n");

            const archive_slice: []const u8 = @as([*]const u8, @ptrFromInt(mod.mod_start))[0..mod_size];

            var cpio_parser = cpio.CpioParser.init(archive_slice);
            var file_count: usize = 0;
            while (cpio_parser.next()) |file| {
                puts("  - File: ");
                puts(file.name);
                puts(" Size: ");
                putDecimal(file.size);
                puts(" bytes\n");
                
                // Print text file contents (e.g. hello.txt)
                if (std.mem.endsWith(u8, file.name, ".txt")) {
                    puts("    Content: \"");
                    const limit = if (file.data.len > 64) 64 else file.data.len;
                    puts(file.data[0..limit]);
                    if (file.data.len > 64) puts("...");
                    puts("\"\n");
                }
                file_count += 1;
            }

            puts("[INITRD] Total files parsed: ");
            putDecimal(file_count);
            puts("\n");
        }
    } else {
        puts("[INITRD] No initrd modules loaded by bootloader.\n");
    }

    // 9. Ready!
    vga_setcolor(0x0B);
    puts("\n=== POLER-OS v0.7.0 — BOOT COMPLETE ===\n");
    puts("HAL + ACPI + POLER Core + Ring 3 — all systems GO\n");
    vga_setcolor(0x07);

    puts("\nInitializing Ring 3 user mode...\n");

    // 10. Initialize Syscalls (Ring 3 → Ring 0 entry via syscall/sysretq)
    // Register print_fn so syscall 1 (print) writes to screen AND serial.
    hal.print_fn = &console_print_fn;
    hal.clear_screen_fn = &clear_screen;
    hal.initSyscalls(@intFromPtr(&syscall_entry));

    // 11. Initialize Scheduler
    scheduler.init();

    // 12. Create Ring 0 kernel tasks
    _ = scheduler.createTask(@intFromPtr(&task1)) catch |err| {
        puts("[SCHED] Failed to create task1: ");
        puts(@errorName(err));
        puts("\n");
    };
    _ = scheduler.createTask(@intFromPtr(&task2)) catch |err| {
        puts("[SCHED] Failed to create task2: ");
        puts(@errorName(err));
        puts("\n");
    };

    // 13. v0.7.0 — Create Ring 3 user task from embedded ELF64 binary
    //
    // Per-process address space isolation:
    //   Step 1: Create per-process PML4 (copies kernel entries WITHOUT User bit)
    //   Step 2: Load ELF binary INTO user PML4 (pages with PTE_USER for Ring 3)
    //   Step 3: Map user stack INTO user PML4 (with PTE_USER)
    //   Step 4: Create user task with entry point, CR3, and user stack
    //
    // This ensures Ring 3 code can only access its own pages (code + stack),
    // NOT kernel memory. The scheduler will CR3-switch on context switch.
    {
    puts("[BOOT] Creating user address space...\n");

    // Step 1: Create user PML4 (kernel entries WITHOUT User bit)
    const user_pml4 = vmm.createUserPML4() catch |err| {
        puts("[VMM] Failed to create user PML4: ");
        puts(@errorName(err));
        puts("\nHalting.\n");
        while (true) { hal.cli(); hal.hlt(); }
    };

    // Step 2: Load ELF binary into user PML4
    puts("[BOOT] Loading user ELF binary into user PML4...\n");
    const elf_result = elf_loader.loadElfIntoPML4(&user_hello_elf, user_pml4) catch |err| {
        puts("[ELF] Failed to load user binary: ");
        puts(@errorName(err));
        puts("\nHalting.\n");
        while (true) { hal.cli(); hal.hlt(); }
    };
    puts("[BOOT] ELF loaded, entry point: ");
    putHex(elf_result.entry_point);
    puts("\n");

    // === PAGE TABLE WALK: Check if mapping exists before accessing memory ===
    const kernel_pml4 = hal.readCr3() & 0x000FFFFFFFFFF000;
    hal.Serial.puts("[DEBUG] Current CR3 (kernel PML4) = ");
    hal.Serial.putHex(kernel_pml4);
    hal.Serial.puts("\n");
    hal.Serial.puts("[DEBUG] User PML4 = ");
    hal.Serial.putHex(user_pml4);
    hal.Serial.puts("\n");
    dumpPageTableWalk(kernel_pml4, USER_CODE_BASE, "kernel PML4 -> user code");
    dumpPageTableWalk(user_pml4, USER_CODE_BASE, "user PML4 -> user code");

    // === MEMORY DUMP: Verify user code was loaded correctly ===
    hal.Serial.puts("\n=== USER CODE PAGE DUMP (via kernel PML4) ===\n");
    memDump(USER_CODE_BASE, 64, "user_code");
    hal.Serial.puts("=== END USER CODE DUMP ===\n\n");

    // Verify the first few bytes match the expected machine code:
    //   48 C7 C0 01 00 00 00  = mov rax, 1
    const code_ptr: [*]const volatile u8 = @ptrFromInt(USER_CODE_BASE);
    const verify_hex = "0123456789ABCDEF";
    if (code_ptr[0] == 0x48 and code_ptr[1] == 0xC7 and code_ptr[2] == 0xC0 and code_ptr[3] == 0x01) {
        hal.Serial.puts("[VERIFY] User code: FIRST INSTRUCTION CORRECT (mov rax, 1)\n");
    } else {
        hal.Serial.puts("[VERIFY] User code: FIRST INSTRUCTION MISMATCH! Expected 48 C7 C0 01, got ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[0] >> 4) & 0xF], verify_hex[code_ptr[0] & 0xF] });
        hal.Serial.puts(" ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[1] >> 4) & 0xF], verify_hex[code_ptr[1] & 0xF] });
        hal.Serial.puts(" ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[2] >> 4) & 0xF], verify_hex[code_ptr[2] & 0xF] });
        hal.Serial.puts(" ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[3] >> 4) & 0xF], verify_hex[code_ptr[3] & 0xF] });
        hal.Serial.puts("\n");
    }

    // Verify syscall instruction at offset 21 (0x0F 0x05)
    if (code_ptr[21] == 0x0F and code_ptr[22] == 0x05) {
        hal.Serial.puts("[VERIFY] User code: SYSCALL INSTRUCTION CORRECT at offset 21\n");
    } else {
        hal.Serial.puts("[VERIFY] User code: SYSCALL INSTRUCTION MISMATCH at offset 21! Expected 0F 05, got ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[21] >> 4) & 0xF], verify_hex[code_ptr[21] & 0xF] });
        hal.Serial.puts(" ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[22] >> 4) & 0xF], verify_hex[code_ptr[22] & 0xF] });
        hal.Serial.puts("\n");
    }

    // Verify second syscall (exit) at offset 32 (0x0F 0x05)
    if (code_ptr[32] == 0x0F and code_ptr[33] == 0x05) {
        hal.Serial.puts("[VERIFY] User code: SYSCALL EXIT INSTRUCTION CORRECT at offset 32\n");
    } else {
        hal.Serial.puts("[VERIFY] User code: SYSCALL EXIT INSTRUCTION at offset 32, got ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[32] >> 4) & 0xF], verify_hex[code_ptr[32] & 0xF] });
        hal.Serial.puts(" ");
        hal.Serial.puts(&.{ verify_hex[(code_ptr[33] >> 4) & 0xF], verify_hex[code_ptr[33] & 0xF] });
        hal.Serial.puts("\n");
    }

    // Verify message string at offset 34
    const msg_ptr: [*]const volatile u8 = @ptrFromInt(USER_CODE_BASE + 34);
    if (msg_ptr[0] == 'H' and msg_ptr[1] == 'e' and msg_ptr[2] == 'l' and msg_ptr[3] == 'l') {
        hal.Serial.puts("[VERIFY] User code: MESSAGE STRING CORRECT (\"Hello...\")\n");
    } else {
        hal.Serial.puts("[VERIFY] User code: MESSAGE STRING MISMATCH! Expected 'H' 'e' 'l' 'l', got ");
        hal.Serial.puts(&.{msg_ptr[0]});
        hal.Serial.puts(" ");
        hal.Serial.puts(&.{msg_ptr[1]});
        hal.Serial.puts("\n");
    }

    // === PHYSICAL PAGE CROSS-CHECK ===
    hal.Serial.puts("\n=== PHYSICAL PAGE CROSS-CHECK ===\n");
    {
        // Walk kernel PML4 to get the PTE
        const kpml4: [*]const volatile u64 = @ptrFromInt(kernel_pml4);
        const kpml4e = kpml4[(USER_CODE_BASE >> 39) & 0x1FF];
        if (kpml4e & vmm.PTE_PRESENT != 0) {
            const kpdpt: [*]const volatile u64 = @ptrFromInt(kpml4e & 0x000FFFFFFFFFF000);
            const kpdpte = kpdpt[(USER_CODE_BASE >> 30) & 0x1FF];
            if (kpdpte & vmm.PTE_PRESENT != 0 and kpdpte & vmm.PTE_HUGE == 0) {
                const kpd: [*]const volatile u64 = @ptrFromInt(kpdpte & 0x000FFFFFFFFFF000);
                const kpde = kpd[(USER_CODE_BASE >> 21) & 0x1FF];
                if (kpde & vmm.PTE_PRESENT != 0 and kpde & vmm.PTE_HUGE == 0) {
                    const kpt: [*]const volatile u64 = @ptrFromInt(kpde & 0x000FFFFFFFFFF000);
                    const kpte = kpt[(USER_CODE_BASE >> 12) & 0x1FF];
                    const kphys = kpte & 0x000FFFFFFFFFF000;

                    // Walk user PML4 to get the PTE
                    const upml4: [*]const volatile u64 = @ptrFromInt(user_pml4);
                    const upml4e = upml4[(USER_CODE_BASE >> 39) & 0x1FF];
                    if (upml4e & vmm.PTE_PRESENT != 0) {
                        const updpt: [*]const volatile u64 = @ptrFromInt(upml4e & 0x000FFFFFFFFFF000);
                        const updpte = updpt[(USER_CODE_BASE >> 30) & 0x1FF];
                        if (updpte & vmm.PTE_PRESENT != 0 and updpte & vmm.PTE_HUGE == 0) {
                            const upd: [*]const volatile u64 = @ptrFromInt(updpte & 0x000FFFFFFFFFF000);
                            const upde = upd[(USER_CODE_BASE >> 21) & 0x1FF];
                            if (upde & vmm.PTE_PRESENT != 0 and upde & vmm.PTE_HUGE == 0) {
                                const upt: [*]const volatile u64 = @ptrFromInt(upde & 0x000FFFFFFFFFF000);
                                const upte = upt[(USER_CODE_BASE >> 12) & 0x1FF];
                                const uphys = upte & 0x000FFFFFFFFFF000;

                                hal.Serial.puts("  Kernel PML4 PTE phys: ");
                                hal.Serial.putHex(kphys);
                                hal.Serial.puts("\n  User PML4   PTE phys: ");
                                hal.Serial.putHex(uphys);
                                hal.Serial.puts("\n");
                                if (kphys == uphys) {
                                    hal.Serial.puts("  MATCH: Both PML4s map to the SAME physical page ✓\n");
                                } else {
                                    hal.Serial.puts("  MISMATCH: Different physical pages! Data copy may have gone to wrong page!\n");
                                }
                                // Also check User bit in user PML4 PTE
                                if (upte & vmm.PTE_USER != 0) {
                                    hal.Serial.puts("  User PML4 PTE has PTE_USER set ✓ (Ring 3 can access)\n");
                                } else {
                                    hal.Serial.puts("  User PML4 PTE MISSING PTE_USER! Ring 3 will #PF!\n");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    hal.Serial.puts("=== END CROSS-CHECK ===\n\n");

    // Step 3: Map user stack page in user PML4 (RW + User for Ring 3)
    hal.Serial.puts("[BOOT] Mapping user stack...\n");
    if (pmm.allocPage()) |stack_phys| {
        hal.Serial.puts("[BOOT] Allocated stack page at phys=");
        hal.Serial.putHex(stack_phys);
        hal.Serial.puts("\n");
        // Map in user PML4 with PTE_USER (Ring 3 can access)
        vmm.mapPageInPML4(user_pml4, USER_STACK_BASE, stack_phys, vmm.PTE_WRITABLE | vmm.PTE_USER) catch |err| {
            hal.Serial.puts("[VMM] Failed to map user stack in user PML4: ");
            hal.Serial.puts(@errorName(err));
            hal.Serial.puts("\nHalting.\n");
            while (true) { hal.cli(); hal.hlt(); }
        };
        hal.Serial.puts("[BOOT] Stack mapped in user PML4\n");
        // Also map in kernel PML4 — needed for zero-fill AND for Ring 3
        // access when CR3 switch is disabled (using kernel PML4 directly).
        _ = vmm.mapPage(USER_STACK_BASE, stack_phys, vmm.PTE_WRITABLE | vmm.PTE_USER) catch null;
        hal.Serial.puts("[BOOT] Stack mapped in kernel PML4\n");
        // Zero-fill the stack page
        const stack_ptr: [*]volatile u8 = @ptrFromInt(USER_STACK_BASE);
        @memset(stack_ptr[0..4096], 0);
        hal.Serial.puts("[BOOT] Stack zero-filled\n");
        puts("[BOOT] User stack mapped at ");
        putHex(USER_STACK_BASE);
        puts("-0x");
        putHex(USER_STACK_TOP);
        puts("\n");
    } else {
        puts("[PMM] Failed to allocate user stack page\nHalting.\n");
        while (true) { hal.cli(); hal.hlt(); }
    }

    // Step 4: Create the Ring 3 user task
    if (true) {
    _ = scheduler.createUserTask(elf_result.entry_point, user_pml4, USER_STACK_TOP) catch |err| {
        puts("[SCHED] Failed to create user task: ");
        puts(@errorName(err));
        puts("\nHalting.\n");
        while (true) { hal.cli(); hal.hlt(); }
    };
    }
    hal.Serial.puts("[BOOT] Ring 3 user task created with per-process CR3 isolation\n");
    }
    hal.Serial.puts("[BOOT] User task block complete, enabling scheduler...\n");

    // NOW enable scheduler preemption — timer ticks will context-switch tasks
    hal.timerTickCallback = scheduler.schedule;
    hal.Serial.puts("[BOOT] Scheduler callback enabled.\n");

    puts("[BOOT] Scheduler active (Ring 0 + Ring 3). Entering shell.\n\n");

    // Drop to interactive shell
    kernel_shell();
}

// ============================================================================
// Kernel Shell — interactive command interpreter (v0.7.1)
// ============================================================================
//
// Simple shell that reads keyboard input and executes built-in commands.
// This replaces the old heartbeat idle loop with a usable command line.
//
// Commands:
//   help     — show available commands
//   clear    — clear screen
//   regs     — show CPU registers (CR0, CR3, CR4, EFER)
//   tasks    — show scheduler task list
//   mem      — show memory info (PMM stats, heap)
//   tick     — show tick count and scheduler stats
//   reboot   — reboot the system (via keyboard controller)
//   about    — show kernel info
// ============================================================================

var shell_line: [256]u8 = undefined;
var shell_line_len: usize = 0;
var shell_running: bool = false;

fn shellPrompt() void {
    const prompt = "poler> ";
    puts_vga_or_fb(prompt);
    hal.Serial.puts(prompt);
}

fn shellPrint(str: []const u8) void {
    puts_vga_or_fb(str);
    hal.Serial.puts(str);
}

fn shellPrintLn(str: []const u8) void {
    puts_vga_or_fb(str);
    puts_vga_or_fb("\n");
    hal.Serial.puts(str);
    hal.Serial.puts("\n");
}

fn shellPutHex(val: u64) void {
    putHex(val);
}

fn shellPutDecimal(val: u64) void {
    putDecimal(val);
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn strStartsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    for (str[0..prefix.len], prefix) |a, b| {
        if (a != b) return false;
    }
    return true;
}

fn trimSpace(str: []const u8) []const u8 {
    var start: usize = 0;
    while (start < str.len and str[start] == ' ') start += 1;
    var end = str.len;
    while (end > start and str[end - 1] == ' ') end -= 1;
    return str[start..end];
}

fn shellExecute(line_raw: []const u8) void {
    const line = trimSpace(line_raw);
    if (line.len == 0) return;

    if (strEqual(line, "help")) {
        shellPrintLn("POLER-OS v0.7.0 — Kernel Shell");
        shellPrintLn("");
        shellPrintLn("  help     — show this help");
        shellPrintLn("  clear    — clear screen");
        shellPrintLn("  regs     — show CPU registers");
        shellPrintLn("  tasks    — show task list");
        shellPrintLn("  mem      — show memory info");
        shellPrintLn("  tick     — show tick/scheduler stats");
        shellPrintLn("  reboot   — reboot system");
        shellPrintLn("  about    — kernel info");
        return;
    }

    if (strEqual(line, "clear")) {
        // Clear screen on display AND serial terminal
        clear_screen();
        hal.Serial.puts("\x1B[2J\x1B[H");
        return;
    }

    if (strEqual(line, "regs")) {
        const cr0 = hal.readCr0();
        const cr3 = hal.readCr3();
        const cr4 = hal.readCr4();
        const efer = hal.readMsr(hal.MSR.EFER);
        shellPrint("  CR0:  "); shellPutHex(cr0); shellPrintLn("");
        shellPrint("  CR3:  "); shellPutHex(cr3); shellPrintLn("");
        shellPrint("  CR4:  "); shellPutHex(cr4); shellPrintLn("");
        shellPrint("  EFER: "); shellPutHex(efer); shellPrintLn("");
        if (efer & hal.EFER.LMA != 0) shellPrintLn("  Long Mode: ACTIVE");
        if (efer & hal.EFER.NXE != 0) shellPrintLn("  NX-bit:    ENABLED");
        return;
    }

    if (strEqual(line, "tasks")) {
        shellPrintLn("ID  State      Priv   CR3             RSP");
        shellPrintLn("--- ---------- ------ --------------- ---------------");
        for (0..scheduler.task_count) |i| {
            const t = scheduler.tasks[i];
            const state_str = switch (t.state) {
                .Ready => "Ready",
                .Running => "Running",
                .Killed => "Killed",
            };
            const priv_str = switch (t.privilege) {
                .Kernel => "Ring0",
                .User => "Ring3",
            };
            shellPrint("  "); shellPutDecimal(t.id);
            shellPrint(" "); shellPrint(state_str);
            shellPrint("   "); shellPrint(priv_str);
            shellPrint("   "); shellPutHex(t.cr3);
            shellPrint(" "); shellPutHex(t.rsp);
            shellPrintLn("");
        }
        shellPrint("  Current task: "); shellPutDecimal(scheduler.current_task_id);
        shellPrint("  Ticks: "); shellPutDecimal(scheduler.scheduler_ticks);
        shellPrintLn("");
        return;
    }

    if (strEqual(line, "mem")) {
        const stats = pmm.getStats();
        shellPrint("  Total RAM:    "); shellPutDecimal(stats.total_kb); shellPrintLn(" KB");
        shellPrint("  Usable pages: "); shellPutDecimal(stats.usable_pages);
        shellPrint(" ("); shellPutDecimal(stats.usable_pages * 4); shellPrintLn(" KB)");
        shellPrint("  Kernel PML4:  "); shellPutHex(hal.readCr3() & 0x000FFFFFFFFFF000); shellPrintLn("");
        heap.printHeapStatus();
        return;
    }

    if (strEqual(line, "tick")) {
        shellPrint("  Ticks: "); shellPutDecimal(hal.tick_count);
        shellPrint("  Scheduler: "); shellPutDecimal(scheduler.scheduler_ticks);
        shellPrint("  t1="); shellPutDecimal(task1_counter);
        shellPrint(" t2="); shellPutDecimal(task2_counter);
        shellPrint(" ring3="); shellPutDecimal(user_task_counter);
        shellPrintLn("");
        return;
    }

    if (strEqual(line, "reboot")) {
        shellPrintLn("Rebooting...");
        // Wait for serial to flush
        var delay: usize = 0;
        while (delay < 1000000) : (delay += 1) {
            asm volatile ("pause");
        }
        // Reset via keyboard controller (pulse reset line)
        hal.outb(0x64, 0xFE);
        // If that didn't work, triple fault
        while (true) {
            asm volatile ("ud2");
        }
    }

    if (strEqual(line, "about")) {
        shellPrintLn("POLER-OS v0.7.0 — Semantic Runtime Kernel");
        shellPrintLn("  Architecture: x86_64 (Long Mode)");
        shellPrintLn("  Boot:         Multiboot2 via GRUB");
        shellPrintLn("  Features:     Ring 3, ELF64 Loader, Per-Process CR3");
        shellPrintLn("  Scheduler:    Round-Robin (8 slots, APIC timer)");
        shellPrintLn("  HAL:          GDT/IDT/TSS, LAPIC/IOAPIC, ACPI");
        shellPrintLn("  Crypto:       POLER Core v8 (PND Mix), SipHash-2-4");
        shellPrintLn("  Language:     Zig 0.13.0 (freestanding)");
        return;
    }

    // Unknown command
    shellPrint("Unknown command: ");
    shellPrint(line);
    shellPrintLn(" (type 'help' for commands)");
}

fn kernel_shell() noreturn {
    shell_running = true;
    shellPrintLn("");
    shellPrintLn("=== POLER-OS Shell v0.7.0 ===");
    shellPrintLn("Type 'help' for available commands.");
    shellPrintLn("");
    shellPrompt();

    while (true) {
        hal.hlt(); // Wait for next interrupt

        // Process all pending keyboard input
        while (true) {
            const ch = hal.kbd_pop();
            if (ch == 0) break; // No more keys

            if (ch == '\n') {
                // Enter — execute command
                shellPrintLn("");
                shellExecute(shell_line[0..shell_line_len]);
                shell_line_len = 0;
                shellPrompt();
            } else if (ch == '\x08') {
                // Backspace — delete last char
                if (shell_line_len > 0) {
                    shell_line_len -= 1;
                    // Erase char on screen AND serial
                    puts_vga_or_fb("\x08 \x08");
                    hal.Serial.puts("\x08 \x08");
                }
            } else if (ch == 0x03) {
                // Ctrl-C — cancel current line
                shellPrintLn("^C");
                shell_line_len = 0;
                shellPrompt();
            } else if (ch >= 0x20 and ch < 0x7F) {
                // Printable character
                if (shell_line_len < shell_line.len - 1) {
                    shell_line[shell_line_len] = ch;
                    shell_line_len += 1;
                    // Echo character back on screen AND serial
                    puts_vga_or_fb(&.{ch});
                    hal.Serial.puts(&.{ch});
                }
            }
            // Ignore other control characters
        }
    }
}

// External assembly syscall entry point
extern fn syscall_entry() void;

// ===========================================================================
// Ring 0 Kernel Tasks — cooperative counters
// ============================================================================

pub var task1_counter: u64 = 0;
pub var task2_counter: u64 = 0;

fn task1() noreturn {
    // Task 1: Counter — increments a global, no I/O
    while (true) {
        task1_counter += 1;
        // Yield CPU with pause (efficient spin-wait for scheduler preemption)
        var i: usize = 0;
        while (i < 5000) : (i += 1) {
            asm volatile ("pause");
        }
    }
}

fn task2() noreturn {
    // Task 2: Counter — increments a global, no I/O
    while (true) {
        task2_counter += 1;
        var i: usize = 0;
        while (i < 5000) : (i += 1) {
            asm volatile ("pause");
        }
    }
}

// ===========================================================================
// v0.7.0 — Embedded ELF64 User Binary (Hello from Ring 3!)
// ===========================================================================
//
// Minimal ELF64 executable that:
//   1. Calls syscall 1 (print) with "Hello from Ring 3!\n"
//   2. Enters infinite pause loop
//
// User virtual address layout:
//   0x100000000: User code (1 page)
//   0x100080000: User stack (1 page, top = 0x100081000)
// ===========================================================================

const USER_CODE_BASE: u64 = 0x100000000; // 4GB virtual — above boot 2MB huge pages
const USER_STACK_BASE: u64 = 0x100080000; // 4GB + 512KB
const USER_STACK_TOP: u64 = 0x100081000; // Top of user stack page

// User task counter — incremented by the Ring 3 program via syscall
pub var user_task_counter: u64 = 0;

// Minimal ELF64 binary: prints "Hello from Ring 3!\n" via syscall, then exits.
//
// Machine code (loaded at 0x100000000):
//   mov rax, 1           ; syscall number = print
//   lea rdi, [rip+msg]   ; string pointer
//   mov rsi, 19          ; string length ("Hello from Ring 3!\n" = 19 bytes)
//   syscall              ; enter kernel
//   mov rax, 4           ; syscall number = exit
//   xor edi, edi         ; exit code = 0
//   syscall              ; exit the process (never returns)
// msg: "Hello from Ring 3!\n"
const user_hello_elf: [173]u8 align(8) = .{
    // ===== ELF64 Header (64 bytes) =====
    0x7F, 0x45, 0x4C, 0x46, // e_ident[0..3]: magic \x7fELF
    0x02,                   // e_ident[4]: ELFCLASS64
    0x01,                   // e_ident[5]: ELFDATA2LSB
    0x01,                   // e_ident[6]: EV_CURRENT
    0x00,                   // e_ident[7]: ELFOSABI_NONE
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_ident[8..15]: padding
    0x02, 0x00,             // e_type: ET_EXEC
    0x3E, 0x00,             // e_machine: EM_X86_64
    0x01, 0x00, 0x00, 0x00, // e_version: EV_CURRENT
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // e_entry: 0x100000000
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff: 64
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff: 0
    0x00, 0x00, 0x00, 0x00, // e_flags
    0x40, 0x00,             // e_ehsize: 64
    0x38, 0x00,             // e_phentsize: 56
    0x01, 0x00,             // e_phnum: 1
    0x00, 0x00,             // e_shentsize: 0
    0x00, 0x00,             // e_shnum: 0
    0x00, 0x00,             // e_shstrndx: 0
    // ===== Program Header (56 bytes) =====
    0x01, 0x00, 0x00, 0x00, // p_type: PT_LOAD
    0x05, 0x00, 0x00, 0x00, // p_flags: PF_R | PF_X
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset: 120
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // p_vaddr: 0x100000000
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // p_paddr: 0x100000000
    0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz: 53
    0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz: 53
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align: 4096
    // ===== Code (34 bytes) =====
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1 (syscall: print)
    0x48, 0x8D, 0x3D, 0x14, 0x00, 0x00, 0x00, // lea rdi, [rip+0x14] (→ msg, 20 bytes ahead)
    0x48, 0xC7, 0xC6, 0x13, 0x00, 0x00, 0x00, // mov rsi, 19 (string length)
    0x0F, 0x05,                               // syscall (print)
    0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00, // mov rax, 4 (syscall: exit)
    0x31, 0xFF,                               // xor edi, edi (exit code 0)
    0x0F, 0x05,                               // syscall (exit — never returns)
    // ===== Message (19 bytes) =====
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20, 0x52, 0x69, 0x6E, 0x67, 0x20, 0x33, 0x21, 0x0A, // "Hello from Ring 3!\n"
};

pub fn panic(msg: []const u8, error_return_trace: ?*@import("std").builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    vga_setcolor(0x0C); // Light red
    puts("\n!!! KERNEL PANIC !!!\n");
    puts(msg);
    puts("\nHalting CPU...\n");
    while (true) {
        hal.cli();
        hal.hlt();
    }
}
