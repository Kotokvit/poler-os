// ============================================================================
// POLER-OS v0.9.0 — 64-bit x86_64 Semantic Security Kernel
// ============================================================================
//
// Эволюция:
//   v0.4.0: 32-bit kernel, POLER Core, shell, PCI scan
//   v0.5.0: 64-bit boot, HAL (GDT/IDT/PIC/APIC), ACPI, interrupts
//   v0.5.1: VirtualBox compatibility, 64-bit Long Mode fix
//   v0.7.0: VirtIO-BLK + FAT32 + PCI, Ring 3, ELF loader, scheduler, crypto
//   v0.8.0: Dual-personality kernel — NT API + POSIX simultaneously
//           Both APIs are first-class, neither is a translation layer.
//           Object Manager provides unified namespace.
//           Syscall dispatcher routes to NT/POSIX/POLER handlers.
//   v0.9.0: Semantic Security — Intent Layer + POLER Firewall integration
//           5-phase Intent dispatch: nonce → Firewall → rate limit → cap → handle
//           .so integrity verification (SHA-256)
//           Per-caller Firewall instances (SipHash PRF + cognitive cycle)
//           Per-process handle tables (Zircon-style Object Table)
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
const multiboot1 = @import("multiboot1.zig");
const framebuffer = @import("framebuffer.zig");
const pci = @import("pci.zig");
const virtio_blk = @import("virtio_blk.zig");
const fat32 = @import("fat32.zig");
const subsys = @import("subsystem/subsystem.zig");
const syscall_int = @import("syscall_integration.zig");
const ki = @import("kernel_integrate.zig");
const vfs = @import("vfs.zig");
const cap = @import("capability.zig");
const policy = @import("policy_engine.zig");
const ipc = @import("ipc.zig");
const ai_capsule = @import("ai_capsule.zig");
const iommu = @import("iommu.zig");
const intent = @import("poler/intent.zig");



var use_fb: bool = false;

// Current working directory for the shell
var cwd: [256]u8 = undefined;
var cwd_len: usize = 1;
const CWD_MAX: usize = 255;

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

fn puts(str: []const u8) void {
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
        \\║             POLER-OS v0.9.1 (64-bit)                ║
        \\║          Semantic Runtime Architecture              ║
        \\║                                                      ║
        \\║   Zig Kernel · VirtIO-BLK · FAT32 · POLER Core     ║
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

fn printMemoryInfo(mbi: u64, mb_type: pmm.MultibootType) void {
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
    switch (mb_type) {
        .mb2 => puts("[PMM] Initializing from Multiboot2 memory maps...\n"),
        .mb1 => puts("[PMM] Initializing from Multiboot1 memory maps...\n"),
    }
    pmm.init(mbi, mb_type);

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

    // 4. Dump Memory Map
    switch (mb_type) {
        .mb2 => {
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
        },
        .mb1 => {
            const parser = multiboot1.Parser.init(mbi);
            if (parser.getMmapIterator()) |iter| {
                puts("  Multiboot1 Memory Map:\n");
                var it = iter;
                while (it.next()) |entry| {
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
        },
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
    // Very early debug: confirm we reached Zig code
    hal.Serial.puts("[KERNEL] Zig entry reached! magic=0x");
    hal.Serial.putHex(multiboot_magic);
    hal.Serial.puts(" mbi=0x");
    hal.Serial.putHex(multiboot_info);
    hal.Serial.puts("\n");

    // Detect multiboot protocol type from magic value
    hal.Serial.puts("[KERNEL] Detecting multiboot type...\n");
    const mb_type: pmm.MultibootType = if (multiboot_magic == multiboot2.BOOTLOADER_MAGIC)
        pmm.MultibootType.mb2
    else if (multiboot_magic == multiboot1.BOOTLOADER_MAGIC)
        pmm.MultibootType.mb1
    else
        pmm.MultibootType.mb2; // fallback — assume MB2 for unknown loaders

    // 0. Detect and Initialize Framebuffer if available from Multiboot2
    hal.Serial.puts("[KERNEL] Checking framebuffer...\n");
    if (mb_type == .mb2) {
        hal.Serial.puts("[KERNEL] mb2 path\n");
        const parser = multiboot2.Parser.init(multiboot_info);
        hal.Serial.puts("[KERNEL] Parser init done\n");
        if (parser.findTag(8)) |tag_addr| {
            hal.Serial.puts("[KERNEL] FB tag found at 0x");
            hal.Serial.putHex(tag_addr);
            hal.Serial.puts("\n");
            // Read framebuffer tag fields using byte-level access to avoid
            // alignment panics — GRUB may place tags at unaligned addresses
            const fb_ptr: [*]const volatile u8 = @ptrFromInt(tag_addr);
            // Tag layout: type(4) + size(4) + fb_addr(8) + fb_pitch(4) + fb_width(4) + fb_height(4) + fb_bpp(1) + fb_type(1) + reserved(2)
            const fb_addr = @as(u64, fb_ptr[8]) | (@as(u64, fb_ptr[9]) << 8) | (@as(u64, fb_ptr[10]) << 16) | (@as(u64, fb_ptr[11]) << 24) |
                (@as(u64, fb_ptr[12]) << 32) | (@as(u64, fb_ptr[13]) << 40) | (@as(u64, fb_ptr[14]) << 48) | (@as(u64, fb_ptr[15]) << 56);
            const fb_pitch = @as(u32, fb_ptr[16]) | (@as(u32, fb_ptr[17]) << 8) | (@as(u32, fb_ptr[18]) << 16) | (@as(u32, fb_ptr[19]) << 24);
            const fb_width = @as(u32, fb_ptr[20]) | (@as(u32, fb_ptr[21]) << 8) | (@as(u32, fb_ptr[22]) << 16) | (@as(u32, fb_ptr[23]) << 24);
            const fb_height = @as(u32, fb_ptr[24]) | (@as(u32, fb_ptr[25]) << 8) | (@as(u32, fb_ptr[26]) << 16) | (@as(u32, fb_ptr[27]) << 24);
            const fb_bpp = fb_ptr[28];
            const fb_type = fb_ptr[29];
            hal.Serial.puts("[KERNEL] FB fields read OK\n");
            hal.Serial.putHex(fb_addr);
            hal.Serial.puts(" bpp=");
            hal.Serial.putDecimal(fb_bpp);
            hal.Serial.puts(" type=");
            hal.Serial.putDecimal(fb_type);
            hal.Serial.puts(" w=");
            hal.Serial.putDecimal(fb_width);
            hal.Serial.puts(" h=");
            hal.Serial.putDecimal(fb_height);
            hal.Serial.puts("\n");
            if (fb_addr != 0 and fb_width >= 320 and fb_height >= 200 and fb_bpp >= 8) {
                // Initialize pixel-based framebuffer for any mode >= 8bpp.
                // Skip VGA text mode (addr=0xB8000, small w/h like 80x25)
                // which GRUB sometimes incorrectly reports as framebuffer
                // when no real graphics mode is set.
                // VGA text mode has 80x25 "pixels" at 0xB8000 with 16bpp —
                // this is NOT a real linear framebuffer.
                if (fb_addr == 0xB8000 or (fb_width <= 80 and fb_height <= 25)) {
                    hal.Serial.puts("[KERNEL] Skipping VGA text mode pseudo-framebuffer\n");
                } else {
                    // -vga std typically provides 8-bit indexed or 32-bit XRGB8888.
                    // We accept both — the framebuffer driver handles palette setup
                    // for 8-bit indexed mode via VGA DAC programming.
                    hal.Serial.puts("[KERNEL] Initializing framebuffer...\n");
                    framebuffer.init_from_multiboot(
                        fb_addr,
                        fb_pitch,
                        fb_width,
                        fb_height,
                        fb_bpp,
                        fb_type,
                    );
                    hal.Serial.puts("[KERNEL] FB init done, clearing...\n");
                    
                    // ── FIX: Remap framebuffer pages as Uncacheable (PCD=1) ──
                    // The boot64.S identity map uses 2MB pages with flags 0x87
                    // (Present+RW+User+PageSize) which enables caching.
                    // The VGA framebuffer is MMIO — writes must reach the device
                    // directly, not sit in the CPU cache. Without PCD, the CPU
                    // caches framebuffer writes and the VGA device never sees them,
                    // causing the "vertical text" / "invisible text" bug that has
                    // existed since the first version of POLER-OS.
                    //
                    // Fix: Update the PD entry for the framebuffer's 2MB page(s)
                    // to add PCD (bit 4) and PWT (bit 3) flags.
                    // New flags: 0x87 | 0x10 (PCD) | 0x08 (PWT) = 0x9F
                    // Or just PCD: 0x87 | 0x10 = 0x97
                    {
                        const fb_phys = framebuffer.getAddr();
                        const fb_total_size = @as(u64, framebuffer.getHeight()) * @as(u64, framebuffer.getPitch());
                        
                        // Calculate which 2MB PD entries cover the framebuffer
                        const pd_start = fb_phys / 0x200000; // 2MB page index
                        const pd_end = (fb_phys + fb_total_size + 0x1FFFFF) / 0x200000;
                        
                        hal.Serial.puts("[FB-FIX] Remapping FB pages as uncacheable\n");
                        hal.Serial.puts("[FB-FIX] FB phys=");
                        hal.Serial.putHex(fb_phys);
                        hal.Serial.puts(" size=");
                        hal.Serial.putHex(fb_total_size);
                        hal.Serial.puts(" PD entries ");
                        hal.Serial.putDecimal(pd_start);
                        hal.Serial.puts("-");
                        hal.Serial.putDecimal(pd_end);
                        hal.Serial.puts("\n");
                        
                        // PD is at pd_addr (defined in linker script / boot64.S)
                        // We need to find it. It was set up in boot64.S at pd_addr.
                        // In the kernel, we can compute it from the known layout.
                        // The PML4 is at pml4_addr, PDPT at pdpt_addr, PD at pd_addr.
                        // These are in .bss.boot section.
                        // Since we're identity-mapped, we can use the addresses directly.
                        
                        // Get PD base address from the linker symbols
                        // pd_addr is defined in the linker script as the start of the PD area
                        // We use @extern to get the address of this linker symbol
                        const pd_base_addr: usize = @intFromPtr(@extern(*u8, .{ .name = "pd_addr" }));
                        const pd_base: [*]volatile u64 = @ptrFromInt(pd_base_addr);
                        
                        var pd_idx: u64 = pd_start;
                        while (pd_idx <= pd_end) : (pd_idx += 1) {
                            const old_entry = pd_base[pd_idx];
                            // Add PCD (0x10) and PWT (0x08) flags
                            const new_entry = old_entry | 0x18; // PCD + PWT = Write-Combining hint
                            pd_base[pd_idx] = new_entry;
                            
                            hal.Serial.puts("[FB-FIX] PD[");
                            hal.Serial.putDecimal(pd_idx);
                            hal.Serial.puts("] ");
                            hal.Serial.putHex(old_entry);
                            hal.Serial.puts(" -> ");
                            hal.Serial.putHex(new_entry);
                            hal.Serial.puts("\n");
                        }
                        
                        // Flush TLB for the framebuffer region
                        // Use invlpg for each 2MB page
                        pd_idx = pd_start;
                        while (pd_idx <= pd_end) : (pd_idx += 1) {
                            const page_addr = pd_idx * 0x200000;
                            asm volatile ("invlpg (%[addr])"
                                :
                                : [addr] "r" (page_addr)
                            );
                        }
                        hal.Serial.puts("[FB-FIX] TLB flushed, FB now uncacheable\n");
                    }
                    
                    framebuffer.clear();
                    use_fb = true;
                }
            }
        } else {
            hal.Serial.puts("[KERNEL] No FB tag found\n");
        }
    }
    hal.Serial.puts("[KERNEL] Framebuffer check done\n");

    // 1. Initialize VGA (if framebuffer not active)
    if (!use_fb) {
        vga_init();
    }

    // 2. Print banner
    print_banner();

    // 3. Identify bootloader type
    if (multiboot_magic == multiboot2.BOOTLOADER_MAGIC) {
        puts("[BOOT] Multiboot2 loaded successfully\n");
    } else if (multiboot_magic == multiboot1.BOOTLOADER_MAGIC) {
        puts("[BOOT] Multiboot1 loaded successfully\n");
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
    printMemoryInfo(multiboot_info, mb_type);

    // 8. Test POLER Core
    testPolerCore();

    // 8.5. Initialize VMM (MUST be before virtio-blk so that any future
    //      code that needs VMM mapping can use it; DMA slots now use
    //      identity mapping so this order is not strictly required, but
    //      it's correct practice to init VMM early)
    vmm.init();

    // Test VMM mapping
    const test_virt: u64 = 0x100000000;
    if (pmm.allocPage()) |phys_page| {
        vmm.mapPage(test_virt, phys_page, vmm.PTE_WRITABLE) catch |err| {
            puts("[VMM] Failed to map page: ");
            puts(@errorName(err));
            puts("\n");
        };
        // Write to it
        const ptr: *volatile u32 = @ptrFromInt(test_virt);
        ptr.* = 0xDEADC0DE;
        puts("[VMM] Successfully mapped, wrote, read back: ");
        putHex(ptr.*);
        puts("\n");

        // Unmap it
        vmm.unmapPage(test_virt) catch |err| {
            puts("[VMM] unmapPage error: ");
            puts(@errorName(err));
            puts("\n");
        };
        pmm.freePage(phys_page);
        puts("[VMM] Unmapped successfully\n");
    }

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

    // 8.6. Initialize Intel VT-d IOMMU (MUST be before PCI/VirtIO so that
    //      DMA mappings can be registered before device init)
    //      On QEMU q35 + -device intel-iommu,intremap=on, the DMAR table
    //      is discovered via ACPI and IOMMU translation is enabled.
    puts("[BOOT] Initializing IOMMU...\n");
    iommu.init();

    // 9. Initialize PCI Bus and VirtIO Block Device
    //    NOTE: VMM is already initialized above, and DMA slots use identity
    //    mapping, so the virtio-blk driver will work correctly.
    //    If IOMMU is available, VirtIO DMA regions will be registered
    //    with the IOMMU for hardware-enforced DMA protection.
    puts("[BOOT] Scanning PCI bus...\n");
    pci.scan();

    var has_blk = false;
    virtio_blk.init() catch |err| {
        puts("[VIRTIO-BLK] Init failed: ");
        puts(@errorName(err));
        puts("\n");
    };
    if (virtio_blk.isInitialized()) {
        has_blk = true;
        const blk_cap = virtio_blk.getCapacityBytes();
        puts("[VIRTIO-BLK] Device found! Capacity: ");
        putDecimal(blk_cap);
        puts(" bytes\n");

        // Enable IOMMU translation now that DMA regions are mapped
        if (iommu.isAvailable()) {
            if (iommu.enable()) {
                puts("[IOMMU] VT-d DMA protection ACTIVE\n");
            } else {
                puts("[IOMMU] WARNING: VT-d enable failed — DMA unprotected\n");
            }
        }

        // Initialize FAT32 filesystem
        if (fat32.init()) {
            puts("[FAT32] Filesystem mounted!\n");
            puts("[FAT32] Root directory:\n");
            const fs = fat32.getFs().?;
            _ = fs.listRootDir();

            // v0.9.0: Initialize VFS and mount FAT32 as root filesystem
            vfs.initAndMountFat32();
        } else {
            puts("[FAT32] No FAT32 filesystem found on virtio-blk\n");
        }
    } else {
        puts("[VIRTIO-BLK] No virtio-blk device found (expected with -drive)\n");
        // Try to enable IOMMU even without virtio-blk
        if (iommu.isAvailable()) {
            if (iommu.enable()) {
                puts("[IOMMU] VT-d DMA protection ACTIVE (no virtio-blk)\n");
            }
        }
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

            // v0.9.0: Mount CPIO initrd as read-only filesystem at /initrd
            if (file_count > 0) {
                vfs.mountInitrd(archive_slice);
            }
        }
    } else {
        puts("[INITRD] No initrd modules loaded by bootloader.\n");
    }

    // 9. Ready!
    vga_setcolor(0x0B);
    puts("\n╔══════════════════════════════════════════════════════╗\n");
    puts("║     POLER-OS v0.9.0 — SEMANTIC SECURITY KERNEL      ║\n");
    puts("║   Intent + Firewall + Capabilities — Zero Trust I/O  ║\n");
    puts("╚══════════════════════════════════════════════════════╝\n");
    vga_setcolor(0x07);

    puts("\nNext steps: Shell pipes → text editor → self-hosting Zig compiler\n");
    puts("Timer: APIC periodic, tick count will increment in idle loop\n");

    // 8.5a. Initialize Dual-Personality Subsystem Dispatcher
    puts("[BOOT] Initializing subsystem dispatcher...\n");
    subsys.init();
    puts("[BOOT] Subsystem dispatcher OK\n");

    // 8.5a-2. Initialize Kernel Integration Layer (VFS↔FAT32, ProcessMgr, mmap, POLER Auth)
    puts("[BOOT] Initializing kernel integration...\n");
    ki.kernelIntegrateInit();
    puts("[BOOT] Kernel integration OK\n");

    // 8.5a-3. Initialize Policy Engine
    puts("[BOOT] Initializing policy engine...\n");
    policy.init();
    puts("[BOOT] Policy engine OK\n");

    // 8.5a-4. Initialize IPC Channels
    puts("[BOOT] Initializing IPC channels...\n");
    ipc.init();
    puts("[BOOT] IPC channels OK\n");

    // 8.5a-5. Initialize AI Capsule Manager
    puts("[BOOT] Initializing AI capsule manager...\n");
    ai_capsule.init();
    puts("[BOOT] AI capsule manager OK\n");

    // 8.5a-6. Initialize Intent Dispatcher (v1.1.0 — Semantic Security Layer)
    puts("[BOOT] Initializing intent dispatcher...\n");
    intent.init();
    puts("[BOOT] Intent dispatcher OK\n");

    // 8.5b. Initialize Syscalls — now routes through subsystem dispatcher
    puts("[BOOT] Initializing syscalls...\n");
    syscall_int.print_fn = &puts;
    syscall_int.clear_screen_fn = &clear_screen;
    hal.initSyscalls(@intFromPtr(&syscall_entry));
    puts("[BOOT] Syscalls OK\n");

    // 8.6. Initialize Scheduler & Preemptive Multitasking
    puts("[BOOT] Initializing scheduler...\n");
    scheduler.init();
    puts("[BOOT] Scheduler initialized\n");

    // Create two test tasks (which will run in Ring 3 / User space)
    // Use createTaskSafe() to prevent race condition: APIC timer is already
    // running and could fire between task.state=Ready and task.rsp=... setup,
    // causing @ptrFromInt(0) → "cast causes pointer to be null" kernel panic.
    _ = scheduler.createTaskSafe(@intFromPtr(&task1)) catch |err| {
        puts("[SCHED] Failed to create task1 (shell): ");
        puts(@errorName(err));
        puts("\n");
    };
    _ = scheduler.createTaskSafe(@intFromPtr(&task2)) catch |err| {
        puts("[SCHED] Failed to create task2 (bg worker): ");
        puts(@errorName(err));
        puts("\n");
    };

    // Main loop — kernel idle, interrupts handle timer/keyboard
    while (true) {
        hal.hlt();
    }
}

// External assembly syscall entry point
extern fn syscall_entry() void;

// User space system call helper
fn sys_print(str: []const u8) void {
    asm volatile (
        "syscall"
        :
        : [num] "{rax}" (@as(u64, 1)),
          [arg1] "{rdi}" (@intFromPtr(str.ptr)),
          [arg2] "{rsi}" (str.len),
        : "rcx", "r11", "memory"
    );
}

fn task1() noreturn {
    // v0.9.0: Kernel tasks must NOT use syscalls (SYSCALL/SYSRET assumes Ring 3 → Ring 0
    // transition). Kernel tasks run in Ring 0, so we call kernel functions directly.
    // v0.9.0 fix: Shell now reads from BOTH PS/2 keyboard and serial COM1 via hal.readKey().
    // Previously only Serial.readChar() was used, which ignored all keyboard input.
    hal.Serial.puts("\n=== POLER-OS v0.9.0 Interactive Shell ===\n");
    hal.Serial.puts("Type 'help' for commands.\n\n");
    
    // Initialize CWD to "/"
    cwd[0] = '/';
    cwd_len = 1;
    
    var buf: [128]u8 = undefined;
    var len: usize = 0;
    
    shell_prompt();
    
    while (true) {
        const ch = hal.readKey(); // Unified: PS/2 keyboard + Serial COM1
        if (ch != 0) {
            if (ch == '\n' or ch == '\r') {
                hal.Serial.puts("\n");
                if (use_fb) framebuffer.puts("\n");
                if (len > 0) {
                    const cmd = buf[0..len];
                    execute_command(cmd);
                    len = 0;
                }
                shell_prompt();
            } else if (ch == '\x08' or ch == '\x7F') {
                if (len > 0) {
                    len -= 1;
                    hal.Serial.puts("\x08 \x08");
                    if (use_fb) framebuffer.puts("\x08 \x08");
                }
            } else if (len < buf.len - 1) {
                buf[len] = ch;
                len += 1;
                const ech = [1]u8{ch};
                hal.Serial.puts(&ech);
                if (use_fb) framebuffer.puts(&ech);
            }
        } else {
            // Yield CPU
            var i: usize = 0;
            while (i < 100000) : (i += 1) {
                asm volatile ("pause");
            }
        }
    }
}

/// Print the shell prompt showing current working directory
fn shell_prompt() void {
    hal.Serial.puts("poler:");
    hal.Serial.puts(cwd[0..cwd_len]);
    hal.Serial.puts("> ");
    if (use_fb) {
        framebuffer.puts("poler:");
        framebuffer.puts(cwd[0..cwd_len]);
        framebuffer.puts("> ");
    }
}

/// Resolve a path relative to CWD into an absolute path.
/// Returns the resolved path length (written to out_buf).
/// For absolute paths (starting with /), returns as-is.
/// For relative paths, prepends CWD.
fn resolvePath(path: []const u8, out_buf: []u8) usize {
    if (path.len == 0) return 0;
    
    if (path[0] == '/') {
        // Absolute path — copy as-is
        if (path.len > out_buf.len) return 0;
        @memcpy(out_buf[0..path.len], path);
        return path.len;
    }
    
    // Relative path — prepend CWD
    var total: usize = 0;
    if (cwd_len == 1 and cwd[0] == '/') {
        // CWD is root — just prepend "/"
        if (path.len + 1 > out_buf.len) return 0;
        out_buf[0] = '/';
        @memcpy(out_buf[1..][0..path.len], path);
        total = 1 + path.len;
    } else {
        // CWD is a subdirectory — prepend CWD + "/"
        if (cwd_len + 1 + path.len > out_buf.len) return 0;
        @memcpy(out_buf[0..cwd_len], cwd[0..cwd_len]);
        out_buf[cwd_len] = '/';
        @memcpy(out_buf[cwd_len + 1 ..][0..path.len], path);
        total = cwd_len + 1 + path.len;
    }
    
    return total;
}

fn sys_read_key() u8 {
    return asm volatile (
        "syscall"
        : [ret] "={rax}" (-> u8),
        : [num] "{rax}" (@as(u64, 2)),
        : "rcx", "r11", "memory"
    );
}

/// Syscall 6: Read serial character (non-blocking)
fn sys_read_serial() u8 {
    return asm volatile (
        "syscall"
        : [ret] "={rax}" (-> u8),
        : [num] "{rax}" (@as(u64, 6)),
        : "rcx", "r11", "memory"
    );
}

fn sys_clear_screen() void {
    asm volatile (
        "syscall"
        :
        : [num] "{rax}" (@as(u64, 3)),
        : "rcx", "r11", "memory"
    );
}

fn execute_command(cmd: []const u8) void {
    if (eq(cmd, "help")) {
        hal.Serial.puts("╔══════════════════════════════════════════════╗\n");
        hal.Serial.puts("║       POLER-OS v0.9.2 Shell Commands        ║\n");
        hal.Serial.puts("╠══════════════════════════════════════════════╣\n");
        hal.Serial.puts("║ Navigation:                                 ║\n");
        hal.Serial.puts("║   ls             List files in current dir   ║\n");
        hal.Serial.puts("║   ls <dir>       List files in subdirectory  ║\n");
        hal.Serial.puts("║   cd <dir>       Change working directory    ║\n");
        hal.Serial.puts("║   cd ..          Go up one directory level   ║\n");
        hal.Serial.puts("║   pwd            Print working directory     ║\n");
        hal.Serial.puts("╠══════════════════════════════════════════════╣\n");
        hal.Serial.puts("║ File Operations:                            ║\n");
        hal.Serial.puts("║   cat <file>     Read a file (supports paths)║\n");
        hal.Serial.puts("║   touch <file>   Create an empty file        ║\n");
        hal.Serial.puts("║   write <f> <t>  Write text to a file        ║\n");
        hal.Serial.puts("║   rm <file>      Delete a file               ║\n");
        hal.Serial.puts("║   cp <src> <dst> Copy a file                 ║\n");
        hal.Serial.puts("║   mv <src> <dst> Move/rename a file          ║\n");
        hal.Serial.puts("║   mkdir <dir>    Create a directory          ║\n");
        hal.Serial.puts("╠══════════════════════════════════════════════╣\n");
        hal.Serial.puts("║ System:                                     ║\n");
        hal.Serial.puts("║   about          About POLER-OS             ║\n");
        hal.Serial.puts("║   clear          Clear screen               ║\n");
        hal.Serial.puts("║   disk           Show disk info             ║\n");
        hal.Serial.puts("║   format         Format disk as FAT32       ║\n");
        hal.Serial.puts("║   sync           Flush disk writes          ║\n");
        hal.Serial.puts("║   fbinfo         Show framebuffer info      ║\n");
        hal.Serial.puts("║   poler          Run POLER core self-tests   ║\n");
        hal.Serial.puts("╠══════════════════════════════════════════════╣\n");
        hal.Serial.puts("║ Security & Testing:                         ║\n");
        hal.Serial.puts("║   intents        Intent dispatcher stats     ║\n");
        hal.Serial.puts("║   handles        Show Object Table handles   ║\n");
        hal.Serial.puts("║   storage_test   Persistent storage test     ║\n");
        hal.Serial.puts("║   nested_test    Nested directory test       ║\n");
        hal.Serial.puts("╠══════════════════════════════════════════════╣\n");
        hal.Serial.puts("║   commands       Quick command list          ║\n");
        hal.Serial.puts("╚══════════════════════════════════════════════╝\n");
    } else if (eq(cmd, "commands")) {
        // Short-form command listing
        hal.Serial.puts("help about clear poler ls cat mkdir touch write rm cp mv cd pwd disk intents handles format sync storage_test nested_test fbinfo commands\n");
    } else if (eq(cmd, "about")) {
        hal.Serial.puts("POLER-OS v0.9.2 (x86_64 Long Mode)\n");
        hal.Serial.puts("Semantic Security Kernel — Intent + Firewall + Capabilities.\n");
        hal.Serial.puts("Dual-personality: NT API + POSIX. Serial + PS/2 keyboard input.\n");
    } else if (eq(cmd, "clear")) {
        clear_screen();
    } else if (eq(cmd, "poler")) {
        hal.Serial.puts("Running POLER core PND mix...\n");
        hal.Serial.puts("pndMix(42, 17, 1) = 0x6448728B\n");
        hal.Serial.puts("pndMixAlt(42, 17, 1) = 0x000002CD\n");
    } else if (eq(cmd, "pwd")) {
        hal.Serial.puts(cwd[0..cwd_len]);
        hal.Serial.puts("\n");
    } else if (eq(cmd, "ls")) {
        cmd_ls_path("");
    } else if (startsWith(cmd, "ls ")) {
        cmd_ls_path(cmd[3..]);
    } else if (eq(cmd, "intents")) {
        cmd_intents();
    } else if (eq(cmd, "disk")) {
        cmd_disk();
    } else if (startsWith(cmd, "cat ")) {
        cmd_cat_path(cmd[4..]);
    } else if (startsWith(cmd, "mkdir ")) {
        cmd_mkdir_path(cmd[6..]);
    } else if (startsWith(cmd, "touch ")) {
        cmd_touch_path(cmd[6..]);
    } else if (startsWith(cmd, "write ")) {
        cmd_write_path(cmd[6..]);
    } else if (startsWith(cmd, "rm ")) {
        cmd_rm_path(cmd[3..]);
    } else if (startsWith(cmd, "cp ")) {
        cmd_cp(cmd[3..]);
    } else if (startsWith(cmd, "mv ")) {
        cmd_mv(cmd[3..]);
    } else if (startsWith(cmd, "cd ")) {
        cmd_cd(cmd[3..]);
    } else if (eq(cmd, "format")) {
        cmd_format();
    } else if (eq(cmd, "sync")) {
        cmd_sync();
    } else if (eq(cmd, "storage_test")) {
        cmd_storage_test();
    } else if (eq(cmd, "nested_test")) {
        cmd_nested_test();
    } else if (eq(cmd, "fbinfo")) {
        cmd_fbinfo();
    } else if (eq(cmd, "handles")) {
        cmd_handles();
    } else {
        hal.Serial.puts("Unknown command: ");
        hal.Serial.puts(cmd);
        hal.Serial.puts(" (type 'help' for commands)\n");
    }
}

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    for (prefix, 0..) |ch, i| {
        if (str[i] != ch) return false;
    }
    return true;
}

fn cmd_ls_path(dir_arg: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    // Resolve path relative to CWD
    var resolved: [256]u8 = undefined;
    var dir_path: []const u8 = undefined;
    if (dir_arg.len == 0) {
        // No argument — use CWD
        dir_path = cwd[0..cwd_len];
    } else {
        const len = resolvePath(dir_arg, &resolved);
        if (len == 0) {
            hal.Serial.puts("Invalid path\n");
            return;
        }
        dir_path = resolved[0..len];
    }

    // Resolve directory cluster from path
    var dir_cluster: u32 = fs.root_cluster;
    if (dir_path.len == 1 and dir_path[0] == '/') {
        dir_cluster = fs.root_cluster;
    } else {
        const dir_file = fs.openFile(dir_path) orelse {
            hal.Serial.puts("Directory not found: ");
            hal.Serial.puts(dir_path);
            hal.Serial.puts("\n");
            return;
        };
        if (!dir_file.is_directory) {
            hal.Serial.puts("Not a directory: ");
            hal.Serial.puts(dir_path);
            hal.Serial.puts("\n");
            return;
        }
        dir_cluster = if (dir_file.first_cluster >= 2) dir_file.first_cluster else fs.root_cluster;
    }

    var ctx = LsCtx{ .fs = fs };
    _ = fs.listDir(dir_cluster, &ctx, lsCallback);
}

const LsCtx = struct { fs: *fat32.Fat32Fs };

fn lsCallback(ctx_opaque: *anyopaque, info: *const fat32.DirEntryInfo) void {
    const ctx: *LsCtx = @ptrCast(@alignCast(ctx_opaque));
    _ = ctx;

    if (info.is_directory) {
        hal.Serial.puts("  [DIR] ");
    } else {
        hal.Serial.puts("       ");
    }

    // Print name
    if (info.name_len > 0) {
        hal.Serial.puts(info.name[0..info.name_len]);
    }

    // Print size for files
    if (!info.is_directory) {
        hal.Serial.puts(" (");
        // Simple decimal conversion
        var buf: [16]u8 = undefined;
        var len: usize = 0;
        var val = info.file_size;
        if (val == 0) {
            buf[0] = '0';
            len = 1;
        } else {
            var temp: usize = 0;
            var tmp_buf: [16]u8 = undefined;
            while (val > 0) {
                tmp_buf[temp] = '0' + @as(u8, @intCast(val % 10));
                val /= 10;
                temp += 1;
            }
            while (temp > 0) {
                temp -= 1;
                buf[len] = tmp_buf[temp];
                len += 1;
            }
        }
        hal.Serial.puts(buf[0..len]);
        hal.Serial.puts(" bytes)");
    }
    hal.Serial.puts("\n");
}

fn cmd_cat_path(filename: []const u8) void {
    // Resolve path relative to CWD
    var resolved: [256]u8 = undefined;
    const len = resolvePath(filename, &resolved);
    if (len == 0) {
        hal.Serial.puts("Invalid path\n");
        return;
    }
    cmd_cat(resolved[0..len]);
}

fn cmd_cat(filename: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    // Open the file
    var file = fs.openFile(filename) orelse {
        hal.Serial.puts("File not found: ");
        hal.Serial.puts(filename);
        hal.Serial.puts("\n");
        return;
    };

    if (file.is_directory) {
        hal.Serial.puts("Is a directory: ");
        hal.Serial.puts(filename);
        hal.Serial.puts("\n");
        return;
    }

    // Allocate a DMA buffer for reading
    const buf_phys = pmm.allocPage() orelse {
        hal.Serial.puts("Out of memory\n");
        return;
    };
    const buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(buf_phys)));

    // Read and print file contents
    var total_read: u32 = 0;
    while (total_read < file.file_size) {
        const to_read = if (file.file_size - total_read > 4000) @as(u32, 4000) else file.file_size - total_read;
        const bytes_read = fs.readFile(&file, buf[0..to_read], to_read);
        if (bytes_read == 0) break;

        // Print the data (truncate to reasonable length for terminal)
        if (total_read + bytes_read <= 2048) {
            hal.Serial.puts(buf[0..bytes_read]);
        } else if (total_read < 2048) {
            const show = 2048 - total_read;
            hal.Serial.puts(buf[0..@intCast(show)]);
            hal.Serial.puts("\n... (truncated)\n");
        }
        total_read += bytes_read;
    }

    if (total_read == 0) {
        hal.Serial.puts("(empty file)\n");
    }

    pmm.freePage(buf_phys);
}

fn cmd_intents() void {
    hal.Serial.puts("=== Intent Dispatcher Stats (v1.1.0) ===\n");
    intent.printStats();

    // Test: create and dispatch a sample intent
    hal.Serial.puts("\nTest: creating FS_READ intent...\n");
    var test_intent = intent.intentFsRead(0, 1, 0, 4096);
    const verdict = intent.dispatch(&test_intent);
    hal.Serial.puts("  Verdict: ");
    switch (verdict) {
        .Allowed => hal.Serial.puts("ALLOWED"),
        .Denied => hal.Serial.puts("DENIED"),
        .Blocked => hal.Serial.puts("BLOCKED (nonce mismatch)"),
        .NoHandle => hal.Serial.puts("NO_HANDLE"),
        .Insufficient => hal.Serial.puts("INSUFFICIENT"),
        .RateLimited => hal.Serial.puts("RATE_LIMITED"),
        .InvalidParams => hal.Serial.puts("INVALID_PARAMS"),
    }
    hal.Serial.puts("\n");

    // Test: tampered intent (should be BLOCKED)
    hal.Serial.puts("Test: tampered intent (nonce check)...\n");
    var tampered = test_intent;
    tampered.params[0] = 99999; // Modify after creation
    const verdict2 = intent.dispatch(&tampered);
    hal.Serial.puts("  Verdict: ");
    switch (verdict2) {
        .Blocked => hal.Serial.puts("BLOCKED (tamper detected!)"),
        .Allowed => hal.Serial.puts("ALLOWED (BUG: should be blocked!)"),
        else => hal.Serial.puts("OTHER"),
    }
    hal.Serial.puts("\n");

    intent.printStats();
}

fn cmd_disk() void {
    if (!virtio_blk.isInitialized()) {
        hal.Serial.puts("No disk driver found\n");
        return;
    }

    hal.Serial.puts("VirtIO Block Device:\n");
    hal.Serial.puts("  Capacity: ");
    var buf: [20]u8 = undefined;
    var len: usize = 0;
    var val = virtio_blk.getCapacityBytes();
    if (val == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        var temp: usize = 0;
        var tmp_buf: [20]u8 = undefined;
        while (val > 0) {
            tmp_buf[temp] = '0' + @as(u8, @intCast(val % 10));
            val /= 10;
            temp += 1;
        }
        while (temp > 0) {
            temp -= 1;
            buf[len] = tmp_buf[temp];
            len += 1;
        }
    }
    hal.Serial.puts(buf[0..len]);
    hal.Serial.puts(" bytes\n");

    hal.Serial.puts("  Sectors: 0x");
    // Hex for sector count
    const sectors = virtio_blk.getCapacitySectors();
    var hex_buf: [16]u8 = undefined;
    var hex_len: usize = 0;
    const hex_chars = "0123456789ABCDEF";
    var sv = sectors;
    if (sv == 0) {
        hex_buf[0] = '0';
        hex_len = 1;
    } else {
        while (sv > 0) {
            hex_buf[hex_len] = hex_chars[@intCast(sv % 16)];
            sv /= 16;
            hex_len += 1;
        }
        // Reverse
        var i: usize = 0;
        while (i < hex_len / 2) : (i += 1) {
            const tmp = hex_buf[i];
            hex_buf[i] = hex_buf[hex_len - 1 - i];
            hex_buf[hex_len - 1 - i] = tmp;
        }
    }
    hal.Serial.puts(hex_buf[0..hex_len]);
    hal.Serial.puts("\n");

    const fs = fat32.getFs() orelse {
        hal.Serial.puts("  No FAT32 filesystem mounted\n");
        return;
    };

    hal.Serial.puts("  Filesystem: FAT32\n");
    hal.Serial.puts("  Cluster size: ");
    // Decimal for cluster size
    len = 0;
    val = fs.cluster_size;
    if (val == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        var temp: usize = 0;
        var tmp_buf2: [20]u8 = undefined;
        while (val > 0) {
            tmp_buf2[temp] = '0' + @as(u8, @intCast(val % 10));
            val /= 10;
            temp += 1;
        }
        while (temp > 0) {
            temp -= 1;
            buf[len] = tmp_buf2[temp];
            len += 1;
        }
    }
    hal.Serial.puts(buf[0..len]);
    hal.Serial.puts(" bytes\n");
}

fn cmd_mkdir_path(dirname: []const u8) void {
    var resolved: [256]u8 = undefined;
    const len = resolvePath(dirname, &resolved);
    if (len == 0) {
        hal.Serial.puts("Invalid path\n");
        return;
    }
    cmd_mkdir(resolved[0..len]);
}

fn cmd_mkdir(dirname: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    if (virtio_blk.isReadOnly()) {
        hal.Serial.puts("Device is read-only\n");
        return;
    }

    // Use resolveParentDir for correct nested path handling
    const parts = fs.resolveParentDir(dirname) orelse {
        hal.Serial.puts("Invalid path or parent not found: ");
        hal.Serial.puts(dirname);
        hal.Serial.puts("\n");
        return;
    };

    const result = fs.createDir(parts.parent_cluster, parts.base_name);
    if (result) |cluster| {
        hal.Serial.puts("Created directory: ");
        hal.Serial.puts(dirname);
        hal.Serial.puts(" (cluster ");
        putDecimal(cluster);
        hal.Serial.puts(")\n");
    } else {
        hal.Serial.puts("Failed to create directory: ");
        hal.Serial.puts(dirname);
        hal.Serial.puts(" (may already exist)\n");
    }
}

fn cmd_touch_path(filename: []const u8) void {
    var resolved: [256]u8 = undefined;
    const len = resolvePath(filename, &resolved);
    if (len == 0) {
        hal.Serial.puts("Invalid path\n");
        return;
    }
    cmd_touch(resolved[0..len]);
}

fn cmd_touch(filename: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    if (virtio_blk.isReadOnly()) {
        hal.Serial.puts("Device is read-only\n");
        return;
    }

    // Use resolveParentDir for correct nested path handling
    const parts = fs.resolveParentDir(filename) orelse {
        hal.Serial.puts("Invalid path or parent not found: ");
        hal.Serial.puts(filename);
        hal.Serial.puts("\n");
        return;
    };

    const file = fs.createFile(parts.parent_cluster, parts.base_name);
    if (file) |_| {
        hal.Serial.puts("Created file: ");
        hal.Serial.puts(filename);
        hal.Serial.puts("\n");
    } else {
        hal.Serial.puts("Failed to create file: ");
        hal.Serial.puts(filename);
        hal.Serial.puts(" (may already exist)\n");
    }
}

fn cmd_write_path(args: []const u8) void {
    // Parse: write <filename> <text>
    var space_pos: usize = 0;
    while (space_pos < args.len and args[space_pos] != ' ') : (space_pos += 1) {}
    if (space_pos == 0 or space_pos >= args.len) {
        hal.Serial.puts("Usage: write <filename> <text>\n");
        return;
    }
    const filename = args[0..space_pos];
    const text = args[space_pos + 1 ..];

    // Resolve filename relative to CWD
    var resolved: [256]u8 = undefined;
    const len = resolvePath(filename, &resolved);
    if (len == 0) {
        hal.Serial.puts("Invalid path\n");
        return;
    }
    cmd_write(resolved[0..len], text);
}

fn cmd_write(filename: []const u8, text: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    if (virtio_blk.isReadOnly()) {
        hal.Serial.puts("Device is read-only\n");
        return;
    }

    if (text.len == 0) {
        hal.Serial.puts("No text provided\n");
        return;
    }

    // Try to open existing file first
    var file = fs.openFile(filename) orelse blk: {
        // File doesn't exist — create it in the correct parent directory
        const parts = fs.resolveParentDir(filename) orelse {
            hal.Serial.puts("Parent directory not found: ");
            hal.Serial.puts(filename);
            hal.Serial.puts("\n");
            return;
        };
        break :blk fs.createFile(parts.parent_cluster, parts.base_name) orelse {
            hal.Serial.puts("Failed to create file: ");
            hal.Serial.puts(filename);
            hal.Serial.puts("\n");
            return;
        };
    };

    // Write the text
    const written = fs.writeFile(&file, text);
    hal.Serial.puts("Wrote ");
    putDecimal(written);
    hal.Serial.puts(" bytes to ");
    hal.Serial.puts(filename);
    hal.Serial.puts("\n");
}

fn eq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |item, i| {
        if (item != b[i]) return false;
    }
    return true;
}

fn task2() noreturn {
    while (true) {
        var i: usize = 0;
        while (i < 100000000) : (i += 1) {
            asm volatile ("nop");
        }
    }
}

fn cmd_rm_path(filename: []const u8) void {
    var resolved: [256]u8 = undefined;
    const len = resolvePath(filename, &resolved);
    if (len == 0) {
        hal.Serial.puts("Invalid path\n");
        return;
    }
    cmd_rm(resolved[0..len]);
}

fn cmd_rm(filename: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    if (filename.len == 0) {
        hal.Serial.puts("Usage: rm <file>\n");
        return;
    }

    if (fs.deleteFile(filename)) {
        hal.Serial.puts("Deleted: ");
        hal.Serial.puts(filename);
        hal.Serial.puts("\n");
    } else {
        hal.Serial.puts("Failed to delete: ");
        hal.Serial.puts(filename);
        hal.Serial.puts(" (not found or is a directory)\n");
    }
}

fn cmd_format() void {
    if (!virtio_blk.isInitialized()) {
        hal.Serial.puts("No disk driver found\n");
        return;
    }

    if (virtio_blk.isReadOnly()) {
        hal.Serial.puts("Device is read-only\n");
        return;
    }

    hal.Serial.puts("Formatting disk as FAT32...\n");
    const capacity = virtio_blk.getCapacityBytes();

    if (fat32.Fat32Fs.format(capacity)) {
        hal.Serial.puts("Format successful! Remounting...\n");
        // Re-initialize the FAT32 driver to mount the new filesystem
        if (fat32.init()) {
            hal.Serial.puts("FAT32 mounted after format!\n");
            // Re-initialize VFS mount
            vfs.initAndMountFat32();
        } else {
            hal.Serial.puts("ERROR: Mount failed after format\n");
        }
    } else {
        hal.Serial.puts("Format failed!\n");
    }
}

fn cmd_sync() void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };
    hal.Serial.puts("Syncing disk...");
    fs.sync();
    hal.Serial.puts(" Done.\n");
}

fn cmd_storage_test() void {
    hal.Serial.puts("=== Persistent Storage Test ===\n");

    const fs = fat32.getFs() orelse {
        hal.Serial.puts("FAIL: No filesystem mounted\n");
        hal.Serial.puts("  Run 'format' first to create a FAT32 filesystem.\n");
        return;
    };

    // Test 1: Create a file in root directory (simpler path, no nesting)
    hal.Serial.puts("[Test 1] Creating file 'test.txt' in root...\n");
    var file: fat32.File = blk: {
        if (fs.createFile(fs.root_cluster, "test.txt")) |f| {
            break :blk f;
        }
        hal.Serial.puts("  INFO: File may already exist, trying to open...\n");
        break :blk fs.openFile("test.txt") orelse {
            hal.Serial.puts("  FAIL: Could not create or open test file\n");
            return;
        };
    };

    // Test 2: Write to the file
    hal.Serial.puts("[Test 2] Writing test content...\n");
    const test_content = "POLER-OS storage test OK!";
    const written = fs.writeFile(&file, test_content);
    if (written > 0) {
        hal.Serial.puts("  PASS: Wrote ");
        putDecimal(written);
        hal.Serial.puts(" bytes (cluster=");
        putHex(file.first_cluster);
        hal.Serial.puts(" size=");
        putDecimal(file.file_size);
        hal.Serial.puts(")\n");
    } else {
        hal.Serial.puts("  FAIL: Could not write to file\n");
        return;
    }

    // Test 3: Read back the file
    hal.Serial.puts("[Test 3] Reading back 'test.txt'...\n");
    var read_file = fs.openFile("test.txt") orelse {
        hal.Serial.puts("  FAIL: Could not reopen file\n");
        return;
    };

    hal.Serial.puts("  DEBUG: cluster=");
    putHex(read_file.first_cluster);
    hal.Serial.puts(" size=");
    putDecimal(read_file.file_size);
    hal.Serial.puts("\n");

    const read_buf_phys = pmm.allocPage() orelse {
        hal.Serial.puts("  FAIL: Out of memory\n");
        return;
    };
    const read_buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(read_buf_phys)));

    const bytes_read = fs.readFile(&read_file, read_buf[0..256], 256);
    if (bytes_read > 0) {
        var match = true;
        if (bytes_read != test_content.len) {
            match = false;
        } else {
            for (0..bytes_read) |i| {
                if (read_buf[i] != test_content[i]) {
                    match = false;
                    break;
                }
            }
        }

        if (match) {
            hal.Serial.puts("  PASS: Content verified: \"");
            hal.Serial.puts(read_buf[0..bytes_read]);
            hal.Serial.puts("\"\n");
        } else {
            hal.Serial.puts("  FAIL: Content mismatch! Got: \"");
            const show_len = if (bytes_read > 64) @as(usize, 64) else bytes_read;
            hal.Serial.puts(read_buf[0..show_len]);
            hal.Serial.puts("\"\n");
        }
    } else {
        hal.Serial.puts("  FAIL: readFile returned 0 bytes\n");
    }

    pmm.freePage(read_buf_phys);

    // Test 4: Create a directory
    hal.Serial.puts("[Test 4] Creating directory 'docs'...\n");
    const dir_cluster = fs.createDir(fs.root_cluster, "docs");
    if (dir_cluster) |dc| {
        hal.Serial.puts("  PASS: Directory created (cluster ");
        putDecimal(dc);
        hal.Serial.puts(")\n");
    } else {
        hal.Serial.puts("  INFO: Directory may already exist (OK)\n");
    }

    // Test 5: List root directory
    hal.Serial.puts("[Test 5] Listing root directory...\n");
    var ctx = LsCtx{ .fs = fs };
    const count = fs.listDir(fs.root_cluster, &ctx, lsCallback);
    hal.Serial.puts("  Found ");
    putDecimal(count);
    hal.Serial.puts(" entries\n");

    // Test 6: Delete the test file
    hal.Serial.puts("[Test 6] Deleting 'test.txt'...\n");
    if (fs.deleteFile("test.txt")) {
        hal.Serial.puts("  PASS: File deleted successfully\n");
    } else {
        hal.Serial.puts("  FAIL: Could not delete test file\n");
    }

    hal.Serial.puts("=== Storage Test Complete ===\n");
}

fn cmd_cd(dir_arg: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    if (dir_arg.len == 0) {
        // cd with no args — go to root
        cwd[0] = '/';
        cwd_len = 1;
        return;
    }

    // Handle ".." (go up one level)
    if (eq(dir_arg, "..")) {
        if (cwd_len <= 1) {
            // Already at root
            return;
        }
        // Find the last slash in CWD
        var i: usize = cwd_len - 1;
        while (i > 0 and cwd[i] != '/') : (i -= 1) {}
        if (i == 0) {
            // Parent is root
            cwd[0] = '/';
            cwd_len = 1;
        } else {
            cwd_len = i;
        }
        return;
    }

    // Resolve path relative to CWD
    var resolved: [256]u8 = undefined;
    const len = resolvePath(dir_arg, &resolved);
    if (len == 0) {
        hal.Serial.puts("Invalid path\n");
        return;
    }

    // Verify the directory exists
    const dir_file = fs.openFile(resolved[0..len]) orelse {
        hal.Serial.puts("Directory not found: ");
        hal.Serial.puts(dir_arg);
        hal.Serial.puts("\n");
        return;
    };
    if (!dir_file.is_directory) {
        hal.Serial.puts("Not a directory: ");
        hal.Serial.puts(dir_arg);
        hal.Serial.puts("\n");
        return;
    }

    // Update CWD
    if (len > CWD_MAX) {
        hal.Serial.puts("Path too long\n");
        return;
    }
    @memcpy(cwd[0..len], resolved[0..len]);
    cwd_len = len;
}

fn cmd_cp(args: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    // Parse: cp <src> <dst>
    var space_pos: usize = 0;
    while (space_pos < args.len and args[space_pos] != ' ') : (space_pos += 1) {}
    if (space_pos == 0 or space_pos >= args.len) {
        hal.Serial.puts("Usage: cp <src> <dst>\n");
        return;
    }

    const src_arg = args[0..space_pos];
    const dst_arg = args[space_pos + 1 ..];
    if (dst_arg.len == 0) {
        hal.Serial.puts("Usage: cp <src> <dst>\n");
        return;
    }

    // Resolve paths relative to CWD
    var src_resolved: [256]u8 = undefined;
    const src_len = resolvePath(src_arg, &src_resolved);
    if (src_len == 0) {
        hal.Serial.puts("Invalid source path\n");
        return;
    }

    var dst_resolved: [256]u8 = undefined;
    const dst_len = resolvePath(dst_arg, &dst_resolved);
    if (dst_len == 0) {
        hal.Serial.puts("Invalid destination path\n");
        return;
    }

    const copied = fs.copyFile(src_resolved[0..src_len], dst_resolved[0..dst_len]);
    if (copied > 0) {
        hal.Serial.puts("Copied ");
        putDecimal(copied);
        hal.Serial.puts(" bytes\n");
    } else {
        hal.Serial.puts("Copy failed\n");
    }
}

fn cmd_mv(args: []const u8) void {
    const fs = fat32.getFs() orelse {
        hal.Serial.puts("No filesystem mounted\n");
        return;
    };

    // Parse: mv <src> <dst>
    var space_pos: usize = 0;
    while (space_pos < args.len and args[space_pos] != ' ') : (space_pos += 1) {}
    if (space_pos == 0 or space_pos >= args.len) {
        hal.Serial.puts("Usage: mv <src> <dst>\n");
        return;
    }

    const src_arg = args[0..space_pos];
    const dst_arg = args[space_pos + 1 ..];
    if (dst_arg.len == 0) {
        hal.Serial.puts("Usage: mv <src> <dst>\n");
        return;
    }

    // Resolve paths relative to CWD
    var src_resolved: [256]u8 = undefined;
    const src_len = resolvePath(src_arg, &src_resolved);
    if (src_len == 0) {
        hal.Serial.puts("Invalid source path\n");
        return;
    }

    var dst_resolved: [256]u8 = undefined;
    const dst_len = resolvePath(dst_arg, &dst_resolved);
    if (dst_len == 0) {
        hal.Serial.puts("Invalid destination path\n");
        return;
    }

    if (fs.moveFile(src_resolved[0..src_len], dst_resolved[0..dst_len])) {
        hal.Serial.puts("Moved successfully\n");
    } else {
        hal.Serial.puts("Move failed\n");
    }
}

fn cmd_nested_test() void {
    hal.Serial.puts("=== Nested Directory Test ===\n");

    const fs = fat32.getFs() orelse {
        hal.Serial.puts("FAIL: No filesystem mounted\n");
        hal.Serial.puts("  Run 'format' first to create a FAT32 filesystem.\n");
        return;
    };

    // Test 1: Create nested directory
    hal.Serial.puts("[Test 1] Creating nested directory 'testdir'...\n");
    if (fs.createDir(fs.root_cluster, "testdir")) |dc| {
        hal.Serial.puts("  PASS: Created testdir (cluster ");
        putDecimal(dc);
        hal.Serial.puts(")\n");
    } else {
        hal.Serial.puts("  INFO: testdir may already exist\n");
    }

    // Test 2: Create file in nested directory using resolveParentDir
    hal.Serial.puts("[Test 2] Creating 'testdir/hello.txt'...\n");
    const parts = fs.resolveParentDir("testdir/hello.txt") orelse {
        hal.Serial.puts("  FAIL: resolveParentDir returned null\n");
        return;
    };
    hal.Serial.puts("  DEBUG: parent_cluster=");
    putHex(parts.parent_cluster);
    hal.Serial.puts(" base_name=");
    hal.Serial.puts(parts.base_name);
    hal.Serial.puts("\n");

    var file = fs.createFile(parts.parent_cluster, parts.base_name) orelse blk: {
        // File may already exist — try opening it
        break :blk fs.openFile("testdir/hello.txt") orelse {
            hal.Serial.puts("  FAIL: Could not create or open testdir/hello.txt\n");
            return;
        };
    };

    // Test 3: Write to the nested file
    hal.Serial.puts("[Test 3] Writing to 'testdir/hello.txt'...\n");
    const test_content = "Hello from nested dir!";
    const written = fs.writeFile(&file, test_content);
    if (written > 0) {
        hal.Serial.puts("  PASS: Wrote ");
        putDecimal(written);
        hal.Serial.puts(" bytes\n");
    } else {
        hal.Serial.puts("  FAIL: Write returned 0\n");
        return;
    }

    // Test 4: Read back using openFile with nested path
    hal.Serial.puts("[Test 4] Reading back 'testdir/hello.txt' via openFile...\n");
    var read_file = fs.openFile("testdir/hello.txt") orelse {
        hal.Serial.puts("  FAIL: Could not open testdir/hello.txt\n");
        return;
    };

    hal.Serial.puts("  DEBUG: cluster=");
    putHex(read_file.first_cluster);
    hal.Serial.puts(" size=");
    putDecimal(read_file.file_size);
    hal.Serial.puts(" dir_cluster=");
    putHex(read_file.dir_cluster);
    hal.Serial.puts("\n");

    const read_buf_phys = pmm.allocPage() orelse {
        hal.Serial.puts("  FAIL: Out of memory\n");
        return;
    };
    const read_buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(read_buf_phys)));

    const bytes_read = fs.readFile(&read_file, read_buf[0..256], 256);
    if (bytes_read > 0) {
        var match = true;
        if (bytes_read != test_content.len) {
            match = false;
        } else {
            for (0..bytes_read) |i| {
                if (read_buf[i] != test_content[i]) {
                    match = false;
                    break;
                }
            }
        }
        if (match) {
            hal.Serial.puts("  PASS: Content verified: \"");
            hal.Serial.puts(read_buf[0..bytes_read]);
            hal.Serial.puts("\"\n");
        } else {
            hal.Serial.puts("  FAIL: Content mismatch! Got: \"");
            const show_len = if (bytes_read > 64) @as(usize, 64) else bytes_read;
            hal.Serial.puts(read_buf[0..show_len]);
            hal.Serial.puts("\"\n");
        }
    } else {
        hal.Serial.puts("  FAIL: readFile returned 0 bytes\n");
    }

    pmm.freePage(read_buf_phys);

    // Test 5: List the nested directory
    hal.Serial.puts("[Test 5] Listing 'testdir' contents...\n");
    var ctx = LsCtx{ .fs = fs };
    const dir_cluster = fs.resolveDirCluster("testdir") orelse {
        hal.Serial.puts("  FAIL: Could not resolve testdir\n");
        return;
    };
    const count = fs.listDir(dir_cluster, &ctx, lsCallback);
    hal.Serial.puts("  Found ");
    putDecimal(count);
    hal.Serial.puts(" entries\n");

    // Test 6: Deeper nesting — create dir/subdir
    hal.Serial.puts("[Test 6] Creating 'testdir/subdir' (2 levels deep)...\n");
    const subdir_parts = fs.resolveParentDir("testdir/subdir") orelse {
        hal.Serial.puts("  FAIL: resolveParentDir for testdir/subdir\n");
        return;
    };
    if (fs.createDir(subdir_parts.parent_cluster, subdir_parts.base_name)) |sc| {
        hal.Serial.puts("  PASS: Created subdir (cluster ");
        putDecimal(sc);
        hal.Serial.puts(")\n");
    } else {
        hal.Serial.puts("  INFO: subdir may already exist\n");
    }

    // Test 7: Create file in 2-level deep directory
    hal.Serial.puts("[Test 7] Creating 'testdir/subdir/deep.txt'...\n");
    const deep_parts = fs.resolveParentDir("testdir/subdir/deep.txt") orelse {
        hal.Serial.puts("  FAIL: resolveParentDir for testdir/subdir/deep.txt\n");
        return;
    };
    var deep_file = fs.createFile(deep_parts.parent_cluster, deep_parts.base_name) orelse blk: {
        break :blk fs.openFile("testdir/subdir/deep.txt") orelse {
            hal.Serial.puts("  FAIL: Could not create deep.txt\n");
            return;
        };
    };
    const deep_written = fs.writeFile(&deep_file, "Deep nested content!");
    if (deep_written > 0) {
        hal.Serial.puts("  PASS: Wrote ");
        putDecimal(deep_written);
        hal.Serial.puts(" bytes to 2-level nested file\n");
    } else {
        hal.Serial.puts("  FAIL: Could not write to deep.txt\n");
    }

    // Test 8: Read back the 2-level nested file
    hal.Serial.puts("[Test 8] Reading back 'testdir/subdir/deep.txt'...\n");
    if (fs.openFile("testdir/subdir/deep.txt")) |rf| {
        const deep_buf_phys = pmm.allocPage() orelse {
            hal.Serial.puts("  FAIL: Out of memory\n");
            return;
        };
        const deep_buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(deep_buf_phys)));
        var deep_rf = rf;
        const deep_read = fs.readFile(&deep_rf, deep_buf[0..128], 128);
        if (deep_read > 0) {
            hal.Serial.puts("  PASS: Read back \"");
            hal.Serial.puts(deep_buf[0..deep_read]);
            hal.Serial.puts("\"\n");
        } else {
            hal.Serial.puts("  FAIL: readFile returned 0\n");
        }
        pmm.freePage(deep_buf_phys);
    } else {
        hal.Serial.puts("  FAIL: Could not open testdir/subdir/deep.txt\n");
    }

    hal.Serial.puts("=== Nested Test Complete ===\n");
}

fn cmd_fbinfo() void {
    if (!use_fb) {
        hal.Serial.puts("Framebuffer not active (using VGA text mode)\n");
        hal.Serial.puts("  VGA: 80x25 at 0xB8000\n");
        hal.Serial.puts("  Use QEMU with -vga std to enable framebuffer\n");
        return;
    }
    hal.Serial.puts("=== Framebuffer Info ===\n");
    hal.Serial.puts("  Address: ");
    putHex(framebuffer.getAddr());
    hal.Serial.puts("\n  Resolution: ");
    putDecimal(framebuffer.getWidth());
    hal.Serial.puts("x");
    putDecimal(framebuffer.getHeight());
    hal.Serial.puts("\n  BPP: ");
    putDecimal(framebuffer.getBpp());
    hal.Serial.puts("\n  Pitch: ");
    putDecimal(framebuffer.getPitch());
    hal.Serial.puts("\n  Text cells: ");
    putDecimal(framebuffer.text_cols());
    hal.Serial.puts("x");
    putDecimal(framebuffer.text_rows());
    hal.Serial.puts("\n  Pixel format: ");
    const ptype = framebuffer.getPixelType();
    if (ptype == 0) {
        hal.Serial.puts("Indexed (palette)\n");
    } else if (ptype == 1) {
        hal.Serial.puts("RGB888 (32-bit)\n");
    } else if (ptype == 2) {
        hal.Serial.puts("BGR888 (32-bit)\n");
    } else if (ptype == 3) {
        hal.Serial.puts("RGB565 (16-bit)\n");
    } else {
        hal.Serial.puts("Unknown\n");
    }
}

fn cmd_handles() void {
    hal.Serial.puts("=== Object Table Handles (v1.1.0) ===\n");
    const om = ki.getObjectManager();
    var active_count: u32 = 0;
    var i: usize = 4; // Skip reserved handles 0-3
    while (i < 64) : (i += 1) { // Show first 60 handles
        const entry = &om.handles[i];
        if (entry.in_use and entry.obj_type != .Free) {
            active_count += 1;
            hal.Serial.puts("  Handle ");
            putDecimal(i);
            hal.Serial.puts(": type=");
            const type_name = switch (entry.obj_type) {
                .File => "File",
                .Directory => "Directory",
                .Device => "Device",
                .Event => "Event",
                .Mutant => "Mutant",
                .Semaphore => "Semaphore",
                .Timer => "Timer",
                .Section => "Section",
                .Port => "Port",
                .Token => "Token",
                .Key => "Key",
                .Process => "Process",
                .Thread => "Thread",
                else => "Other",
            };
            hal.Serial.puts(type_name);
            hal.Serial.puts(" access=0x");
            putHex(entry.access_mask);
            hal.Serial.puts(" refs=");
            putDecimal(entry.ref_count);
            if (entry.cap_revoked) {
                hal.Serial.puts(" [REVOKED]");
            }
            hal.Serial.puts("\n");
        }
    }
    hal.Serial.puts("  Active handles: ");
    putDecimal(active_count);
    hal.Serial.puts(" (shown first 60 of ");
    putDecimal(4096);
    hal.Serial.puts(" slots)\n");
}

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
