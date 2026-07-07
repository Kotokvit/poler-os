const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize: std.builtin.OptimizeMode = .Debug;

    // ═══ 32-bit Kernel Build (legacy) ════════════════════════════════════
    const kernel32_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const kernel32 = b.addExecutable(.{
        .name = "poler-os32",
        .root_source_file = b.path("src/main32.zig"),
        .target = kernel32_target,
        .optimize = optimize,
    });

    kernel32.setLinkerScript(b.path("src/linker32.ld"));
    kernel32.link_gc_sections = false;
    kernel32.addAssemblyFile(b.path("src/boot32.S"));
    kernel32.addAssemblyFile(b.path("src/isr32.S"));
    b.installArtifact(kernel32);

    // ═══ 64-bit Kernel Build (POLER-OS v0.5.1 → v0.6.0) ════════════════
    const kernel64_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const kernel64 = b.addExecutable(.{
        .name = "poler-os64",
        .root_source_file = b.path("src64/main64.zig"),
        .target = kernel64_target,
        .optimize = optimize,
    });

    kernel64.setLinkerScript(b.path("src64/linker64.ld"));
    kernel64.link_gc_sections = false;
    kernel64.addAssemblyFile(b.path("src64/boot64.S"));
    kernel64.addAssemblyFile(b.path("src64/isr64.S"));
    b.installArtifact(kernel64);

    // ═══ Run 32-bit kernel in QEMU ═══════════════════════════════════════
    const run32_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os32",
        "-m", "128M",
        "-serial", "stdio",
        "-no-reboot",
    });
    run32_cmd.step.dependOn(b.getInstallStep());

    const run32_step = b.step("run32", "Run 32-bit kernel in QEMU");
    run32_step.dependOn(&run32_cmd.step);

    // ═══ Run 64-bit kernel in QEMU ═══════════════════════════════════════
    const run64_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os64",
        "-m", "256M",
        "-serial", "stdio",
        "-no-reboot",
    });
    run64_cmd.step.dependOn(b.getInstallStep());

    const run64_step = b.step("run64", "Run 64-bit kernel in QEMU");
    run64_step.dependOn(&run64_cmd.step);

    // ═══ Run 64-bit kernel headless (serial only) ═════════════════════════
    const run64_headless_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os64",
        "-m", "256M",
        "-nographic",
        "-no-reboot",
    });
    run64_headless_cmd.step.dependOn(b.getInstallStep());

    const run64_headless_step = b.step("run64-headless", "Run 64-bit kernel headless (serial only)");
    run64_headless_step.dependOn(&run64_headless_cmd.step);

    // ═══ POLER Core Tests (native x86_64 linux) ════════════════════════════
    const test_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .gnu,
    });

    const poler_core_tests = b.addTest(.{
        .root_source_file = b.path("src/poler_core.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    const test_step = b.step("test", "Run POLER Core unit tests");
    test_step.dependOn(&poler_core_tests.step);

    // ═══ Build ISO step ══════════════════════════════════════════════════
    const iso_cp_cmd = b.addSystemCommand(&.{
        "cp", "zig-out/bin/poler-os64", "iso/boot/poler-os64",
    });
    iso_cp_cmd.step.dependOn(b.getInstallStep());

    const iso_grub_cmd = b.addSystemCommand(&.{
        "grub-mkrescue", "-o", "poler-os64.iso", "iso",
    });
    iso_grub_cmd.step.dependOn(&iso_cp_cmd.step);

    const iso_step = b.step("iso", "Build POLER-OS bootable ISO");
    iso_step.dependOn(&iso_grub_cmd.step);
}

