const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{ .cpu_arch = .x86, .os_tag = .freestanding, .abi = .none });
    const mod = b.createModule(.{
        .root_source_file = b.path("src/main_minimal.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
    });
    mod.addAssemblyFile(b.path("src/boot32_test.S"));
    const exe = b.addExecutable(.{ .name = "poler-test", .root_module = mod });
    exe.setLinkerScript(b.path("src/linker32.ld"));
    exe.link_gc_sections = false;
    b.installArtifact(exe);
}
