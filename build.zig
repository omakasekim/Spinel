const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Native CLI executable
    const exe = b.addExecutable(.{
        .name = "spinel",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    // Freestanding WebAssembly artifact
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });
    const wasm = b.addExecutable(.{
        .name = "spinel",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wasm.zig"),
            .target = wasm_target,
            .optimize = .ReleaseSmall,
        }),
    });
    wasm.entry = .disabled;
    wasm.root_module.export_symbol_names = &.{
        "spinel_calc_entropy",
        "spinel_detect_format",
        "spinel_sliding_window",
        // 0.2.0
        "spinel_version",
        "spinel_window_count",
        "spinel_inspect",
        "spinel_sections",
        "spinel_high_entropy_regions",
        "spinel_block_diff",
        "spinel_histogram_distance",
        "spinel_buffer",
    };
    b.installArtifact(wasm);
    const wasm_step = b.step("wasm", "Build only the WebAssembly module (zig-out/bin/spinel.wasm)");
    wasm_step.dependOn(&b.addInstallArtifact(wasm, .{}).step);

    // Test runner
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
