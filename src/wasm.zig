// Copyright (c) 2026 jk9576. All rights reserved.
// Spinel: High-Entropy Binary Section Map & Structural Diff Engine
// Licensed under the MIT License.
//
// C ABI exported by the freestanding WebAssembly module. Pointers are linear
// memory addresses. On wasm every (pointer, length) pair is checked against the
// current memory size first, so a bad range returns an empty result or an error
// code instead of trapping. Output pointers do not need any particular alignment.

const std = @import("std");
const builtin = @import("builtin");
pub const entropy = @import("entropy.zig");
pub const sections = @import("sections.zig");
pub const diff = @import("diff.zig");

/// 0x00MMmmpp: major, minor, patch.
pub const version_packed: u32 = 0x00_02_00;

const is_wasm = builtin.cpu.arch.isWasm();

/// Error codes returned (negated) by the exports that return i32.
pub const err_truncated: i32 = -1;
pub const err_malformed: i32 = -2;
pub const err_no_such_slice: i32 = -3;
pub const err_bad_range: i32 = -4;

fn validRange(ptr: usize, len: u64) bool {
    if (!is_wasm) return true;
    const mem_bytes: u64 = @as(u64, @wasmMemorySize(0)) * 65536;
    return ptr <= mem_bytes and len <= mem_bytes - ptr;
}

fn validOut(ptr: usize, count: usize, comptime T: type) bool {
    const bytes = std.math.mul(u64, count, @sizeOf(T)) catch return false;
    return validRange(ptr, bytes);
}

fn errorCode(err: sections.ParseError) i32 {
    return switch (err) {
        error.Truncated => err_truncated,
        error.Malformed => err_malformed,
        error.NoSuchSlice => err_no_such_slice,
    };
}

// ------------------------------------------------------------ 0.1.0 exports

pub export fn spinel_calc_entropy(ptr: [*]const u8, len: usize) f64 {
    if (!validRange(@intFromPtr(ptr), len)) return 0.0;
    return entropy.calculateEntropy(ptr[0..len]);
}

pub export fn spinel_detect_format(ptr: [*]const u8, len: usize) u32 {
    if (!validRange(@intFromPtr(ptr), len)) return 0;
    return switch (entropy.detectFormat(ptr[0..len])) {
        .elf => 1,
        .macho => 2,
        .pe => 3,
        .raw => 0,
    };
}

pub export fn spinel_sliding_window(
    in_ptr: [*]const u8,
    in_len: usize,
    win_size: usize,
    step: usize,
    out_ptr: [*]align(1) f64,
    out_cap: usize,
) usize {
    if (!validRange(@intFromPtr(in_ptr), in_len)) return 0;
    if (!validOut(@intFromPtr(out_ptr), out_cap, f64)) return 0;
    return entropy.slidingWindowEntropy(in_ptr[0..in_len], win_size, step, out_ptr[0..out_cap]);
}

// ------------------------------------------------------------ 0.2.0 exports

/// Returns `version_packed` (0x000200 for 0.2.0).
pub export fn spinel_version() u32 {
    return version_packed;
}

/// Number of windows `spinel_sliding_window` produces for these parameters.
pub export fn spinel_window_count(in_len: usize, win_size: usize, step: usize) usize {
    if (win_size == 0 or step == 0 or win_size > in_len) return 0;
    return (in_len - win_size) / step + 1;
}

/// Header and verdict for an executable, written to `out_ptr`.
pub const InspectRecord = extern struct {
    /// Same codes as spinel_detect_format: 0 raw, 1 ELF, 2 Mach-O, 3 PE.
    format: u32,
    /// 16 (DOS MZ only), 32 or 64; 0 for raw data.
    bits: u32,
    /// e_machine (ELF), Machine (PE) or cputype (Mach-O).
    machine: u32,
    /// 0 little endian, 1 big endian.
    endian: u32,
    /// Number of slices in a universal Mach-O, else 0.
    slices: u32,
    /// sections.Packer code.
    packer: u32,
    section_count: u32,
    /// Bit 0: entropy work budget exhausted.
    flags: u32,
    slice_offset: u64,
    analyzed_bytes: u64,
};

/// One section, written by `spinel_sections`. Name pointers are absolute linear
/// memory addresses (into the input buffer, or into the module's data for
/// synthesized names such as "LOAD").
pub const SectionRecord = extern struct {
    offset: u64,
    size: u64,
    vaddr: u64,
    mem_size: u64,
    entropy: f64,
    name_ptr: u32,
    name_len: u32,
    segment_ptr: u32,
    segment_len: u32,
    /// entropy.SectionFlags bits: 0 executable, 1 writable, 2 packed, 3 nobits,
    /// 4 truncated, 5 from_segment, 6 entropy_skipped.
    flags: u32,
    _reserved: u32 = 0,
};

fn formatCode(f: entropy.BinaryFormat) u32 {
    return switch (f) {
        .raw => 0,
        .elf => 1,
        .macho => 2,
        .pe => 3,
    };
}

fn analyzeInto(data: []const u8, slice: u32, out: []align(1) SectionRecord) sections.ParseError!sections.Summary {
    var a = try sections.Analyzer.init(data, slice);
    var written: usize = 0;
    while (try a.next()) |s| {
        if (written < out.len) {
            out[written] = .{
                .offset = s.offset,
                .size = s.size,
                .vaddr = s.vaddr,
                .mem_size = s.mem_size,
                .entropy = s.entropy,
                .name_ptr = @truncate(@intFromPtr(s.name.ptr)),
                .name_len = @truncate(s.name.len),
                .segment_ptr = @truncate(@intFromPtr(s.segment.ptr)),
                .segment_len = @truncate(s.segment.len),
                .flags = @bitCast(s.flags),
            };
            written += 1;
        }
    }
    var sum = a.finish();
    sum.written = written;
    return sum;
}

/// Parses the section table (selecting slice `slice` of a universal Mach-O) and
/// writes one InspectRecord. Returns 0 or a negative error code.
pub export fn spinel_inspect(ptr: [*]const u8, len: usize, slice: u32, out_ptr: *align(1) InspectRecord) i32 {
    if (!validRange(@intFromPtr(ptr), len)) return err_bad_range;
    if (!validOut(@intFromPtr(out_ptr), 1, InspectRecord)) return err_bad_range;
    const sum = analyzeInto(ptr[0..len], slice, &.{}) catch |e| return errorCode(e);
    out_ptr.* = .{
        .format = formatCode(sum.header.format),
        .bits = sum.header.bits,
        .machine = sum.header.machine,
        .endian = @intFromBool(sum.header.endian == .big),
        .slices = sum.header.slices,
        .packer = @backingInt(sum.packer),
        .section_count = @truncate(sum.total),
        .flags = @intFromBool(sum.budget_exhausted),
        .slice_offset = sum.header.slice_offset,
        .analyzed_bytes = sum.analyzed_bytes,
    };
    return 0;
}

/// Writes up to `out_cap` SectionRecords and returns the total number of sections
/// (which may exceed `out_cap`), or a negative error code.
pub export fn spinel_sections(ptr: [*]const u8, len: usize, slice: u32, out_ptr: [*]align(1) SectionRecord, out_cap: usize) i32 {
    if (!validRange(@intFromPtr(ptr), len)) return err_bad_range;
    if (!validOut(@intFromPtr(out_ptr), out_cap, SectionRecord)) return err_bad_range;
    const sum = analyzeInto(ptr[0..len], slice, out_ptr[0..out_cap]) catch |e| return errorCode(e);
    return @intCast(@min(sum.total, std.math.maxInt(i32)));
}

/// Finds high-entropy regions (see entropy.findHighEntropyRegions). Each region
/// is four f64 values: start, end, mean, peak. Writes up to `out_cap` regions and
/// returns the total found.
pub export fn spinel_high_entropy_regions(
    in_ptr: [*]const u8,
    in_len: usize,
    win_size: usize,
    step: usize,
    threshold: f64,
    out_ptr: [*]align(1) entropy.Region,
    out_cap: usize,
) usize {
    if (!validRange(@intFromPtr(in_ptr), in_len)) return 0;
    if (!validOut(@intFromPtr(out_ptr), out_cap, entropy.Region)) return 0;
    return entropy.findHighEntropyRegions(in_ptr[0..in_len], win_size, step, threshold, out_ptr[0..out_cap]);
}

/// Positional block diff: one status byte per block (0 identical, 1 modified,
/// 2 removed, 3 added). Writes up to `out_cap` bytes, returns the total blocks.
pub export fn spinel_block_diff(
    a_ptr: [*]const u8,
    a_len: usize,
    b_ptr: [*]const u8,
    b_len: usize,
    block: usize,
    out_ptr: [*]u8,
    out_cap: usize,
) usize {
    if (!validRange(@intFromPtr(a_ptr), a_len) or !validRange(@intFromPtr(b_ptr), b_len)) return 0;
    if (!validRange(@intFromPtr(out_ptr), out_cap)) return 0;
    return diff.blockDiff(a_ptr[0..a_len], b_ptr[0..b_len], block, out_ptr[0..out_cap]);
}

/// Byte-distribution distance in [0, 1] between two buffers; -1 on a bad range.
pub export fn spinel_histogram_distance(a_ptr: [*]const u8, a_len: usize, b_ptr: [*]const u8, b_len: usize) f64 {
    if (!validRange(@intFromPtr(a_ptr), a_len) or !validRange(@intFromPtr(b_ptr), b_len)) return -1.0;
    return diff.histogramDistance(a_ptr[0..a_len], b_ptr[0..b_len]);
}

// Scratch buffer above the static data and stack. Only meaningful on wasm,
// where the linker defines __heap_base.
extern var __heap_base: u8;

/// Returns a 16-byte aligned address of a scratch region with at least `len`
/// bytes, growing linear memory as needed, or 0 if memory cannot grow. The region
/// starts at the same address on every call (it only grows), so request the
/// total size needed for all inputs and outputs at once.
fn spinelBuffer(len: usize) callconv(.c) usize {
    const base = std.mem.alignForward(usize, @intFromPtr(&__heap_base), 16);
    const need: u64 = @as(u64, base) + len;
    const have: u64 = @as(u64, @wasmMemorySize(0)) * 65536;
    if (need > have) {
        const pages = (need - have + 65535) / 65536;
        if (pages > std.math.maxInt(u32)) return 0;
        if (@wasmMemoryGrow(0, @intCast(pages)) < 0) return 0;
    }
    return base;
}

comptime {
    if (is_wasm) @export(&spinelBuffer, .{ .name = "spinel_buffer" });
}

// ---------------------------------------------------------------------------
// Tests (native): the ABI layer over real buffers.

const testing = std.testing;

test "record layouts are stable" {
    try testing.expectEqual(@as(usize, 48), @sizeOf(InspectRecord));
    try testing.expectEqual(@as(usize, 64), @sizeOf(SectionRecord));
    try testing.expectEqual(@as(usize, 32), @sizeOf(entropy.Region));
    try testing.expectEqual(@as(usize, 40), @offsetOf(SectionRecord, "name_ptr"));
}

test "legacy exports keep their results" {
    var buf: [256]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i);
    try testing.expectApproxEqAbs(@as(f64, 8.0), spinel_calc_entropy(&buf, buf.len), 1e-9);
    try testing.expectEqual(@as(u32, 1), spinel_detect_format("\x7FELF", 4));
    try testing.expectEqual(@as(u32, 3), spinel_detect_format("MZ", 2));
    try testing.expectEqual(@as(u32, 0), spinel_detect_format("xx", 2));
    var out: [64]f64 = undefined;
    const n = spinel_sliding_window(&buf, buf.len, 64, 16, &out, out.len);
    try testing.expectEqual(spinel_window_count(buf.len, 64, 16), n);
    try testing.expectEqual(@as(usize, 13), n);
    try testing.expectEqual(@as(usize, 0), spinel_sliding_window(&buf, buf.len, 64, 0, &out, out.len));
}

test "sliding window export writes through unaligned output pointers" {
    var buf: [128]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i * 7);
    var raw: [8 * 9 + 1]u8 align(8) = undefined;
    const out: [*]align(1) f64 = @ptrFromInt(@intFromPtr(&raw) + 1);
    const n = spinel_sliding_window(&buf, buf.len, 64, 8, out, 9);
    try testing.expectEqual(@as(usize, 9), n);
    var expect: [9]f64 = undefined;
    _ = entropy.slidingWindowEntropyNaive(&buf, 64, 8, &expect);
    for (expect, 0..) |e, i| try testing.expectEqual(e, out[i]);
}

test "inspect and sections exports on a raw buffer and on garbage" {
    var rec: InspectRecord = undefined;
    try testing.expectEqual(@as(i32, 0), spinel_inspect("hello", 5, 0, &rec));
    try testing.expectEqual(@as(u32, 0), rec.format);
    try testing.expectEqual(@as(u32, 0), rec.section_count);
    // ELF magic with an invalid class byte.
    try testing.expectEqual(err_malformed, spinel_inspect("\x7FELF\x09\x01", 6, 0, &rec));
    try testing.expectEqual(err_truncated, spinel_inspect("\x7FELF\x02\x01", 6, 0, &rec));
    var recs: [4]SectionRecord = undefined;
    try testing.expectEqual(@as(i32, 0), spinel_sections("hello", 5, 0, &recs, recs.len));
}

test "region and diff exports" {
    var data: [4096]u8 = @splat(0);
    var prng = std.Random.DefaultPrng.init(5);
    prng.random().bytes(data[1024..2048]);
    var regions: [4]entropy.Region = undefined;
    try testing.expectEqual(@as(usize, 1), spinel_high_entropy_regions(&data, data.len, 256, 64, 7.0, &regions, regions.len));
    try testing.expectEqual(@as(f64, 1024), regions[0].start);
    try testing.expectEqual(@as(f64, 2048), regions[0].end);
    var other = data;
    other[3000] = 1;
    var statuses: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), spinel_block_diff(&data, data.len, &other, other.len, 1024, &statuses, statuses.len));
    try testing.expectEqualSlices(u8, &.{ 0, 0, 1, 0 }, statuses[0..4]);
    try testing.expectEqual(@as(f64, 0.0), spinel_histogram_distance(&data, data.len, &data, data.len));
    try testing.expectEqual(@as(u32, 0x000200), spinel_version());
}
