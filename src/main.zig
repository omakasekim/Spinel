// Copyright (c) 2026 jk9576. All rights reserved.
// Spinel: High-Entropy Binary Section Map & Structural Diff Engine
// Licensed under the MIT License.

const std = @import("std");
pub const entropy = @import("entropy.zig");
pub const sections = @import("sections.zig");
pub const diff = @import("diff.zig");
pub const abi = @import("wasm.zig");

pub const version = "0.2.0";

// WebAssembly exports (defined in wasm.zig, re-exported here so existing
// references to them through this module keep working).
pub const spinel_calc_entropy = abi.spinel_calc_entropy;
pub const spinel_detect_format = abi.spinel_detect_format;
pub const spinel_sliding_window = abi.spinel_sliding_window;

const Io = std.Io;
const Writer = Io.Writer;
const Allocator = std.mem.Allocator;

/// Largest input file the CLI reads.
pub const max_file_size: usize = 1 << 30;

const CliError = error{Usage};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) return legacyDemo();

    var out_buf: [16 * 1024]u8 = undefined;
    var out_file = Io.File.stdout().writerStreaming(init.io, &out_buf);
    const out = &out_file.interface;

    const cmd: []const u8 = args[1];
    const rest = args[2..];
    const result = if (std.mem.eql(u8, cmd, "scan"))
        cmdScan(init, rest, out)
    else if (std.mem.eql(u8, cmd, "sections"))
        cmdSections(init, rest, out)
    else if (std.mem.eql(u8, cmd, "diff"))
        cmdDiff(init, rest, out)
    else if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version"))
        out.print("spinel {s}\n", .{version})
    else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h"))
        out.writeAll(usage_text)
    else blk: {
        std.debug.print("spinel: unknown command '{s}'\n\n{s}", .{ cmd, usage_text });
        break :blk error.Usage;
    };
    result catch |err| {
        out.flush() catch {};
        switch (err) {
            error.Usage => std.process.exit(2),
            error.Reported => std.process.exit(1),
            error.Truncated, error.Malformed, error.NoSuchSlice => {
                std.debug.print("spinel: {s}\n", .{switch (err) {
                    error.Truncated => "truncated input: a header or table runs past the end of the file",
                    error.Malformed => "malformed header: inconsistent class, entry size or load command size",
                    else => "no such universal Mach-O slice",
                }});
                std.process.exit(1);
            },
            else => {
                std.debug.print("spinel: {s}\n", .{@errorName(err)});
                std.process.exit(1);
            },
        }
    };
    try out.flush();
}

const usage_text =
    \\usage:
    \\  spinel                         run the built-in sample analysis
    \\  spinel scan FILE [--window N] [--step N] [--threshold T] [--width N] [--json]
    \\                                 entropy profile, Braille map and high-entropy regions
    \\  spinel sections FILE [--slice N] [--json]
    \\                                 ELF / PE / Mach-O section table with per-section entropy
    \\                                 and packer verdict (--slice picks a universal Mach-O slice)
    \\  spinel diff OLD NEW [--block N] [--slice N] [--all] [--json]
    \\                                 structural diff: section changes and block changes
    \\  spinel version
    \\
;

fn legacyDemo() void {
    // Sample payload: low entropy zeros + medium code + high entropy pseudo-random
    var buffer: [1024]u8 = undefined;
    @memset(buffer[0..256], 0); // Zero sparse data
    for (buffer[256..512], 0..) |*b, i| {
        b.* = @truncate(i % 16); // Patterned low-entropy data
    }
    var prng = std.Random.DefaultPrng.init(0x1337);
    prng.random().bytes(buffer[512..1024]); // High-entropy simulated encrypted payload

    const overall = entropy.calculateEntropy(&buffer);
    std.debug.print("Spinel: Analyzed 1024-byte payload. Overall Shannon Entropy: {d:.4} bits/byte\n", .{overall});
    std.debug.print("Format: {s}\n", .{@tagName(entropy.detectFormat(&buffer))});
}

// ---------------------------------------------------------------- arguments

const ArgIter = struct {
    args: []const [:0]const u8,
    i: usize = 0,

    fn next(self: *ArgIter) ?[]const u8 {
        if (self.i >= self.args.len) return null;
        defer self.i += 1;
        return self.args[self.i];
    }

    fn value(self: *ArgIter, flag: []const u8) CliError![]const u8 {
        return self.next() orelse usage("{s} needs a value", .{flag});
    }
};

fn usage(comptime fmt: []const u8, args: anytype) CliError {
    std.debug.print("spinel: " ++ fmt ++ "\n", args);
    return error.Usage;
}

fn parseCount(flag: []const u8, s: []const u8, min: usize, max: usize) CliError!usize {
    const v = std.fmt.parseInt(usize, s, 0) catch return usage("{s}: '{s}' is not a number", .{ flag, s });
    if (v < min or v > max) return usage("{s} must be between {d} and {d}", .{ flag, min, max });
    return v;
}

fn readInput(init: std.process.Init, path: []const u8) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(init.io, path, init.arena.allocator(), .limited(max_file_size)) catch |err| {
        switch (err) {
            error.StreamTooLong => std.debug.print("spinel: {s}: larger than {d} bytes\n", .{ path, max_file_size }),
            error.FileNotFound => std.debug.print("spinel: {s}: no such file\n", .{path}),
            else => std.debug.print("spinel: {s}: {s}\n", .{ path, @errorName(err) }),
        }
        return error.Reported;
    };
}

// ---------------------------------------------------------------- scan

pub const ScanOptions = struct {
    /// Zero selects the default: 1024 bytes, or the input size if smaller.
    window: usize = 0,
    /// Zero selects the default: a quarter of the window.
    step: usize = 0,
    threshold: f64 = entropy.packed_threshold,
    width: usize = 64,
    json: bool = false,
};

fn cmdScan(init: std.process.Init, rest: []const [:0]const u8, out: *Writer) !void {
    var opts: ScanOptions = .{};
    var path: ?[]const u8 = null;
    var it = ArgIter{ .args = rest };
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--json")) {
            opts.json = true;
        } else if (std.mem.eql(u8, a, "--window")) {
            opts.window = try parseCount(a, try it.value(a), 1, max_file_size);
        } else if (std.mem.eql(u8, a, "--step")) {
            opts.step = try parseCount(a, try it.value(a), 1, max_file_size);
        } else if (std.mem.eql(u8, a, "--width")) {
            opts.width = try parseCount(a, try it.value(a), 1, 4096);
        } else if (std.mem.eql(u8, a, "--threshold")) {
            const v = try it.value(a);
            opts.threshold = std.fmt.parseFloat(f64, v) catch return usage("--threshold: '{s}' is not a number", .{v});
            if (!(opts.threshold >= 0.0 and opts.threshold <= 8.0)) return usage("--threshold must be between 0 and 8", .{});
        } else if (a.len > 1 and a[0] == '-') {
            return usage("scan: unknown option {s}", .{a});
        } else if (path == null) {
            path = a;
        } else return usage("scan: expected one FILE", .{});
    }
    const p = path orelse return usage("scan: missing FILE", .{});
    const data = try readInput(init, p);
    try writeScan(init.arena.allocator(), out, p, data, opts);
}

/// Downsamples a window profile to `width` columns, keeping the maximum of each
/// column so a short high-entropy run stays visible.
fn downsample(gpa: Allocator, vals: []const f64, width: usize) ![]f64 {
    const cols = @min(width, vals.len);
    const res = try gpa.alloc(f64, cols);
    for (res, 0..) |*r, c| {
        const lo = c * vals.len / cols;
        const hi = @max(lo + 1, (c + 1) * vals.len / cols);
        r.* = std.mem.max(f64, vals[lo..hi]);
    }
    return res;
}

pub fn writeScan(gpa: Allocator, out: *Writer, name: []const u8, data: []const u8, opts: ScanOptions) !void {
    const window = if (opts.window != 0) @min(opts.window, @max(data.len, 1)) else @min(@as(usize, 1024), @max(data.len, 1));
    const step = if (opts.step != 0) opts.step else @max(window / 4, 1);

    var wit = entropy.WindowIterator.init(data, window, step);
    const vals = try gpa.alloc(f64, wit.count());
    defer gpa.free(vals);
    for (vals) |*v| v.* = wit.next().?;
    const profile = try downsample(gpa, vals, opts.width);
    defer gpa.free(profile);

    const n_regions = entropy.findHighEntropyRegions(data, window, step, opts.threshold, &.{});
    const regions = try gpa.alloc(entropy.Region, n_regions);
    defer gpa.free(regions);
    _ = entropy.findHighEntropyRegions(data, window, step, opts.threshold, regions);

    var header: sections.Header = .{ .format = entropy.detectFormat(data) };
    if (sections.SectionIterator.init(data)) |si| header = si.header else |_| {}
    const overall = entropy.calculateEntropy(data);
    const class = entropy.classify(overall);
    var high_bytes: u64 = 0;
    for (regions) |r| high_bytes += r.endOffset() - r.startOffset();

    if (opts.json) {
        try out.writeAll("{\"file\":");
        try writeJsonString(out, name);
        try out.print(",\"size\":{d},", .{data.len});
        try writeHeaderJson(out, header);
        try out.print(",\"entropy\":{d:.6},\"class\":\"{s}\",\"window\":{d},\"step\":{d},\"threshold\":{d:.4},\"windows\":{d},\"high_entropy_bytes\":{d},\"profile\":[", .{
            overall, class.label(), window, step, opts.threshold, vals.len, high_bytes,
        });
        for (profile, 0..) |v, i| {
            if (i > 0) try out.writeByte(',');
            try out.print("{d:.4}", .{v});
        }
        try out.writeAll("],\"regions\":[");
        for (regions, 0..) |r, i| {
            if (i > 0) try out.writeByte(',');
            try out.print("{{\"start\":{d},\"end\":{d},\"mean\":{d:.4},\"peak\":{d:.4}}}", .{ r.startOffset(), r.endOffset(), r.mean, r.peak });
        }
        try out.writeAll("]}\n");
        return;
    }

    try out.writeAll("file:     ");
    _ = try writeSafe(out, name);
    try out.print("\nsize:     {d} bytes\nformat:   ", .{data.len});
    try writeHeaderText(out, header);
    try out.print("\nentropy:  {d:.4} bits/byte ({s})\n", .{ overall, class.label() });
    try out.print("windows:  {d} (window {d}, step {d})\n", .{ vals.len, window, step });
    try out.writeAll("map:      ");
    try entropy.renderBrailleSparkline(profile, out);
    try out.print("\nregions:  {d} at >= {d:.2} bits/byte, {d} bytes\n", .{ regions.len, opts.threshold, high_bytes });
    for (regions) |r| {
        try out.print("  0x{x:0>8}-0x{x:0>8}  {d:>10} bytes  mean {d:.3}  peak {d:.3}\n", .{
            r.startOffset(), r.endOffset(), r.endOffset() - r.startOffset(), r.mean, r.peak,
        });
    }
}

// ---------------------------------------------------------------- sections

fn cmdSections(init: std.process.Init, rest: []const [:0]const u8, out: *Writer) !void {
    var json = false;
    var slice: u32 = 0;
    var path: ?[]const u8 = null;
    var it = ArgIter{ .args = rest };
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--json")) {
            json = true;
        } else if (std.mem.eql(u8, a, "--slice")) {
            slice = @intCast(try parseCount(a, try it.value(a), 0, 1 << 16));
        } else if (a.len > 1 and a[0] == '-') {
            return usage("sections: unknown option {s}", .{a});
        } else if (path == null) {
            path = a;
        } else return usage("sections: expected one FILE", .{});
    }
    const p = path orelse return usage("sections: missing FILE", .{});
    const data = try readInput(init, p);
    try writeSections(init.arena.allocator(), out, p, data, slice, json);
}

pub fn writeSections(gpa: Allocator, out: *Writer, name: []const u8, data: []const u8, slice: u32, json: bool) !void {
    const owned = try sections.analyzeAlloc(gpa, data, slice);
    defer owned.deinit(gpa);
    const sum = owned.summary;
    if (json) {
        try out.writeAll("{\"file\":");
        try writeJsonString(out, name);
        try out.print(",\"size\":{d},", .{data.len});
        try writeHeaderJson(out, sum.header);
        try out.print(",\"packer\":\"{s}\",\"budget_exhausted\":{},\"sections\":[", .{ sum.packer.label(), sum.budget_exhausted });
        for (owned.sections, 0..) |s, i| {
            if (i > 0) try out.writeByte(',');
            try writeSectionJson(out, s);
        }
        try out.writeAll("]}\n");
        return;
    }
    try out.writeAll("file:     ");
    _ = try writeSafe(out, name);
    try out.writeAll("\nformat:   ");
    try writeHeaderText(out, sum.header);
    try out.print("\nsections: {d}\npacker:   {s}\n", .{ sum.total, sum.packer.label() });
    if (sum.budget_exhausted) try out.writeAll("note:     entropy work budget exhausted; some sections were not measured\n");
    if (owned.sections.len == 0) return;
    try out.print("  {s:>3}  {s:<24} {s:>10} {s:>10} {s:>18} {s:>7}  {s}\n", .{ "#", "name", "offset", "size", "vaddr", "entropy", "flags" });
    for (owned.sections, 0..) |s, i| {
        try out.print("  {d:>3}  ", .{i});
        try writePadded(out, s, 24);
        try out.print(" 0x{x:0>8} {d:>10} 0x{x:0>16} ", .{ s.offset, s.size, s.vaddr });
        if (s.flags.entropy_skipped) try out.writeAll("      -") else try out.print("{d:>7.3}", .{s.entropy});
        try out.writeAll("  ");
        try writeFlags(out, s.flags);
        try out.writeByte('\n');
    }
    try out.writeAll("  flags: x exec, w write, P packed, n no file data, t truncated, s from segment\n");
}

fn writeFlags(out: *Writer, f: entropy.SectionFlags) !void {
    try out.writeByte(if (f.executable) 'x' else '-');
    try out.writeByte(if (f.writable) 'w' else '-');
    try out.writeByte(if (f.is_packed) 'P' else '-');
    try out.writeByte(if (f.nobits) 'n' else '-');
    try out.writeByte(if (f.truncated) 't' else '-');
    try out.writeByte(if (f.from_segment) 's' else '-');
}

/// Writes "segment,name" (or just the name) padded to `width` columns.
fn writePadded(out: *Writer, s: entropy.SectionInfo, width: usize) !void {
    var n: usize = 0;
    if (s.segment.len > 0 and !std.mem.eql(u8, s.segment, s.name)) {
        n += try writeSafe(out, s.segment);
        try out.writeByte(',');
        n += 1;
    }
    n += try writeSafe(out, if (s.name.len > 0) s.name else "(unnamed)");
    if (n < width) try out.splatByteAll(' ', width - n);
}

fn writeSectionJson(out: *Writer, s: entropy.SectionInfo) !void {
    try out.writeAll("{\"name\":");
    try writeJsonString(out, s.name);
    try out.writeAll(",\"segment\":");
    try writeJsonString(out, s.segment);
    try out.print(",\"offset\":{d},\"size\":{d},\"vaddr\":{d},\"mem_size\":{d},\"entropy\":", .{ s.offset, s.size, s.vaddr, s.mem_size });
    if (s.flags.entropy_skipped) try out.writeAll("null") else try out.print("{d:.6}", .{s.entropy});
    try out.print(",\"packed\":{},\"executable\":{},\"writable\":{},\"nobits\":{},\"truncated\":{},\"from_segment\":{}}}", .{
        s.is_packed, s.flags.executable, s.flags.writable, s.flags.nobits, s.flags.truncated, s.flags.from_segment,
    });
}

// ---------------------------------------------------------------- diff

pub const DiffOptions = struct {
    block: usize = 4096,
    slice: u32 = 0,
    all: bool = false,
    json: bool = false,
};

fn cmdDiff(init: std.process.Init, rest: []const [:0]const u8, out: *Writer) !void {
    var opts: DiffOptions = .{};
    var paths: [2][]const u8 = undefined;
    var n_paths: usize = 0;
    var it = ArgIter{ .args = rest };
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--json")) {
            opts.json = true;
        } else if (std.mem.eql(u8, a, "--all")) {
            opts.all = true;
        } else if (std.mem.eql(u8, a, "--block")) {
            opts.block = try parseCount(a, try it.value(a), 1, 1 << 24);
        } else if (std.mem.eql(u8, a, "--slice")) {
            opts.slice = @intCast(try parseCount(a, try it.value(a), 0, 1 << 16));
        } else if (a.len > 1 and a[0] == '-') {
            return usage("diff: unknown option {s}", .{a});
        } else if (n_paths < 2) {
            paths[n_paths] = a;
            n_paths += 1;
        } else return usage("diff: expected OLD and NEW", .{});
    }
    if (n_paths != 2) return usage("diff: expected OLD and NEW", .{});
    const a = try readInput(init, paths[0]);
    const b = try readInput(init, paths[1]);
    try writeDiff(init.arena.allocator(), out, paths[0], a, paths[1], b, opts);
}

const SideSections = struct {
    owned: ?sections.Owned,
    err: ?anyerror,
    header: sections.Header,
};

fn loadSide(gpa: Allocator, data: []const u8, slice: u32) SideSections {
    const owned = sections.analyzeAlloc(gpa, data, slice) catch |e| {
        return .{ .owned = null, .err = e, .header = .{ .format = entropy.detectFormat(data) } };
    };
    return .{ .owned = owned, .err = null, .header = owned.summary.header };
}

pub fn writeDiff(gpa: Allocator, out: *Writer, old_name: []const u8, old: []const u8, new_name: []const u8, new: []const u8, opts: DiffOptions) !void {
    const sa = loadSide(gpa, old, opts.slice);
    defer if (sa.owned) |o| o.deinit(gpa);
    const sb = loadSide(gpa, new, opts.slice);
    defer if (sb.owned) |o| o.deinit(gpa);

    const have_sections = sa.owned != null and sb.owned != null and
        (sa.owned.?.sections.len > 0 or sb.owned.?.sections.len > 0);
    const deltas: []diff.SectionDelta = if (have_sections)
        try diff.diffSections(gpa, old, sa.owned.?.sections, new, sb.owned.?.sections)
    else
        &.{};
    defer if (have_sections) gpa.free(deltas);
    const side_err: ?anyerror = if (sa.err) |e| e else sb.err;
    var counts: [4]usize = @splat(0);
    for (deltas) |d| counts[@backingInt(d.status)] += 1;

    const rep = try diff.blockReport(gpa, old, new, opts.block);
    defer rep.deinit(gpa);

    if (opts.json) {
        try out.writeAll("{\"old\":");
        try writeSideJson(out, old_name, old, sa.header);
        try out.writeAll(",\"new\":");
        try writeSideJson(out, new_name, new, sb.header);
        try out.print(",\"identical\":{},\"sections\":{{\"available\":{}", .{ std.mem.eql(u8, old, new), have_sections });
        if (side_err) |e| try out.print(",\"error\":\"{s}\"", .{@errorName(e)});
        try out.print(",\"unchanged\":{d},\"modified\":{d},\"added\":{d},\"removed\":{d},\"changes\":[", .{ counts[0], counts[1], counts[2], counts[3] });
        var first = true;
        for (deltas) |d| {
            if (d.status == .unchanged and !opts.all) continue;
            if (!first) try out.writeByte(',');
            first = false;
            try out.print("{{\"status\":\"{s}\",\"name\":", .{d.status.label()});
            try writeJsonString(out, d.name);
            try out.writeAll(",\"segment\":");
            try writeJsonString(out, d.segment);
            try out.writeAll(",\"old\":");
            if (d.old) |s| try writeSectionJson(out, s) else try out.writeAll("null");
            try out.writeAll(",\"new\":");
            if (d.new) |s| try writeSectionJson(out, s) else try out.writeAll("null");
            try out.print(",\"distance\":{d:.6},\"differing_bytes\":{d}}}", .{ d.distance, d.differing_bytes });
        }
        try out.print("]}},\"blocks\":{{\"block\":{d},\"old\":{d},\"new\":{d},\"identical\":{d},\"moved\":{d},\"modified\":{d},\"added\":{d},\"removed\":{d},\"similarity\":{d:.6},\"differing_bytes\":{d},\"ranges\":[", .{
            rep.block, rep.blocks_old, rep.blocks_new, rep.identical, rep.moved, rep.modified, rep.added, rep.removed, rep.similarity(), rep.differing_bytes,
        });
        for (rep.ranges, 0..) |r, i| {
            if (i > 0) try out.writeByte(',');
            try out.print("{{\"status\":\"{s}\",\"start\":{d},\"end\":{d},\"blocks\":{d},\"entropy_old\":{d:.4},\"entropy_new\":{d:.4}}}", .{
                r.status.label(), r.start, r.end, r.blocks, r.entropy_old, r.entropy_new,
            });
        }
        try out.writeAll("]}}\n");
        return;
    }

    try out.writeAll("old:      ");
    try writeSideText(out, old_name, old, sa.header);
    try out.writeAll("new:      ");
    try writeSideText(out, new_name, new, sb.header);
    if (std.mem.eql(u8, old, new)) {
        try out.writeAll("result:   identical\n");
        return;
    }
    if (have_sections) {
        try out.print("sections: {d} unchanged, {d} modified, {d} added, {d} removed\n", .{ counts[0], counts[1], counts[2], counts[3] });
        for (deltas) |d| {
            if (d.status == .unchanged and !opts.all) continue;
            try out.print("  {s:<9} ", .{d.status.label()});
            try writePadded(out, d.old orelse d.new.?, 24);
            const so = d.old;
            const sn = d.new;
            if (so != null and sn != null) {
                try out.print(" size {d} -> {d}  entropy {d:.3} -> {d:.3}  distance {d:.4}  differing {d}\n", .{
                    so.?.size, sn.?.size, so.?.entropy, sn.?.entropy, d.distance, d.differing_bytes,
                });
            } else {
                const s = so orelse sn.?;
                try out.print(" size {d}  entropy {d:.3}\n", .{ s.size, s.entropy });
            }
        }
    } else if (side_err) |e| {
        try out.print("sections: unavailable ({s})\n", .{@errorName(e)});
    } else {
        try out.writeAll("sections: none (no section tables)\n");
    }
    try out.print("blocks:   {d}-byte blocks, {d} identical, {d} moved, {d} modified, {d} added, {d} removed\n", .{
        rep.block, rep.identical, rep.moved, rep.modified, rep.added, rep.removed,
    });
    try out.print("          similarity {d:.4}, {d} differing bytes\n", .{ rep.similarity(), rep.differing_bytes });
    for (rep.ranges) |r| {
        try out.print("  {s:<9} 0x{x:0>8}-0x{x:0>8}  {d:>6} blocks  entropy {d:.3} -> {d:.3}\n", .{
            r.status.label(), r.start, r.end, r.blocks, r.entropy_old, r.entropy_new,
        });
    }
}

fn writeSideJson(out: *Writer, name: []const u8, data: []const u8, h: sections.Header) !void {
    try out.writeAll("{\"file\":");
    try writeJsonString(out, name);
    try out.print(",\"size\":{d},", .{data.len});
    try writeHeaderJson(out, h);
    try out.writeByte('}');
}

fn writeSideText(out: *Writer, name: []const u8, data: []const u8, h: sections.Header) !void {
    _ = try writeSafe(out, name);
    try out.print(" ({d} bytes, ", .{data.len});
    try writeHeaderText(out, h);
    try out.writeAll(")\n");
}

// ---------------------------------------------------------------- shared output

fn formatName(f: entropy.BinaryFormat) []const u8 {
    return switch (f) {
        .elf => "ELF",
        .pe => "PE",
        .macho => "Mach-O",
        .raw => "raw",
    };
}

fn writeHeaderText(out: *Writer, h: sections.Header) !void {
    if (h.format == .raw) return out.writeAll("raw (no executable header)");
    if (h.format == .pe and h.bits == 16) return out.writeAll("DOS MZ (no PE header)");
    if (h.bits == 0) return out.print("{s} (header could not be parsed)", .{formatName(h.format)});
    try out.print("{s} {d}-bit {s} {s}", .{ formatName(h.format), h.bits, @tagName(h.endian), h.archName() });
    if (h.slices > 0) try out.print(", universal slice at 0x{x} of {d}", .{ h.slice_offset, h.slices });
}

fn writeHeaderJson(out: *Writer, h: sections.Header) !void {
    try out.print("\"format\":\"{s}\",\"bits\":{d},\"endian\":\"{s}\",\"arch\":\"{s}\",\"slices\":{d},\"slice_offset\":{d}", .{
        @tagName(h.format), h.bits, @tagName(h.endian), h.archName(), h.slices, h.slice_offset,
    });
}

/// Writes text taken from an untrusted file to a terminal: printable ASCII is
/// kept, everything else (including escape sequences) becomes '?'. Returns the
/// number of columns written.
fn writeSafe(out: *Writer, s: []const u8) !usize {
    for (s) |c| try out.writeByte(if (c >= 0x20 and c < 0x7f) c else '?');
    return s.len;
}

/// Writes `s` as a JSON string literal, escaping quotes, backslashes and
/// control characters. Bytes that are not valid UTF-8 are emitted as \u00XX.
pub fn writeJsonString(w: *Writer, s: []const u8) !void {
    try w.writeByte('"');
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...0x1f, 0x7f => try w.print("\\u{x:0>4}", .{c}),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(c),
            0x80...0xff => {
                const n = std.unicode.utf8ByteSequenceLength(c) catch 0;
                if (n != 0 and i + n <= s.len and std.unicode.utf8ValidateSlice(s[i .. i + n])) {
                    try w.writeAll(s[i .. i + n]);
                    i += n;
                    continue;
                }
                try w.print("\\u{x:0>4}", .{c});
            },
        }
        i += 1;
    }
    try w.writeByte('"');
}

// ---------------------------------------------------------------- tests

test "Shannon entropy of zero buffer is 0.0" {
    var zeros: [256]u8 = undefined;
    @memset(&zeros, 0);
    const h = entropy.calculateEntropy(&zeros);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), h, 0.0001);
}

test "Shannon entropy of uniform distribution is 8.0" {
    var uniform: [256]u8 = undefined;
    for (&uniform, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    const h = entropy.calculateEntropy(&uniform);
    try std.testing.expectApproxEqAbs(@as(f64, 8.0), h, 0.0001);
}

test "Format detection identifies ELF, Mach-O, and PE" {
    try std.testing.expectEqual(entropy.BinaryFormat.elf, entropy.detectFormat("\x7FELF\x02\x01\x01\x00"));
    try std.testing.expectEqual(entropy.BinaryFormat.pe, entropy.detectFormat("MZ\x90\x00\x03\x00\x00\x00"));
}

test "Sliding window entropy calculates windows correctly" {
    var data: [256]u8 = undefined;
    @memset(data[0..128], 0);
    @memset(data[128..256], 0xFF);
    var out: [16]f64 = undefined;
    const written = entropy.slidingWindowEntropy(&data, 64, 32, &out);
    try std.testing.expect(written > 0);
}

const testing = std.testing;

fn expectValidJson(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
}

test "json strings escape hostile bytes and stay parseable" {
    var buf: [256]u8 = undefined;
    var w = Writer.fixed(&buf);
    try writeJsonString(&w, "a\"b\\c\n\x01\x7f\xff\xc3\xa9");
    const written = w.buffered();
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\n\\u0001\\u007f\\u00ffé\"", written);
    const parsed = try std.json.parseFromSlice([]const u8, testing.allocator, written, .{});
    defer parsed.deinit();
}

test "scan json is valid and reports the planted region" {
    var data: [16384]u8 = @splat(0);
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(data[4096..8192]);
    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeScan(testing.allocator, &aw.writer, "x\"y", &data, .{ .window = 512, .step = 128, .threshold = 7.0, .width = 16, .json = true });
    const parsed = try expectValidJson(aw.written());
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("x\"y", root.get("file").?.string);
    try testing.expectEqual(@as(i64, 16384), root.get("size").?.integer);
    try testing.expectEqual(@as(usize, 16), root.get("profile").?.array.items.len);
    const regions = root.get("regions").?.array.items;
    try testing.expectEqual(@as(usize, 1), regions.len);
    try testing.expectEqual(@as(i64, 4096), regions[0].object.get("start").?.integer);
    try testing.expectEqual(@as(i64, 8192), regions[0].object.get("end").?.integer);
}

test "scan handles empty and tiny inputs" {
    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeScan(testing.allocator, &aw.writer, "empty", "", .{ .json = true });
    try writeScan(testing.allocator, &aw.writer, "tiny", "ab", .{});
    var it = std.mem.splitScalar(u8, aw.written(), '\n');
    const parsed = try expectValidJson(it.first());
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 0), parsed.value.object.get("windows").?.integer);
}

test "sections json on an ELF fixture and text output sanitizes names" {
    // Build a small ELF whose only named section carries an escape sequence.
    var buf: [512]u8 = @splat(0);
    @memcpy(buf[0..4], "\x7FELF");
    buf[4] = 2;
    buf[5] = 1;
    const strtab = "\x00.ev\x1b[31m\x00.shstrtab\x00";
    @memcpy(buf[64..][0..strtab.len], strtab);
    std.mem.writeInt(u64, buf[0x28..0x30], 128, .little);
    std.mem.writeInt(u16, buf[0x3A..0x3C], 64, .little);
    std.mem.writeInt(u16, buf[0x3C..0x3E], 3, .little);
    std.mem.writeInt(u16, buf[0x3E..0x40], 2, .little);
    const sh1 = 128 + 64;
    std.mem.writeInt(u32, buf[sh1..][0..4], 1, .little);
    std.mem.writeInt(u32, buf[sh1 + 4 ..][0..4], 1, .little);
    std.mem.writeInt(u64, buf[sh1 + 24 ..][0..8], 0, .little);
    std.mem.writeInt(u64, buf[sh1 + 32 ..][0..8], 64, .little);
    const sh2 = 128 + 128;
    std.mem.writeInt(u32, buf[sh2..][0..4], 10, .little);
    std.mem.writeInt(u32, buf[sh2 + 4 ..][0..4], 3, .little);
    std.mem.writeInt(u64, buf[sh2 + 24 ..][0..8], 64, .little);
    std.mem.writeInt(u64, buf[sh2 + 32 ..][0..8], strtab.len, .little);

    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeSections(testing.allocator, &aw.writer, "f.elf", &buf, 0, true);
    const parsed = try expectValidJson(aw.written());
    defer parsed.deinit();
    const secs = parsed.value.object.get("sections").?.array.items;
    try testing.expectEqual(@as(usize, 2), secs.len);
    try testing.expectEqualStrings(".ev\x1b[31m", secs[0].object.get("name").?.string);
    try testing.expectEqualStrings(".shstrtab", secs[1].object.get("name").?.string);

    aw.clearRetainingCapacity();
    try writeSections(testing.allocator, &aw.writer, "f.elf", &buf, 0, false);
    try testing.expect(std.mem.indexOfScalar(u8, aw.written(), 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), ".ev?[31m") != null);
}

test "diff json is valid for raw inputs and counts blocks" {
    var old: [8192]u8 = @splat(3);
    var new = old;
    new[5000] = 4;
    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeDiff(testing.allocator, &aw.writer, "a", &old, "b", &new, .{ .block = 1024, .json = true });
    const parsed = try expectValidJson(aw.written());
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expect(!root.get("identical").?.bool);
    try testing.expect(!root.get("sections").?.object.get("available").?.bool);
    const blocks = root.get("blocks").?.object;
    try testing.expectEqual(@as(i64, 1), blocks.get("modified").?.integer);
    // Block 4 changed in place; the other seven are identical but every block
    // is the same constant data, so the modified one is not a relocation.
    try testing.expectEqual(@as(i64, 7), blocks.get("identical").?.integer);
    try testing.expectEqual(@as(i64, 1), blocks.get("differing_bytes").?.integer);
}

test "downsample keeps column maxima" {
    const vals = [_]f64{ 1, 2, 8, 1, 1, 1, 1, 3 };
    const r = try downsample(testing.allocator, &vals, 4);
    defer testing.allocator.free(r);
    try testing.expectEqualSlices(f64, &.{ 2, 8, 1, 3 }, r);
    const same = try downsample(testing.allocator, &vals, 100);
    defer testing.allocator.free(same);
    try testing.expectEqual(@as(usize, 8), same.len);
}

test {
    _ = entropy;
    _ = sections;
    _ = diff;
    _ = abi;
}
