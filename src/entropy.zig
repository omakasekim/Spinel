// Copyright (c) 2026 jk9576. All rights reserved.
// Spinel: High-Entropy Binary Section Map & Structural Diff Engine
// Licensed under the MIT License.

const std = @import("std");

pub const BinaryFormat = enum {
    elf,
    macho,
    pe,
    raw,
};

pub const SectionFlags = packed struct(u32) {
    /// The section or segment holds executable code.
    executable: bool = false,
    /// The section or segment is writable at run time.
    writable: bool = false,
    /// Entropy is at or above `packed_threshold` over at least `min_packed_size` bytes.
    is_packed: bool = false,
    /// The section occupies no bytes in the file (ELF SHT_NOBITS, Mach-O zerofill,
    /// PE uninitialized data).
    nobits: bool = false,
    /// The declared file range ran past the end of the input and was clamped.
    truncated: bool = false,
    /// The entry was synthesized from an ELF program header because the file has
    /// no section header table (common for packed ELF executables).
    from_segment: bool = false,
    /// Entropy was not computed because the analysis work budget was exhausted
    /// (only possible with hostile, heavily overlapping section tables).
    entropy_skipped: bool = false,
    _reserved: u25 = 0,
};

pub const SectionInfo = struct {
    name: []const u8,
    /// File offset of the bytes analyzed.
    offset: u64,
    /// Number of file bytes analyzed (after clamping to the input).
    size: u64,
    entropy: f64,
    is_packed: bool,
    /// Mach-O segment name (for example `__TEXT`); empty for other formats.
    segment: []const u8 = "",
    /// Virtual address the section is mapped at.
    vaddr: u64 = 0,
    /// Size the section occupies in memory (can exceed `size`, for example .bss).
    mem_size: u64 = 0,
    flags: SectionFlags = .{},
};

/// Entropy at or above this value is treated as compressed or encrypted.
pub const packed_threshold: f64 = 7.2;
/// Sections smaller than this are never flagged as packed: a run of n bytes cannot
/// exceed log2(n) bits of entropy, so tiny sections give no meaningful signal.
pub const min_packed_size: u64 = 256;

pub fn detectFormat(data: []const u8) BinaryFormat {
    if (data.len >= 4) {
        if (std.mem.eql(u8, data[0..4], "\x7FELF")) return .elf;
        const magic = std.mem.readInt(u32, data[0..4], .little);
        if (magic == 0xFEEDFACE or magic == 0xFEEDFACF or magic == 0xCEFAEDFE or magic == 0xCFFAEDFE) {
            return .macho;
        }
        if (isFatMachO(data)) return .macho;
    }
    if (data.len >= 2 and data[0] == 'M' and data[1] == 'Z') {
        return .pe;
    }
    return .raw;
}

/// Universal (fat) Mach-O headers share the 0xCAFEBABE magic with Java class
/// files. A Java class stores its version there instead of an architecture count,
/// and class file major versions start at 45, so a small count means Mach-O.
pub fn isFatMachO(data: []const u8) bool {
    if (data.len < 8) return false;
    const magic = std.mem.readInt(u32, data[0..4], .big);
    if (magic != 0xCAFEBABE and magic != 0xCAFEBABF) return false;
    const nfat = std.mem.readInt(u32, data[4..8], .big);
    return nfat > 0 and nfat < 45;
}

/// Shannon entropy in bits per byte of a 256-bin histogram holding `total` samples.
pub fn entropyFromCounts(counts: *const [256]u64, total: u64) f64 {
    if (total == 0) return 0.0;
    const n: f64 = @floatFromInt(total);
    var entropy: f64 = 0.0;
    for (counts) |c| {
        if (c > 0) {
            const p: f64 = @as(f64, @floatFromInt(c)) / n;
            entropy -= p * @log2(p);
        }
    }
    return entropy;
}

/// Computes Shannon entropy over a byte slice. Value range is [0.0, 8.0].
pub fn calculateEntropy(data: []const u8) f64 {
    if (data.len == 0) return 0.0;
    var counts: [256]u64 = @splat(0);
    for (data) |b| counts[b] += 1;
    return entropyFromCounts(&counts, data.len);
}

/// Streams the entropy of every window `[i * step, i * step + window)` that fits
/// inside `data`. The byte histogram is updated incrementally (bytes leaving the
/// window are removed, bytes entering are added), so the cost is O(len + windows * 256)
/// instead of O(windows * window). Results are bit-identical to `calculateEntropy`
/// applied to each window. A zero window or zero step yields no windows.
pub const WindowIterator = struct {
    data: []const u8,
    window: usize,
    step: usize,
    /// Start offset of the next window to produce.
    offset: usize = 0,
    counts: [256]u64 = @splat(0),
    /// Start offset of the window currently held in `counts`, if any.
    loaded: ?usize = null,
    done: bool = false,

    pub fn init(data: []const u8, window: usize, step: usize) WindowIterator {
        return .{
            .data = data,
            .window = window,
            .step = step,
            .done = window == 0 or step == 0 or window > data.len,
        };
    }

    /// Number of windows the iterator produces in total.
    pub fn count(self: *const WindowIterator) usize {
        if (self.window == 0 or self.step == 0 or self.window > self.data.len) return 0;
        return (self.data.len - self.window) / self.step + 1;
    }

    pub fn next(self: *WindowIterator) ?f64 {
        if (self.done) return null;
        const start = self.offset;
        const w = self.window;
        if (self.loaded) |prev| {
            const delta = start - prev;
            if (delta < w) {
                for (self.data[prev .. prev + delta]) |b| self.counts[b] -= 1;
                for (self.data[prev + w .. start + w]) |b| self.counts[b] += 1;
            } else {
                self.reload(start);
            }
        } else {
            self.reload(start);
        }
        self.loaded = start;
        const h = entropyFromCounts(&self.counts, w);
        // Advance without overflowing: stop when the next window would not fit.
        const remaining = self.data.len - start - w;
        if (self.step > remaining) {
            self.done = true;
        } else {
            self.offset = start + self.step;
        }
        return h;
    }

    fn reload(self: *WindowIterator, start: usize) void {
        self.counts = @splat(0);
        for (self.data[start .. start + self.window]) |b| self.counts[b] += 1;
    }
};

/// Computes sliding-window Shannon entropy array. Returns the number of values
/// written to `out` (at most `out.len`). A zero window or zero step writes nothing.
/// `out` may be unaligned, which matters for callers that hand in raw addresses.
pub fn slidingWindowEntropy(data: []const u8, window_size: usize, step_size: usize, out: []align(1) f64) usize {
    if (out.len == 0) return 0;
    var it = WindowIterator.init(data, window_size, step_size);
    var written: usize = 0;
    while (written < out.len) {
        out[written] = it.next() orelse break;
        written += 1;
    }
    return written;
}

/// Reference implementation that recomputes every window from scratch. Kept for
/// differential testing of `slidingWindowEntropy`.
pub fn slidingWindowEntropyNaive(data: []const u8, window_size: usize, step_size: usize, out: []f64) usize {
    if (window_size == 0 or step_size == 0 or data.len < window_size or out.len == 0) return 0;
    var written: usize = 0;
    var offset: usize = 0;
    while (written < out.len) {
        out[written] = calculateEntropy(data[offset .. offset + window_size]);
        written += 1;
        if (step_size > data.len - offset - window_size) break;
        offset += step_size;
    }
    return written;
}

/// A contiguous byte range whose sliding-window entropy stayed at or above a threshold.
pub const Region = extern struct {
    start: f64,
    end: f64,
    mean: f64,
    peak: f64,

    pub fn startOffset(self: Region) u64 {
        return @intFromFloat(self.start);
    }
    pub fn endOffset(self: Region) u64 {
        return @intFromFloat(self.end);
    }
};

/// Finds byte ranges covered by windows whose entropy is >= `threshold`. Each
/// region is a union of qualifying windows: windows that overlap or touch are
/// merged, and `mean`/`peak` summarize the qualifying windows only. Fields are stored
/// as f64 (exact for offsets below 2^53) so a JavaScript caller can read regions
/// through a Float64Array. Writes at most `out.len` regions and returns the total
/// number found, so a caller can size a buffer with an empty `out`.
pub fn findHighEntropyRegions(data: []const u8, window: usize, step: usize, threshold: f64, out: []align(1) Region) usize {
    var it = WindowIterator.init(data, window, step);
    var total: usize = 0;
    var open = false;
    var cur_start: usize = 0;
    var cur_end: usize = 0;
    var sum: f64 = 0;
    var n: usize = 0;
    var peak: f64 = 0;
    var start: usize = 0;
    while (it.next()) |h| : (start += step) {
        if (h >= threshold) {
            if (open and start <= cur_end) {
                cur_end = start + window;
            } else {
                if (open) emitRegion(out, &total, cur_start, cur_end, sum, n, peak);
                open = true;
                cur_start = start;
                cur_end = start + window;
                sum = 0;
                n = 0;
                peak = 0;
            }
            sum += h;
            n += 1;
            peak = @max(peak, h);
        }
    }
    if (open) emitRegion(out, &total, cur_start, cur_end, sum, n, peak);
    return total;
}

fn emitRegion(out: []align(1) Region, total: *usize, start: usize, end: usize, sum: f64, n: usize, peak: f64) void {
    if (total.* < out.len) {
        out[total.*] = .{
            .start = @floatFromInt(start),
            .end = @floatFromInt(end),
            .mean = sum / @as(f64, @floatFromInt(n)),
            .peak = peak,
        };
    }
    total.* += 1;
}

pub const Class = enum {
    sparse,
    structured,
    code,
    packed_or_encrypted,

    pub fn label(self: Class) []const u8 {
        return switch (self) {
            .sparse => "sparse",
            .structured => "structured",
            .code => "code",
            .packed_or_encrypted => "packed",
        };
    }
};

/// Coarse content class for an entropy value, using the same bands as the
/// Braille map: below 1.0 is padding or zero fill, below 5.5 text, tables and
/// patterned data, below 7.2 machine code or mixed data, and above that
/// compressed or encrypted bytes.
pub fn classify(entropy: f64) Class {
    if (entropy < 1.0) return .sparse;
    if (entropy < 5.5) return .structured;
    if (entropy < packed_threshold) return .code;
    return .packed_or_encrypted;
}

/// Converts an entropy value [0.0, 8.0] into a Braille bar character.
pub fn entropyToBraille(entropy: f64) []const u8 {
    if (entropy < 1.0) return " ";
    if (entropy < 2.5) return "⣀";
    if (entropy < 4.0) return "⣤";
    if (entropy < 5.5) return "⣶";
    if (entropy < 7.2) return "⣿";
    return "█"; // High-entropy encrypted/packed marker
}

/// Renders a Braille sparkline representation of the entropy buffer into a slice.
pub fn renderBrailleSparkline(entropy_vals: []const f64, writer: anytype) !void {
    for (entropy_vals) |val| {
        try writer.print("{s}", .{entropyToBraille(val)});
    }
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn fillRandom(seed: u64, buf: []u8) void {
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(buf);
}

test "incremental sliding window is bit-identical to the naive reference" {
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const r = prng.random();
    var data: [3000]u8 = undefined;
    var fast: [4000]f64 = undefined;
    var slow: [4000]f64 = undefined;
    var case: usize = 0;
    while (case < 400) : (case += 1) {
        const len = r.uintLessThan(usize, data.len + 1);
        // Mix uniform, low-alphabet and runs so histogram updates hit every path.
        const alphabet = switch (case % 3) {
            0 => @as(u16, 256),
            1 => @as(u16, 4),
            else => @as(u16, 2),
        };
        for (data[0..len]) |*b| b.* = @intCast(r.uintLessThan(u16, alphabet));
        const window = r.uintLessThan(usize, 300);
        const step = r.uintLessThan(usize, 400);
        const cap = r.uintLessThan(usize, fast.len);
        const a = slidingWindowEntropy(data[0..len], window, step, fast[0..cap]);
        const b = slidingWindowEntropyNaive(data[0..len], window, step, slow[0..cap]);
        try testing.expectEqual(b, a);
        for (fast[0..a], slow[0..b]) |x, y| try testing.expectEqual(y, x);
        const it = WindowIterator.init(data[0..len], window, step);
        try testing.expectEqual(@min(it.count(), cap), a);
    }
}

test "sliding window rejects degenerate parameters instead of looping" {
    var data: [64]u8 = @splat(7);
    var out: [8]f64 = undefined;
    try testing.expectEqual(@as(usize, 0), slidingWindowEntropy(&data, 0, 4, &out));
    try testing.expectEqual(@as(usize, 0), slidingWindowEntropy(&data, 16, 0, &out));
    try testing.expectEqual(@as(usize, 0), slidingWindowEntropy(&data, 65, 1, &out));
    try testing.expectEqual(@as(usize, 1), slidingWindowEntropy(&data, 64, std.math.maxInt(usize), &out));
    try testing.expectEqual(@as(usize, 1), slidingWindowEntropy(&data, 60, 8, &out));
}

test "window count matches the closed form" {
    const data: [100]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 1), WindowIterator.init(&data, 100, 1).count());
    try testing.expectEqual(@as(usize, 91), WindowIterator.init(&data, 10, 1).count());
    try testing.expectEqual(@as(usize, 10), WindowIterator.init(&data, 10, 10).count());
    try testing.expectEqual(@as(usize, 4), WindowIterator.init(&data, 10, 30).count());
}

test "high-entropy regions merge overlapping windows and report exact bounds" {
    var data: [8192]u8 = @splat(0);
    fillRandom(1, data[2048..4096]);
    fillRandom(2, data[6144..7168]);
    var regions: [8]Region = undefined;
    const n = findHighEntropyRegions(&data, 256, 64, 7.0, &regions);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(u64, 2048), regions[0].startOffset());
    try testing.expectEqual(@as(u64, 4096), regions[0].endOffset());
    try testing.expectEqual(@as(u64, 6144), regions[1].startOffset());
    try testing.expectEqual(@as(u64, 7168), regions[1].endOffset());
    for (regions[0..n]) |reg| {
        try testing.expect(reg.mean >= 7.0 and reg.mean <= reg.peak and reg.peak <= 8.0);
    }
    // Counting mode: an empty output buffer still reports the total.
    try testing.expectEqual(@as(usize, 2), findHighEntropyRegions(&data, 256, 64, 7.0, &.{}));
    // Truncated output keeps the first regions.
    var one: [1]Region = undefined;
    try testing.expectEqual(@as(usize, 2), findHighEntropyRegions(&data, 256, 64, 7.0, &one));
    try testing.expectEqual(@as(u64, 2048), one[0].startOffset());
}

test "regions with gapped windows do not merge across the gap" {
    var data: [4096]u8 = undefined;
    fillRandom(3, &data);
    var regions: [16]Region = undefined;
    // step > window: windows never touch, so each one is its own region.
    const n = findHighEntropyRegions(&data, 256, 512, 7.0, &regions);
    try testing.expectEqual(WindowIterator.init(&data, 256, 512).count(), n);
    // Threshold above the maximum finds nothing.
    try testing.expectEqual(@as(usize, 0), findHighEntropyRegions(&data, 256, 64, 8.5, &regions));
}

test "regions equal the union of qualifying windows (property test against a coverage mask)" {
    var prng = std.Random.DefaultPrng.init(0xC0DE);
    const r = prng.random();
    var data: [2048]u8 = undefined;
    var covered: [2048]bool = undefined;
    var vals: [2048]f64 = undefined;
    var regions: [2048]Region = undefined;
    var case: usize = 0;
    while (case < 200) : (case += 1) {
        // Alternate random and zero stretches so regions start and stop.
        var i: usize = 0;
        while (i < data.len) {
            const run = @min(data.len - i, 1 + r.uintLessThan(usize, 300));
            if (r.boolean()) r.bytes(data[i .. i + run]) else @memset(data[i .. i + run], 0);
            i += run;
        }
        const window = 1 + r.uintLessThan(usize, 200);
        const step = 1 + r.uintLessThan(usize, 250);
        const threshold = 3.0 + r.float(f64) * 4.0;
        const nw = slidingWindowEntropyNaive(&data, window, step, &vals);
        @memset(&covered, false);
        for (vals[0..nw], 0..) |h, k| {
            if (h >= threshold) @memset(covered[k * step .. k * step + window], true);
        }
        var expected: usize = 0;
        const n = findHighEntropyRegions(&data, window, step, threshold, &regions);
        var pos: usize = 0;
        while (pos < covered.len) {
            if (!covered[pos]) {
                pos += 1;
                continue;
            }
            const s = pos;
            while (pos < covered.len and covered[pos]) pos += 1;
            try testing.expect(expected < n);
            try testing.expectEqual(@as(u64, s), regions[expected].startOffset());
            try testing.expectEqual(@as(u64, pos), regions[expected].endOffset());
            expected += 1;
        }
        try testing.expectEqual(expected, n);
    }
}

test "classification bands" {
    try testing.expectEqual(Class.sparse, classify(0.0));
    try testing.expectEqual(Class.structured, classify(4.2));
    try testing.expectEqual(Class.code, classify(6.1));
    try testing.expectEqual(Class.packed_or_encrypted, classify(7.9));
}

test "fat Mach-O is detected but Java class files are not" {
    try testing.expectEqual(BinaryFormat.macho, detectFormat("\xCA\xFE\xBA\xBE\x00\x00\x00\x02"));
    try testing.expectEqual(BinaryFormat.macho, detectFormat("\xCA\xFE\xBA\xBF\x00\x00\x00\x01"));
    // Java 8 class file: minor 0, major 52.
    try testing.expectEqual(BinaryFormat.raw, detectFormat("\xCA\xFE\xBA\xBE\x00\x00\x00\x34"));
    try testing.expectEqual(BinaryFormat.raw, detectFormat("\xCA\xFE\xBA\xBE"));
}
