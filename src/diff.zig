// Copyright (c) 2026 jk9576. All rights reserved.
// Spinel: High-Entropy Binary Section Map & Structural Diff Engine
// Licensed under the MIT License.
//
// Structural diff between two binaries at two levels:
//   - sections: tables are matched by (segment, name, occurrence) and each pair
//     is compared by content, size and byte-distribution distance;
//   - blocks: both files are cut into fixed-size blocks, compared positionally,
//     and changed blocks of the new file are looked up in the old file by
//     content hash to tell relocated content from genuinely new bytes.

const std = @import("std");
const entropy = @import("entropy.zig");

const SectionInfo = entropy.SectionInfo;
const Allocator = std.mem.Allocator;

/// Total variation distance between the byte distributions of `a` and `b`:
/// 0.0 when both use bytes in the same proportions, 1.0 when they share no byte
/// value. Two empty inputs are at distance 0; one empty input is at distance 1.
pub fn histogramDistance(a: []const u8, b: []const u8) f64 {
    if (a.len == 0 and b.len == 0) return 0.0;
    if (a.len == 0 or b.len == 0) return 1.0;
    var ca: [256]u64 = @splat(0);
    var cb: [256]u64 = @splat(0);
    for (a) |x| ca[x] += 1;
    for (b) |x| cb[x] += 1;
    const na: f64 = @floatFromInt(a.len);
    const nb: f64 = @floatFromInt(b.len);
    var sum: f64 = 0;
    for (ca, cb) |x, y| {
        sum += @abs(@as(f64, @floatFromInt(x)) / na - @as(f64, @floatFromInt(y)) / nb);
    }
    return @min(1.0, sum / 2.0);
}

/// Number of byte positions that differ, counting the length difference as
/// differing bytes.
pub fn differingBytes(a: []const u8, b: []const u8) u64 {
    const n = @min(a.len, b.len);
    var count: u64 = 0;
    for (a[0..n], b[0..n]) |x, y| count += @intFromBool(x != y);
    return count + (@max(a.len, b.len) - n);
}

pub const BlockStatus = enum(u8) {
    identical = 0,
    modified = 1,
    /// Block exists only in the old file (the new file is shorter).
    removed = 2,
    /// Block exists only in the new file (the new file is longer).
    added = 3,
    /// Block of the new file differs positionally, but its exact content is a
    /// block of the old file at another offset.
    moved = 4,

    pub fn label(self: BlockStatus) []const u8 {
        return @tagName(self);
    }
};

fn blockSlice(data: []const u8, block: usize, i: usize) []const u8 {
    const start = i * block;
    if (start >= data.len) return data[data.len..];
    return data[start..@min(data.len, start + block)];
}

fn blockCount(len: usize, block: usize) usize {
    return (len + block - 1) / block;
}

/// Positional block comparison. Writes one `BlockStatus` byte (identical,
/// modified, removed or added; never moved) per block for up to `out.len` blocks
/// and returns the total number of blocks, max(blocks(a), blocks(b)). A zero
/// block size returns 0.
pub fn blockDiff(a: []const u8, b: []const u8, block: usize, out: []u8) usize {
    if (block == 0) return 0;
    const na = blockCount(a.len, block);
    const nb = blockCount(b.len, block);
    const total = @max(na, nb);
    for (out[0..@min(out.len, total)], 0..) |*o, i| {
        const status: BlockStatus = if (i >= nb)
            .removed
        else if (i >= na)
            .added
        else if (std.mem.eql(u8, blockSlice(a, block, i), blockSlice(b, block, i)))
            .identical
        else
            .modified;
        o.* = @backingInt(status);
    }
    return total;
}

pub const Range = struct {
    status: BlockStatus,
    /// Byte range in the new file (or the old file for `removed`).
    start: u64,
    end: u64,
    blocks: usize,
    entropy_old: f64,
    entropy_new: f64,
};

pub const BlockReport = struct {
    block: usize,
    blocks_old: usize,
    blocks_new: usize,
    identical: usize = 0,
    modified: usize = 0,
    moved: usize = 0,
    added: usize = 0,
    removed: usize = 0,
    differing_bytes: u64,
    /// Runs of consecutive non-identical blocks with the same status.
    ranges: []Range,

    pub fn deinit(self: BlockReport, gpa: Allocator) void {
        gpa.free(self.ranges);
    }

    /// Fraction of the new file's blocks that are identical in place or relocated.
    pub fn similarity(self: BlockReport) f64 {
        if (self.blocks_new == 0) return if (self.blocks_old == 0) 1.0 else 0.0;
        const same: f64 = @floatFromInt(self.identical + self.moved);
        return same / @as(f64, @floatFromInt(@max(self.blocks_new, self.blocks_old)));
    }
};

/// Full block-level comparison including relocation detection. Only full-size
/// blocks of the old file are indexed for relocation; hash hits are confirmed
/// byte for byte, so a hash collision can never report a false `moved`.
pub fn blockReport(gpa: Allocator, a: []const u8, b: []const u8, block: usize) !BlockReport {
    if (block == 0) return error.InvalidBlockSize;
    const na = blockCount(a.len, block);
    const nb = blockCount(b.len, block);

    var index: std.AutoHashMapUnmanaged(u64, u32) = .empty;
    defer index.deinit(gpa);
    const full_a = a.len / block;
    if (full_a > std.math.maxInt(u32)) return error.InputTooLarge;
    try index.ensureTotalCapacity(gpa, @intCast(full_a));
    for (0..full_a) |i| {
        const h = std.hash.Wyhash.hash(0, a[i * block ..][0..block]);
        const gop = index.getOrPutAssumeCapacity(h);
        if (!gop.found_existing) gop.value_ptr.* = @intCast(i);
    }

    var report: BlockReport = .{
        .block = block,
        .blocks_old = na,
        .blocks_new = nb,
        .differing_bytes = differingBytes(a, b),
        .ranges = &.{},
    };
    var ranges: std.ArrayList(Range) = .empty;
    errdefer ranges.deinit(gpa);

    const total = @max(na, nb);
    for (0..total) |i| {
        const sb = blockSlice(b, block, i);
        const sa = blockSlice(a, block, i);
        const status: BlockStatus = if (i >= nb)
            .removed
        else if (i < na and std.mem.eql(u8, sa, sb))
            .identical
        else if (sb.len == block and isRelocated(&index, a, block, sb))
            .moved
        else if (i >= na)
            .added
        else
            .modified;
        switch (status) {
            .identical => report.identical += 1,
            .modified => report.modified += 1,
            .moved => report.moved += 1,
            .added => report.added += 1,
            .removed => report.removed += 1,
        }
        if (status == .identical) continue;
        const start: u64 = @as(u64, i) * block;
        const end: u64 = start + (if (status == .removed) sa.len else sb.len);
        if (ranges.items.len > 0) {
            const last = &ranges.items[ranges.items.len - 1];
            if (last.status == status and last.end == start) {
                last.end = end;
                last.blocks += 1;
                continue;
            }
        }
        try ranges.append(gpa, .{ .status = status, .start = start, .end = end, .blocks = 1, .entropy_old = 0, .entropy_new = 0 });
    }
    for (ranges.items) |*r| {
        r.entropy_old = entropy.calculateEntropy(clampSlice(a, r.start, r.end));
        r.entropy_new = entropy.calculateEntropy(clampSlice(b, r.start, r.end));
    }
    report.ranges = try ranges.toOwnedSlice(gpa);
    return report;
}

fn isRelocated(index: *const std.AutoHashMapUnmanaged(u64, u32), a: []const u8, block: usize, sb: []const u8) bool {
    const at = index.get(std.hash.Wyhash.hash(0, sb)) orelse return false;
    return std.mem.eql(u8, a[@as(usize, at) * block ..][0..block], sb);
}

fn clampSlice(data: []const u8, start: u64, end: u64) []const u8 {
    if (start >= data.len) return data[data.len..];
    return data[@intCast(start)..@intCast(@min(end, data.len))];
}

pub const SectionStatus = enum {
    unchanged,
    modified,
    added,
    removed,

    pub fn label(self: SectionStatus) []const u8 {
        return @tagName(self);
    }
};

pub const SectionDelta = struct {
    status: SectionStatus,
    name: []const u8,
    segment: []const u8,
    old: ?SectionInfo,
    new: ?SectionInfo,
    /// Byte-distribution distance between old and new content (0 when either is missing).
    distance: f64 = 0,
    /// Differing byte positions between old and new content.
    differing_bytes: u64 = 0,
};

fn sectionBytes(data: []const u8, s: SectionInfo) []const u8 {
    return clampSlice(data, s.offset, s.offset +| s.size);
}

/// Matches sections by (segment, name, occurrence) and classifies each pair.
/// Old-file order is kept; sections only present in the new file follow in
/// new-file order. The returned slice is owned by the caller.
pub fn diffSections(
    gpa: Allocator,
    old_data: []const u8,
    old: []const SectionInfo,
    new_data: []const u8,
    new: []const SectionInfo,
) ![]SectionDelta {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Key -> queue of new-section indices, consumed in order so that the n-th
    // old section with a given key pairs with the n-th new one.
    const Queue = struct { items: std.ArrayList(usize) = .empty, head: usize = 0 };
    var by_key: std.StringHashMapUnmanaged(Queue) = .empty;
    for (new, 0..) |s, i| {
        const key = try std.fmt.allocPrint(arena, "{s}\x00{s}", .{ s.segment, s.name });
        const gop = try by_key.getOrPut(arena, key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.items.append(arena, i);
    }
    const matched = try arena.alloc(bool, new.len);
    @memset(matched, false);

    var out: std.ArrayList(SectionDelta) = .empty;
    errdefer out.deinit(gpa);
    for (old) |so| {
        const key = try std.fmt.allocPrint(arena, "{s}\x00{s}", .{ so.segment, so.name });
        const q = by_key.getPtr(key);
        if (q == null or q.?.head >= q.?.items.items.len) {
            try out.append(gpa, .{ .status = .removed, .name = so.name, .segment = so.segment, .old = so, .new = null });
            continue;
        }
        const j = q.?.items.items[q.?.head];
        q.?.head += 1;
        matched[j] = true;
        const sn = new[j];
        const bo = sectionBytes(old_data, so);
        const bn = sectionBytes(new_data, sn);
        const same = so.size == sn.size and so.mem_size == sn.mem_size and std.mem.eql(u8, bo, bn);
        try out.append(gpa, .{
            .status = if (same) .unchanged else .modified,
            .name = so.name,
            .segment = so.segment,
            .old = so,
            .new = sn,
            .distance = histogramDistance(bo, bn),
            .differing_bytes = differingBytes(bo, bn),
        });
    }
    for (new, 0..) |sn, j| {
        if (matched[j]) continue;
        try out.append(gpa, .{ .status = .added, .name = sn.name, .segment = sn.segment, .old = null, .new = sn });
    }
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "histogram distance bounds" {
    try testing.expectEqual(@as(f64, 0.0), histogramDistance("abcabc", "cba"));
    try testing.expectEqual(@as(f64, 1.0), histogramDistance("aaaa", "bbbb"));
    try testing.expectApproxEqAbs(@as(f64, 0.5), histogramDistance("aabb", "aacc"), 1e-12);
    try testing.expectEqual(@as(f64, 0.0), histogramDistance("", ""));
    try testing.expectEqual(@as(f64, 1.0), histogramDistance("", "x"));
}

test "differing bytes counts substitutions and length change" {
    try testing.expectEqual(@as(u64, 0), differingBytes("same", "same"));
    try testing.expectEqual(@as(u64, 2), differingBytes("abcd", "abXY"));
    try testing.expectEqual(@as(u64, 3), differingBytes("ab", "aXcd"));
}

test "positional block diff statuses" {
    var a: [40]u8 = @splat(1);
    var b: [56]u8 = @splat(1);
    b[17] = 9; // block 1 modified
    var out: [8]u8 = undefined;
    const n = blockDiff(&a, &b, 16, &out);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 1, 3 }, out[0..4]); // block 2: 8 vs 16 bytes -> modified
    try testing.expectEqual(@as(usize, 4), blockDiff(&b, &a, 16, &out));
    try testing.expectEqual(@as(u8, 2), out[3]);
    try testing.expectEqual(@as(usize, 0), blockDiff(&a, &b, 0, &out));
    // Truncated output still reports the total.
    try testing.expectEqual(@as(usize, 4), blockDiff(&a, &b, 16, out[0..1]));
}

test "block report finds relocated blocks and merges ranges" {
    const gpa = testing.allocator;
    const bs = 64;
    var a: [bs * 8]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(21);
    prng.random().bytes(&a);
    // New file: blocks 0..3 same, then old block 6 and 7 moved to 4 and 5,
    // then two new random blocks, then one extra appended block.
    var b: [bs * 9]u8 = undefined;
    @memcpy(b[0 .. bs * 4], a[0 .. bs * 4]);
    @memcpy(b[bs * 4 .. bs * 6], a[bs * 6 .. bs * 8]);
    prng.random().bytes(b[bs * 6 ..]);
    const rep = try blockReport(gpa, &a, &b, bs);
    defer rep.deinit(gpa);
    try testing.expectEqual(@as(usize, 4), rep.identical);
    try testing.expectEqual(@as(usize, 2), rep.moved);
    try testing.expectEqual(@as(usize, 2), rep.modified);
    try testing.expectEqual(@as(usize, 1), rep.added);
    try testing.expectEqual(@as(usize, 3), rep.ranges.len);
    try testing.expectEqual(BlockStatus.moved, rep.ranges[0].status);
    try testing.expectEqual(@as(u64, bs * 4), rep.ranges[0].start);
    try testing.expectEqual(@as(u64, bs * 6), rep.ranges[0].end);
    try testing.expectEqual(BlockStatus.modified, rep.ranges[1].status);
    try testing.expectEqual(@as(usize, 2), rep.ranges[1].blocks);
    try testing.expectEqual(BlockStatus.added, rep.ranges[2].status);
    try testing.expectApproxEqAbs(@as(f64, 6.0 / 9.0), rep.similarity(), 1e-12);
    try testing.expectError(error.InvalidBlockSize, blockReport(gpa, &a, &b, 0));
}

test "block report of identical inputs" {
    const gpa = testing.allocator;
    var data: [600]u8 = undefined;
    for (&data, 0..) |*c, i| c.* = "spinel"[i % 6];
    const rep = try blockReport(gpa, &data, &data, 32);
    defer rep.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), rep.ranges.len);
    try testing.expectEqual(@as(u64, 0), rep.differing_bytes);
    try testing.expectEqual(@as(f64, 1.0), rep.similarity());
}

test "block report agrees with positional diff when nothing moved (property)" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(77);
    const r = prng.random();
    var a: [1500]u8 = undefined;
    var b: [1500]u8 = undefined;
    var statuses: [1500]u8 = undefined;
    for (0..100) |_| {
        const la = r.uintLessThan(usize, a.len);
        const lb = r.uintLessThan(usize, b.len);
        r.bytes(a[0..la]);
        @memcpy(b[0..@min(la, lb)], a[0..@min(la, lb)]);
        if (lb > la) r.bytes(b[la..lb]);
        for (0..r.uintLessThan(usize, 6)) |_| {
            if (lb > 0) b[r.uintLessThan(usize, lb)] = r.int(u8);
        }
        const bs = 1 + r.uintLessThan(usize, 200);
        const rep = try blockReport(gpa, a[0..la], b[0..lb], bs);
        defer rep.deinit(gpa);
        const n = blockDiff(a[0..la], b[0..lb], bs, &statuses);
        var counts: [5]usize = @splat(0);
        for (statuses[0..n]) |s| counts[s] += 1;
        // Relocation detection only reclassifies blocks the positional diff
        // calls modified or added; every other count must match it.
        try testing.expectEqual(counts[0], rep.identical);
        try testing.expectEqual(counts[2], rep.removed);
        try testing.expectEqual(counts[1] + counts[3], rep.modified + rep.added + rep.moved);
        try testing.expectEqual(differingBytes(a[0..la], b[0..lb]), rep.differing_bytes);
    }
}

test "section diff pairs by name and occurrence" {
    const gpa = testing.allocator;
    const old_data = "AAAABBBBCCCCDDDD";
    const new_data = "AAAAbbbbCCCCEEEEFFFF";
    const S = struct {
        fn mk(name: []const u8, off: u64, size: u64) SectionInfo {
            return .{ .name = name, .offset = off, .size = size, .entropy = 0, .is_packed = false, .mem_size = size };
        }
    };
    const old = [_]SectionInfo{ S.mk(".a", 0, 4), S.mk(".b", 4, 4), S.mk(".dup", 8, 4), S.mk(".dup", 12, 4) };
    const new = [_]SectionInfo{ S.mk(".a", 0, 4), S.mk(".b", 4, 4), S.mk(".dup", 8, 4), S.mk(".new", 12, 8) };
    const d = try diffSections(gpa, old_data, &old, new_data, &new);
    defer gpa.free(d);
    try testing.expectEqual(@as(usize, 5), d.len);
    try testing.expectEqual(SectionStatus.unchanged, d[0].status);
    try testing.expectEqual(SectionStatus.modified, d[1].status);
    try testing.expectEqual(@as(u64, 4), d[1].differing_bytes);
    try testing.expectEqual(@as(f64, 1.0), d[1].distance);
    try testing.expectEqual(SectionStatus.unchanged, d[2].status);
    try testing.expectEqual(SectionStatus.removed, d[3].status);
    try testing.expectEqual(SectionStatus.added, d[4].status);
    try testing.expectEqualStrings(".new", d[4].name);
}
