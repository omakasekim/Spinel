// Copyright (c) 2026 jk9576. All rights reserved.
// Spinel: High-Entropy Binary Section Map & Structural Diff Engine
// Licensed under the MIT License.
//
// Bounds-checked section table parsers for ELF (32/64-bit, either byte order),
// PE/COFF (PE32 and PE32+), and Mach-O (32/64-bit, either byte order, thin or
// universal). Every read is validated against the input, nothing is allocated,
// and the cost of a pass is bounded by the size of the input, so the parsers are
// safe to run on hostile files and inside a freestanding WebAssembly module.

const std = @import("std");
const entropy = @import("entropy.zig");

const BinaryFormat = entropy.BinaryFormat;
const SectionInfo = entropy.SectionInfo;
const SectionFlags = entropy.SectionFlags;
const Endian = std.builtin.Endian;

pub const ParseError = error{
    /// A header or table extends past the end of the input.
    Truncated,
    /// A header field is inconsistent (bad class, bad entry size, bad command size).
    Malformed,
    /// The requested universal Mach-O slice does not exist.
    NoSuchSlice,
};

pub const Header = struct {
    format: BinaryFormat,
    /// 16 for a DOS MZ executable without a PE header, otherwise 32 or 64; 0 for raw data.
    bits: u8 = 0,
    endian: Endian = .little,
    /// e_machine (ELF), Machine (PE) or cputype (Mach-O).
    machine: u32 = 0,
    /// Universal Mach-O only: number of slices and the file offset of the parsed one.
    slices: u32 = 0,
    slice_offset: u64 = 0,

    pub fn archName(self: Header) []const u8 {
        return switch (self.format) {
            .elf => switch (self.machine) {
                3 => "x86",
                8 => "mips",
                20 => "ppc",
                21 => "ppc64",
                40 => "arm",
                62 => "x86_64",
                183 => "aarch64",
                243 => "riscv",
                258 => "loongarch",
                else => "unknown",
            },
            .pe => switch (self.machine) {
                0x14c => "x86",
                0x8664 => "x86_64",
                0xaa64 => "aarch64",
                0x1c0, 0x1c2, 0x1c4 => "arm",
                0x5064 => "riscv64",
                else => if (self.bits == 16) "dos" else "unknown",
            },
            .macho => switch (self.machine) {
                7 => "x86",
                0x01000007 => "x86_64",
                12 => "arm",
                0x0100000c => "aarch64",
                0x0200000c => "arm64_32",
                18 => "ppc",
                0x01000012 => "ppc64",
                else => "unknown",
            },
            .raw => "none",
        };
    }
};

fn readAt(comptime T: type, data: []const u8, off: u64, endian: Endian) ?T {
    const n = @sizeOf(T);
    if (off > data.len or data.len - off < n) return null;
    const o: usize = @intCast(off);
    return std.mem.readInt(T, data[o..][0..n], endian);
}

fn rd(comptime T: type, data: []const u8, off: u64, endian: Endian) ParseError!T {
    return readAt(T, data, off, endian) orelse error.Truncated;
}

/// Checks that `count` entries of `entsize` bytes starting at `off` fit in `len`.
fn tableFits(len: usize, off: u64, count: u64, entsize: u64) bool {
    const bytes = std.math.mul(u64, count, entsize) catch return false;
    const end = std.math.add(u64, off, bytes) catch return false;
    return end <= len;
}

const Clamped = struct { offset: u64, size: u64, truncated: bool };

fn clampRange(len: usize, off: u64, size: u64) Clamped {
    if (off >= len) return .{ .offset = off, .size = 0, .truncated = size != 0 };
    const avail = len - off;
    return .{ .offset = off, .size = @min(size, avail), .truncated = size > avail };
}

/// Returns the NUL-terminated string at `off` inside `table`, bounded by the table.
fn cString(table: []const u8, off: u64) []const u8 {
    if (off >= table.len) return "";
    const o: usize = @intCast(off);
    const s = table[o..];
    return s[0 .. std.mem.indexOfScalar(u8, s, 0) orelse s.len];
}

fn fixedName(field: []const u8) []const u8 {
    return field[0 .. std.mem.indexOfScalar(u8, field, 0) orelse field.len];
}

const ElfState = struct {
    is64: bool,
    use_segments: bool,
    table: u64,
    entsize: u64,
    count: u64,
    index: u64 = 0,
    strtab: []const u8 = "",
};

const PeState = struct {
    table: u64,
    count: u64,
    index: u64 = 0,
    image_base: u64,
    /// COFF string table used by "/123" long section names, if present.
    strtab: []const u8 = "",
};

const MachoState = struct {
    is64: bool,
    /// File offset of the parsed (thin) image; nonzero inside a universal binary.
    base: u64,
    image: []const u8,
    ncmds: u32,
    cmd_index: u32 = 0,
    cursor: u64,
    cmds_end: u64,
    // Current segment being walked.
    seg_name: []const u8 = "",
    seg_prot: u32 = 0,
    sect_cursor: u64 = 0,
    sect_left: u32 = 0,
};

/// Walks the section table of an executable. Entries come back with `entropy`
/// set to 0; `Analyzer` fills it in.
pub const SectionIterator = struct {
    data: []const u8,
    header: Header,
    state: union(enum) {
        none,
        elf: ElfState,
        pe: PeState,
        macho: MachoState,
    },

    pub fn init(data: []const u8) ParseError!SectionIterator {
        return initSlice(data, 0);
    }

    /// Like `init`, but for a universal Mach-O selects slice `slice_index`.
    pub fn initSlice(data: []const u8, slice_index: u32) ParseError!SectionIterator {
        return switch (entropy.detectFormat(data)) {
            .elf => initElf(data),
            .pe => initPe(data),
            .macho => initMacho(data, slice_index),
            .raw => .{ .data = data, .header = .{ .format = .raw }, .state = .none },
        };
    }

    pub fn next(self: *SectionIterator) ParseError!?SectionInfo {
        return switch (self.state) {
            .none => null,
            .elf => |*s| self.nextElf(s),
            .pe => |*s| self.nextPe(s),
            .macho => |*s| self.nextMacho(s),
        };
    }

    // ---------------------------------------------------------------- ELF

    fn initElf(data: []const u8) ParseError!SectionIterator {
        if (data.len < 6) return error.Truncated;
        const is64 = switch (data[4]) {
            1 => false,
            2 => true,
            else => return error.Malformed,
        };
        const endian: Endian = switch (data[5]) {
            1 => .little,
            2 => .big,
            else => return error.Malformed,
        };
        if (data.len < @as(usize, if (is64) 64 else 52)) return error.Truncated;
        const machine = try rd(u16, data, 0x12, endian);
        const phoff: u64 = if (is64) try rd(u64, data, 0x20, endian) else try rd(u32, data, 0x1C, endian);
        const shoff: u64 = if (is64) try rd(u64, data, 0x28, endian) else try rd(u32, data, 0x20, endian);
        const base: u64 = if (is64) 0x36 else 0x2A;
        const phentsize = try rd(u16, data, base, endian);
        const phnum = try rd(u16, data, base + 2, endian);
        const shentsize = try rd(u16, data, base + 4, endian);
        var shnum: u64 = try rd(u16, data, base + 6, endian);
        var shstrndx: u64 = try rd(u16, data, base + 8, endian);

        var it: SectionIterator = .{
            .data = data,
            .header = .{ .format = .elf, .bits = if (is64) 64 else 32, .endian = endian, .machine = machine },
            .state = .none,
        };
        const sh_min: u64 = if (is64) 64 else 40;
        if (shoff != 0) {
            if (shentsize < sh_min) return error.Malformed;
            // Extended numbering: the real count and string table index live in
            // section header 0 when they do not fit in the ELF header.
            if (shnum == 0) {
                shnum = if (is64) try rd(u64, data, shoff +| 32, endian) else try rd(u32, data, shoff +| 20, endian);
            }
            if (shstrndx == 0xFFFF) {
                shstrndx = try rd(u32, data, shoff +| @as(u64, if (is64) 40 else 24), endian);
            }
        }
        if (shoff != 0 and shnum != 0) {
            if (!tableFits(data.len, shoff, shnum, shentsize)) return error.Truncated;
            var strtab: []const u8 = "";
            if (shstrndx != 0 and shstrndx < shnum) {
                const h = shoff + shstrndx * shentsize;
                const off: u64 = if (is64) try rd(u64, data, h + 24, endian) else try rd(u32, data, h + 16, endian);
                const size: u64 = if (is64) try rd(u64, data, h + 32, endian) else try rd(u32, data, h + 20, endian);
                const c = clampRange(data.len, off, size);
                if (c.size > 0) strtab = data[@intCast(c.offset)..][0..@intCast(c.size)];
            }
            it.state = .{ .elf = .{ .is64 = is64, .use_segments = false, .table = shoff, .entsize = shentsize, .count = shnum, .strtab = strtab } };
        } else if (phoff != 0 and phnum != 0) {
            const ph_min: u64 = if (is64) 56 else 32;
            if (phentsize < ph_min) return error.Malformed;
            if (!tableFits(data.len, phoff, phnum, phentsize)) return error.Truncated;
            it.state = .{ .elf = .{ .is64 = is64, .use_segments = true, .table = phoff, .entsize = phentsize, .count = phnum } };
        } else {
            it.state = .{ .elf = .{ .is64 = is64, .use_segments = false, .table = 0, .entsize = sh_min, .count = 0 } };
        }
        return it;
    }

    fn nextElf(self: *SectionIterator, s: *ElfState) ParseError!?SectionInfo {
        const d = self.data;
        const e = self.header.endian;
        while (s.index < s.count) {
            const h = s.table + s.index * s.entsize;
            s.index += 1;
            if (s.use_segments) {
                if (try rd(u32, d, h, e) != 1) continue; // PT_LOAD only
                var pflags: u32 = undefined;
                var off: u64 = undefined;
                var vaddr: u64 = undefined;
                var filesz: u64 = undefined;
                var memsz: u64 = undefined;
                if (s.is64) {
                    pflags = try rd(u32, d, h + 4, e);
                    off = try rd(u64, d, h + 8, e);
                    vaddr = try rd(u64, d, h + 16, e);
                    filesz = try rd(u64, d, h + 32, e);
                    memsz = try rd(u64, d, h + 40, e);
                } else {
                    off = try rd(u32, d, h + 4, e);
                    vaddr = try rd(u32, d, h + 8, e);
                    filesz = try rd(u32, d, h + 16, e);
                    memsz = try rd(u32, d, h + 20, e);
                    pflags = try rd(u32, d, h + 24, e);
                }
                const c = clampRange(d.len, off, filesz);
                return .{
                    .name = "LOAD",
                    .offset = c.offset,
                    .size = c.size,
                    .entropy = 0,
                    .is_packed = false,
                    .vaddr = vaddr,
                    .mem_size = memsz,
                    .flags = .{
                        .executable = pflags & 1 != 0,
                        .writable = pflags & 2 != 0,
                        .nobits = filesz == 0,
                        .truncated = c.truncated,
                        .from_segment = true,
                    },
                };
            }
            const sh_type = try rd(u32, d, h + 4, e);
            if (sh_type == 0) continue; // SHT_NULL
            const name_off = try rd(u32, d, h, e);
            var flags: u64 = undefined;
            var addr: u64 = undefined;
            var off: u64 = undefined;
            var size: u64 = undefined;
            if (s.is64) {
                flags = try rd(u64, d, h + 8, e);
                addr = try rd(u64, d, h + 16, e);
                off = try rd(u64, d, h + 24, e);
                size = try rd(u64, d, h + 32, e);
            } else {
                flags = try rd(u32, d, h + 8, e);
                addr = try rd(u32, d, h + 12, e);
                off = try rd(u32, d, h + 16, e);
                size = try rd(u32, d, h + 20, e);
            }
            const nobits = sh_type == 8; // SHT_NOBITS
            const c = clampRange(d.len, off, if (nobits) 0 else size);
            return .{
                .name = cString(s.strtab, name_off),
                .offset = c.offset,
                .size = c.size,
                .entropy = 0,
                .is_packed = false,
                .vaddr = addr,
                .mem_size = size,
                .flags = .{
                    .executable = flags & 0x4 != 0, // SHF_EXECINSTR
                    .writable = flags & 0x1 != 0, // SHF_WRITE
                    .nobits = nobits,
                    .truncated = c.truncated,
                },
            };
        }
        return null;
    }

    // ---------------------------------------------------------------- PE

    fn initPe(data: []const u8) ParseError!SectionIterator {
        var it: SectionIterator = .{ .data = data, .header = .{ .format = .pe, .bits = 16 }, .state = .none };
        // A DOS executable without a PE header has no section table.
        const lfanew = readAt(u32, data, 0x3C, .little) orelse return it;
        if (!tableFits(data.len, lfanew, 1, 24)) return it;
        if (!std.mem.eql(u8, data[lfanew..][0..4], "PE\x00\x00")) return it;
        const coff: u64 = lfanew + 4;
        const machine = try rd(u16, data, coff, .little);
        const nsections = try rd(u16, data, coff + 2, .little);
        const symtab = try rd(u32, data, coff + 8, .little);
        const nsyms = try rd(u32, data, coff + 12, .little);
        const opt_size = try rd(u16, data, coff + 16, .little);
        const opt: u64 = coff + 20;
        var bits: u8 = 32;
        var image_base: u64 = 0;
        if (opt_size >= 2) {
            switch (try rd(u16, data, opt, .little)) {
                0x10b => {
                    if (opt_size >= 32) image_base = try rd(u32, data, opt + 28, .little);
                },
                0x20b => {
                    bits = 64;
                    if (opt_size >= 32) image_base = try rd(u64, data, opt + 24, .little);
                },
                else => return error.Malformed,
            }
        }
        it.header = .{ .format = .pe, .bits = bits, .machine = machine };
        const table = opt + opt_size;
        if (!tableFits(data.len, table, nsections, 40)) return error.Truncated;
        var strtab: []const u8 = "";
        if (symtab != 0) {
            const st = std.math.add(u64, symtab, @as(u64, nsyms) * 18) catch data.len;
            if (st < data.len) strtab = data[@intCast(st)..];
        }
        it.state = .{ .pe = .{ .table = table, .count = nsections, .image_base = image_base, .strtab = strtab } };
        return it;
    }

    fn nextPe(self: *SectionIterator, s: *PeState) ParseError!?SectionInfo {
        if (s.index >= s.count) return null;
        const d = self.data;
        const h = s.table + s.index * 40;
        s.index += 1;
        const raw_name = fixedName(d[@intCast(h)..][0..8]);
        const vsize = try rd(u32, d, h + 8, .little);
        const vaddr = try rd(u32, d, h + 12, .little);
        const raw_size = try rd(u32, d, h + 16, .little);
        const raw_ptr = try rd(u32, d, h + 20, .little);
        const chars = try rd(u32, d, h + 36, .little);
        const nobits = raw_size == 0 or raw_ptr == 0;
        // SizeOfRawData is rounded up to the file alignment; the loader maps only
        // VirtualSize bytes, so the zero padding past it is left out of the entropy.
        const file_size: u32 = if (vsize != 0) @min(raw_size, vsize) else raw_size;
        const c = clampRange(d.len, raw_ptr, if (nobits) 0 else file_size);
        return .{
            .name = peLongName(raw_name, s.strtab),
            .offset = c.offset,
            .size = c.size,
            .entropy = 0,
            .is_packed = false,
            .vaddr = s.image_base +% vaddr,
            .mem_size = vsize,
            .flags = .{
                .executable = chars & 0x20000000 != 0 or chars & 0x20 != 0,
                .writable = chars & 0x80000000 != 0,
                .nobits = nobits,
                .truncated = c.truncated,
            },
        };
    }

    /// Resolves a "/123" section name through the COFF string table; any other
    /// name, or one that does not resolve, is returned unchanged.
    fn peLongName(name: []const u8, strtab: []const u8) []const u8 {
        if (name.len < 2 or name[0] != '/' or strtab.len == 0) return name;
        const off = std.fmt.parseInt(u32, name[1..], 10) catch return name;
        const s = cString(strtab, off);
        return if (s.len == 0) name else s;
    }

    // ---------------------------------------------------------------- Mach-O

    fn initMacho(data: []const u8, slice_index: u32) ParseError!SectionIterator {
        var base: u64 = 0;
        var image = data;
        var slices: u32 = 0;
        if (entropy.isFatMachO(data)) {
            const fat64 = std.mem.readInt(u32, data[0..4], .big) == 0xCAFEBABF;
            slices = std.mem.readInt(u32, data[4..8], .big);
            if (slice_index >= slices) return error.NoSuchSlice;
            const entsize: u64 = if (fat64) 32 else 20;
            if (!tableFits(data.len, 8, slices, entsize)) return error.Truncated;
            const a = 8 + slice_index * entsize;
            const off: u64 = if (fat64) try rd(u64, data, a + 8, .big) else try rd(u32, data, a + 8, .big);
            const size: u64 = if (fat64) try rd(u64, data, a + 16, .big) else try rd(u32, data, a + 12, .big);
            if (!tableFits(data.len, off, 1, size)) return error.Truncated;
            base = off;
            image = data[@intCast(off)..][0..@intCast(size)];
            if (image.len < 4) return error.Truncated;
            if (entropy.isFatMachO(image)) return error.Malformed; // no nesting
        } else if (slice_index != 0) {
            return error.NoSuchSlice;
        }
        const magic = readAt(u32, image, 0, .little) orelse return error.Truncated;
        const is64, const endian: Endian = switch (magic) {
            0xFEEDFACE => .{ false, .little },
            0xFEEDFACF => .{ true, .little },
            0xCEFAEDFE => .{ false, .big },
            0xCFFAEDFE => .{ true, .big },
            else => return error.Malformed,
        };
        const hdr: u64 = if (is64) 32 else 28;
        const cputype = try rd(u32, image, 4, endian);
        const ncmds = try rd(u32, image, 16, endian);
        const sizeofcmds = try rd(u32, image, 20, endian);
        if (!tableFits(image.len, hdr, 1, sizeofcmds)) return error.Truncated;
        return .{
            .data = data,
            .header = .{
                .format = .macho,
                .bits = if (is64) 64 else 32,
                .endian = endian,
                .machine = cputype,
                .slices = slices,
                .slice_offset = base,
            },
            .state = .{ .macho = .{
                .is64 = is64,
                .base = base,
                .image = image,
                .ncmds = ncmds,
                .cursor = hdr,
                .cmds_end = hdr + sizeofcmds,
            } },
        };
    }

    fn nextMacho(self: *SectionIterator, s: *MachoState) ParseError!?SectionInfo {
        const img = s.image;
        const e = self.header.endian;
        while (true) {
            if (s.sect_left > 0) {
                s.sect_left -= 1;
                const h = s.sect_cursor;
                s.sect_cursor += if (s.is64) 80 else 68;
                const sectname = fixedName(img[@intCast(h)..][0..16]);
                const segname = fixedName(img[@intCast(h + 16)..][0..16]);
                var addr: u64 = undefined;
                var size: u64 = undefined;
                var off: u64 = undefined;
                var flags: u32 = undefined;
                if (s.is64) {
                    addr = try rd(u64, img, h + 32, e);
                    size = try rd(u64, img, h + 40, e);
                    off = try rd(u32, img, h + 48, e);
                    flags = try rd(u32, img, h + 64, e);
                } else {
                    addr = try rd(u32, img, h + 32, e);
                    size = try rd(u32, img, h + 36, e);
                    off = try rd(u32, img, h + 40, e);
                    flags = try rd(u32, img, h + 56, e);
                }
                const kind = flags & 0xff;
                const nobits = kind == 0x1 or kind == 0xc or kind == 0x12; // zerofill variants
                const c = clampRange(img.len, off, if (nobits) 0 else size);
                return .{
                    .name = sectname,
                    .segment = if (segname.len > 0) segname else s.seg_name,
                    .offset = s.base + c.offset,
                    .size = c.size,
                    .entropy = 0,
                    .is_packed = false,
                    .vaddr = addr,
                    .mem_size = size,
                    .flags = .{
                        .executable = flags & 0x80000000 != 0 or flags & 0x400 != 0,
                        .writable = s.seg_prot & 2 != 0,
                        .nobits = nobits,
                        .truncated = c.truncated,
                    },
                };
            }
            if (s.cmd_index >= s.ncmds) return null;
            s.cmd_index += 1;
            if (s.cmds_end - s.cursor < 8) return error.Malformed;
            const cmd = try rd(u32, img, s.cursor, e);
            const cmdsize = try rd(u32, img, s.cursor + 4, e);
            if (cmdsize < 8 or cmdsize > s.cmds_end - s.cursor) return error.Malformed;
            const c0 = s.cursor;
            s.cursor += cmdsize;
            const want: u32 = if (s.is64) 0x19 else 0x1; // LC_SEGMENT_64 / LC_SEGMENT
            if (cmd != want) continue;
            const seg_hdr: u64 = if (s.is64) 72 else 56;
            const sect_size: u64 = if (s.is64) 80 else 68;
            if (cmdsize < seg_hdr) return error.Malformed;
            const segname = fixedName(img[@intCast(c0 + 8)..][0..16]);
            var vmaddr: u64 = undefined;
            var vmsize: u64 = undefined;
            var fileoff: u64 = undefined;
            var filesize: u64 = undefined;
            var initprot: u32 = undefined;
            var nsects: u32 = undefined;
            if (s.is64) {
                vmaddr = try rd(u64, img, c0 + 24, e);
                vmsize = try rd(u64, img, c0 + 32, e);
                fileoff = try rd(u64, img, c0 + 40, e);
                filesize = try rd(u64, img, c0 + 48, e);
                initprot = try rd(u32, img, c0 + 60, e);
                nsects = try rd(u32, img, c0 + 64, e);
            } else {
                vmaddr = try rd(u32, img, c0 + 24, e);
                vmsize = try rd(u32, img, c0 + 28, e);
                fileoff = try rd(u32, img, c0 + 32, e);
                filesize = try rd(u32, img, c0 + 36, e);
                initprot = try rd(u32, img, c0 + 44, e);
                nsects = try rd(u32, img, c0 + 48, e);
            }
            if (@as(u64, nsects) * sect_size > cmdsize - seg_hdr) return error.Malformed;
            s.seg_name = segname;
            s.seg_prot = initprot;
            if (nsects > 0) {
                s.sect_left = nsects;
                s.sect_cursor = c0 + seg_hdr;
                continue;
            }
            // A segment without sections (for example __LINKEDIT) is reported as a whole.
            const c = clampRange(img.len, fileoff, filesize);
            return .{
                .name = segname,
                .segment = segname,
                .offset = s.base + c.offset,
                .size = c.size,
                .entropy = 0,
                .is_packed = false,
                .vaddr = vmaddr,
                .mem_size = vmsize,
                .flags = .{
                    .executable = initprot & 4 != 0,
                    .writable = initprot & 2 != 0,
                    .nobits = filesize == 0,
                    .truncated = c.truncated,
                    .from_segment = true,
                },
            };
        }
    }
};

pub const Packer = enum(u32) {
    none = 0,
    upx = 1,
    aspack = 2,
    mpress = 3,
    petite = 4,
    themida = 5,
    vmprotect = 6,
    enigma = 7,
    nspack = 8,
    /// No known packer signature, but an executable section is high entropy.
    high_entropy_code = 9,

    pub fn label(self: Packer) []const u8 {
        return @tagName(self);
    }
};

const packer_names = [_]struct { prefix: []const u8, packer: Packer }{
    .{ .prefix = "UPX", .packer = .upx },
    .{ .prefix = ".aspack", .packer = .aspack },
    .{ .prefix = ".MPRESS", .packer = .mpress },
    .{ .prefix = ".petite", .packer = .petite },
    .{ .prefix = ".themida", .packer = .themida },
    .{ .prefix = ".winlice", .packer = .themida },
    .{ .prefix = ".vmp", .packer = .vmprotect },
    .{ .prefix = ".enigma", .packer = .enigma },
    .{ .prefix = ".nsp", .packer = .nspack },
};

/// Matches a section or segment name against known packer section names.
pub fn packerForName(name: []const u8) Packer {
    for (packer_names) |p| {
        if (std.mem.startsWith(u8, name, p.prefix)) {
            // ".vmp" must be followed by a digit to avoid unrelated names.
            if (p.packer == .vmprotect and (name.len <= 4 or !std.ascii.isDigit(name[4]))) continue;
            return p.packer;
        }
    }
    return .none;
}

pub const Summary = struct {
    header: Header,
    /// Number of sections found (may exceed the number written to an output buffer).
    total: usize = 0,
    written: usize = 0,
    packer: Packer = .none,
    /// Total file bytes covered by section entries (overlaps counted twice).
    analyzed_bytes: u64 = 0,
    budget_exhausted: bool = false,
};

/// Wraps `SectionIterator`, computes per-section entropy, packed flags and the
/// packer verdict. Entropy work is capped at 32 passes over the input (plus a
/// 16 MiB allowance) so a table of thousands of sections that all span the whole
/// file cannot make analysis quadratic; entries past the budget are flagged
/// `entropy_skipped`.
pub const Analyzer = struct {
    it: SectionIterator,
    summary: Summary,
    budget: u64,
    named_packer: Packer = .none,
    packed_code: bool = false,

    pub fn init(data: []const u8, slice_index: u32) ParseError!Analyzer {
        const it = try SectionIterator.initSlice(data, slice_index);
        return .{
            .it = it,
            .summary = .{ .header = it.header },
            .budget = @as(u64, data.len) *| 32 +| (16 << 20),
        };
    }

    pub fn next(self: *Analyzer) ParseError!?SectionInfo {
        var s = (try self.it.next()) orelse return null;
        self.summary.total += 1;
        if (self.named_packer == .none) {
            self.named_packer = packerForName(s.name);
            if (self.named_packer == .none and s.segment.len > 0) self.named_packer = packerForName(s.segment);
        }
        if (s.size > 0) {
            if (s.size > self.budget) {
                s.flags.entropy_skipped = true;
                self.summary.budget_exhausted = true;
            } else {
                self.budget -= s.size;
                self.summary.analyzed_bytes += s.size;
                const o: usize = @intCast(s.offset);
                s.entropy = entropy.calculateEntropy(self.it.data[o..][0..@intCast(s.size)]);
                s.is_packed = s.entropy >= entropy.packed_threshold and s.size >= entropy.min_packed_size;
                s.flags.is_packed = s.is_packed;
                if (s.is_packed and s.flags.executable) self.packed_code = true;
            }
        }
        return s;
    }

    pub fn finish(self: *Analyzer) Summary {
        var p = self.named_packer;
        if (p == .none and self.it.header.format == .elf and self.it.state == .elf and self.it.state.elf.use_segments) {
            // UPX-packed ELF files drop the section table and keep the "UPX!"
            // l_info magic in the first page.
            const head = self.it.data[0..@min(self.it.data.len, 4096)];
            if (std.mem.indexOf(u8, head, "UPX!") != null) p = .upx;
        }
        if (p == .none and self.packed_code) p = .high_entropy_code;
        self.summary.packer = p;
        return self.summary;
    }
};

/// Parses and analyzes the section table, writing up to `out.len` sections.
pub fn analyze(data: []const u8, slice_index: u32, out: []SectionInfo) ParseError!Summary {
    var a = try Analyzer.init(data, slice_index);
    while (try a.next()) |s| {
        if (a.summary.written < out.len) {
            out[a.summary.written] = s;
            a.summary.written += 1;
        }
    }
    return a.finish();
}

pub const Owned = struct {
    summary: Summary,
    sections: []SectionInfo,

    pub fn deinit(self: Owned, gpa: std.mem.Allocator) void {
        gpa.free(self.sections);
    }
};

/// Like `analyze`, but collects every section into an allocated slice. Section
/// names point into `data`.
pub fn analyzeAlloc(gpa: std.mem.Allocator, data: []const u8, slice_index: u32) (ParseError || std.mem.Allocator.Error)!Owned {
    var a = try Analyzer.init(data, slice_index);
    var list: std.ArrayList(SectionInfo) = .empty;
    errdefer list.deinit(gpa);
    while (try a.next()) |s| try list.append(gpa, s);
    var summary = a.finish();
    summary.written = list.items.len;
    return .{ .summary = summary, .sections = try list.toOwnedSlice(gpa) };
}

// ---------------------------------------------------------------------------
// Test fixtures: minimal but structurally valid images built in memory.

const testing = std.testing;

fn put(comptime T: type, buf: []u8, off: usize, v: T, endian: Endian) void {
    std.mem.writeInt(T, buf[off..][0..@sizeOf(T)], v, endian);
}

/// ELF with sections: NULL, .text (random, exec), .data (zeros, writable),
/// .bss (NOBITS), .shstrtab.
fn buildElf(buf: []u8, is64: bool, endian: Endian) usize {
    @memset(buf, 0);
    const strtab = "\x00.text\x00.data\x00.bss\x00.shstrtab\x00";
    const text_off: usize = 0x100;
    const text_len: usize = 0x400;
    const data_off = text_off + text_len;
    const data_len: usize = 0x100;
    const str_off = data_off + data_len;
    const sh_off = std.mem.alignForward(usize, str_off + strtab.len, 8);
    const shent: usize = if (is64) 64 else 40;
    @memcpy(buf[0..4], "\x7FELF");
    buf[4] = if (is64) 2 else 1;
    buf[5] = if (endian == .little) 1 else 2;
    buf[6] = 1;
    put(u16, buf, 0x12, 62, endian);
    if (is64) {
        put(u64, buf, 0x28, sh_off, endian);
        put(u16, buf, 0x3A, @intCast(shent), endian);
        put(u16, buf, 0x3C, 5, endian);
        put(u16, buf, 0x3E, 4, endian);
    } else {
        put(u32, buf, 0x20, @intCast(sh_off), endian);
        put(u16, buf, 0x2E, @intCast(shent), endian);
        put(u16, buf, 0x30, 5, endian);
        put(u16, buf, 0x32, 4, endian);
    }
    var prng = std.Random.DefaultPrng.init(9);
    prng.random().bytes(buf[text_off..][0..text_len]);
    @memcpy(buf[str_off..][0..strtab.len], strtab);
    const Sh = struct { name: u32, ty: u32, flags: u64, addr: u64, off: u64, size: u64 };
    const shs = [_]Sh{
        .{ .name = 0, .ty = 0, .flags = 0, .addr = 0, .off = 0, .size = 0 },
        .{ .name = 1, .ty = 1, .flags = 0x6, .addr = 0x401000, .off = text_off, .size = text_len },
        .{ .name = 7, .ty = 1, .flags = 0x3, .addr = 0x402000, .off = data_off, .size = data_len },
        .{ .name = 13, .ty = 8, .flags = 0x3, .addr = 0x403000, .off = str_off, .size = 0x2000 },
        .{ .name = 18, .ty = 3, .flags = 0, .addr = 0, .off = str_off, .size = strtab.len },
    };
    for (shs, 0..) |sh, i| {
        const h = sh_off + i * shent;
        put(u32, buf, h, sh.name, endian);
        put(u32, buf, h + 4, sh.ty, endian);
        if (is64) {
            put(u64, buf, h + 8, sh.flags, endian);
            put(u64, buf, h + 16, sh.addr, endian);
            put(u64, buf, h + 24, sh.off, endian);
            put(u64, buf, h + 32, sh.size, endian);
        } else {
            put(u32, buf, h + 8, @intCast(sh.flags), endian);
            put(u32, buf, h + 12, @intCast(sh.addr), endian);
            put(u32, buf, h + 16, @intCast(sh.off), endian);
            put(u32, buf, h + 20, @intCast(sh.size), endian);
        }
    }
    return sh_off + shs.len * shent;
}

/// PE32+ with .text (random), .rdata, UPX1 and a "/4" long name resolved
/// through the COFF string table.
fn buildPe(buf: []u8) usize {
    @memset(buf, 0);
    buf[0] = 'M';
    buf[1] = 'Z';
    const lfanew: usize = 0x80;
    put(u32, buf, 0x3C, lfanew, .little);
    @memcpy(buf[lfanew..][0..4], "PE\x00\x00");
    const coff = lfanew + 4;
    const opt_size: usize = 0xF0;
    const table = coff + 20 + opt_size;
    const raw0: usize = 0x400;
    const strtab_off: usize = 0x1000;
    put(u16, buf, coff, 0x8664, .little);
    put(u16, buf, coff + 2, 4, .little);
    put(u32, buf, coff + 8, strtab_off, .little); // PointerToSymbolTable
    put(u32, buf, coff + 12, 0, .little); // NumberOfSymbols
    put(u16, buf, coff + 16, opt_size, .little);
    put(u16, buf, coff + 20, 0x20b, .little);
    put(u64, buf, coff + 20 + 24, 0x140000000, .little);
    // String table: u32 size, then strings; offset 4 is the first string.
    const long = ".debug_spinel";
    put(u32, buf, strtab_off, 4 + long.len + 1, .little);
    @memcpy(buf[strtab_off + 4 ..][0..long.len], long);
    var prng = std.Random.DefaultPrng.init(11);
    prng.random().bytes(buf[raw0..][0..0x200]);
    @memset(buf[raw0 + 0x200 ..][0..0x200], 'A');
    prng.random().bytes(buf[raw0 + 0x400 ..][0..0x200]);
    const S = struct { name: []const u8, vsize: u32, va: u32, raw: u32, ptr: u32, ch: u32 };
    const secs = [_]S{
        .{ .name = ".text", .vsize = 0x200, .va = 0x1000, .raw = 0x200, .ptr = raw0, .ch = 0x60000020 },
        .{ .name = ".rdata", .vsize = 0x200, .va = 0x2000, .raw = 0x200, .ptr = raw0 + 0x200, .ch = 0x40000040 },
        .{ .name = "UPX1", .vsize = 0x200, .va = 0x3000, .raw = 0x200, .ptr = raw0 + 0x400, .ch = 0xE0000040 },
        .{ .name = "/4", .vsize = 0x10, .va = 0x4000, .raw = 0, .ptr = 0, .ch = 0x42000040 },
    };
    for (secs, 0..) |s, i| {
        const h = table + i * 40;
        @memcpy(buf[h..][0..s.name.len], s.name);
        put(u32, buf, h + 8, s.vsize, .little);
        put(u32, buf, h + 12, s.va, .little);
        put(u32, buf, h + 16, s.raw, .little);
        put(u32, buf, h + 20, s.ptr, .little);
        put(u32, buf, h + 36, s.ch, .little);
    }
    return strtab_off + 4 + long.len + 1;
}

/// 64-bit Mach-O: __PAGEZERO, __TEXT with __text and __cstring, __DATA with a
/// zerofill __bss, and a section-less __LINKEDIT.
fn buildMacho(buf: []u8, endian: Endian) usize {
    @memset(buf, 0);
    put(u32, buf, 0, 0xFEEDFACF, endian);
    put(u32, buf, 4, 0x0100000c, endian);
    put(u32, buf, 12, 2, endian);
    var cur: usize = 32;
    const Seg = struct { name: []const u8, fileoff: u64, filesize: u64, prot: u32, sects: []const struct { name: []const u8, off: u32, size: u64, flags: u32 } };
    const segs = [_]Seg{
        .{ .name = "__PAGEZERO", .fileoff = 0, .filesize = 0, .prot = 0, .sects = &.{} },
        .{ .name = "__TEXT", .fileoff = 0, .filesize = 0x1000, .prot = 5, .sects = &.{
            .{ .name = "__text", .off = 0x800, .size = 0x400, .flags = 0x80000400 },
            .{ .name = "__cstring", .off = 0xC00, .size = 0x100, .flags = 0x2 },
        } },
        .{ .name = "__DATA", .fileoff = 0x1000, .filesize = 0x100, .prot = 3, .sects = &.{
            .{ .name = "__bss", .off = 0, .size = 0x800, .flags = 0x1 },
        } },
        .{ .name = "__LINKEDIT", .fileoff = 0x1100, .filesize = 0x80, .prot = 1, .sects = &.{} },
    };
    for (segs) |seg| {
        const size = 72 + seg.sects.len * 80;
        put(u32, buf, cur, 0x19, endian);
        put(u32, buf, cur + 4, @intCast(size), endian);
        @memcpy(buf[cur + 8 ..][0..seg.name.len], seg.name);
        put(u64, buf, cur + 24, 0x100000000 + seg.fileoff, endian);
        put(u64, buf, cur + 32, @max(seg.filesize, 0x1000), endian);
        put(u64, buf, cur + 40, seg.fileoff, endian);
        put(u64, buf, cur + 48, seg.filesize, endian);
        put(u32, buf, cur + 56, seg.prot, endian);
        put(u32, buf, cur + 60, seg.prot, endian);
        put(u32, buf, cur + 64, @intCast(seg.sects.len), endian);
        for (seg.sects, 0..) |sect, i| {
            const h = cur + 72 + i * 80;
            @memcpy(buf[h..][0..sect.name.len], sect.name);
            @memcpy(buf[h + 16 ..][0..seg.name.len], seg.name);
            put(u64, buf, h + 32, 0x100000000 + @as(u64, sect.off), endian);
            put(u64, buf, h + 40, sect.size, endian);
            put(u32, buf, h + 48, sect.off, endian);
            put(u32, buf, h + 64, sect.flags, endian);
        }
        cur += size;
    }
    put(u32, buf, 16, segs.len, endian);
    put(u32, buf, 20, @intCast(cur - 32), endian);
    var prng = std.Random.DefaultPrng.init(13);
    prng.random().bytes(buf[0x800..0xC00]);
    @memcpy(buf[0xC00..][0..12], "hello world\x00");
    return 0x1180;
}

test "ELF section tables parse in every class and byte order" {
    var buf: [4096]u8 = undefined;
    for ([_]bool{ true, false }) |is64| {
        for ([_]Endian{ .little, .big }) |endian| {
            const len = buildElf(&buf, is64, endian);
            var out: [8]SectionInfo = undefined;
            const sum = try analyze(buf[0..len], 0, &out);
            try testing.expectEqual(BinaryFormat.elf, sum.header.format);
            try testing.expectEqual(@as(u8, if (is64) 64 else 32), sum.header.bits);
            try testing.expectEqualStrings("x86_64", sum.header.archName());
            try testing.expectEqual(@as(usize, 4), sum.total);
            try testing.expectEqualStrings(".text", out[0].name);
            try testing.expectEqual(@as(u64, 0x100), out[0].offset);
            try testing.expectEqual(@as(u64, 0x400), out[0].size);
            try testing.expectEqual(@as(u64, 0x401000), out[0].vaddr);
            try testing.expect(out[0].flags.executable and !out[0].flags.writable);
            try testing.expect(out[0].entropy > 7.0 and out[0].is_packed);
            try testing.expectEqualStrings(".data", out[1].name);
            try testing.expect(out[1].flags.writable and out[1].entropy == 0.0 and !out[1].is_packed);
            try testing.expectEqualStrings(".bss", out[2].name);
            try testing.expect(out[2].flags.nobits and out[2].size == 0 and out[2].mem_size == 0x2000);
            try testing.expectEqualStrings(".shstrtab", out[3].name);
            // High-entropy executable code without a named packer.
            try testing.expectEqual(Packer.high_entropy_code, sum.packer);
        }
    }
}

test "ELF without section headers falls back to PT_LOAD segments and spots UPX" {
    var buf: [1024]u8 = @splat(0);
    @memcpy(buf[0..4], "\x7FELF");
    buf[4] = 2;
    buf[5] = 1;
    put(u64, &buf, 0x20, 64, .little); // e_phoff
    put(u16, &buf, 0x36, 56, .little);
    put(u16, &buf, 0x38, 2, .little);
    // PT_LOAD r-x covering the whole file, PT_NOTE ignored.
    put(u32, &buf, 64, 1, .little);
    put(u32, &buf, 68, 5, .little);
    put(u64, &buf, 72, 0, .little);
    put(u64, &buf, 80, 0x400000, .little);
    put(u64, &buf, 96, 2048, .little); // filesz past EOF -> truncated
    put(u64, &buf, 104, 4096, .little);
    put(u32, &buf, 120, 4, .little);
    @memcpy(buf[0x200..0x204], "UPX!");
    var out: [4]SectionInfo = undefined;
    const sum = try analyze(&buf, 0, &out);
    try testing.expectEqual(@as(usize, 1), sum.total);
    try testing.expectEqualStrings("LOAD", out[0].name);
    try testing.expect(out[0].flags.from_segment and out[0].flags.executable and out[0].flags.truncated);
    try testing.expectEqual(@as(u64, 1024), out[0].size);
    try testing.expectEqual(Packer.upx, sum.packer);
}

test "ELF extended section numbering reads the count from section 0" {
    var buf: [4096]u8 = undefined;
    const len = buildElf(&buf, true, .little);
    const shoff: usize = @intCast(std.mem.readInt(u64, buf[0x28..0x30], .little));
    put(u16, &buf, 0x3C, 0, .little); // e_shnum = 0
    put(u16, &buf, 0x3E, 0xFFFF, .little); // e_shstrndx = SHN_XINDEX
    put(u64, &buf, shoff + 32, 5, .little); // sh_size of section 0
    put(u32, &buf, shoff + 40, 4, .little); // sh_link of section 0
    var out: [8]SectionInfo = undefined;
    const sum = try analyze(buf[0..len], 0, &out);
    try testing.expectEqual(@as(usize, 4), sum.total);
    try testing.expectEqualStrings(".shstrtab", out[3].name);
}

test "PE sections, long names, image base and UPX names" {
    var buf: [8192]u8 = undefined;
    const len = buildPe(&buf);
    var out: [8]SectionInfo = undefined;
    const sum = try analyze(buf[0..len], 0, &out);
    try testing.expectEqual(BinaryFormat.pe, sum.header.format);
    try testing.expectEqual(@as(u8, 64), sum.header.bits);
    try testing.expectEqualStrings("x86_64", sum.header.archName());
    try testing.expectEqual(@as(usize, 4), sum.total);
    try testing.expectEqualStrings(".text", out[0].name);
    try testing.expectEqual(@as(u64, 0x140001000), out[0].vaddr);
    try testing.expect(out[0].flags.executable);
    try testing.expectEqualStrings(".rdata", out[1].name);
    try testing.expectEqual(@as(f64, 0.0), out[1].entropy);
    try testing.expectEqualStrings("UPX1", out[2].name);
    try testing.expect(out[2].flags.writable and out[2].flags.executable);
    try testing.expectEqualStrings(".debug_spinel", out[3].name);
    try testing.expect(out[3].flags.nobits);
    try testing.expectEqual(Packer.upx, sum.packer);
}

test "DOS MZ without a PE header has no sections" {
    var buf: [128]u8 = @splat(0);
    buf[0] = 'M';
    buf[1] = 'Z';
    put(u32, &buf, 0x3C, 0x1000, .little);
    var out: [1]SectionInfo = undefined;
    const sum = try analyze(&buf, 0, &out);
    try testing.expectEqual(@as(u8, 16), sum.header.bits);
    try testing.expectEqual(@as(usize, 0), sum.total);
}

test "Mach-O 64-bit sections, zerofill and section-less segments in both byte orders" {
    var buf: [0x1200]u8 = undefined;
    for ([_]Endian{ .little, .big }) |endian| {
        const len = buildMacho(&buf, endian);
        var out: [8]SectionInfo = undefined;
        const sum = try analyze(buf[0..len], 0, &out);
        try testing.expectEqual(BinaryFormat.macho, sum.header.format);
        try testing.expectEqualStrings("aarch64", sum.header.archName());
        try testing.expectEqual(@as(usize, 5), sum.total);
        try testing.expectEqualStrings("__PAGEZERO", out[0].name);
        try testing.expect(out[0].flags.nobits and out[0].flags.from_segment);
        try testing.expectEqualStrings("__text", out[1].name);
        try testing.expectEqualStrings("__TEXT", out[1].segment);
        try testing.expectEqual(@as(u64, 0x800), out[1].offset);
        try testing.expect(out[1].flags.executable and !out[1].flags.writable and out[1].is_packed);
        try testing.expectEqualStrings("__cstring", out[2].name);
        try testing.expect(!out[2].flags.executable);
        try testing.expectEqualStrings("__bss", out[3].name);
        try testing.expect(out[3].flags.nobits and out[3].flags.writable and out[3].mem_size == 0x800);
        try testing.expectEqualStrings("__LINKEDIT", out[4].name);
        try testing.expectEqual(@as(u64, 0x80), out[4].size);
    }
}

test "universal Mach-O selects slices and offsets section positions" {
    var buf: [0x4000]u8 = @splat(0);
    var thin: [0x1200]u8 = undefined;
    const len = buildMacho(&thin, .little);
    put(u32, &buf, 0, 0xCAFEBABE, .big);
    put(u32, &buf, 4, 2, .big);
    for ([_]u32{ 0x1000, 0x2800 }, 0..) |off, i| {
        const a = 8 + i * 20;
        put(u32, &buf, a, 0x0100000c, .big);
        put(u32, &buf, a + 8, off, .big);
        put(u32, &buf, a + 12, @intCast(len), .big);
        @memcpy(buf[off..][0..len], thin[0..len]);
    }
    var out: [8]SectionInfo = undefined;
    const s0 = try analyze(&buf, 0, &out);
    try testing.expectEqual(@as(u32, 2), s0.header.slices);
    try testing.expectEqual(@as(u64, 0x1000 + 0x800), out[1].offset);
    const s1 = try analyze(&buf, 1, &out);
    try testing.expectEqual(@as(u64, 0x2800), s1.header.slice_offset);
    try testing.expectEqual(@as(u64, 0x2800 + 0x800), out[1].offset);
    try testing.expectError(error.NoSuchSlice, analyze(&buf, 2, &out));
    // Slice pointing past the end of the file.
    put(u32, &buf, 8 + 12, 0x10000, .big);
    try testing.expectError(error.Truncated, analyze(&buf, 0, &out));
}

test "malformed Mach-O load commands are rejected, not looped on" {
    var buf: [0x1200]u8 = undefined;
    const len = buildMacho(&buf, .little);
    put(u32, &buf, 32 + 4, 0, .little); // cmdsize = 0
    var out: [8]SectionInfo = undefined;
    try testing.expectError(error.Malformed, analyze(buf[0..len], 0, &out));
    _ = buildMacho(&buf, .little);
    put(u32, &buf, 32 + 72 + 64, 1000, .little); // nsects exceeds cmdsize
    try testing.expectError(error.Malformed, analyze(buf[0..len], 0, &out));
}

test "raw input has no sections" {
    var out: [1]SectionInfo = undefined;
    const sum = try analyze("plain text", 0, &out);
    try testing.expectEqual(BinaryFormat.raw, sum.header.format);
    try testing.expectEqual(@as(usize, 0), sum.total);
    try testing.expectEqual(Packer.none, sum.packer);
}

test "output buffer smaller than the table still counts every section" {
    var buf: [4096]u8 = undefined;
    const len = buildElf(&buf, true, .little);
    var out: [2]SectionInfo = undefined;
    const sum = try analyze(buf[0..len], 0, &out);
    try testing.expectEqual(@as(usize, 4), sum.total);
    try testing.expectEqual(@as(usize, 2), sum.written);
    const counted = try analyze(buf[0..len], 0, &.{});
    try testing.expectEqual(@as(usize, 4), counted.total);
}

test "overlapping hostile section tables stay within the work budget" {
    // 2000 PE sections that each claim the whole 128 KiB file.
    const n_sections = 2000;
    const size = 128 * 1024;
    const buf = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(buf);
    @memset(buf, 0);
    buf[0] = 'M';
    buf[1] = 'Z';
    put(u32, buf, 0x3C, 0x40, .little);
    @memcpy(buf[0x40..0x44], "PE\x00\x00");
    put(u16, buf, 0x46, n_sections, .little);
    for (0..n_sections) |i| {
        const h = 0x40 + 24 + i * 40;
        @memcpy(buf[h..][0..4], ".big");
        put(u32, buf, h + 16, size, .little);
        put(u32, buf, h + 20, 1, .little);
    }
    var a = try Analyzer.init(buf, 0);
    var skipped: usize = 0;
    while (try a.next()) |s| {
        if (s.flags.entropy_skipped) skipped += 1;
    }
    const sum = a.finish();
    try testing.expectEqual(@as(usize, n_sections), sum.total);
    try testing.expect(sum.budget_exhausted and skipped > 0);
    try testing.expect(sum.analyzed_bytes <= @as(u64, size) * 32 + (16 << 20));
}

test "fuzz: mutated and truncated headers never crash or read out of bounds" {
    var prng = std.Random.DefaultPrng.init(0xF022);
    const r = prng.random();
    var seeds: [4][0x2000]u8 = undefined;
    var lens: [4]usize = undefined;
    lens[0] = buildElf(&seeds[0], true, .little);
    lens[1] = buildElf(&seeds[1], false, .big);
    lens[2] = buildPe(&seeds[2]);
    lens[3] = buildMacho(&seeds[3], .little);
    var work: [0x2000]u8 = undefined;
    var out: [16]SectionInfo = undefined;
    var iter: usize = 0;
    var parsed: usize = 0;
    while (iter < 20000) : (iter += 1) {
        const k = iter % seeds.len;
        const len = if (r.uintLessThan(u8, 4) == 0) r.uintLessThan(usize, lens[k] + 1) else lens[k];
        @memcpy(work[0..len], seeds[k][0..len]);
        const flips = 1 + r.uintLessThan(usize, 8);
        for (0..flips) |_| {
            if (len == 0) break;
            // Bias mutations toward the headers where the interesting fields live.
            const pos = if (r.boolean()) r.uintLessThan(usize, @min(len, 0x400)) else r.uintLessThan(usize, len);
            work[pos] = switch (r.uintLessThan(u8, 4)) {
                0 => 0,
                1 => 0xFF,
                else => r.int(u8),
            };
        }
        if (analyze(work[0..len], 0, &out)) |sum| {
            parsed += 1;
            for (out[0..sum.written]) |s| {
                try testing.expect(s.offset +| s.size <= len or s.size == 0);
                try testing.expect(s.entropy >= 0.0 and s.entropy <= 8.0);
            }
        } else |_| {}
    }
    try testing.expect(parsed > 1000);
}

test "packer names" {
    try testing.expectEqual(Packer.upx, packerForName("UPX0"));
    try testing.expectEqual(Packer.vmprotect, packerForName(".vmp0"));
    try testing.expectEqual(Packer.none, packerForName(".vmpx"));
    try testing.expectEqual(Packer.mpress, packerForName(".MPRESS1"));
    try testing.expectEqual(Packer.none, packerForName(".text"));
}
