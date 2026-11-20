# Spinel

High-Entropy Binary Section Map & Structural Diff Engine

A headless, fast binary section parser for ELF, Mach-O, and PE targets that calculates sliding-window Shannon entropy, detects packing/obfuscation signatures, and renders terminal Braille density maps.

## Architecture

- Shannon Entropy Engine: Calculates exact byte frequency tables and Shannon entropy over arbitrary windows, differentiating between sparse data, machine code, and encrypted/virtualized bytecode blocks. Sliding windows update one histogram incrementally, so a scan costs O(len + windows x 256) instead of O(windows x window).
- Format Identification: Inspects binary headers for ELF (magic \x7FELF), Mach-O (32-bit and 64-bit, thin or universal fat), and PE/COFF (MZ signature).
- Section Tables: Bounds-checked parsers for ELF (32/64-bit, little and big endian, extended section numbering, PT_LOAD fallback when there is no section table), PE32 and PE32+ (long `/N` section names, image base), and Mach-O (32/64-bit, both byte orders, universal slices, zerofill sections).
- Structural Diff: Section-level and block-level comparison of two binaries.
- Freestanding WebAssembly: Compiles to a freestanding WASM artifact of about 16 KB (`spinel.wasm`) with no imports, for in-browser drag-and-drop entropy mapping.
- Visual Terminal Sparkline: Generates Unicode Braille representations directly to stdout for terminal inspection workflows.

## Exported WebAssembly API

```c
double spinel_calc_entropy(const uint8_t* ptr, size_t len);
uint32_t spinel_detect_format(const uint8_t* ptr, size_t len);
size_t spinel_sliding_window(
    const uint8_t* in_ptr,
    size_t in_len,
    size_t win_size,
    size_t step,
    double* out_ptr,
    size_t out_cap
);
```

`spinel_detect_format` returns 0 raw, 1 ELF, 2 Mach-O, 3 PE.

## Building and Testing

```bash
# Run unit tests
zig build test

# Compile native binary and freestanding WASM
zig build -Doptimize=ReleaseFast

# Build only the WASM module (zig-out/bin/spinel.wasm)
zig build wasm
```

## 0.2.0: Sections, Structural Diff and Region Detection

### Command line

```bash
zig build -Doptimize=ReleaseFast

# Section table with per-section entropy, flags and packer verdict
./zig-out/bin/spinel sections zig-out/bin/spinel
./zig-out/bin/spinel sections /bin/ls --slice 1 --json   # second slice of a universal binary

# Entropy profile, Braille map and high-entropy regions
./zig-out/bin/spinel scan zig-out/bin/spinel.wasm --window 256 --step 64 --width 48

# Structural diff of two builds
zig build -Doptimize=ReleaseSmall --prefix zig-out/small
./zig-out/bin/spinel diff zig-out/bin/spinel zig-out/small/bin/spinel
./zig-out/bin/spinel diff zig-out/bin/spinel zig-out/small/bin/spinel --json

./zig-out/bin/spinel version
```

Every subcommand accepts `--json`. Exit status is 0 on success, 2 on a usage error, and 1 when a file cannot be read or when `sections` finds a truncated or malformed header (`diff` then reports the sections as unavailable and still compares blocks). Running `spinel` with no arguments still runs the built-in sample analysis.

`sections` prints one row per section: offset and size of the bytes in the file, virtual address, entropy and flags (`x` executable, `w` writable, `P` packed, `n` no file data such as `.bss` or zerofill, `t` range clamped at end of file, `s` synthesized from a segment). Mach-O segments without sections (`__PAGEZERO`, `__LINKEDIT`) and ELF `PT_LOAD` segments of files that have no section header table are listed as segment entries. For PE, the bytes measured are `min(SizeOfRawData, VirtualSize)`, which leaves out file-alignment padding. A section is flagged packed when its entropy is at least 7.2 bits/byte over at least 256 bytes.

The packer verdict is one of `none`, `upx`, `aspack`, `mpress`, `petite`, `themida`, `vmprotect`, `enigma`, `nspack` (matched on section or segment names such as `UPX0`, `.aspack`, `.MPRESS1`, `.vmp0`), or `high_entropy_code` when no name matches but an executable section is packed. An ELF without a section header table whose first 4 KiB contain the `UPX!` marker is reported as `upx`.

`scan` uses a 1024-byte window (or the file size, if smaller) and a step of a quarter of the window unless `--window` and `--step` are given. The map is downsampled to `--width` columns (default 64), keeping the highest entropy in each column. Regions are the union of windows whose entropy is at least `--threshold` (default 7.2); overlapping or touching windows merge.

`diff` matches sections by segment, name and occurrence and reports each as unchanged, modified, added or removed, with the size and entropy before and after, the number of differing bytes, and the distance between the two byte distributions (total variation distance: 0 for the same byte proportions, 1 for no byte values in common). `--all` also lists unchanged sections. Both files are also cut into `--block` sized blocks (default 4096): a block is identical in place, moved (its exact content is a block of the old file at another offset, confirmed byte for byte after a hash lookup), modified, added or removed. Similarity is the share of identical plus moved blocks.

### Hardening

All header and table reads are bounds checked; truncated or inconsistent headers return an error instead of reading past the input, a Mach-O load command of size zero is rejected rather than looped on, and section ranges past the end of the file are clamped and flagged. Entropy work for one file is capped at 32 passes over the input plus 16 MiB, so a table of thousands of sections that each claim the whole file cannot make analysis quadratic; sections past the cap report `"entropy": null`. Section names are escaped in JSON and replaced with `?` for non-printable bytes in text output, so a hostile name cannot inject terminal escape sequences. A zero window or zero step in `spinel_sliding_window` now returns 0 instead of filling the output with repeated values.

### New WebAssembly exports

All 0.1.0 exports keep their names and signatures. In the WebAssembly build, every pointer and length pair is now checked against the current memory size, so an out-of-range call returns 0 (or a negative code) instead of trapping, and output pointers may be unaligned.

```c
uint32_t spinel_version(void);                         // 0x000200
size_t   spinel_window_count(size_t len, size_t win, size_t step);
size_t   spinel_buffer(size_t len);                     // scratch area, grows memory, 0 on failure
int32_t  spinel_inspect(const uint8_t* p, size_t len, uint32_t slice, InspectRecord* out);
int32_t  spinel_sections(const uint8_t* p, size_t len, uint32_t slice,
                         SectionRecord* out, size_t out_cap);
size_t   spinel_high_entropy_regions(const uint8_t* p, size_t len, size_t win, size_t step,
                                     double threshold, double* out, size_t out_cap);
size_t   spinel_block_diff(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len,
                           size_t block, uint8_t* out, size_t out_cap);
double   spinel_histogram_distance(const uint8_t* a, size_t a_len,
                                   const uint8_t* b, size_t b_len);
```

- `spinel_buffer(len)` returns a 16-byte aligned address above the module's stack and static data with at least `len` bytes available. It returns the same address on every call, so request the total size needed for inputs and outputs at once.
- `spinel_inspect` writes a 48-byte `InspectRecord` (u32 fields: format, bits, machine, endian (0 little, 1 big), slices, packer, section_count, flags (bit 0: entropy budget exhausted); then u64 slice_offset and analyzed_bytes) and returns 0, or -1 truncated, -2 malformed, -3 no such slice, -4 pointer range outside memory.
- `spinel_sections` writes up to `out_cap` 64-byte `SectionRecord`s (u64 offset, size, vaddr, mem_size; f64 entropy; u32 name_ptr, name_len, segment_ptr, segment_len, flags, reserved) and returns the total number of sections or a negative code. Name pointers are absolute memory addresses. Flag bits: 0 executable, 1 writable, 2 packed, 3 no file data, 4 truncated, 5 from segment, 6 entropy skipped.
- `spinel_high_entropy_regions` writes four f64 values per region (start, end, mean, peak) and returns the total number of regions found, which may exceed `out_cap`.
- `spinel_block_diff` writes one status byte per block (0 identical, 1 modified, 2 removed, 3 added) and returns the total number of blocks.
- `spinel_histogram_distance` returns the byte distribution distance in [0, 1], or -1 for an out-of-range pointer.

Packer codes: 0 none, 1 upx, 2 aspack, 3 mpress, 4 petite, 5 themida, 6 vmprotect, 7 enigma, 8 nspack, 9 high_entropy_code.

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
