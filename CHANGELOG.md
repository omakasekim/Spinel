# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-11-20

### Added
- Section table parsers for ELF (32/64-bit, little and big endian, extended section numbering, PT_LOAD fallback for files without section headers), PE32/PE32+ (long `/N` names through the COFF string table, image base) and Mach-O (32/64-bit, both byte orders, universal slices, zerofill sections, section-less segments), with per-section entropy, executable/writable/packed flags and a packer verdict (UPX, ASPack, MPRESS, Petite, Themida, VMProtect, Enigma, NsPack, or high-entropy executable code).
- Structural diff engine: section matching by segment, name and occurrence with size, entropy, differing-byte and byte-distribution distance per section; block-level comparison that separates in-place changes from relocated blocks (hash lookup confirmed byte for byte).
- High-entropy region detection that merges overlapping qualifying windows into byte ranges with mean and peak entropy.
- CLI subcommands `scan`, `sections`, `diff` and `version`, each with `--json` output. Running `spinel` without arguments still prints the sample analysis.
- WebAssembly exports `spinel_version`, `spinel_window_count`, `spinel_buffer`, `spinel_inspect`, `spinel_sections`, `spinel_high_entropy_regions`, `spinel_block_diff` and `spinel_histogram_distance`, and a `zig build wasm` step.
- Tests: differential test of the incremental sliding window against the reference implementation, property tests for region merging and block diff, parser fixtures for every format and byte order, a 20,000-case header mutation fuzz test, JSON validity tests for every subcommand, and ABI tests for the exports.

### Changed
- Sliding-window entropy updates one histogram incrementally instead of recounting every window; results are bit-identical.
- `spinel_detect_format` now recognizes universal (fat) Mach-O binaries (returns 2), which 0.1.0 reported as raw; Java class files, which share the magic, still return raw.
- In the WebAssembly build, all exports check pointer ranges against memory size and return an empty result instead of trapping; output pointers may be unaligned.
- A zero window or zero step passed to `spinel_sliding_window` returns 0 instead of filling the output with repeated values.
- The WebAssembly module is now about 16 KB.
- CI: fixed the `mlugg/setup-zig` pin and added a CLI smoke test.

## 0.1.0 - 2026-11-08

### Added
- Initial release of Spinel high-entropy binary section map and structural diff engine.
- Shannon entropy calculator with sliding-window analysis and Braille sparkline generation.
- Format detection for ELF, Mach-O, and PE binary headers.
- Freestanding WebAssembly compilation target yielding a 1.3 KB artifact for client-side forensics.
