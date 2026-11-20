# Spinel (고엔트로피 바이너리 섹션 맵 & 구조적 Diff 엔진)

[English](README.md) · [라이선스](LICENSE) · [라이브 워크벤치](https://aetherx86.github.io/spinel/)

Spinel은 ELF, Mach-O, PE/COFF 바이너리를 초고속으로 파싱하여 슬라이딩 윈도우 섀넌 엔트로피(Shannon Entropy)를 계산하고, 패킹 및 난독화 서명을 감지하며, 터미널 유니코드 브라유(Braille) 밀도 맵을 렌더링하는 헤드리스 분석 엔진입니다.

## 아키텍처 개요

- **섀넌 엔트로피 엔진**: 임의의 윈도우 크기에 대해 바이트 빈도 분포와 엔트로피를 정밀 계산하여 일반 데이터, 네이티브 기계어 코드, 암호화/가상화된 패킹 바이트코드 블록을 즉시 식별합니다.
- **다중 포맷 자동 식별**: ELF(매직 바이트 `\x7FELF`), Mach-O(32/64비트 유니버설 팻 및 단일 아키텍처), PE/COFF(`MZ` 시그니처) 헤더를 자동 판별합니다.
- **자립형 WebAssembly 배포**: 약 16 KB 자립형 WASM 아티팩트(`spinel.wasm`)로 컴파일되어 웹 브라우저에서 드래그 앤 드롭으로 즉각 실행됩니다.
- **터미널 스파크라인 시각화**: 유니코드 브라유 문자를 터미널 stdout으로 직접 출력하여 CLI 워크플로에서도 직관적인 엔트로피 맵을 제공합니다.

## WebAssembly C-ABI 인터페이스

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

## 빌드 및 검증

```bash
# 단위 테스트 실행
zig build test

# 네이티브 바이너리와 WebAssembly 모듈 빌드
zig build -Doptimize=ReleaseFast

# WebAssembly 모듈만 빌드 (zig-out/bin/spinel.wasm)
zig build wasm
```

## 0.2.0 변경 사항

- ELF(32/64비트, 리틀/빅 엔디언), PE32/PE32+, Mach-O(32/64비트, 유니버설 슬라이스) 섹션 테이블 파서를 추가했습니다. 섹션별 엔트로피, 실행/쓰기/패킹 플래그와 패커 판정(UPX, ASPack, MPRESS, VMProtect 등)을 제공합니다.
- 구조적 Diff 엔진: 섹션 단위 비교(크기, 엔트로피, 바이트 분포 거리)와 블록 단위 비교(제자리 변경과 이동된 블록 구분)를 제공합니다.
- 고엔트로피 구간 탐지와 증분 히스토그램 기반 슬라이딩 윈도우(기존 결과와 비트 단위로 동일)를 추가했습니다.
- CLI 서브커맨드 `scan`, `sections`, `diff`, `version`과 `--json` 출력을 추가했습니다.

```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/spinel sections zig-out/bin/spinel
./zig-out/bin/spinel scan zig-out/bin/spinel.wasm --window 256 --step 64 --width 48
zig build -Doptimize=ReleaseSmall --prefix zig-out/small
./zig-out/bin/spinel diff zig-out/bin/spinel zig-out/small/bin/spinel --json
```

- 기존 WASM 익스포트 3종의 이름과 시그니처는 그대로 유지되며, `spinel_version`, `spinel_window_count`, `spinel_buffer`, `spinel_inspect`, `spinel_sections`, `spinel_high_entropy_regions`, `spinel_block_diff`, `spinel_histogram_distance`가 추가되었습니다. 모든 익스포트는 포인터 범위를 메모리 크기와 대조하여 트랩 대신 빈 결과 또는 음수 오류 코드를 반환합니다.
- `spinel_detect_format`이 유니버설(fat) Mach-O를 인식합니다(2 반환).

## 라이선스

MIT License. Copyright (c) 2026 Jeong Hoon Kim (Aether Systems & Research Lab).
