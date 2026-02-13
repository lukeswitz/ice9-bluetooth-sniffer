# BLE Detection Improvements

## Overview

This document describes improvements made to ice9-bluetooth-sniffer:

1. Optional CRC-24 validation with Wireshark integration
2. Access Address correlator for dramatically improved packet detection
3. OpenCL GPU acceleration for the polyphase channelizer + FFT

## Changes Made

### 1. Optional CRC-24 Validation

**Problem:**
The original implementation did not validate BLE CRC-24 checksums, so
there was no way to distinguish packets with bit errors from clean ones.

**Solution:**
Implemented CRC-24 validation with PCAP flag support for Wireshark:

- CRC-24/BLE algorithm (polynomial x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1)
- Reflected polynomial implementation (0xDA6000) with reflected init
- Init value: 0x555555 for advertising channels, lower 24 bits of AA for data channels
- Optional via `--check-crc` flag (default: OFF for backward compatibility)
- Sets PCAP flags LE_CRC_CHECKED and LE_CRC_VALID for Wireshark

**Live Testing Results (USRP B210, USB 3.0):**
- CRC valid rate depends on channel count and signal strength
- At 48 channels: ~71% valid (best), at 40 channels: ~57% valid
- See section 3 (Channel Count Sensitivity) for details

**Usage:**
```bash
# Without CRC checking (default, backward compatible)
ice9-bluetooth -l -i usrp-B210-xxx -c 2441 -C 40 -w output.pcap

# With CRC checking
ice9-bluetooth -l -i usrp-B210-xxx -c 2441 -C 40 -w output.pcap --check-crc

# With CRC checking and statistics
ice9-bluetooth -l -i usrp-B210-xxx -c 2441 -C 40 -w output.pcap --check-crc --stats
```

**Statistics Output:**
When both `--check-crc` and `--stats` are enabled, periodic output includes:
```
CRC: 404 valid, 164 invalid (71.1% valid)
```

### 2. Access Address Correlator (Addresses Issue #34)

**Problem:**
The original BLE detection relies on a strict preamble check: the first 6
sliced bits must show a perfect alternating pattern before the access address
is even examined. Without symbol timing recovery (the symsync code in fsk.c
is commented out), the bit slicer often samples at the wrong phase, corrupting
the preamble and causing the entire packet to be missed.

Analysis of the example capture data from issue #34 confirmed this: of 38
bursts that were clearly BLE advertising packets, only 1 (3%) was detected
by the original preamble-first method. The remaining 37 failed at the
preamble check despite containing valid BLE data.

**Solution:**
Implemented an Access Address correlator that works on the analog FM-demodulated
signal before bit slicing. This bypasses the preamble check entirely and finds
packets by matching the known BLE advertising access address (0x8E89BED6)
pattern directly in the continuous signal.

The correlator:
- Pre-computes an AA template at startup (+1/-1 values, 2 samples per symbol)
- Slides the template across the entire demod signal using normalized
  cross-correlation
- If the best score exceeds 0.6, tries both sample phases for bit extraction
- Accepts packets with up to 4 bit errors in the AA (hamming distance <= 4)
- Falls back gracefully: the original preamble method runs first, and the
  correlator only activates when preamble detection fails

**Prototype Validation (Issue #34 Data):**

| Method | Detected | Rate |
|--------|----------|------|
| Original (preamble-first) | 1/38 | 3% |
| AA Correlator | 35/38 | 92% |

The 3 undetected bursts had correlation scores below 0.5 (likely non-BLE
or severely corrupted). All 35 detected bursts decoded to valid BLE PDU
types (ADV_NONCONN_IND, SCAN_REQ, ADV_IND).

**Live Capture Results (USRP B210, -C 40, 30 seconds):**

| Version | Packets | Improvement |
|---------|---------|-------------|
| Original | 185 | -- |
| With AA correlator | 512 | +177% (2.8x) |

**Performance:**
- Template pre-computed at startup (negligible cost)
- Correlator is O(n*64) per burst where n = burst length in samples
- Only runs when preamble method fails (zero overhead for already-detected packets)
- Maintains 100% realtime at 40 Msamp/sec on USB 3.0

**Acknowledgment:**
This improvement was made possible by the example capture data posted in
issue #34, which provided the real-world burst samples needed to diagnose
the preamble detection bottleneck and validate the correlator approach.

### 3. OpenCL GPU Acceleration

**Problem:**
The CPU-based polyphase filterbank channelizer (PFBCH2) is the main
throughput bottleneck. At high channel counts, the per-sample dot
products and FFT consume most of the processing budget, limiting
realtime performance.

**Solution:**
Moved both the PFB filterbank and FFT to the GPU, running in a pipeline:

- Custom OpenCL kernel for PFB dot products, followed by VkFFT for the FFT
- Both run on the GPU in the same command queue; data stays in GPU memory
- Double-buffered: one batch processes on GPU while the next fills on CPU
- Pre-roll mechanism preserves window history across batch boundaries
- Auto-detected at build time; no runtime flags needed
- Falls back to FFTW when OpenCL is not available

**Additional SIMD improvements:**
- AVX2 runtime dispatch for the CPU dot product (window.c), with SSE2 fallback
- SSE4.1 vectorized int16-to-float conversion in the CPU channelizer path
- Fixed a bug in the scalar fallback that used the real buffer for both
  real and imaginary accumulation

**Testing Results (USRP B210, USB 3.0):**

*Intel UHD integrated GPU:*

| Channels | Throughput | CRC Valid Rate |
|----------|-----------|----------------|
| 40 | 100% realtime | ~57% |
| 48 | ~98% realtime | ~71% |

*NVIDIA GeForce RTX 3060 Laptop GPU:*

| Channels | Throughput | CRC Valid Rate |
|----------|-----------|----------------|
| 48 | 100% realtime | ~75% |
| 52 | 100% realtime | ~3% |
| 56 | 100% realtime | ~1.5% |
| 60 | 100% realtime | ~82% |

With the RTX 3060, the GPU has significant headroom (AGC reports 300%+
realtime). The channelizer is no longer the bottleneck at any channel
count the USRP B210 supports.

CRC validation rates match the CPU-only path exactly, confirming the
GPU implementation produces correct output.

**GPU Compatibility:**
The implementation uses standard OpenCL 1.2 and should work with any
OpenCL-capable GPU:
- **NVIDIA**: Requires proprietary driver (includes OpenCL ICD). Tested.
- **AMD**: Should work via ROCm or AMDGPU-PRO driver. Not yet tested.
- **Intel**: Works with Intel OpenCL runtime (intel-opencl-icd). Tested.

On Linux, ensure the appropriate OpenCL ICD is installed:
```bash
# NVIDIA (installed with driver)
ls /etc/OpenCL/vendors/nvidia.icd

# AMD
sudo apt install rocm-opencl-icd    # or amdgpu-pro

# Intel
sudo apt install intel-opencl-icd
```

**Channel Count Sensitivity:**
Testing revealed that certain channel counts produce poor CRC validation
rates regardless of CPU or GPU path. This is a characteristic of the
PFBCH2 filterbank, not a bug in the GPU implementation:

| Channels | CRC Valid Rate | Notes |
|----------|---------------|-------|
| 40 | ~57% | Good |
| 44 | ~2% | Poor |
| 48 | ~71% | Good |
| 52 | ~3% | Poor |
| 56 | ~1.5% | Poor |
| 60 | ~82% | Best (slightly exceeds B210 analog BW) |

Recommended channel counts: 40, 48, or 60 (with capable GPU).

**Heavy RF Environment Test (NVIDIA RTX 3060, 60 channels):**

| Metric | Value |
|--------|-------|
| Duration | ~5 minutes |
| Channels | 60 |
| Total packets | 29,296 |
| CRC valid | 15,227 (52.0%) |
| CRC invalid | 14,069 |
| Channelizer | 60.0 Msamp/sec (100% realtime) |
| AGC headroom | ~280-315 Msamp/sec (245-270% realtime) |
| Overflows | 0 |

In a congested RF environment the CRC valid rate drops from ~82% to ~52%
due to collisions and multipath, but the channelizer maintains 100%
realtime with zero drops. The GPU has substantial headroom even under
heavy load.

## Files Modified

- **bluetooth.c**: CRC-24 algorithm, CRC validation logic, AA correlator
- **bluetooth.h**: Added `bluetooth_init()` declaration, CRC fields to `ble_packet_t`, updated `bluetooth_detect()` signature
- **main.c**: Added `bluetooth_init()` call, CRC statistics globals, pass demod signal to detector, GPU channelizer thread
- **options.c**: Added `--check-crc` command-line option
- **pcap.c**: Added CRC PCAP flags, conditional flag setting
- **opencl/fft.c**: GPU PFB+FFT kernel (new file)
- **opencl/fft.h**: GPU PFB+FFT header (new file)
- **window.c**: AVX2 runtime dispatch, SSE2 madd optimization, scalar bug fix
- **window.h**: Added `window_dotprod_init()` declaration
- **CMakeLists.txt**: OpenCL auto-detection and build integration

## Backward Compatibility

All changes are fully backward compatible:

- CRC validation is OFF by default (requires `--check-crc` flag)
- PCAP format unchanged when CRC checking disabled
- Original behavior preserved for existing workflows
- No breaking changes to command-line interface

## References

- Bluetooth Core Specification Volume 6, Part B, Section 3.1.1 (CRC)
- PCAP DLT_BLUETOOTH_LE_LL_WITH_PHDR format specification
