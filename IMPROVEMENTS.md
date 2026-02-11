# BLE Detection Improvements

## Overview

This document describes improvements made to ice9-bluetooth-sniffer:

1. Optional CRC-24 validation with Wireshark integration
2. Access Address correlator for dramatically improved packet detection

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

**Live Testing Results (USRP B210, 4 channels, 22 seconds):**
- 9 valid CRCs out of 48 total packets (18.8%)
- Valid rate depends on signal strength and RF environment
- Stronger signals produce higher CRC pass rates

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
CRC: 9 valid, 39 invalid (18.8% valid)
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

## Files Modified

- **bluetooth.c**: CRC-24 algorithm, CRC validation logic, AA correlator
- **bluetooth.h**: Added `bluetooth_init()` declaration, CRC fields to `ble_packet_t`, updated `bluetooth_detect()` signature
- **main.c**: Added `bluetooth_init()` call, CRC statistics globals, pass demod signal to detector
- **options.c**: Added `--check-crc` command-line option
- **pcap.c**: Added CRC PCAP flags, conditional flag setting

## Backward Compatibility

All changes are fully backward compatible:

- CRC validation is OFF by default (requires `--check-crc` flag)
- PCAP format unchanged when CRC checking disabled
- Original behavior preserved for existing workflows
- No breaking changes to command-line interface

## References

- Bluetooth Core Specification Volume 6, Part B, Section 3.1.1 (CRC)
- PCAP DLT_BLUETOOTH_LE_LL_WITH_PHDR format specification
