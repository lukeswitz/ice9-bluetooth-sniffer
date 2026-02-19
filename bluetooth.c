/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bluetooth.h"
#include "btbb/btbb.h"
#include "pcap.h"

static float rssi_calibration_offset = 0.0f;
extern pcap_t *pcap;
extern int check_crc;
extern int verbose;
extern unsigned long crc_total;
extern unsigned long crc_valid_count;
extern unsigned long crc_invalid_count;
#ifdef HAVE_ZMQ
extern int zmq_pub_active;
#endif

// Pre-computed 127-bit whitening sequence (7-bit maximal-length LFSR, period 127)
// All 40 BLE channels use the same sequence at different offsets
static const uint8_t whitening[] = {
    1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0,
    1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1,
    0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1,
    0, 1,
};

// Per-channel starting offset into the whitening sequence
static const uint8_t whitening_index[] = {
    70, 62, 120, 111, 77, 46, 15, 101, 66, 39, 31, 26, 80, 83, 125, 89, 10, 35,
    8, 54, 122, 17, 33, 0, 58, 115, 6, 94, 86, 49, 52, 20, 40, 27, 84, 90, 63,
    112, 47, 102,
};

// AA correlator: pre-computed template for BLE advertising access address
#define BLE_ADV_AA       0x8E89BED6u
#define BLE_SPS          2          // samples per symbol (2 MHz channel, 1 Msym/s BLE)
#define BLE_AA_BITS      32
#define BLE_AA_TLEN      (BLE_AA_BITS * BLE_SPS)  // 64 samples
#define BLE_CORR_THRESH  0.6f
#define BLE_MAX_HD       4          // max hamming distance for AA match

static float aa_template[BLE_AA_TLEN];
static float aa_template_norm;      // pre-computed sqrt(sum(template^2))

#ifndef MAX
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))
#endif

// Initialize Bluetooth subsystem (call once at program startup)
void bluetooth_init(void) {
    // Build AA correlation template: +1 for bit=1, -1 for bit=0, repeated SPS times
    uint32_t aa = BLE_ADV_AA;
    float sum_sq = 0;
    for (unsigned i = 0; i < BLE_AA_BITS; i++) {
        float val = ((aa >> i) & 1) ? 1.0f : -1.0f;
        for (unsigned j = 0; j < BLE_SPS; j++) {
            aa_template[i * BLE_SPS + j] = val;
            sum_sq += 1.0f;  // val^2 is always 1
        }
    }
    aa_template_norm = sqrtf(sum_sq);
}

void bluetooth_set_rssi_offset(float offset_db) {
    rssi_calibration_offset = offset_db;
}

float bluetooth_get_rssi_offset(void) {
    return rssi_calibration_offset;
}

void bluetooth_init_rssi_calibration(const char *sdr_name, int gain, unsigned channels) {
    // Compensate for two factors:
    //   +20*log10(N): agc_submit divides each channel by N before the AGC
    //   -60 dB: burst_catcher sets signal_level=1e-3, which shifts get_rssi by
    //           -20*log10(1e-3) = +60 dB; subtract it back out here
    rssi_calibration_offset = 20.0f * log10f((float)channels) - 60.0f;
    fprintf(stderr, "RSSI: calibration offset = %.1f dB (channels=%u)\n",
            rssi_calibration_offset, channels);
}

// Whitening bit lookup: index into pre-computed sequence at channel-specific offset
static inline uint8_t ble_whitening_bit(unsigned channel, unsigned bit_position) {
    return whitening[(whitening_index[channel] + bit_position) % 127];
}

static unsigned freq_to_channel(unsigned freq) {
    unsigned phys_channel = (freq - 2402) / 2;
    if (phys_channel == 0) return 37;
    if (phys_channel == 12) return 38;
    if (phys_channel == 39) return 39;
    if (phys_channel < 12) return phys_channel - 1;
    return phys_channel - 2;
}

// BLE CRC-24 implementation
// Polynomial: x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1
// Reflected polynomial for right-shifting CRC: 0xDA6000
// Init: 0x555555 for advertising channels, lower 24 bits of AA for data channels
// Init value must be bit-reversed for the reflected CRC algorithm
static uint32_t ble_crc24(const uint8_t *data, unsigned len, uint32_t init) {
    // Reflect the 24-bit init value for right-shifting CRC
    uint32_t crc = 0;
    uint32_t v = init & 0xFFFFFF;
    unsigned i, j;
    for (j = 0; j < 24; j++) {
        crc = (crc << 1) | (v & 1);
        v >>= 1;
    }

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xDA6000;
            else
                crc >>= 1;
        }
    }

    return crc & 0xFFFFFF;
}

// AA correlator: find BLE advertising packets by correlating the analog demod
// signal against the known access address pattern. This catches packets that the
// preamble-first method misses due to symbol timing errors.
static ble_packet_t *ble_burst_correlator(float *demod, unsigned demod_len,
                                           unsigned silence_offset, unsigned freq,
                                           struct timespec timestamp) {
    unsigned i, j;
    (void)silence_offset;  // correlator searches entire signal

    if (demod_len < BLE_AA_TLEN + 80)
        return NULL;

    // Slide template across demod, find best normalized correlation
    // Start from sample 1 to skip potentially wild first sample (see fsk.c)
    unsigned search_end = demod_len - BLE_AA_TLEN;
    float best_score = 0;
    unsigned best_idx = 0;

    for (i = 1; i <= search_end; i++) {
        float dot = 0, win_sq = 0;
        for (j = 0; j < BLE_AA_TLEN; j++) {
            float s = demod[i + j];
            dot += s * aa_template[j];
            win_sq += s * s;
        }
        float win_norm = sqrtf(win_sq);
        if (win_norm > 0.001f) {
            float score = dot / (win_norm * aa_template_norm);
            if (score > best_score) {
                best_score = score;
                best_idx = i;
            }
        }
    }

    if (best_score < BLE_CORR_THRESH)
        return NULL;

    // Try both sample phases for bit extraction, pick lowest hamming distance
    unsigned best_phase = 0;
    unsigned best_hd = 33;

    for (unsigned phase = 0; phase < BLE_SPS; phase++) {
        uint32_t aa = 0;
        for (i = 0; i < 32; i++) {
            unsigned idx = best_idx + phase + i * BLE_SPS;
            if (idx < demod_len && demod[idx] > 0)
                aa |= 1u << i;
        }
        unsigned hd = __builtin_popcount(aa ^ BLE_ADV_AA);
        if (hd < best_hd) {
            best_hd = hd;
            best_phase = phase;
        }
    }

    if (best_hd > BLE_MAX_HD)
        return NULL;

    // Extract bits starting at AA position with best phase
    unsigned bit_start = best_idx + best_phase;
    unsigned max_bits = (demod_len - bit_start) / BLE_SPS;

    if (max_bits < 32 + 16)
        return NULL;

    // Slice bits from analog signal
    uint8_t *bits = malloc(max_bits);
    for (i = 0; i < max_bits; i++) {
        unsigned idx = bit_start + i * BLE_SPS;
        bits[i] = (demod[idx] > 0) ? 1 : 0;
    }

    unsigned channel = freq_to_channel(freq);

    // Extract length byte (PDU byte 1) with dewhitening
    uint8_t header_len = 0;
    for (j = 0; j < 8; j++) {
        uint8_t whiten_bit = ble_whitening_bit(channel, 8 + j);
        if (32 + 8 + j < max_bits)
            header_len |= (bits[32 + 8 + j] ^ whiten_bit) << j;
    }

    // Validate: BLE advertising PDU payload max 37 bytes
    unsigned needed_bits = 32 + 16 + header_len * 8 + 24;
    if (header_len > 37 || needed_bits > max_bits) {
        free(bits);
        return NULL;
    }

    // Build packet (same structure as ble_burst)
    ble_packet_t *p = malloc(sizeof(*p) + MAX(4 + 2 + header_len + 3, 64));
    p->aa = BLE_ADV_AA;
    p->freq = freq;
    p->len = 4 + 2 + header_len + 3;
    p->data[0] = (BLE_ADV_AA >>  0) & 0xff;
    p->data[1] = (BLE_ADV_AA >>  8) & 0xff;
    p->data[2] = (BLE_ADV_AA >> 16) & 0xff;
    p->data[3] = (BLE_ADV_AA >> 24) & 0xff;

    for (i = 0; i < p->len - 4; i++) {
        uint8_t byte = 0;
        for (j = 0; j < 8; j++) {
            uint8_t whiten_bit = ble_whitening_bit(channel, i * 8 + j);
            if (32 + i * 8 + j < max_bits)
                byte |= (bits[32 + i * 8 + j] ^ whiten_bit) << j;
        }
        p->data[i + 4] = byte;
    }
    p->timestamp = timestamp;

    // CRC validation
    p->crc_checked = 0;
    p->crc_valid = 0;
    if (check_crc) {
        uint32_t crc_init = (channel >= 37) ? 0x555555 : (BLE_ADV_AA & 0xFFFFFF);
        unsigned crc_len = p->len - 4 - 3;
        uint32_t computed_crc = ble_crc24(&p->data[4], crc_len, crc_init);
        uint32_t received_crc = p->data[p->len-3] |
                               (p->data[p->len-2] << 8) |
                               (p->data[p->len-1] << 16);
        p->crc_checked = 1;
        p->crc_valid = (computed_crc == received_crc) ? 1 : 0;
    }

    free(bits);
    return p;
}

ble_packet_t *ble_burst(uint8_t *bits, unsigned bits_len, unsigned freq, struct timespec timestamp) {
    unsigned i, j;
    // unsigned burst_len = (unsigned)roundf((float)bits_len / 8.0f);
    unsigned smallest_delta = 0xffffffff;
    unsigned smallest_offset = 0;
    uint32_t smallest_aa = 0;
    uint8_t smallest_header_len;

    // possibly BLE, extract access address
    if (bits[0] == bits[2] && bits[2] == bits[4] &&
            bits[1] == bits[3] && bits[3] == bits[5]) {
        unsigned channel = freq_to_channel(freq);

        // try three candidates for AA
        for (i = 6; i < 9; ++i) {
            uint32_t aa = 0;
            for (j = 0; j < 32; ++j)
                aa |= bits[i+j] << j;
            uint8_t header_len = 0;
            for (j = 0; j < 8; ++j) {
                // Length byte is at PDU offset 8 (after the PDU type byte)
                uint8_t whiten_bit = ble_whitening_bit(channel, 8 + j);
                header_len |= (bits[i+32+8+j] ^ whiten_bit) << j;
            }
            unsigned bit_len = 8 + 32 + 16 + header_len * 8 + 24; // preamble + AA + header + body + CRC
            int delta = (int)bits_len - (int)bit_len;
            if (delta > 0 && (unsigned)delta < smallest_delta) {
                smallest_delta = delta;
                smallest_offset = i;
                smallest_aa = aa;
                smallest_header_len = header_len;
            }
        }

        // see if any of the candidates have a length that makes sense
        if (smallest_delta < 20) {
            ble_packet_t *p = malloc(sizeof(*p) + MAX(4 + 2 + smallest_header_len + 3, 64)); // FIXME bug in libbtbb
            p->aa = smallest_aa;
            p->freq = freq;
            p->len = 4 + 2 + smallest_header_len + 3;
            p->data[0] = (smallest_aa >>  0) & 0xff;
            p->data[1] = (smallest_aa >>  8) & 0xff;
            p->data[2] = (smallest_aa >> 16) & 0xff;
            p->data[3] = (smallest_aa >> 24) & 0xff;
            for (i = 0; i < p->len-4; ++i) {
                uint8_t byte = 0;
                for (j = 0; j < 8; ++j) {
                    // Dewhiten using channel-specific LFSR
                    uint8_t whiten_bit = ble_whitening_bit(channel, i*8 + j);
                    byte |= (bits[smallest_offset+32+i*8+j] ^ whiten_bit) << j;
                }
                p->data[i+4] = byte;
            }
            p->timestamp = timestamp;

            // CRC validation
            p->crc_checked = 0;
            p->crc_valid = 0;

            if (check_crc) {
                unsigned channel = freq_to_channel(freq);
                uint32_t crc_init;

                if (channel >= 37) {
                    // Advertising channel: use 0x555555 per BLE spec
                    crc_init = 0x555555;
                } else {
                    // Data channel: use lower 24 bits of AA directly
                    crc_init = smallest_aa & 0xFFFFFF;
                }

                // Compute CRC over header + payload (excluding AA and CRC)
                // data[0-3] = AA (skip)
                // data[4...len-4] = header + payload (include)
                // data[len-3...len-1] = CRC (skip)
                unsigned crc_len = p->len - 4 - 3;
                uint32_t computed_crc = ble_crc24(&p->data[4], crc_len, crc_init);

                // Extract received CRC (last 3 bytes, LSB first)
                uint32_t received_crc = p->data[p->len-3] |
                                       (p->data[p->len-2] << 8) |
                                       (p->data[p->len-1] << 16);

                p->crc_checked = 1;
                p->crc_valid = (computed_crc == received_crc) ? 1 : 0;

                if (verbose) {
                    printf("CRC Debug: ch=%u, init=0x%06X, computed=0x%06X, received=0x%06X %s\n",
                           channel, crc_init, computed_crc, received_crc,
                           p->crc_valid ? "[VALID]" : "[INVALID]");
                    printf("  PDU (%u bytes): ", crc_len);
                    for (unsigned k = 0; k < crc_len && k < 16; k++) {
                        printf("%02X ", p->data[4+k]);
                    }
                    if (crc_len > 16) printf("...");
                    printf("\n");
                }
            }

            return p;
        }
    }
    return NULL;
}

void bluetooth_detect(uint8_t *bits, unsigned len, float *demod, unsigned demod_len,
                      unsigned silence_offset, unsigned freq, float rssi, float noise, 
                      struct timespec timestamp, uint32_t *lap_out, uint32_t *aa_out) {
    int ac_offset = 0;
    uint8_t ac_errors = 0;
    uint32_t lap = btbb_find_ac_offset((char *)bits, len, 1, &ac_offset, &ac_errors);
    if (lap != 0xffffffff) {
        *lap_out = lap;

        // Build Classic BT packet for PCAP/ZMQ
        classic_bt_packet_t bt_pkt = {0};
        bt_pkt.lap = lap;
        bt_pkt.ac_errors = ac_errors;
        bt_pkt.rssi_db = rssi;
        bt_pkt.noise_db = noise;
        bt_pkt.freq = freq;
        bt_pkt.timestamp = timestamp;

        // Extract 54 raw header bits after the 64-bit sync word
        unsigned header_start = ac_offset + 64;
        if (header_start + 54 <= len) {
            bt_pkt.has_header = 1;
            memset(bt_pkt.raw_header, 0, sizeof(bt_pkt.raw_header));
            for (unsigned i = 0; i < 54; i++)
                bt_pkt.raw_header[i / 8] |= (bits[header_start + i] & 1) << (i % 8);
        }

        if (pcap
#ifdef HAVE_ZMQ
            || zmq_pub_active
#endif
        )
            pcap_write_bt(pcap, &bt_pkt);
    } else {
        // Apply RSSI calibration
        float calibrated_rssi = rssi + rssi_calibration_offset;

        // Try preamble-first detection...
        ble_packet_t *p = ble_burst(bits, len, freq, timestamp);
        if (p == NULL && demod != NULL)
            p = ble_burst_correlator(demod, demod_len, silence_offset, freq, timestamp);

        if (p != NULL) {
            // Store calibrated RSSI
            p->rssi_db = (int)roundf(calibrated_rssi);
            p->noise_db = (int)roundf(noise);
            *aa_out = p->aa;

            // Track CRC statistics
            if (p->crc_checked) {
                crc_total++;
                if (p->crc_valid) {
                    crc_valid_count++;
                } else {
                    crc_invalid_count++;
                }
            }

            if (pcap
#ifdef HAVE_ZMQ
                || zmq_pub_active
#endif
            )
                pcap_write_ble(pcap, p);
            free(p);
        }
    }
}
