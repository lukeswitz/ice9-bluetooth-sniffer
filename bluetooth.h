/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#ifndef __BLUETOOTH_H__
#define __BLUETOOTH_H__

#include <stdint.h>
#include <time.h>

void bluetooth_init(void);
void bluetooth_init_rssi_calibration(const char *sdr_name, int gain, unsigned channels);
float bluetooth_get_rssi_offset(void);
void bluetooth_detect(uint8_t *bits, unsigned len, float *demod, unsigned demod_len, unsigned silence_offset, unsigned freq, float rssi, float noise, struct timespec timestamp, uint32_t *lap_out, uint32_t *aa_out);

typedef struct _ble_packet_t {
    uint32_t aa;
    int rssi_db;
    int noise_db;
    unsigned freq; // frequency in MHz
    unsigned len; // length including AA + header + CRC
    struct timespec timestamp;
    uint8_t crc_checked;    // Was CRC validation performed?
    uint8_t crc_valid;      // Is CRC valid? (only meaningful if crc_checked)
    uint8_t data[0]; // data starts at AA
} ble_packet_t;

typedef struct _classic_bt_packet_t {
    uint32_t lap;
    uint8_t ac_errors;
    int rssi_db;
    int noise_db;
    unsigned freq;              // frequency in MHz
    struct timespec timestamp;
    uint8_t raw_header[7];      // 54 FEC-encoded header bits packed LSB-first
    uint8_t has_header;         // 1 if raw_header was captured
} classic_bt_packet_t;

#endif
