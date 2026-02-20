/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#ifndef __BLUETOOTH_H__
#define __BLUETOOTH_H__

#include <stdint.h>
#include <time.h>

void bluetooth_init(void);
void bluetooth_detect(uint8_t *bits, unsigned len, float *demod, unsigned demod_len, unsigned silence_offset, unsigned freq, unsigned rssi, unsigned noise, struct timespec timestamp, uint32_t *lap_out, uint32_t *aa_out);

typedef struct _ble_packet_t {
    uint32_t aa;
    int rssi_db;
    int noise_db;
    unsigned freq; // frequency in MHz
    unsigned len; // length including AA + header + CRC
    struct timespec timestamp;
    uint8_t crc_checked;    // Was CRC validation performed?
    uint8_t crc_valid;      // Is CRC valid? (only meaningful if crc_checked)
    uint8_t is_data;        // 1 if data channel packet (not advertising)
    uint8_t conn_valid;     // 1 if packet matched a tracked connection
    uint8_t data[0]; // data starts at AA
} ble_packet_t;

/* BLE connection tracking (populated from CONNECT_IND packets) */
#define BLE_MAX_CONNECTIONS 128

typedef struct {
    uint32_t aa;            /* connection access address */
    uint32_t crc_init;      /* CRC initialization value */
    uint8_t  init_addr[6];  /* initiator address */
    uint8_t  adv_addr[6];   /* advertiser address */
    uint8_t  init_addr_type;/* 0=public, 1=random (TxAdd) */
    uint8_t  adv_addr_type; /* 0=public, 1=random (RxAdd) */
    uint8_t  channel_map[5];/* 37-bit channel map */
    uint8_t  hop_increment; /* 5-bit hop increment */
    uint16_t interval;      /* connection interval (1.25 ms units) */
    uint16_t latency;       /* slave latency */
    uint16_t timeout;       /* supervision timeout (10 ms units) */
    time_t   created;       /* when CONNECT_IND was seen */
    time_t   last_seen;     /* last data packet timestamp */
    uint32_t pkt_count;     /* data packets observed */
    uint8_t  active;        /* slot in use */
} ble_connection_t;

unsigned ble_conn_get_count(void);
const ble_connection_t *ble_conn_get_table(void);

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
