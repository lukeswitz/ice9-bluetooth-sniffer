/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#ifndef __PCAP_H__
#define __PCAP_H__

#include "bluetooth.h"

typedef struct _pcap_t pcap_t;

pcap_t *pcap_open(char *path);
void pcap_close(pcap_t *p);
void pcap_write_ble(pcap_t *p, ble_packet_t *b);

#ifdef HAVE_ZMQ
int zmq_pub_init(const char *endpoint, const char *curve_keyfile, int connect_mode);
void zmq_pub_close(void);
int zmq_control_init(const char *endpoint);
void *zmq_control_thread(void *arg);
void zmq_control_close(void);
#endif

/* ZMQ GPS frame structure (sent as frame 1 of multipart message) */
typedef struct __attribute__((packed)) _zmq_gps_frame_t {
    double latitude;
    double longitude;
    double altitude;
} zmq_gps_frame_t;

#endif
