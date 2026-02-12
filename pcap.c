/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap.h"

#ifdef HAVE_ZMQ
#include <zmq.h>

static void *zmq_ctx = NULL;
static void *zmq_pub = NULL;
#endif

struct _pcap_t {
    FILE *f;
};

typedef struct __attribute__((packed)) _pcap_hdr_t {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct __attribute__((packed)) _pcaprec_hdr_t {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

typedef struct __attribute__((packed)) _pcap_le_header_t {
    uint8_t rf_channel;
    int8_t signal_power;
    int8_t noise_power;
    uint8_t aa_offenses;
    uint32_t ref_aa;
    uint16_t flags;
} pcap_le_header_t;

#define LE_DEWHITENED         0x0001
#define LE_SIGNAL_POWER_VALID 0x0002
#define LE_NOISE_POWER_VALID  0x0004
#define LE_CRC_CHECKED        0x0400  // CRC validation was performed (bit 10)
#define LE_CRC_VALID          0x0800  // CRC is valid (only meaningful with LE_CRC_CHECKED) (bit 11)


#if !defined( DLT_BLUETOOTH_LE_LL_WITH_PHDR )
#define DLT_BLUETOOTH_LE_LL_WITH_PHDR 256
#endif

pcap_t *pcap_open(char *path) {
    pcap_t *p;
    pcap_hdr_t h = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .snaplen = 4 + 2 + 255 + 3,
        .network = DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    };

    FILE *f = fopen(path, "w");
    if (f == NULL)
        return NULL;
    p = malloc(sizeof(*p));
    p->f = f;

    // write header
    fwrite(&h, sizeof(h), 1, p->f);

    return p;
}

void pcap_close(pcap_t *p) {
    fclose(p->f);
    free(p);
}

#ifdef HAVE_ZMQ
static int parse_curve_keyfile(const char *path, char *public_key, char *secret_key) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[256];
    int got_pub = 0, got_sec = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (strncmp(line, "public_key=", 11) == 0) {
            strncpy(public_key, line + 11, 40);
            public_key[40] = '\0';
            got_pub = 1;
        } else if (strncmp(line, "secret_key=", 11) == 0) {
            strncpy(secret_key, line + 11, 40);
            secret_key[40] = '\0';
            got_sec = 1;
        }
    }
    fclose(f);
    return (got_pub && got_sec) ? 0 : -1;
}

int zmq_pub_init(const char *endpoint, const char *curve_keyfile) {
    zmq_ctx = zmq_ctx_new();
    if (!zmq_ctx)
        return -1;
    zmq_pub = zmq_socket(zmq_ctx, ZMQ_PUB);
    if (!zmq_pub) {
        zmq_ctx_destroy(zmq_ctx);
        zmq_ctx = NULL;
        return -1;
    }
    int sndhwm = 1000;
    zmq_setsockopt(zmq_pub, ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm));

    if (curve_keyfile) {
        char public_key[41], secret_key[41];
        if (parse_curve_keyfile(curve_keyfile, public_key, secret_key) != 0) {
            fprintf(stderr, "Failed to read CURVE keys from %s\n", curve_keyfile);
            zmq_close(zmq_pub);
            zmq_ctx_destroy(zmq_ctx);
            zmq_pub = NULL;
            zmq_ctx = NULL;
            return -1;
        }
        int server = 1;
        zmq_setsockopt(zmq_pub, ZMQ_CURVE_SERVER, &server, sizeof(server));
        zmq_setsockopt(zmq_pub, ZMQ_CURVE_SECRETKEY, secret_key, 40);
        zmq_setsockopt(zmq_pub, ZMQ_CURVE_PUBLICKEY, public_key, 40);
        fprintf(stderr, "ZMQ CURVE: encrypted (server key: %.8s...)\n", public_key);
    }

    if (zmq_bind(zmq_pub, endpoint) != 0) {
        zmq_close(zmq_pub);
        zmq_ctx_destroy(zmq_ctx);
        zmq_pub = NULL;
        zmq_ctx = NULL;
        return -1;
    }
    return 0;
}

void zmq_pub_close(void) {
    if (zmq_pub) {
        zmq_close(zmq_pub);
        zmq_pub = NULL;
    }
    if (zmq_ctx) {
        zmq_ctx_destroy(zmq_ctx);
        zmq_ctx = NULL;
    }
}

static void zmq_pub_packet(pcaprec_hdr_t *ph, pcap_le_header_t *lh, uint8_t *data, unsigned len) {
    if (!zmq_pub)
        return;
    unsigned msg_len = sizeof(*ph) + sizeof(*lh) + len;
    uint8_t *buf = malloc(msg_len);
    if (!buf)
        return;
    memcpy(buf, ph, sizeof(*ph));
    memcpy(buf + sizeof(*ph), lh, sizeof(*lh));
    memcpy(buf + sizeof(*ph) + sizeof(*lh), data, len);
    zmq_send(zmq_pub, buf, msg_len, ZMQ_DONTWAIT);
    free(buf);
}
#endif

// TODO timestamp
void pcap_write_ble(pcap_t *p, ble_packet_t *b) {
    uint16_t flags = LE_DEWHITENED | LE_SIGNAL_POWER_VALID | LE_NOISE_POWER_VALID;

    // Add CRC flags if checked
    if (b->crc_checked) {
        flags |= LE_CRC_CHECKED;
        if (b->crc_valid) {
            flags |= LE_CRC_VALID;
        }
    }

    pcap_le_header_t le_header = {
        .rf_channel = (b->freq - 2402) / 2,
        .signal_power = b->rssi_db,
        .noise_power = b->noise_db,
        .flags = flags,
    };
    pcaprec_hdr_t pcap_header = {
        .ts_sec   = b->timestamp.tv_sec,
        .ts_usec  = b->timestamp.tv_nsec/1000,
        .incl_len = b->len + sizeof(le_header),
        .orig_len = b->len + sizeof(le_header),
    };
    if (p) {
        fwrite(&pcap_header, sizeof(pcap_header), 1, p->f);
        fwrite(&le_header, sizeof(le_header), 1, p->f);
        fwrite(b->data, b->len, 1, p->f);
        fflush(p->f);
    }

#ifdef HAVE_ZMQ
    zmq_pub_packet(&pcap_header, &le_header, b->data, b->len);
#endif
}
