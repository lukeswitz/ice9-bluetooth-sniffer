/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <liquid/liquid.h>

#include "pcap.h"
#include "bluetooth.h"
#include "hackrf.h"
#include "bladerf.h"
#include "usrp.h"
#ifdef HAVE_SOAPYSDR
#include "soapysdr.h"
#endif
#include "burst_catcher.h"

#ifdef HAVE_GPS
#include "gps_tag.h"
extern int gpsd_active;
#endif

#ifdef HAVE_ZMQ
#include <zmq.h>
#include <pthread.h>

static void *zmq_ctx = NULL;
static void *zmq_pub = NULL;
static void *zmq_control = NULL;
extern sig_atomic_t running;
extern hackrf_device *hackrf_device_global;
extern struct bladerf *bladerf_device_global;
extern uhd_usrp_handle usrp_device_global;
#ifdef HAVE_SOAPYSDR
extern SoapySDRDevice *soapy_device_global;
#endif
extern void **agc_array_global;
extern unsigned num_agcs_global;
extern float sql;

// Track initial gain values for distance calculation compensation
static unsigned initial_vga_gain = 0;
static unsigned initial_lna_gain = 0;
static int initial_gain_captured = 0;
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

#define DLT_PPI 192

/* PPI (Per-Packet Information) header structures */
typedef struct __attribute__((packed)) _ppi_header_t {
    uint8_t  pph_version;       /* 0 */
    uint8_t  pph_flags;         /* 0 */
    uint16_t pph_len;           /* total PPI header length */
    uint32_t pph_dlt;           /* encapsulated DLT */
} ppi_header_t;

/* PPI field header (TLV) */
typedef struct __attribute__((packed)) _ppi_field_header_t {
    uint16_t pfh_type;          /* field type */
    uint16_t pfh_datalen;       /* field data length (excluding this header) */
} ppi_field_header_t;

/* PPI-GPS geotag (field type 30002) */
#define PPI_FIELD_GPS 30002

typedef struct __attribute__((packed)) _ppi_gps_t {
    uint8_t  geotag_ver;        /* 2 */
    uint8_t  geotag_pad;        /* 0 */
    uint16_t geotag_len;        /* 24 */
    uint32_t present_flags;     /* bitmask of present fields */
    uint32_t gps_flags;         /* GPS fix flags */
    uint32_t lat;               /* fixed-point latitude */
    uint32_t lon;               /* fixed-point longitude */
    uint32_t alt;               /* fixed-point altitude */
} ppi_gps_t;

/* PPI-GPS present flags (bit positions per PPI geolocation spec) */
#define PPI_GPS_FLAG_GPSFLAGS 0x00000001  /* bit 0: GPSFlags field present */
#define PPI_GPS_FLAG_LAT      0x00000002  /* bit 1: latitude */
#define PPI_GPS_FLAG_LON      0x00000004  /* bit 2: longitude */
#define PPI_GPS_FLAG_ALT      0x00000008  /* bit 3: altitude */

/* Convert double to PPI fixed3_7 format (for lat/lon, unsigned with +180 offset) */
static uint32_t ppi_fixed3_7(double val) {
    return (uint32_t)((val + 180.0) * 1e7);
}

/* Convert double to PPI fixed6_4 format (for altitude, unsigned with +180000m offset) */
static uint32_t ppi_fixed6_4(double val) {
    return (uint32_t)((val + 180000.0) * 1e4);
}

/* Size of minimal PPI header (no fields) */
#define PPI_HDR_SIZE sizeof(ppi_header_t)

/* Size of PPI header with GPS field */
#define PPI_GPS_SIZE (sizeof(ppi_header_t) + sizeof(ppi_field_header_t) + sizeof(ppi_gps_t))

pcap_t *pcap_open(char *path) {
    pcap_t *p;
    uint32_t dlt = DLT_BLUETOOTH_LE_LL_WITH_PHDR;
    uint32_t snaplen = 4 + 2 + 255 + 3;

#ifdef HAVE_GPS
    if (gpsd_active) {
        dlt = DLT_PPI;
        snaplen += PPI_GPS_SIZE;  /* room for PPI + GPS field */
    }
#endif

    pcap_hdr_t h = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .snaplen = snaplen,
        .network = dlt,
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

int zmq_pub_init(const char *endpoint, const char *curve_keyfile, int connect_mode) {
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

    int rc;
    if (connect_mode)
        rc = zmq_connect(zmq_pub, endpoint);
    else
        rc = zmq_bind(zmq_pub, endpoint);

    if (rc != 0) {
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

int zmq_control_init(const char *endpoint) {
    if (!zmq_ctx) {
        zmq_ctx = zmq_ctx_new();
        if (!zmq_ctx)
            return -1;
    }
    zmq_control = zmq_socket(zmq_ctx, ZMQ_REP);
    if (!zmq_control)
        return -1;
    if (zmq_bind(zmq_control, endpoint) != 0) {
        zmq_close(zmq_control);
        zmq_control = NULL;
        return -1;
    }
    return 0;
}

void zmq_control_close(void) {
    if (zmq_control) {
        zmq_close(zmq_control);
        zmq_control = NULL;
    }
}

void *zmq_control_thread(void *arg) {
    (void)arg;
    if (!zmq_control)
        return NULL;

    char buf[256];
    while (running) {
        zmq_pollitem_t items[] = {{zmq_control, 0, ZMQ_POLLIN, 0}};
        int rc = zmq_poll(items, 1, 1000);
        if (rc <= 0)
            continue;

        int len = zmq_recv(zmq_control, buf, sizeof(buf) - 1, ZMQ_DONTWAIT);
        if (len < 0)
            continue;
        buf[len] = '\0';

        // Handle "status" command without requiring colon
        if (strcmp(buf, "status") == 0 || strcmp(buf, "status:") == 0) {
            // Capture initial gain values on first status request
            if (!initial_gain_captured) {
                initial_vga_gain = vga_gain;
                initial_lna_gain = lna_gain;
                initial_gain_captured = 1;
            }
            float rssi_offset = bluetooth_get_rssi_offset();
            snprintf(buf, sizeof(buf), "vga=%u lna=%u squelch=%.1f rssi_offset=%.1f vga0=%u lna0=%u",
                     vga_gain, lna_gain, sql, rssi_offset, initial_vga_gain, initial_lna_gain);
            zmq_send(zmq_control, buf, strlen(buf), 0);
            continue;
        }

        char *colon = strchr(buf, ':');
        if (!colon) {
            zmq_send(zmq_control, "ERR invalid_format", 18, 0);
            continue;
        }

        *colon = '\0';
        char *cmd = buf;
        char *val = colon + 1;

        if (strcmp(cmd, "vga") == 0 || strcmp(cmd, "gain") == 0) {
            int v = atoi(val);
            if (hackrf_device_global) {
                // HackRF VGA: 0-62 in steps of 2 dB
                v = (v / 2) * 2;
                if (v < 0) v = 0;
                if (v > 62) v = 62;
                hackrf_set_gains(hackrf_device_global, v, lna_gain);
                zmq_send(zmq_control, "OK", 2, 0);
            } else if (bladerf_device_global) {
                bladerf_set_rx_gain(bladerf_device_global, v);
                zmq_send(zmq_control, "OK", 2, 0);
            } else if (usrp_device_global) {
                usrp_set_gain(usrp_device_global, (float)v);
                zmq_send(zmq_control, "OK", 2, 0);
#ifdef HAVE_SOAPYSDR
            } else if (soapy_device_global) {
                soapy_set_gain(soapy_device_global, (double)v);
                zmq_send(zmq_control, "OK", 2, 0);
#endif
            } else {
                zmq_send(zmq_control, "ERR no_device", 13, 0);
            }
        } else if (strcmp(cmd, "lna") == 0) {
            int v = atoi(val);
            if (hackrf_device_global) {
                // HackRF LNA: only 0, 8, 16, 24, 32, or 40 dB
                if (v <= 4) v = 0;
                else if (v <= 12) v = 8;
                else if (v <= 20) v = 16;
                else if (v <= 28) v = 24;
                else if (v <= 36) v = 32;
                else v = 40;
                hackrf_set_gains(hackrf_device_global, vga_gain, v);
                zmq_send(zmq_control, "OK", 2, 0);
            } else {
                // Other SDRs don't have separate LNA, ignore
                zmq_send(zmq_control, "OK", 2, 0);
            }
        } else if (strcmp(cmd, "squelch") == 0) {
            float v = atof(val);
            sql = v;
            if (agc_array_global && num_agcs_global > 0) {
                burst_catcher_t *catcher_array = (burst_catcher_t *)agc_array_global;
                for (unsigned i = 0; i < num_agcs_global; ++i) {
                    burst_catcher_t *c = &catcher_array[i];
                    if (c->agc)
                        burst_catcher_set_squelch(c, v);
                }
                zmq_send(zmq_control, "OK", 2, 0);
            } else {
                zmq_send(zmq_control, "ERR no_agc", 10, 0);
            }
        } else {
            zmq_send(zmq_control, "ERR unknown_cmd", 15, 0);
        }
    }
    return NULL;
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

static void zmq_pub_packet_gps(zmq_gps_frame_t *gps, pcaprec_hdr_t *ph, pcap_le_header_t *lh, uint8_t *data, unsigned len) {
    if (!zmq_pub)
        return;
    unsigned msg_len = sizeof(*ph) + sizeof(*lh) + len;
    uint8_t *buf = malloc(msg_len);
    if (!buf)
        return;
    memcpy(buf, ph, sizeof(*ph));
    memcpy(buf + sizeof(*ph), lh, sizeof(*lh));
    memcpy(buf + sizeof(*ph) + sizeof(*lh), data, len);

    /* Send as multipart: frame 1 = GPS, frame 2 = PCAP record */
    zmq_send(zmq_pub, gps, sizeof(*gps), ZMQ_DONTWAIT | ZMQ_SNDMORE);
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

    unsigned ble_payload_len = b->len + sizeof(le_header);

#ifdef HAVE_GPS
    gps_fix_t fix = {0};
    if (gpsd_active)
        gps_tag_get_fix(&fix);

    if (gpsd_active) {
        /* PPI-wrapped output */
        unsigned ppi_len;
        if (fix.valid)
            ppi_len = PPI_GPS_SIZE;
        else
            ppi_len = PPI_HDR_SIZE;

        pcaprec_hdr_t pcap_header = {
            .ts_sec   = b->timestamp.tv_sec,
            .ts_usec  = b->timestamp.tv_nsec/1000,
            .incl_len = ppi_len + ble_payload_len,
            .orig_len = ppi_len + ble_payload_len,
        };

        /* Build PPI header */
        ppi_header_t ppi_hdr = {
            .pph_version = 0,
            .pph_flags = 0,
            .pph_len = ppi_len,
            .pph_dlt = DLT_BLUETOOTH_LE_LL_WITH_PHDR,
        };

        if (p) {
            fwrite(&pcap_header, sizeof(pcap_header), 1, p->f);
            fwrite(&ppi_hdr, sizeof(ppi_hdr), 1, p->f);

            if (fix.valid) {
                ppi_field_header_t fld_hdr = {
                    .pfh_type = PPI_FIELD_GPS,
                    .pfh_datalen = sizeof(ppi_gps_t),
                };
                ppi_gps_t gps = {
                    .geotag_ver = 2,
                    .geotag_pad = 0,
                    .geotag_len = sizeof(ppi_gps_t),
                    .present_flags = PPI_GPS_FLAG_GPSFLAGS | PPI_GPS_FLAG_LAT | PPI_GPS_FLAG_LON | PPI_GPS_FLAG_ALT,
                    .gps_flags = 0,
                    .lat = ppi_fixed3_7(fix.latitude),
                    .lon = ppi_fixed3_7(fix.longitude),
                    .alt = ppi_fixed6_4(fix.altitude),
                };
                fwrite(&fld_hdr, sizeof(fld_hdr), 1, p->f);
                fwrite(&gps, sizeof(gps), 1, p->f);
            }

            fwrite(&le_header, sizeof(le_header), 1, p->f);
            fwrite(b->data, b->len, 1, p->f);
            fflush(p->f);
        }

#ifdef HAVE_ZMQ
        /* ZMQ: send GPS as separate frame (multipart) */
        if (fix.valid) {
            zmq_gps_frame_t gps_frame = {
                .latitude = fix.latitude,
                .longitude = fix.longitude,
                .altitude = fix.altitude,
            };
            /* Build PCAP record without PPI (DLT 256 format) for ZMQ */
            pcaprec_hdr_t zmq_pcap_header = {
                .ts_sec   = b->timestamp.tv_sec,
                .ts_usec  = b->timestamp.tv_nsec/1000,
                .incl_len = ble_payload_len,
                .orig_len = ble_payload_len,
            };
            zmq_pub_packet_gps(&gps_frame, &zmq_pcap_header, &le_header, b->data, b->len);
        } else {
            pcaprec_hdr_t zmq_pcap_header = {
                .ts_sec   = b->timestamp.tv_sec,
                .ts_usec  = b->timestamp.tv_nsec/1000,
                .incl_len = ble_payload_len,
                .orig_len = ble_payload_len,
            };
            zmq_pub_packet(&zmq_pcap_header, &le_header, b->data, b->len);
        }
#endif
    } else
#endif /* HAVE_GPS */
    {
        /* Standard DLT 256 output (no GPS) */
        pcaprec_hdr_t pcap_header = {
            .ts_sec   = b->timestamp.tv_sec,
            .ts_usec  = b->timestamp.tv_nsec/1000,
            .incl_len = ble_payload_len,
            .orig_len = ble_payload_len,
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
}
