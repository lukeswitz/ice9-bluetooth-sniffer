/*
 * Copyright 2025-2026 CEMAXECUTER LLC
 */

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <gps.h>

#include "gps_tag.h"

/* ── shared state ── */
static gps_fix_t cached_fix;
static struct timespec last_poll;
static int gps_connected = 0;
static int use_serial    = 0;

/* ── gpsd state ── */
static struct gps_data_t gpsd_state;

/* ── serial state ── */
static int  serial_fd  = -1;
static char line_buf[256];
static int  line_pos   = 0;

/* ── NMEA helpers ── */

/* Extract the nth comma-separated field from an NMEA sentence into out[]. */
static int nmea_field(const char *s, int idx, char *out, int sz) {
    int f = 0;
    const char *p = s;
    while (*p && f < idx) {
        if (*p++ == ',') f++;
    }
    int len = 0;
    while (*p && *p != ',' && *p != '*' && *p != '\r' && *p != '\n' && len < sz - 1)
        out[len++] = *p++;
    out[len] = '\0';
    return len;
}

/* Convert ddmm.mmmm + hemisphere to decimal degrees. */
static double nmea_coord(const char *coord, char hemi) {
    if (!coord || coord[0] == '\0') return 0.0;
    double raw  = atof(coord);
    int    deg  = (int)(raw / 100);
    double mins = raw - (double)(deg * 100);
    double dec  = (double)deg + mins / 60.0;
    return (hemi == 'S' || hemi == 'W') ? -dec : dec;
}

/* Update cached_fix from one NMEA sentence. */
static void process_nmea_line(const char *line) {
    char type[8];
    nmea_field(line, 0, type, sizeof(type));

    if (strcmp(type, "$GPRMC") == 0 || strcmp(type, "$GNRMC") == 0) {
        char status[4], lat[16], ns[4], lon[16], ew[4];
        nmea_field(line, 2, status, sizeof(status));
        if (status[0] != 'A') {
            cached_fix.valid = 0;
            return;
        }
        nmea_field(line, 3, lat, sizeof(lat));
        nmea_field(line, 4, ns,  sizeof(ns));
        nmea_field(line, 5, lon, sizeof(lon));
        nmea_field(line, 6, ew,  sizeof(ew));
        cached_fix.latitude  = nmea_coord(lat, ns[0]);
        cached_fix.longitude = nmea_coord(lon, ew[0]);
        cached_fix.valid     = (lat[0] != '\0' && lon[0] != '\0') ? 1 : 0;

    } else if (strcmp(type, "$GPGGA") == 0 || strcmp(type, "$GNGGA") == 0) {
        char fix_q[4], lat[16], ns[4], lon[16], ew[4], nsv[4], alt[16];
        nmea_field(line, 6,  fix_q, sizeof(fix_q));
        if (fix_q[0] == '0' || fix_q[0] == '\0') {
            cached_fix.valid = 0;
            return;
        }
        nmea_field(line, 2, lat,   sizeof(lat));
        nmea_field(line, 3, ns,    sizeof(ns));
        nmea_field(line, 4, lon,   sizeof(lon));
        nmea_field(line, 5, ew,    sizeof(ew));
        nmea_field(line, 7, nsv,   sizeof(nsv));
        nmea_field(line, 9, alt,   sizeof(alt));
        cached_fix.latitude  = nmea_coord(lat, ns[0]);
        cached_fix.longitude = nmea_coord(lon, ew[0]);
        cached_fix.altitude  = alt[0] ? atof(alt) : 0.0;
        cached_fix.sats_used = nsv[0] ? atoi(nsv) : 0;
        cached_fix.valid     = (lat[0] != '\0' && lon[0] != '\0') ? 1 : 0;
    }
}

/* Read all pending bytes from serial_fd, process complete NMEA lines. */
static void drain_serial(void) {
    char ch;
    while (read(serial_fd, &ch, 1) == 1) {
        if (ch == '\n') {
            line_buf[line_pos] = '\0';
            if (line_pos > 5 && line_buf[0] == '$')
                process_nmea_line(line_buf);
            line_pos = 0;
        } else if (ch != '\r' && line_pos < (int)sizeof(line_buf) - 1) {
            line_buf[line_pos++] = ch;
        }
    }
}

/* ── public API ── */

int gps_tag_init(void) {
    if (gps_open("localhost", "2947", &gpsd_state) != 0) {
        fprintf(stderr, "GPS: failed to connect to gpsd at localhost:2947\n");
        return -1;
    }
    gps_stream(&gpsd_state, WATCH_ENABLE | WATCH_JSON, NULL);
    use_serial    = 0;
    gps_connected = 1;
    memset(&cached_fix, 0, sizeof(cached_fix));
    memset(&last_poll,  0, sizeof(last_poll));
    return 0;
}

int gps_tag_init_serial(const char *device) {
    serial_fd = open(device, O_RDONLY | O_NOCTTY | O_NONBLOCK);
    if (serial_fd < 0) {
        fprintf(stderr, "GPS: failed to open %s\n", device);
        return -1;
    }

    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    tcgetattr(serial_fd, &tty);
    cfsetspeed(&tty, B9600);
    tty.c_cflag  = CS8 | CLOCAL | CREAD;
    tty.c_iflag  = IGNPAR;
    tty.c_oflag  = 0;
    tty.c_lflag  = 0;
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 0;
    tcsetattr(serial_fd, TCSANOW, &tty);

    use_serial    = 1;
    gps_connected = 1;
    line_pos      = 0;
    memset(&cached_fix, 0, sizeof(cached_fix));
    memset(&last_poll,  0, sizeof(last_poll));
    fprintf(stderr, "GPS: opened serial device %s\n", device);
    return 0;
}

void gps_tag_close(void) {
    if (!gps_connected) return;
    if (use_serial) {
        if (serial_fd >= 0) {
            close(serial_fd);
            serial_fd = -1;
        }
    } else {
        gps_stream(&gpsd_state, WATCH_DISABLE, NULL);
        gps_close(&gpsd_state);
    }
    gps_connected = 0;
    use_serial    = 0;
}

void gps_tag_get_fix(gps_fix_t *fix) {
    if (!gps_connected) {
        memset(fix, 0, sizeof(*fix));
        return;
    }

    /* Only poll at most once per second */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (now.tv_sec != last_poll.tv_sec) {
        last_poll = now;

        if (use_serial) {
            drain_serial();
        } else {
            while (gps_waiting(&gpsd_state, 0))
                gps_read(&gpsd_state, NULL, 0);

            memset(&cached_fix, 0, sizeof(cached_fix));
            if (gpsd_state.fix.mode >= MODE_2D &&
                isfinite(gpsd_state.fix.latitude) &&
                isfinite(gpsd_state.fix.longitude)) {
                cached_fix.latitude  = gpsd_state.fix.latitude;
                cached_fix.longitude = gpsd_state.fix.longitude;
                cached_fix.altitude  = isfinite(gpsd_state.fix.altMSL)
                                       ? gpsd_state.fix.altMSL : 0.0;
                cached_fix.sats_used = gpsd_state.satellites_used;
                cached_fix.valid = 1;
            }
        }
    }

    *fix = cached_fix;
}
