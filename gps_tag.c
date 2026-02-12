/*
 * Copyright 2025-2026 CEMAXECUTER LLC
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <gps.h>

#include "gps_tag.h"

static struct gps_data_t gpsd_state;
static int gps_connected = 0;

/* Cached GPS fix - only poll gpsd once per second since GPS updates at ~1Hz */
static gps_fix_t cached_fix;
static struct timespec last_poll;

int gps_tag_init(void) {
    if (gps_open("localhost", "2947", &gpsd_state) != 0) {
        fprintf(stderr, "GPS: failed to connect to gpsd at localhost:2947\n");
        return -1;
    }
    gps_stream(&gpsd_state, WATCH_ENABLE | WATCH_JSON, NULL);
    gps_connected = 1;
    memset(&cached_fix, 0, sizeof(cached_fix));
    memset(&last_poll, 0, sizeof(last_poll));
    return 0;
}

void gps_tag_close(void) {
    if (gps_connected) {
        gps_stream(&gpsd_state, WATCH_DISABLE, NULL);
        gps_close(&gpsd_state);
        gps_connected = 0;
    }
}

void gps_tag_get_fix(gps_fix_t *fix) {
    if (!gps_connected) {
        memset(fix, 0, sizeof(*fix));
        return;
    }

    /* Only poll gpsd at most once per second */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (now.tv_sec != last_poll.tv_sec) {
        last_poll = now;

        while (gps_waiting(&gpsd_state, 0))
            gps_read(&gpsd_state, NULL, 0);

        memset(&cached_fix, 0, sizeof(cached_fix));
        if (gpsd_state.fix.mode >= MODE_2D &&
            isfinite(gpsd_state.fix.latitude) &&
            isfinite(gpsd_state.fix.longitude)) {
            cached_fix.latitude = gpsd_state.fix.latitude;
            cached_fix.longitude = gpsd_state.fix.longitude;
            cached_fix.altitude = isfinite(gpsd_state.fix.altMSL) ? gpsd_state.fix.altMSL : 0.0;
            cached_fix.valid = 1;
        }
    }

    *fix = cached_fix;
}
