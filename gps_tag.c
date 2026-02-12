/*
 * Copyright 2025-2026 CEMAXECUTER LLC
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <gps.h>

#include "gps_tag.h"

static struct gps_data_t gpsd_state;
static int gps_connected = 0;

int gps_tag_init(void) {
    if (gps_open("localhost", "2947", &gpsd_state) != 0) {
        fprintf(stderr, "GPS: failed to connect to gpsd at localhost:2947\n");
        return -1;
    }
    gps_stream(&gpsd_state, WATCH_ENABLE | WATCH_JSON, NULL);
    gps_connected = 1;
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
    memset(fix, 0, sizeof(*fix));

    if (!gps_connected)
        return;

    // Non-blocking read: consume any pending data from gpsd
    while (gps_waiting(&gpsd_state, 0))
        gps_read(&gpsd_state, NULL, 0);

    if (gpsd_state.fix.mode >= MODE_2D &&
        isfinite(gpsd_state.fix.latitude) &&
        isfinite(gpsd_state.fix.longitude)) {
        fix->latitude = gpsd_state.fix.latitude;
        fix->longitude = gpsd_state.fix.longitude;
        fix->altitude = isfinite(gpsd_state.fix.altMSL) ? gpsd_state.fix.altMSL : 0.0;
        fix->valid = 1;
    }
}
