/*
 * Copyright 2025-2026 CEMAXECUTER LLC
 */

#ifndef __GPS_TAG_H__
#define __GPS_TAG_H__

#include <stdint.h>

typedef struct _gps_fix_t {
    double latitude;
    double longitude;
    double altitude;
    int valid;          // nonzero if we have a fix
} gps_fix_t;

int gps_tag_init(void);
int gps_tag_init_serial(const char *device);
void gps_tag_close(void);
void gps_tag_get_fix(gps_fix_t *fix);

#endif
