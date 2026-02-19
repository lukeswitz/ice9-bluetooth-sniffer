/*
 * Copyright 2022 ICE9 Consulting LLC
 */

#ifndef __USRP_H__
#define __USRP_H__

#include <uhd.h>

extern float usrp_gain_val;

void usrp_list(void);
uhd_usrp_handle usrp_setup(char *serial);
char *usrp_get_serial(char *name);
void *usrp_stream_thread(void *arg);
void usrp_close(uhd_usrp_handle usrp);
void usrp_set_gain(uhd_usrp_handle usrp, float gain);
int usrp_set_gain_runtime(void *dev, double gain);

#endif
