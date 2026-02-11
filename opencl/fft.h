/*
 * Copyright 2025 CEMAXECUTER LLC
 * OpenCL fused PFB + FFT backend header
 */

#pragma once
#include "../vkfft/fft.h"

#include <stdint.h>

void init_pfb_gpu(int16_t *h_sub, unsigned M, unsigned m, unsigned h_sub_len);
int8_t *get_next_raw_buffer(void);
