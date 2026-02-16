/*
 * Copyright 2026 ICE9 Consulting LLC
 * Metal PFB kernel - ported from OpenCL version
 *
 * Polyphase filterbank channelizer compute kernel for Apple Silicon GPU.
 * Processes raw int8 I/Q samples through filter bank to produce channelized
 * float complex output for subsequent FFT.
 */

#include <metal_stdlib>
using namespace metal;

kernel void pfb_channelize(
    const device char *raw_input [[buffer(0)]],
    const device float *h_sub [[buffer(1)]],
    device float *fft_buffer [[buffer(2)]],
    constant uint &M [[buffer(3)]],
    constant uint &M2 [[buffer(4)]],
    constant uint &h_sub_len [[buffer(5)]],
    constant uint &pre_roll_steps [[buffer(6)]],
    constant uint &batch_size [[buffer(7)]],
    constant uint &initial_flag [[buffer(8)]],
    uint2 gid [[thread_position_in_grid]])
{
    uint t = gid.x;   // time index
    uint ch = gid.y;  // channel index

    if (t >= batch_size || ch >= M) return;

    uint abs_t = t + pre_roll_steps;
    uint flag_at_t = (initial_flag + abs_t) & 1u;

    uint sub_offset = flag_at_t
        ? ((M2 + ch) >= M ? (M2 + ch - M) : (M2 + ch))
        : ch;

    uint is_lower = (ch < M2) ? 1u : 0u;
    uint push_parity = is_lower
        ? (initial_flag & 1u)
        : ((initial_flag + 1u) & 1u);

    uint latest_push = ((abs_t & 1u) == push_parity)
        ? abs_t : (abs_t - 1u);

    uint ch_pos = is_lower
        ? (M2 - 1u - ch)
        : (M - 1u - ch);

    float real_sum = 0.0f, imag_sum = 0.0f;
    for (uint k = 0; k < h_sub_len; ++k) {
        uint push_step = latest_push - 2u * (h_sub_len - 1u - k);
        uint raw_idx = push_step * M2 + ch_pos;
        float sr = (float)(raw_input[raw_idx * 2u]);
        float si = (float)(raw_input[raw_idx * 2u + 1u]);
        float coeff = h_sub[sub_offset * h_sub_len + k];
        real_sum += sr * coeff;
        imag_sum += si * coeff;
    }

    float scale = 1.0f / 256.0f;
    uint out_idx = t * M + ch;
    fft_buffer[out_idx * 2u] = real_sum * scale;
    fft_buffer[out_idx * 2u + 1u] = imag_sum * scale;
}
