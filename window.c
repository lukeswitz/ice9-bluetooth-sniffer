/*
 * Copyright 2023 ICE9 Consulting LLC
 */

#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "window.h"

void window_init(window_t *w, unsigned n) {
    memset(w, 0, sizeof(*w));

    w->len = n;
    w->m = (unsigned)floor(log2(n)) + 1;
    w->n = 1 << w->m;
    w->mask = w->n - 1;

    w->num_allocated = w->n + w->len - 1;
    w->r = malloc(sizeof(int16_t) * w->num_allocated);
    w->i = malloc(sizeof(int16_t) * w->num_allocated);
}

void window_release(window_t *w) {
    free(w->r);
    free(w->i);
}

void window_push(window_t *w, int8_t *v) {
    ++w->read_index;
    w->read_index &= w->mask;
    if (w->read_index == 0) {
        memmove(w->r, w->r + w->n, (w->len - 1) * sizeof(*w->r));
        memmove(w->i, w->i + w->n, (w->len - 1) * sizeof(*w->i));
    }
    w->r[w->read_index + w->len - 1] = (int16_t)v[0] << 8;
    w->i[w->read_index + w->len - 1] = (int16_t)v[1] << 8;
}

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>

void window_dotprod(window_t *w, int16_t *b, int16_t *out) {
    unsigned i;
    int32x4_t real_acc = vdupq_n_s32(0), imag_acc = vdupq_n_s32(0);;

    for (i = 0; i < w->len; i += 4) {
        int16x4_t real_a_vec = vld1_s16(&w->r[w->read_index + i]);
        int16x4_t imag_a_vec = vld1_s16(&w->i[w->read_index + i]);
        int16x4_t b_vec = vld1_s16(&b[i]);

        int32x4_t real_a_ext = vmovl_s16(real_a_vec);
        int32x4_t imag_a_ext = vmovl_s16(imag_a_vec);
        int32x4_t b_ext = vmovl_s16(b_vec);

        real_acc = vmlaq_s32(real_acc, real_a_ext, b_ext);
        imag_acc = vmlaq_s32(imag_acc, imag_a_ext, b_ext);
    }

    int32_t real_sum = vgetq_lane_s32(real_acc, 0) + vgetq_lane_s32(real_acc, 1) +
                       vgetq_lane_s32(real_acc, 2) + vgetq_lane_s32(real_acc, 3);
    int32_t imag_sum = vgetq_lane_s32(imag_acc, 0) + vgetq_lane_s32(imag_acc, 1) +
                       vgetq_lane_s32(imag_acc, 2) + vgetq_lane_s32(imag_acc, 3);

    out[0] = real_sum >> 16;
    out[1] = imag_sum >> 16;
}

void window_dotprod_init(void) {
    fprintf(stderr, "SIMD: NEON\n");
}

#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <emmintrin.h>
#include <immintrin.h>

/*
 * Runtime-dispatched dot product implementations.
 *
 * SSE2 path uses _mm_madd_epi16 which multiplies 8 int16 pairs and
 * accumulates adjacent products into 4 int32 values in a single
 * instruction - much faster than the old SSE4.1 extend-to-32-and-multiply
 * approach.
 *
 * AVX2 path uses _mm256_madd_epi16 for 16-element chunks, falling
 * back to SSE2 for remainders. Useful for larger filter semi-lengths.
 *
 * Binary is portable: compiled with -msse4.1 baseline, AVX2 functions
 * use __attribute__((target("avx2"))) so they're only called on CPUs
 * that support it. Runtime check via __builtin_cpu_supports.
 */

typedef void (*dotprod_fn_t)(window_t *, int16_t *, int16_t *);
static dotprod_fn_t dotprod_impl = NULL;

static void dotprod_sse2(window_t *w, int16_t *b, int16_t *out) {
    unsigned i = 0;
    __m128i r_acc = _mm_setzero_si128();
    __m128i i_acc = _mm_setzero_si128();

    for (; i + 8 <= w->len; i += 8) {
        __m128i r_vec = _mm_loadu_si128((__m128i*)&w->r[w->read_index + i]);
        __m128i i_vec = _mm_loadu_si128((__m128i*)&w->i[w->read_index + i]);
        __m128i b_vec = _mm_loadu_si128((__m128i*)&b[i]);

        r_acc = _mm_add_epi32(r_acc, _mm_madd_epi16(r_vec, b_vec));
        i_acc = _mm_add_epi32(i_acc, _mm_madd_epi16(i_vec, b_vec));
    }

    /* handle remaining 4 elements (loadl zero-extends upper half) */
    if (i + 4 <= w->len) {
        __m128i r_vec = _mm_loadl_epi64((__m128i*)&w->r[w->read_index + i]);
        __m128i i_vec = _mm_loadl_epi64((__m128i*)&w->i[w->read_index + i]);
        __m128i b_vec = _mm_loadl_epi64((__m128i*)&b[i]);

        r_acc = _mm_add_epi32(r_acc, _mm_madd_epi16(r_vec, b_vec));
        i_acc = _mm_add_epi32(i_acc, _mm_madd_epi16(i_vec, b_vec));
    }

    /* horizontal sum of 4 int32 values */
    r_acc = _mm_add_epi32(r_acc, _mm_shuffle_epi32(r_acc, _MM_SHUFFLE(0,1,2,3)));
    r_acc = _mm_add_epi32(r_acc, _mm_shuffle_epi32(r_acc, _MM_SHUFFLE(2,3,0,1)));

    i_acc = _mm_add_epi32(i_acc, _mm_shuffle_epi32(i_acc, _MM_SHUFFLE(0,1,2,3)));
    i_acc = _mm_add_epi32(i_acc, _mm_shuffle_epi32(i_acc, _MM_SHUFFLE(2,3,0,1)));

    out[0] = _mm_cvtsi128_si32(r_acc) >> 16;
    out[1] = _mm_cvtsi128_si32(i_acc) >> 16;
}

__attribute__((target("avx2")))
static void dotprod_avx2(window_t *w, int16_t *b, int16_t *out) {
    unsigned i = 0;
    __m256i r_acc256 = _mm256_setzero_si256();
    __m256i i_acc256 = _mm256_setzero_si256();

    /* process 16 int16 elements at a time with AVX2 */
    for (; i + 16 <= w->len; i += 16) {
        __m256i r_vec = _mm256_loadu_si256((__m256i*)&w->r[w->read_index + i]);
        __m256i i_vec = _mm256_loadu_si256((__m256i*)&w->i[w->read_index + i]);
        __m256i b_vec = _mm256_loadu_si256((__m256i*)&b[i]);

        r_acc256 = _mm256_add_epi32(r_acc256, _mm256_madd_epi16(r_vec, b_vec));
        i_acc256 = _mm256_add_epi32(i_acc256, _mm256_madd_epi16(i_vec, b_vec));
    }

    /* reduce 256-bit to 128-bit */
    __m128i r_acc = _mm_add_epi32(_mm256_castsi256_si128(r_acc256),
                                  _mm256_extracti128_si256(r_acc256, 1));
    __m128i i_acc = _mm_add_epi32(_mm256_castsi256_si128(i_acc256),
                                  _mm256_extracti128_si256(i_acc256, 1));

    /* handle remaining 8 elements with SSE2 */
    for (; i + 8 <= w->len; i += 8) {
        __m128i r_vec = _mm_loadu_si128((__m128i*)&w->r[w->read_index + i]);
        __m128i i_vec = _mm_loadu_si128((__m128i*)&w->i[w->read_index + i]);
        __m128i b_vec = _mm_loadu_si128((__m128i*)&b[i]);

        r_acc = _mm_add_epi32(r_acc, _mm_madd_epi16(r_vec, b_vec));
        i_acc = _mm_add_epi32(i_acc, _mm_madd_epi16(i_vec, b_vec));
    }

    /* handle remaining 4 elements */
    if (i + 4 <= w->len) {
        __m128i r_vec = _mm_loadl_epi64((__m128i*)&w->r[w->read_index + i]);
        __m128i i_vec = _mm_loadl_epi64((__m128i*)&w->i[w->read_index + i]);
        __m128i b_vec = _mm_loadl_epi64((__m128i*)&b[i]);

        r_acc = _mm_add_epi32(r_acc, _mm_madd_epi16(r_vec, b_vec));
        i_acc = _mm_add_epi32(i_acc, _mm_madd_epi16(i_vec, b_vec));
    }

    /* horizontal sum of 4 int32 values */
    r_acc = _mm_add_epi32(r_acc, _mm_shuffle_epi32(r_acc, _MM_SHUFFLE(0,1,2,3)));
    r_acc = _mm_add_epi32(r_acc, _mm_shuffle_epi32(r_acc, _MM_SHUFFLE(2,3,0,1)));

    i_acc = _mm_add_epi32(i_acc, _mm_shuffle_epi32(i_acc, _MM_SHUFFLE(0,1,2,3)));
    i_acc = _mm_add_epi32(i_acc, _mm_shuffle_epi32(i_acc, _MM_SHUFFLE(2,3,0,1)));

    out[0] = _mm_cvtsi128_si32(r_acc) >> 16;
    out[1] = _mm_cvtsi128_si32(i_acc) >> 16;
}

void window_dotprod_init(void) {
    if (__builtin_cpu_supports("avx2")) {
        fprintf(stderr, "SIMD: AVX2\n");
        dotprod_impl = dotprod_avx2;
    } else {
        fprintf(stderr, "SIMD: SSE2\n");
        dotprod_impl = dotprod_sse2;
    }
}

void window_dotprod(window_t *w, int16_t *b, int16_t *out) {
    dotprod_impl(w, b, out);
}

#else
#warning Using non-vectorized dotprod

void window_dotprod(window_t *w, int16_t *b, int16_t *out) {
    unsigned i;
    int32_t sum_real = 0, sum_imag = 0;
    for (i = 0; i < w->len; ++i) {
        sum_real += w->r[w->read_index + i] * b[i];
        sum_imag += w->i[w->read_index + i] * b[i];
    }
    out[0] = sum_real >> 16;
    out[1] = sum_imag >> 16;
}

void window_dotprod_init(void) {
    fprintf(stderr, "SIMD: scalar\n");
}

#endif
