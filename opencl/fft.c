/*
 * Copyright 2025-2026 CEMAXECUTER LLC
 * OpenCL PFB + FFT backend using VkFFT
 *
 * Runs the polyphase filterbank channelizer and FFT entirely on GPU,
 * eliminating the CPU PFB bottleneck. The host just stages raw int8
 * samples; all heavy computation happens on the GPU.
 */

#define CL_TARGET_OPENCL_VERSION 120
#define VKFFT_BACKEND 3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <CL/opencl.h>

#include "vkFFT.h"
#include "fft.h"

extern volatile sig_atomic_t running;
extern void fft_done(void *, void *);

#define NUM_FFT 2
#define BATCH_SIZE 4096

/* ------------------------------------------------------------------ */
/* OpenCL PFB kernel source (embedded)                                 */
/* ------------------------------------------------------------------ */
static const char *pfb_kernel_source =
"__kernel void pfb_channelize(\n"
"    __global const char *raw_input,\n"
"    __global const float *h_sub,\n"
"    __global float *fft_buffer,\n"
"    const uint M,\n"
"    const uint M2,\n"
"    const uint h_sub_len,\n"
"    const uint pre_roll_steps,\n"
"    const uint batch_size,\n"
"    const uint initial_flag\n"
") {\n"
"    uint t = get_global_id(0);\n"
"    uint ch = get_global_id(1);\n"
"    if (t >= batch_size || ch >= M) return;\n"
"\n"
"    uint abs_t = t + pre_roll_steps;\n"
"    uint flag_at_t = (initial_flag + abs_t) & 1u;\n"
"\n"
"    uint sub_offset = flag_at_t\n"
"        ? ((M2 + ch) >= M ? (M2 + ch - M) : (M2 + ch))\n"
"        : ch;\n"
"\n"
"    uint is_lower = (ch < M2) ? 1u : 0u;\n"
"    uint push_parity = is_lower\n"
"        ? (initial_flag & 1u)\n"
"        : ((initial_flag + 1u) & 1u);\n"
"\n"
"    uint latest_push = ((abs_t & 1u) == push_parity)\n"
"        ? abs_t : (abs_t - 1u);\n"
"\n"
"    uint ch_pos = is_lower\n"
"        ? (M2 - 1u - ch)\n"
"        : (M - 1u - ch);\n"
"\n"
"    float real_sum = 0.0f, imag_sum = 0.0f;\n"
"    for (uint k = 0; k < h_sub_len; ++k) {\n"
"        uint push_step = latest_push - 2u * (h_sub_len - 1u - k);\n"
"        uint raw_idx = push_step * M2 + ch_pos;\n"
"        float sr = (float)(raw_input[raw_idx * 2u]);\n"
"        float si = (float)(raw_input[raw_idx * 2u + 1u]);\n"
"        float coeff = h_sub[sub_offset * h_sub_len + k];\n"
"        real_sum += sr * coeff;\n"
"        imag_sum += si * coeff;\n"
"    }\n"
"\n"
"    float scale = 1.0f / 256.0f;\n"
"    uint out_idx = t * M + ch;\n"
"    fft_buffer[out_idx * 2u] = real_sum * scale;\n"
"    fft_buffer[out_idx * 2u + 1u] = imag_sum * scale;\n"
"}\n";

/* ------------------------------------------------------------------ */
/* Per-buffer context (double-buffered)                                */
/* ------------------------------------------------------------------ */
typedef struct {
    VkFFTApplication app;
    cl_command_queue queue;

    /* GPU buffers */
    cl_mem cl_fft_buffer;       /* float complex [BATCH_SIZE * M] */
    cl_mem cl_raw_buffer;       /* int8 [(pre_roll_steps + BATCH_SIZE) * M] */

    /* Host buffers */
    float *fft_host_ptr;        /* FFT output readback */
    int8_t *raw_host_ptr;       /* pre-roll + batch raw input */

    uint64_t fft_buffer_size;
    uint64_t raw_buffer_size;

    enum {
        BUFFER_STATE_READY,
        BUFFER_STATE_FILLING,
        BUFFER_STATE_EXECUTING,
    } buffer_state;

    pthread_mutex_t mutex;
    pthread_cond_t state_cond;
} fft_context_t;

static fft_context_t fft_ctx[NUM_FFT];
static unsigned cur_fft = 0;

/* OpenCL globals */
static cl_context cl_ctx;
static cl_device_id cl_device;
static cl_program pfb_program;
static cl_kernel pfb_kern;
static cl_mem cl_h_sub;         /* GPU: float subfilter coefficients */

/* PFB parameters */
static unsigned pfb_M, pfb_M2, pfb_h_sub_len;
static unsigned pre_roll_steps;
static unsigned pre_roll_bytes;
static unsigned initial_flag;   /* flag at start of pre-roll data */
static int8_t *pre_roll_buf;   /* saved pre-roll between batches */

static pthread_t fft_worker_thread;

/* ------------------------------------------------------------------ */
/* GPU worker thread                                                   */
/* ------------------------------------------------------------------ */
static void *fft_worker(void *arg) {
    unsigned idx = 0;

    while (running) {
        fft_context_t *f = &fft_ctx[idx];

        /* wait for buffer to be submitted */
        pthread_mutex_lock(&f->mutex);
        while (running && f->buffer_state != BUFFER_STATE_EXECUTING)
            pthread_cond_wait(&f->state_cond, &f->mutex);
        pthread_mutex_unlock(&f->mutex);
        if (!running) break;

        /* 1. Upload raw int8 data to GPU */
        cl_int err = clEnqueueWriteBuffer(f->queue, f->cl_raw_buffer,
                                          CL_TRUE, 0, f->raw_buffer_size,
                                          f->raw_host_ptr, 0, NULL, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "OpenCL raw upload error: %d\n", err);
            break;
        }

        /* 2. Launch PFB kernel */
        size_t global_work[2] = { BATCH_SIZE, pfb_M };
        err  = clSetKernelArg(pfb_kern, 0, sizeof(cl_mem), &f->cl_raw_buffer);
        err |= clSetKernelArg(pfb_kern, 1, sizeof(cl_mem), &cl_h_sub);
        err |= clSetKernelArg(pfb_kern, 2, sizeof(cl_mem), &f->cl_fft_buffer);
        err |= clSetKernelArg(pfb_kern, 3, sizeof(cl_uint), &pfb_M);
        err |= clSetKernelArg(pfb_kern, 4, sizeof(cl_uint), &pfb_M2);
        err |= clSetKernelArg(pfb_kern, 5, sizeof(cl_uint), &pfb_h_sub_len);
        err |= clSetKernelArg(pfb_kern, 6, sizeof(cl_uint), &pre_roll_steps);
        cl_uint bs = BATCH_SIZE;
        err |= clSetKernelArg(pfb_kern, 7, sizeof(cl_uint), &bs);
        err |= clSetKernelArg(pfb_kern, 8, sizeof(cl_uint), &initial_flag);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "OpenCL kernel arg error: %d\n", err);
            break;
        }

        err = clEnqueueNDRangeKernel(f->queue, pfb_kern, 2, NULL,
                                     global_work, NULL, 0, NULL, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "OpenCL PFB kernel error: %d\n", err);
            break;
        }

        /* 3. Run VkFFT (inverse FFT, in-place on cl_fft_buffer) */
        VkFFTLaunchParams params = {};
        params.commandQueue = &f->queue;
        VkFFTResult res = VkFFTAppend(&f->app, 1, &params);
        if (res != VKFFT_SUCCESS) {
            fprintf(stderr, "VkFFT execute error: %d\n", res);
            break;
        }
        clFinish(f->queue);

        /* 4. Read FFT output back to host */
        err = clEnqueueReadBuffer(f->queue, f->cl_fft_buffer, CL_TRUE,
                                  0, f->fft_buffer_size, f->fft_host_ptr,
                                  0, NULL, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "OpenCL readback error: %d\n", err);
            break;
        }

        /* 5. Signal completion */
        fft_done(f, f->fft_host_ptr);

        idx = (idx + 1) % NUM_FFT;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Initialization                                                      */
/* ------------------------------------------------------------------ */
static cl_device_id find_opencl_device(void) {
    cl_int err;
    cl_uint num_platforms;
    cl_platform_id platforms[16];
    cl_device_id device = 0;
    char name[256], plat_name[256];

    err = clGetPlatformIDs(16, platforms, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0)
        return 0;

    /* prefer GPU */
    for (cl_uint p = 0; p < num_platforms; p++) {
        err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 1, &device, NULL);
        if (err == CL_SUCCESS) {
            clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(name), name, NULL);
            clGetPlatformInfo(platforms[p], CL_PLATFORM_NAME,
                              sizeof(plat_name), plat_name, NULL);
            fprintf(stderr, "OpenCL GPU: %s (%s)\n", name, plat_name);
            return device;
        }
    }

    /* fall back to any device */
    for (cl_uint p = 0; p < num_platforms; p++) {
        err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, 1, &device, NULL);
        if (err == CL_SUCCESS) {
            clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(name), name, NULL);
            fprintf(stderr, "OpenCL device: %s\n", name);
            return device;
        }
    }

    return 0;
}

static VkFFTResult init_fft_context(fft_context_t *f, unsigned width,
                                    unsigned batch_size) {
    cl_int err;

    pthread_mutex_init(&f->mutex, NULL);
    pthread_cond_init(&f->state_cond, NULL);
    f->buffer_state = BUFFER_STATE_READY;

    f->queue = clCreateCommandQueue(cl_ctx, cl_device, 0, &err);
    if (err != CL_SUCCESS) return VKFFT_ERROR_FAILED_TO_CREATE_COMMAND_QUEUE;

    /* FFT buffer: float complex [batch_size * width] */
    f->fft_buffer_size = (uint64_t)sizeof(float) * 2 * width * batch_size;
    f->fft_host_ptr = malloc(f->fft_buffer_size);
    if (!f->fft_host_ptr) return VKFFT_ERROR_MALLOC_FAILED;

    f->cl_fft_buffer = clCreateBuffer(cl_ctx, CL_MEM_READ_WRITE,
                                      f->fft_buffer_size, NULL, &err);
    if (err != CL_SUCCESS) return VKFFT_ERROR_FAILED_TO_CREATE_BUFFER;

    /* Raw input buffer: int8 [(pre_roll_steps + batch_size) * M] bytes */
    f->raw_buffer_size = (uint64_t)(pre_roll_steps + batch_size) * pfb_M;
    f->raw_host_ptr = calloc(1, f->raw_buffer_size);
    if (!f->raw_host_ptr) return VKFFT_ERROR_MALLOC_FAILED;

    f->cl_raw_buffer = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY,
                                      f->raw_buffer_size, NULL, &err);
    if (err != CL_SUCCESS) return VKFFT_ERROR_FAILED_TO_CREATE_BUFFER;

    /* VkFFT setup for the FFT buffer */
    VkFFTConfiguration config = {};
    config.FFTdim = 1;
    config.size[0] = width;
    config.numberBatches = batch_size;
    config.device = &cl_device;
    config.context = &cl_ctx;
    config.commandQueue = &f->queue;
    config.buffer = &f->cl_fft_buffer;
    config.bufferSize = &f->fft_buffer_size;

    return initializeVkFFT(&f->app, config);
}

static int compile_pfb_kernel(void) {
    cl_int err;

    pfb_program = clCreateProgramWithSource(cl_ctx, 1, &pfb_kernel_source,
                                            NULL, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL create program error: %d\n", err);
        return -1;
    }

    err = clBuildProgram(pfb_program, 1, &cl_device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        char log[4096];
        clGetProgramBuildInfo(pfb_program, cl_device, CL_PROGRAM_BUILD_LOG,
                              sizeof(log), log, NULL);
        fprintf(stderr, "OpenCL build error: %s\n", log);
        return -1;
    }

    pfb_kern = clCreateKernel(pfb_program, "pfb_channelize", &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL create kernel error: %d\n", err);
        return -1;
    }

    return 0;
}

/* saved for deferred GPU upload in init_fft */
static int16_t *saved_h_sub = NULL;
static unsigned saved_h_sub_count = 0;

void init_pfb_gpu(int16_t *h_sub, unsigned M, unsigned m, unsigned h_sub_len) {
    pfb_M = M;
    pfb_M2 = M / 2;
    pfb_h_sub_len = h_sub_len;

    /* pre-roll: enough steps so all channels have full windows */
    pre_roll_steps = 2 * h_sub_len - 1;
    pre_roll_bytes = pre_roll_steps * pfb_M;

    /*
     * initial_flag: the PFB flag at step 0 of the raw buffer.
     * The CPU PFB starts with flag=0 at step 0, alternating each step.
     * Flag at step s is simply s & 1.  Since abs_t in the kernel already
     * represents the buffer step index, initial_flag must be 0 so that
     * flag_at_t = (0 + abs_t) & 1 = abs_t & 1.
     */
    initial_flag = 0;

    /* pre-roll buffer (zeros at startup = zero-initialized windows) */
    pre_roll_buf = calloc(1, pre_roll_bytes);
    if (!pre_roll_buf) {
        fprintf(stderr, "Failed to allocate pre-roll buffer\n");
        return;
    }

    /* save coefficients for upload after OpenCL context is created */
    saved_h_sub_count = M * h_sub_len;
    saved_h_sub = malloc(saved_h_sub_count * sizeof(int16_t));
    if (!saved_h_sub) {
        fprintf(stderr, "Failed to allocate coefficient buffer\n");
        return;
    }
    memcpy(saved_h_sub, h_sub, saved_h_sub_count * sizeof(int16_t));

    fprintf(stderr, "GPU PFB: M=%u h_sub_len=%u pre_roll=%u initial_flag=%u\n",
            pfb_M, pfb_h_sub_len, pre_roll_steps, initial_flag);
}

static void upload_pfb_coefficients(void) {
    cl_int err;
    float *h_sub_float = malloc(saved_h_sub_count * sizeof(float));
    if (!h_sub_float) {
        fprintf(stderr, "Failed to allocate PFB coefficient buffer\n");
        return;
    }
    for (unsigned i = 0; i < saved_h_sub_count; i++)
        h_sub_float[i] = (float)saved_h_sub[i] / 32768.0f;

    cl_h_sub = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                              saved_h_sub_count * sizeof(float), h_sub_float, &err);
    free(h_sub_float);
    free(saved_h_sub);
    saved_h_sub = NULL;
    if (err != CL_SUCCESS)
        fprintf(stderr, "OpenCL h_sub buffer error: %d\n", err);
}

VkFFTResult init_fft(unsigned width, unsigned batch_size) {
    cl_int err;
    VkFFTResult r;

    cl_device = find_opencl_device();
    if (!cl_device) {
        fprintf(stderr, "No OpenCL device found\n");
        return VKFFT_ERROR_FAILED_TO_FIND_PHYSICAL_DEVICE;
    }

    cl_ctx = clCreateContext(NULL, 1, &cl_device, NULL, NULL, &err);
    if (err != CL_SUCCESS) return VKFFT_ERROR_FAILED_TO_CREATE_CONTEXT;

    /* upload PFB coefficients to GPU (needs context) */
    upload_pfb_coefficients();

    /* compile PFB kernel */
    if (compile_pfb_kernel() != 0)
        return VKFFT_ERROR_FAILED_TO_COMPILE_PROGRAM;

    for (unsigned i = 0; i < NUM_FFT; i++) {
        r = init_fft_context(&fft_ctx[i], width, batch_size);
        if (r != VKFFT_SUCCESS) {
            fprintf(stderr, "VkFFT init error: %d\n", r);
            return r;
        }
    }

    pthread_create(&fft_worker_thread, NULL, fft_worker, NULL);

    return VKFFT_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Buffer management                                                   */
/* ------------------------------------------------------------------ */
static void submit_fft(fft_context_t *f) {
    if (f->buffer_state != BUFFER_STATE_FILLING)
        return;

    pthread_mutex_lock(&f->mutex);
    f->buffer_state = BUFFER_STATE_EXECUTING;
    pthread_cond_signal(&f->state_cond);
    pthread_mutex_unlock(&f->mutex);
}

int8_t *get_next_raw_buffer(void) {
    fft_context_t *f = &fft_ctx[cur_fft];

    if (f->buffer_state == BUFFER_STATE_FILLING) {
        /* save tail of current buffer as pre-roll for next batch */
        /* the batch data starts at pre_roll_bytes in raw_host_ptr */
        /* tail = last pre_roll_steps steps of the batch */
        size_t batch_tail = pre_roll_bytes +
                            (size_t)(BATCH_SIZE - pre_roll_steps) * pfb_M;
        memcpy(pre_roll_buf, &f->raw_host_ptr[batch_tail], pre_roll_bytes);
    }

    /* submit current buffer to GPU */
    submit_fft(f);

    /* switch to next buffer */
    cur_fft = (cur_fft + 1) % NUM_FFT;
    f = &fft_ctx[cur_fft];

    /* wait for it to be available */
    pthread_mutex_lock(&f->mutex);
    while (running && f->buffer_state != BUFFER_STATE_READY)
        pthread_cond_wait(&f->state_cond, &f->mutex);
    if (!running) {
        pthread_mutex_unlock(&f->mutex);
        pthread_exit(NULL);
    }
    f->buffer_state = BUFFER_STATE_FILLING;
    pthread_mutex_unlock(&f->mutex);

    /* copy pre-roll to beginning of buffer */
    memcpy(f->raw_host_ptr, pre_roll_buf, pre_roll_bytes);

    /* return pointer to batch region (after pre-roll) */
    return &f->raw_host_ptr[pre_roll_bytes];
}

/* legacy interface for compatibility */
void *get_next_buffer(void) {
    return (void *)get_next_raw_buffer();
}

void release_buffer(void *fft_in) {
    fft_context_t *f = (fft_context_t *)fft_in;
    pthread_mutex_lock(&f->mutex);
    f->buffer_state = BUFFER_STATE_READY;
    pthread_cond_signal(&f->state_cond);
    pthread_mutex_unlock(&f->mutex);
}

/* ------------------------------------------------------------------ */
/* Cleanup                                                             */
/* ------------------------------------------------------------------ */
static void cleanup_fft_context(fft_context_t *f) {
    if (f->cl_fft_buffer) clReleaseMemObject(f->cl_fft_buffer);
    if (f->cl_raw_buffer) clReleaseMemObject(f->cl_raw_buffer);
    if (f->queue) clReleaseCommandQueue(f->queue);
    free(f->fft_host_ptr);
    free(f->raw_host_ptr);
    deleteVkFFT(&f->app);
    pthread_mutex_destroy(&f->mutex);
    pthread_cond_destroy(&f->state_cond);
}

void deinit_vkfft(void) {
    /*
     * Best-effort cleanup. The worker thread may be blocked inside a
     * GPU operation (clFinish, VkFFTAppend) that won't return until
     * the current batch completes, so we can't reliably join it.
     * Cancel and detach instead -- the OS will reclaim GPU resources
     * on process exit.
     */
    pthread_cancel(fft_worker_thread);
    pthread_detach(fft_worker_thread);

    /* Free host-side allocations */
    free(pre_roll_buf);
    pre_roll_buf = NULL;

    for (unsigned i = 0; i < NUM_FFT; i++) {
        free(fft_ctx[i].fft_host_ptr);
        fft_ctx[i].fft_host_ptr = NULL;
        free(fft_ctx[i].raw_host_ptr);
        fft_ctx[i].raw_host_ptr = NULL;
        pthread_mutex_destroy(&fft_ctx[i].mutex);
        pthread_cond_destroy(&fft_ctx[i].state_cond);
    }

    /*
     * OpenCL objects (cl_mem, cl_context, cl_kernel, cl_program) and
     * VkFFT applications are left for the driver to clean up on exit.
     * Releasing them while the worker thread may still reference them
     * would be a use-after-free.
     */
}
