/*
 * Copyright 2023 ICE9 Consulting LLC
 */

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

//general parts
#include <stdio.h>
#include <vector>
#include <memory>
#include <string.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

#include "vkFFT.h"

#include "Foundation/Foundation.hpp"
#include "QuartzCore/QuartzCore.hpp"
#include "Metal/Metal.hpp"

extern sig_atomic_t running;

#include "fft.h"

struct VkGPU {
    MTL::Device* device;
    MTL::CommandQueue* queue;
};

struct fft_t {
    VkGPU gpu;
    VkFFTApplication app;

    MTL::Buffer *buffer;        /* FFT buffer (float complex) */
    MTL::Buffer *raw_buffer;    /* PFB raw input (int8) */
    uint64_t bufferSize;
    uint64_t rawBufferSize;
    enum buffer_state_t {
        BUFFER_STATE_READY,
        BUFFER_STATE_FILLING,
        BUFFER_STATE_EXECUTING,
        BUFFER_STATE_DONE,
        BUFFER_STATE_EMPTYING,
    } buffer_state;

    pthread_mutex_t mutex;
    pthread_cond_t buffer_state_cond;
};

/* PFB globals */
static MTL::ComputePipelineState *pfb_pipeline = nullptr;
static MTL::Buffer *pfb_coeff_buffer = nullptr;
static unsigned pfb_M, pfb_M2, pfb_h_sub_len;
static unsigned pre_roll_steps;
static unsigned pre_roll_bytes;
static unsigned initial_flag;
static int8_t *pre_roll_buf = nullptr;

#define NUM_FFT 2
fft_t fft[NUM_FFT] = {};
unsigned cur_fft = 0;

extern "C" {
    void fft_done(void *, void *);
    void init_pfb_gpu(int16_t *h_sub, unsigned M, unsigned m, unsigned h_sub_len);
    int8_t *get_next_raw_buffer(void);
}

VkFFTResult init_fft(fft_t *f, unsigned width, unsigned batch_size, MTL::Device *device) {
    pthread_cond_init(&f->buffer_state_cond, NULL);
    pthread_mutex_init(&f->mutex, NULL);

    f->buffer_state = fft_t::BUFFER_STATE_READY;

    f->gpu.device = device;
    MTL::CommandQueue* queue = device->newCommandQueue();
    f->gpu.queue = queue;
    VkFFTResult resFFT = VKFFT_SUCCESS;

    VkFFTConfiguration configuration = {};
    configuration.FFTdim = 1;
    configuration.size[0] = width;
    configuration.numberBatches = batch_size;

    configuration.device = f->gpu.device;
    configuration.queue = f->gpu.queue;

    // FFT buffer (float complex)
    f->bufferSize = (uint64_t)sizeof(float) * 2 * width * batch_size;
    f->buffer = f->gpu.device->newBuffer(f->bufferSize, MTL::ResourceStorageModeShared);
    configuration.buffer = &f->buffer;
    configuration.bufferSize = &f->bufferSize;

    // Raw input buffer for PFB (int8 I/Q samples)
    f->rawBufferSize = (uint64_t)(pre_roll_steps + batch_size) * pfb_M;
    f->raw_buffer = f->gpu.device->newBuffer(f->rawBufferSize, MTL::ResourceStorageModeShared);

    // Initialize VkFFT
    resFFT = initializeVkFFT(&f->app, configuration);
    return resFFT;
}

static bool compile_pfb_kernel(MTL::Device *device) {
    NS::Error *error = nullptr;

    /* load Metal library from the compiled metallib file */
    NS::String *lib_path = NS::String::string("default.metallib", NS::UTF8StringEncoding);
    MTL::Library *lib = device->newLibrary(lib_path, &error);
    if (!lib || error) {
        if (error) {
            NS::String *desc = error->localizedDescription();
            fprintf(stderr, "Metal: Failed to load library: %s\n", desc->utf8String());
        }
        return false;
    }

    /* get the PFB kernel function */
    NS::String *kernel_name = NS::String::string("pfb_channelize", NS::UTF8StringEncoding);
    MTL::Function *pfb_func = lib->newFunction(kernel_name);
    if (!pfb_func) {
        fprintf(stderr, "Metal: Failed to find pfb_channelize kernel\n");
        lib->release();
        return false;
    }

    /* create compute pipeline state */
    pfb_pipeline = device->newComputePipelineState(pfb_func, &error);
    if (!pfb_pipeline || error) {
        if (error) {
            NS::String *desc = error->localizedDescription();
            fprintf(stderr, "Metal: Pipeline creation error: %s\n", desc->utf8String());
        }
        pfb_func->release();
        lib->release();
        return false;
    }

    pfb_func->release();
    lib->release();
    return true;
}

/* saved for deferred GPU upload */
static int16_t *saved_h_sub = nullptr;
static unsigned saved_h_sub_count = 0;

void init_pfb_gpu(int16_t *h_sub, unsigned M, unsigned m, unsigned h_sub_len) {
    pfb_M = M;
    pfb_M2 = M / 2;
    pfb_h_sub_len = h_sub_len;

    pre_roll_steps = 2 * h_sub_len - 1;
    pre_roll_bytes = pre_roll_steps * pfb_M;
    initial_flag = 0;

    pre_roll_buf = (int8_t *)calloc(1, pre_roll_bytes);
    if (!pre_roll_buf) {
        fprintf(stderr, "Failed to allocate pre-roll buffer\n");
        return;
    }

    /* save coefficients for upload after Metal device is available */
    saved_h_sub_count = M * h_sub_len;
    saved_h_sub = (int16_t *)malloc(saved_h_sub_count * sizeof(int16_t));
    if (!saved_h_sub) {
        fprintf(stderr, "Failed to allocate coefficient buffer\n");
        return;
    }
    memcpy(saved_h_sub, h_sub, saved_h_sub_count * sizeof(int16_t));

    fprintf(stderr, "Metal PFB: M=%u h_sub_len=%u pre_roll=%u\n",
            pfb_M, pfb_h_sub_len, pre_roll_steps);
}

static void upload_pfb_coefficients(MTL::Device *device) {
    if (!saved_h_sub || saved_h_sub_count == 0)
        return;

    /* convert int16 to float */
    float *h_sub_float = (float *)malloc(saved_h_sub_count * sizeof(float));
    if (!h_sub_float) {
        fprintf(stderr, "Failed to allocate PFB coefficient buffer\n");
        return;
    }

    for (unsigned i = 0; i < saved_h_sub_count; i++)
        h_sub_float[i] = (float)saved_h_sub[i] / 32768.0f;

    /* create Metal buffer and upload */
    pfb_coeff_buffer = device->newBuffer(h_sub_float,
                                         saved_h_sub_count * sizeof(float),
                                         MTL::ResourceStorageModeShared);

    free(h_sub_float);
    free(saved_h_sub);
    saved_h_sub = nullptr;

    if (!pfb_coeff_buffer)
        fprintf(stderr, "Failed to create PFB coefficient buffer\n");
}

VkFFTResult init_fft(unsigned width, unsigned batch_size) {
    NS::Array* devices = MTL::CopyAllDevices();
    MTL::Device* device = (MTL::Device*)devices->object(0);
    VkFFTResult r;

    /* compile PFB kernel */
    if (!compile_pfb_kernel(device)) {
        fprintf(stderr, "Failed to compile PFB kernel\n");
        devices->release();
        return VKFFT_ERROR_FAILED_TO_COMPILE_PROGRAM;
    }

    /* upload PFB coefficients */
    upload_pfb_coefficients(device);

    for (unsigned i = 0; i < NUM_FFT; ++i)
        if ((r = init_fft(&fft[i], width, batch_size, device)) != VKFFT_SUCCESS)
            return r;

    devices->release();

    return r;
}

VkFFTResult submit_fft(void) {
    VkFFTResult resFFT = VKFFT_SUCCESS;
    fft_t *f = &fft[cur_fft];
    VkFFTLaunchParams launchParams = {};

    if (f->buffer_state != fft_t::BUFFER_STATE_FILLING)
        return VKFFT_SUCCESS;

    f->buffer_state = fft_t::BUFFER_STATE_EXECUTING;

    MTL::CommandBuffer* commandBuffer = f->gpu.queue->commandBuffer();
    if (commandBuffer == NULL) return VKFFT_ERROR_FAILED_TO_CREATE_COMMAND_LIST;

    /* First dispatch PFB kernel if pipeline is available */
    if (pfb_pipeline != nullptr) {
        MTL::ComputeCommandEncoder* pfbEncoder = commandBuffer->computeCommandEncoder();
        if (!pfbEncoder) return VKFFT_ERROR_FAILED_TO_CREATE_COMMAND_LIST;

        pfbEncoder->setComputePipelineState(pfb_pipeline);
        pfbEncoder->setBuffer(f->raw_buffer, 0, 0);           /* raw_input */
        pfbEncoder->setBuffer(pfb_coeff_buffer, 0, 1);        /* h_sub */
        pfbEncoder->setBuffer(f->buffer, 0, 2);               /* fft_buffer */
        pfbEncoder->setBytes(&pfb_M, sizeof(uint32_t), 3);
        pfbEncoder->setBytes(&pfb_M2, sizeof(uint32_t), 4);
        pfbEncoder->setBytes(&pfb_h_sub_len, sizeof(uint32_t), 5);
        pfbEncoder->setBytes(&pre_roll_steps, sizeof(uint32_t), 6);
        uint32_t batch_size = 4096;  /* BATCH_SIZE */
        pfbEncoder->setBytes(&batch_size, sizeof(uint32_t), 7);
        pfbEncoder->setBytes(&initial_flag, sizeof(uint32_t), 8);

        /* grid size: [BATCH_SIZE, M] */
        MTL::Size gridSize = MTL::Size(batch_size, pfb_M, 1);
        MTL::Size threadgroupSize = MTL::Size(
            std::min((uint32_t)16, batch_size),
            std::min((uint32_t)16, pfb_M),
            1
        );

        pfbEncoder->dispatchThreads(gridSize, threadgroupSize);
        pfbEncoder->endEncoding();

        static int dispatch_count = 0;
        if (++dispatch_count <= 3) {
            fprintf(stderr, "Metal PFB dispatched: grid=%u,%u threads=%u,%u\n",
                    (unsigned)gridSize.width, (unsigned)gridSize.height,
                    (unsigned)threadgroupSize.width, (unsigned)threadgroupSize.height);
        }
    }

    /* Then dispatch FFT */
    launchParams.commandBuffer = commandBuffer;
    MTL::ComputeCommandEncoder* commandEncoder = commandBuffer->computeCommandEncoder();
    if (commandEncoder == 0) return VKFFT_ERROR_FAILED_TO_CREATE_COMMAND_LIST;
    launchParams.commandEncoder = commandEncoder;
    resFFT = VkFFTAppend(&f->app, 1, &launchParams);
    if (resFFT != VKFFT_SUCCESS) return resFFT;
    commandEncoder->endEncoding();

    commandBuffer->addCompletedHandler([f](MTL::CommandBuffer *completedCommandBuffer) {
        f->buffer_state = fft_t::BUFFER_STATE_DONE;
        fft_done(f, f->buffer->contents());
    });

    commandBuffer->commit();

    return resFFT;
}

// start FFT of first buffer on GPU
// then ready next buffer
void *get_next_buffer(void) {
    VkFFTResult r = submit_fft();
    if (r != VKFFT_SUCCESS) return NULL;

    cur_fft = (cur_fft + 1) % NUM_FFT;
    fft_t *f = &fft[cur_fft];

    pthread_mutex_lock(&f->mutex);
    while (running && f->buffer_state != fft_t::BUFFER_STATE_READY)
        pthread_cond_wait(&f->buffer_state_cond, &f->mutex);
    if (!running) {
        pthread_mutex_unlock(&f->mutex);
        pthread_exit(NULL);
    }
    f->buffer_state = fft_t::BUFFER_STATE_FILLING;
    pthread_mutex_unlock(&f->mutex);
    return f->buffer->contents();
}

int8_t *get_next_raw_buffer(void) {
    fft_t *f = &fft[cur_fft];

    if (f->buffer_state == fft_t::BUFFER_STATE_FILLING) {
        /* save tail of current buffer as pre-roll for next batch */
        size_t batch_tail = pre_roll_bytes +
                            (size_t)(4096 - pre_roll_steps) * pfb_M;  /* BATCH_SIZE=4096 */
        void *raw_contents = f->raw_buffer->contents();
        memcpy(pre_roll_buf, (int8_t *)raw_contents + batch_tail, pre_roll_bytes);
    }

    /* submit current buffer */
    submit_fft();

    /* switch to next buffer */
    cur_fft = (cur_fft + 1) % NUM_FFT;
    f = &fft[cur_fft];

    /* wait for it to be available */
    pthread_mutex_lock(&f->mutex);
    while (running && f->buffer_state != fft_t::BUFFER_STATE_READY)
        pthread_cond_wait(&f->buffer_state_cond, &f->mutex);
    if (!running) {
        pthread_mutex_unlock(&f->mutex);
        pthread_exit(NULL);
    }
    f->buffer_state = fft_t::BUFFER_STATE_FILLING;
    pthread_mutex_unlock(&f->mutex);

    /* copy pre-roll to beginning of buffer */
    void *raw_contents = f->raw_buffer->contents();
    memcpy(raw_contents, pre_roll_buf, pre_roll_bytes);

    /* return pointer to batch region (after pre-roll) */
    return (int8_t *)raw_contents + pre_roll_bytes;
}

void release_buffer(void *fft_in) {
    fft_t *f = (fft_t *)fft_in;
    pthread_mutex_lock(&f->mutex);
    f->buffer_state = fft_t::BUFFER_STATE_READY;
    pthread_cond_signal(&f->buffer_state_cond);
    pthread_mutex_unlock(&f->mutex);
}
