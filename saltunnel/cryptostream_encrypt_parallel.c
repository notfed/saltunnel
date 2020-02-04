//
//  cryptostream_encrypt.c
//  saltunnel2
//

#include "cryptostream.h"
#include "uninterruptable.h"
#include "oops.h"
#include "sodium.h"
#include "nonce.h"
#include "log.h"
#include "uint16.h"
#include "chaos.h"
#include "math.h"
#include "crypto_secretbox_salsa20poly1305.h"
#include "threadpool.h"
#include <unistd.h>
#include <stdio.h>

typedef struct encrypt_thread_param {
    int buffer_encrypt_count; int buffer_encrypt_start_i; int bytesread; cryptostream *cs; unsigned char *key; nonce8 nonce;
} encrypt_thread_param;

void encrypt_thread_action(void* params_v) {
    encrypt_thread_param* p = (encrypt_thread_param*)params_v;
    nonce8 zero_nonce = {0}; // TODO: Use real nonce in parallel
    encrypt_all_serial(p->buffer_encrypt_count, p->buffer_encrypt_start_i, p->bytesread, p->cs, p->key, zero_nonce);
}

void encrypt_all_parallel(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, unsigned char *key) {

    // Allocate a list of "tasks" and their associated params
    threadpool_task tasks[THREADPOOL_THREAD_COUNT] = {0};
    encrypt_thread_param params[THREADPOOL_THREAD_COUNT] = {0};
    
    // Populate the tasks and params
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT; thread_i++) {
        // Initialize Task Params
        encrypt_thread_param* p = &params[thread_i];
        p->buffer_encrypt_count = buffer_encrypt_count/THREADPOOL_THREAD_COUNT;
        p->buffer_encrypt_start_i = buffer_encrypt_start_i + thread_i*buffer_encrypt_count/THREADPOOL_THREAD_COUNT;
        p->bytesread = bytesread;
        p->cs = cs;
        p->key = key;
        // Initialize Task
        tasks[thread_i].action = encrypt_thread_action;
        tasks[thread_i].param = p;
        // TODO: Debug
        if(buffer_encrypt_count%THREADPOOL_THREAD_COUNT!=0) oops_fatal("assertion failed");
    }
    
    // TODO: Using zero nonce for now
//    nonce8_increment(cs->nonce, params[0].nonce);
//    for(int i = 0; i < THREADPOOL_THREAD_COUNT-2; i++) {
//        nonce8_increment(params[i].nonce, params[i+1].nonce);
//    }
//    nonce8_copy(params[THREADPOOL_THREAD_COUNT-1].nonce, cs->nonce);
    
    // Run tasks in parallel
    threadpool_for(&tp1, tasks);
    
    log_debug("encrypt_all_parallel: successfully encrypted entire span");
    memset(params, 0, sizeof(params)); // TODO: Debug
    memset(tasks, 0, sizeof(tasks)); // TODO: Debug
}
