//
//  cryptostream_encrypt_parallel.c
//  saltunnel2
//

#include "config.h"
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
#include "saltunnel.h"
#include "config.h"
#include <unistd.h>
#include <stdio.h>

typedef struct encrypt_thread_param {
    int buffer_encrypt_count; int buffer_encrypt_start_i; int bytesread; cryptostream* cs; nonce8 nonce;
} encrypt_thread_param;

void encrypt_thread_action(void* params_v) {
    encrypt_thread_param* p = (encrypt_thread_param*)params_v;
    encrypt_all_serial(p->buffer_encrypt_count, p->buffer_encrypt_start_i, p->bytesread, p->cs, p->nonce);
}

void encrypt_all_parallel(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs) {

    // Allocate a list of "tasks" and their associated params
    threadpool_task tasks[THREADPOOL_THREAD_COUNT] = {0};
    encrypt_thread_param params[THREADPOOL_THREAD_COUNT] = {0};
    nonce8 nonce_current;
    nonce8_copy(cs->nonce, nonce_current);
    
    // Populate the tasks and params
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT; thread_i++) {
        // Initialize Task Params
        encrypt_thread_param* p = &params[thread_i];
        p->buffer_encrypt_count = buffer_encrypt_count/THREADPOOL_THREAD_COUNT;
        p->buffer_encrypt_start_i = buffer_encrypt_start_i + thread_i*buffer_encrypt_count/THREADPOOL_THREAD_COUNT;
        p->bytesread = bytesread;
        p->cs = cs;
        nonce8_copy(nonce_current, p->nonce);
        nonce8_increment_by(nonce_current, nonce_current, p->buffer_encrypt_count);
        // Initialize Task
        tasks[thread_i].action = encrypt_thread_action;
        tasks[thread_i].param = p;
        // TODO: Debug
        if(buffer_encrypt_count%THREADPOOL_THREAD_COUNT!=0) oops_fatal("assertion failed");
    }
    nonce8_copy(nonce_current, cs->nonce);
    
    // Run tasks in parallel
    threadpool_for(0, tasks);
    
    log_debug("encrypt_all_parallel: successfully encrypted entire span");
    memset(params, 0, sizeof(params)); // TODO: Debug
    memset(tasks, 0, sizeof(tasks)); // TODO: Debug
}
