//
//  cryptostream_derypt_parallel.c
//  saltunnel2
//

#include "config.h"
#include "cryptostream.h"
#include "rwn.h"
#include "oops.h"
#include "sodium.h"
#include "nonce.h"
#include "log.h"
#include "uint16.h"
#include "math.h"
#include "crypto_secretbox_salsa20poly1305.h"
#include "threadpool.h"
#include "saltunnel.h"
#include <unistd.h>
#include <stdio.h>

typedef struct decrypt_thread_param {
    int buffer_decrypt_count; int buffer_decrypt_start_i; cryptostream *cs; nonce8 nonce;
} decrypt_thread_param;

void decrypt_thread_action(void* params_v) {
    decrypt_thread_param* p = (decrypt_thread_param*)params_v;
    decrypt_all_serial(p->buffer_decrypt_count, p->buffer_decrypt_start_i, p->cs, p->nonce);
}

void decrypt_all_parallel(int buffer_decrypt_count, int buffer_decrypt_start, cryptostream *cs) {
    
    // Allocate a list of "tasks" and their associated params
    threadpool_task tasks[THREADPOOL_THREAD_COUNT] = {0};
    decrypt_thread_param params[THREADPOOL_THREAD_COUNT] = {0};
    nonce8 nonce_current;
    nonce8_copy(cs->nonce, nonce_current);
    
    // Populate the tasks and params
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT; thread_i++) {
        // Initialize Task Params
        decrypt_thread_param* p = &params[thread_i];
        p->buffer_decrypt_count = buffer_decrypt_count/THREADPOOL_THREAD_COUNT;
        p->buffer_decrypt_start_i = buffer_decrypt_start + thread_i*buffer_decrypt_count/THREADPOOL_THREAD_COUNT;
        p->cs = cs;
        nonce8_copy(nonce_current, p->nonce);
        nonce8_increment_by(nonce_current, nonce_current, p->buffer_decrypt_count);
        // Initialize Task
        tasks[thread_i].action = decrypt_thread_action;
        tasks[thread_i].param = p;
    }
    nonce8_copy(nonce_current, cs->nonce);
    
    // Run tasks in parallel
    threadpool_for(1, tasks);
}
