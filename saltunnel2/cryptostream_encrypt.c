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
#include "crypto_secretbox_salsa2012poly1305.h"
#include "threadpool.h"
#include <unistd.h>
#include <stdio.h>


void encrypt_all_serial(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, unsigned char *key, int do_inc_nonce, nonce8 nonce) {
    for(int buffer_i = buffer_encrypt_start_i; buffer_i < buffer_encrypt_start_i+buffer_encrypt_count; buffer_i++)
    {
        encrypt_one(buffer_i, buffer_i-buffer_encrypt_start_i, (uint16)bytesread, cs, key, do_inc_nonce, nonce);
        log_debug("cryptostream_encrypt_feed_read: encrypted %d bytes (buffer %d/%d)", CRYPTOSTREAM_BUFFER_MAXBYTES, buffer_i-buffer_encrypt_start_i+1, buffer_encrypt_count);
    }
}

static nonce8 zero_nonce = {0}; // TODO: Use real nonce in parallel

void encrypt_one(int buffer_i, int buffer_n, int bytesread, cryptostream *cs, unsigned char *key, int do_inc_nonce, nonce8 nonce) {
    
    int current_bytes_to_encrypt = MIN(CRYPTOSTREAM_BUFFER_MAXBYTES_DATA,
                                       bytesread - CRYPTOSTREAM_BUFFER_MAXBYTES_DATA*buffer_n);
    if(current_bytes_to_encrypt<0) oops_fatal("assertion failed");
    
    // Find the pointers to the start of the buffers
    unsigned char* plaintext_buffer_ptr = cs->plaintext_vector[buffer_i].iov_base - 32-2;
    unsigned char* ciphertext_buffer_ptr = cs->ciphertext_vector[buffer_i].iov_base - 16;
    
    // Fill zeros (32 bytes)
    memset((void*)plaintext_buffer_ptr, 0, 32);
    
    // Fill len (2 bytes)
    uint16_pack(((void*)plaintext_buffer_ptr+32), current_bytes_to_encrypt);
    
    // Fill unused data (0-494 bytes)
    memset((void*)plaintext_buffer_ptr+32+2+current_bytes_to_encrypt, 0, CRYPTOSTREAM_BUFFER_MAXBYTES_DATA-current_bytes_to_encrypt);
    
    // Encrypt chunk from plaintext to ciphertext (494 bytes)
    
    // crypto_secretbox:
    // - signature: crypto_secretbox(c,m,mlen,n,k);
    // - input structure:
    //   - [0..32] == zero
    //   - [32..]  == plaintext
    // - output structure:
    //   - [0..16]  == zero
    //   - [16..32] == auth
    //   - [32..]   == ciphertext
    try(crypto_secretbox_salsa2012poly1305(ciphertext_buffer_ptr, plaintext_buffer_ptr,
                         CRYPTOSTREAM_BUFFER_MAXBYTES, zero_nonce, key)) || oops_fatal("failed to encrypt");
    
    // Increment nonce
    if(do_inc_nonce)
        nonce8_increment(cs->nonce,cs->nonce);
}

typedef struct encrypt_thread_param {
    int buffer_encrypt_count; int buffer_encrypt_start_i; int bytesread; cryptostream *cs; unsigned char *key; nonce8 nonce;
} encrypt_thread_param;

void encrypt_thread_action(void* params_v) {
    encrypt_thread_param* p = (encrypt_thread_param*)params_v;
    encrypt_all_serial(p->buffer_encrypt_count, p->buffer_encrypt_start_i, p->bytesread, p->cs, p->key, 0, p->nonce);
}

threadpool tp;
int tp_initialized = 0;

void encrypt_all_parallel(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, unsigned char *key) {
    // One-time init
    if(!tp_initialized) {
        threadpool_init(&tp, THREADPOOL_THREAD_COUNT);
        tp_initialized = 1;
    }
    
    // Per-run init
    encrypt_thread_param params[THREADPOOL_THREAD_COUNT]; // OOPS, scoped!
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT; thread_i++) {
        encrypt_thread_param* p = &params[thread_i];
        p->buffer_encrypt_start_i = buffer_encrypt_start_i + thread_i*buffer_encrypt_count/THREADPOOL_THREAD_COUNT;
        p->buffer_encrypt_count = buffer_encrypt_count/THREADPOOL_THREAD_COUNT;
        if(buffer_encrypt_count%THREADPOOL_THREAD_COUNT!=0) oops_fatal("assertion failed");
        p->bytesread = bytesread;
        p->cs = cs;
        p->key = key;
        tp.tasks[thread_i].param = p;
        tp.tasks[thread_i].action = encrypt_thread_action;
    }
    nonce8_increment(cs->nonce, params[0].nonce);
    for(int i = 0; i < THREADPOOL_THREAD_COUNT-2; i++) {
        nonce8_increment(params[i].nonce, params[i+1].nonce);
    }
    nonce8_copy(params[THREADPOOL_THREAD_COUNT-1].nonce, cs->nonce);
    
    // Run
    threadpool_for(&tp);
    
    log_info("memset reached");
    memset(params, 1, sizeof(params)); // TODO: For debug. Weird...'params' should not longer be used...
}

void encrypt_all(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, unsigned char *key) {
    if(buffer_encrypt_count==CRYPTOSTREAM_BUFFER_COUNT)
        encrypt_all_parallel(buffer_encrypt_count, buffer_encrypt_start_i, bytesread, cs, key);
    else
        encrypt_all_serial(buffer_encrypt_count, buffer_encrypt_start_i, bytesread, cs, key, 1, cs->nonce);
}
