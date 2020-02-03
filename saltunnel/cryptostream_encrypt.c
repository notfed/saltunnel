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
#include "stopwatch.h"
#include <unistd.h>
#include <stdio.h>

static unsigned long total_elapsed = 0;
void encrypt_all(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, unsigned char *key) {
//
//    stopwatch sw;
//    stopwatch_start(&sw);
    
    int do_parallel = (buffer_encrypt_count==CRYPTOSTREAM_BUFFER_COUNT);
    if(do_parallel) {
        encrypt_all_parallel(buffer_encrypt_count, buffer_encrypt_start_i, bytesread, cs, key);
    }
    else {
        log_info("encrypt serial");
        encrypt_all_serial(buffer_encrypt_count, buffer_encrypt_start_i, bytesread, cs, key, cs->nonce);
    }
//    
//    long elapsed = stopwatch_elapsed(&sw);
//    total_elapsed += elapsed;
////    log_info("encrypt_all took %dus (total %dus)", (int)elapsed, (int)total_elapsed);
}

void encrypt_all_serial(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, unsigned char *key, nonce8 nonce) {
    for(int buffer_i = buffer_encrypt_start_i; buffer_i < buffer_encrypt_start_i+buffer_encrypt_count; buffer_i++)
    {
        encrypt_one(buffer_i, buffer_i-buffer_encrypt_start_i, (uint16)bytesread, cs, key, nonce);
//        log_debug("encrypt_all_serial: encrypted (buffer %d/%d)", buffer_i-buffer_encrypt_start_i+1, buffer_encrypt_count);
    }
}

void encrypt_one(int buffer_i, int buffer_n, int bytesread, cryptostream *cs, unsigned char *key, nonce8 nonce) {
    
    int current_bytes_to_encrypt = MIN(CRYPTOSTREAM_BUFFER_MAXBYTES_DATA,
                                       bytesread - CRYPTOSTREAM_BUFFER_MAXBYTES_DATA*buffer_n);
    if(current_bytes_to_encrypt<0) oops_fatal("assertion failed");
    if(buffer_i<0 || buffer_i>=CRYPTOSTREAM_BUFFER_COUNT*2) oops_fatal("assertion failed");
    
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
                         CRYPTOSTREAM_BUFFER_MAXBYTES, nonce, key)) || oops_fatal("failed to encrypt");
    
    // Increment nonce
//    nonce8_increment(cs->nonce,cs->nonce); // TODO: Using zero-nonce for now
}
