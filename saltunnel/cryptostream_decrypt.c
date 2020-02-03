//
//  cryptostream_decrypt.c
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
#include "stopwatch.h"
#include <unistd.h>
#include <stdio.h>

static unsigned long total_elapsed = 0;
void decrypt_all(int buffer_decrypt_count, int buffer_decrypt_start_i, cryptostream *cs, unsigned char *key) {

//    stopwatch sw;
//    stopwatch_start(&sw);
//    log_info("decrypt_all: going to decrypt %d buffers", buffer_decrypt_count);
    int do_parallel = (buffer_decrypt_count==CRYPTOSTREAM_BUFFER_COUNT);
    if(do_parallel) {
        decrypt_all_parallel(buffer_decrypt_count, buffer_decrypt_start_i, cs, key);
    }
    else {
//        log_info("decrypt serial");
        decrypt_all_serial(buffer_decrypt_count, buffer_decrypt_start_i, cs, key);
    }
//    long elapsed = stopwatch_elapsed(&sw);
//    total_elapsed += elapsed;
//    log_info("decrypt_all took %dus (total %dus)", (int)elapsed, (int)total_elapsed);
}

void decrypt_all_serial(int buffer_decrypt_count, int buffer_decrypt_start, cryptostream *cs, unsigned char *key) {
    for(int buffer_i = buffer_decrypt_start; buffer_i < buffer_decrypt_start+buffer_decrypt_count; buffer_i++)
    {
        decrypt_one(buffer_i, cs, key);
//        log_debug("cryptostream_decrypt_feed_read: decrypted (buffer %d/%d)", buffer_i-buffer_decrypt_start+1, buffer_decrypt_count);
    }
    log_debug("cryptostream_decrypt_feed_read: decrypted %d buffers", buffer_decrypt_count);
}

static nonce8 zero_nonce = {0}; // TODO: Use real nonce in parallel

void decrypt_one(int buffer_i, cryptostream *cs, unsigned char *key) {
    
    unsigned char* plaintext_buffer_ptr = cs->plaintext_vector[buffer_i].iov_base - 32-2;
    unsigned char* ciphertext_buffer_ptr = cs->ciphertext_vector[buffer_i].iov_base - 16;
    
    // Decrypt chunk from ciphertext to plaintext (512 bytes)
    
    // crypto_secretbox_open:
    // - signature: crypto_secretbox_open(m,c,clen,n,k)
    // - input structure:
    //   - [0..16]  == zero
    //   - [16..32] == auth
    //   - [32..]   == ciphertext
    // - output structure:
    //   - [0..32] == zero
    //   - [32..]  == plaintext
    try(crypto_secretbox_salsa2012poly1305_open(plaintext_buffer_ptr, ciphertext_buffer_ptr,
                              CRYPTOSTREAM_BUFFER_MAXBYTES,zero_nonce,key)) ||
        oops_fatal("failed to decrypt");
    
//    // Increment nonce
//    nonce8_increment(cs->nonce,cs->nonce); // Debug: Using zero nonces for now
    
    // Extract datalen
    uint16 datalen_current = 0;
    uint16_unpack((char*)plaintext_buffer_ptr + 32, &datalen_current);
    
    // Update vector length
    vector_buffer_set_len(cs->plaintext_vector, buffer_i, datalen_current);
}
