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
#include <unistd.h>
#include <stdio.h>

void encrypt_all(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, unsigned char *key) {
    for(int buffer_i = buffer_encrypt_start_i; buffer_i < buffer_encrypt_start_i+buffer_encrypt_count; buffer_i++)
    {
        encrypt_one(buffer_i, buffer_i-buffer_encrypt_start_i, (uint16)bytesread, cs, key);
        log_debug("cryptostream_encrypt_feed_read: encrypted %d bytes (buffer %d/%d)", CRYPTOSTREAM_BUFFER_MAXBYTES, buffer_i-buffer_encrypt_start_i+1, buffer_encrypt_count);
    }
}

void encrypt_one(int buffer_i, int buffer_n, int bytesread, cryptostream *cs, unsigned char *key) {
    
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
                         CRYPTOSTREAM_BUFFER_MAXBYTES, cs->nonce, key)) || oops_fatal("failed to encrypt");
    
    // Increment nonce
    nonce8_increment(cs->nonce);
}
