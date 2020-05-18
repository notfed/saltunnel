//
//  cryptostream_encrypt.c
//  saltunnel
//

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
#include "stopwatch.h"
#include <unistd.h>
#include <stdio.h>

int encrypt_all(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs) {

    int all_buffers_full = (buffer_encrypt_count==CRYPTOSTREAM_BUFFER_COUNT);
    if(all_buffers_full && threadpool_enough_cpus_for_parallel()) {
        if(encrypt_all_parallel(buffer_encrypt_count, buffer_encrypt_start_i, bytesread, cs)<0)
            return -1;
    }
    else {
        if(encrypt_all_serial(buffer_encrypt_count, buffer_encrypt_start_i, bytesread, cs, cs->nonce)<0)
            return -1;
    }
}

int encrypt_all_serial(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, nonce8 nonce) {
    for(int buffer_i = buffer_encrypt_start_i; buffer_i < buffer_encrypt_start_i+buffer_encrypt_count; buffer_i++)
    {
        if(encrypt_one(buffer_i, buffer_i-buffer_encrypt_start_i, bytesread, cs, nonce)<0)
            return -1;;
        nonce8_increment(nonce, nonce);
    }
    return 0;
}

int encrypt_one(int buffer_i, int buffer_n, int bytesread, cryptostream *cs, nonce8 nonce) {
    
    int current_bytes_to_encrypt = MIN(CRYPTOSTREAM_BUFFER_MAXBYTES_DATA,
                                       bytesread - CRYPTOSTREAM_BUFFER_MAXBYTES_DATA*buffer_n);
    
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
    if(crypto_secretbox_salsa20poly1305(ciphertext_buffer_ptr, plaintext_buffer_ptr,
                         CRYPTOSTREAM_BUFFER_MAXBYTES, nonce, cs->key)<0) 
    { return oops_warn("failed to encrypt"); }

    return 0;
}
