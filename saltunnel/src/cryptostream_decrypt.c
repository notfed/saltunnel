//
//  cryptostream_decrypt.c
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
#include "stopwatch.h"

#include <unistd.h>
#include <stdio.h>

int decrypt_all(int buffer_decrypt_count, int buffer_decrypt_start_i, cryptostream *cs) {

    int all_buffers_full = (buffer_decrypt_count==CRYPTOSTREAM_BUFFER_COUNT);
    if(all_buffers_full && threadpool_enough_cpus_for_parallel()) {
        if(decrypt_all_parallel(buffer_decrypt_count, buffer_decrypt_start_i, cs)<0)
            return -1;
    }
    else {
        if(decrypt_all_serial(buffer_decrypt_count, buffer_decrypt_start_i, cs, cs->nonce)<0)
            return -1;
    }
    return 0;
}

int decrypt_all_serial(int buffer_decrypt_count, int buffer_decrypt_start, cryptostream *cs, nonce8 nonce) {
    for(int buffer_i = buffer_decrypt_start; buffer_i < buffer_decrypt_start+buffer_decrypt_count; buffer_i++)
    {
        if(decrypt_one(buffer_i, cs, nonce)<0)
            return -1;
        nonce8_increment(nonce, nonce);
    }
    log_trace("cryptostream_decrypt_feed_read: decrypted %d buffers", buffer_decrypt_count);
    return 0;
}

int decrypt_one(int buffer_i, cryptostream *cs, nonce8 nonce) {
    
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
    if(crypto_secretbox_salsa20poly1305_open(plaintext_buffer_ptr, ciphertext_buffer_ptr,
                              CRYPTOSTREAM_BUFFER_MAXBYTES, nonce, cs->key)<0)
    { errno = EBADMSG; return oops("failed to decrypt"); }
    
    // Extract datalen
    uint16_t datalen_current = 0;
    uint16_unpack((char*)plaintext_buffer_ptr + 32, &datalen_current);
    
    // Update vector length
    vector_buffer_set_len(cs->plaintext_vector, buffer_i, datalen_current);

    return 0;
}
