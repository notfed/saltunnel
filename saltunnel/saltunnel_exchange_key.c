//
//  saltunnel_exchange_key.c
//  saltunnel
//

#include "saltunnel.h"
#include "uninterruptable.h"
#include "sodium.h"
#include "oops.h"
#include "log.h"
#include <string.h>

static unsigned char version[] = { 0x06,0x05,0x28,0x84,0x9a,0x61,0x08,0xc7 }; // 0x060528849a6108c7

typedef struct buffer0 {
    union {
        unsigned char nonce[24];
        struct {
            unsigned char unused[8];
            unsigned char prezeros[16];
        };
    };
    unsigned char auth[16];
    unsigned char version[8];
    unsigned char pk[32];
    unsigned char zeros[432];
} buffer0;

void exchange_session_key(cryptostream *ingress, cryptostream *egress,
                          unsigned char* long_term_key,
                          unsigned char* session_key_out) {
    
    buffer0 my_buffer_plaintext = {0};
    
    // Create an ephemeral keypair
    unsigned char my_sk[32];
    crypto_box_curve25519xsalsa20poly1305_keypair(my_buffer_plaintext.pk,my_sk);
    
    // Generate a nonce
    unsigned char my_nonce[24];
    randombytes(my_nonce, 24);
    
    // Serialize buffer
    memcpy(my_buffer_plaintext.version, version, 8);
    memcpy(my_buffer_plaintext.pk, my_buffer_plaintext.pk, 32);
    
    // Encrypt buffer
    buffer0 my_buffer_ciphertext = {0};
    try(crypto_secretbox_xsalsa20poly1305(my_buffer_ciphertext.prezeros,
                                          my_buffer_plaintext.prezeros,
                                          512-8, my_nonce, long_term_key))
    || oops_fatal("encryption failed");
    
    // Put nonce in buffer
    memcpy(my_buffer_ciphertext.nonce, my_nonce, 24);
    
    // Send encrypted buffer
    try(uninterruptable_writen(write, egress->to_fd, (char*)&my_buffer_ciphertext, 512))
    || oops_fatal("write failed");
    
    // ---- ---- ---- ----
    
    // Receive encrypted buffer
    buffer0 their_buffer_ciphertext = {0};
    try(uninterruptable_readn(ingress->from_fd, (char*)&their_buffer_ciphertext, 512))
    || oops_fatal("read failed");
    
    // Get nonce
    unsigned char their_nonce[24];
    memcpy(their_nonce, their_buffer_ciphertext.nonce, 24);
    
    // Decrypt encrypted buffer
    buffer0 their_buffer_plaintext = {0};
    try(crypto_secretbox_xsalsa20poly1305_open((unsigned char*)&their_buffer_plaintext.prezeros,
                                               (unsigned char*)&their_buffer_ciphertext.prezeros,
                                               512-8, their_buffer_ciphertext.nonce, long_term_key))
    || oops_fatal("decryption failed");
    
    // Verify version
    if(sodium_compare(their_buffer_plaintext.version, version, 8) != 0)
        oops_fatal("version mismatch");
    
    // Calculate shared key
    try(crypto_box_curve25519xsalsa20poly1305_beforenm(session_key_out, their_buffer_plaintext.pk, my_sk))
    || oops_fatal("diffie-hellman failed");
    //  NOTE: Need to differentiate between server and client keys
    
}
