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

void exchange_session_key(cryptostream *ingress, cryptostream *egress,
                          unsigned char* long_term_key,
                          unsigned char* session_key_out) {
    
    // Create an ephemeral keypair
    unsigned char my_sk[32];
    unsigned char my_pk[32+32]; // zeros=>[0..32], pk=>[32..64]
    memset(my_pk, 0, 32);
    crypto_box_curve25519xsalsa20poly1305_keypair(my_pk+32,my_sk);
    
    // Encrypt ephemeral public key
    unsigned char my_nonce[24];
    randombytes(my_nonce, 24);
    unsigned char my_pk_encrypted[16+16+32+464] = {0}; // zeros=>[0..16], auth=>[16..32], pk=>[32..64], randomness[64..464]
    try(crypto_secretbox_xsalsa20poly1305(my_pk_encrypted,my_pk,16+16+32,my_nonce,long_term_key))
    || oops_fatal("encryption failed");
    
    try(crypto_secretbox_xsalsa20poly1305_open(my_pk,my_pk_encrypted,16+16+32,my_nonce,long_term_key))
    || oops_fatal("decryption failed");
    
    // Pack chunk
    unsigned char write_chunk[512] = {0}; // nonce=>[0..24], auth=>[24..40], pk=>[40..72], randomness[72..512]
    memcpy(write_chunk, my_nonce, 24);
    memcpy(write_chunk+24, my_pk_encrypted+16, 16+32);
    randombytes(my_pk_encrypted+72, 512-72); // TODO: Makes more sense to just encrypt/decrypt entire 512-block
    
    // Send chunk
    try(uninterruptable_writen(write, egress->to_fd, (char*)write_chunk, 512))
    || oops_fatal("write failed");
    
    // ---- ---- ---- ----
    
    // Receive chunk
    unsigned char read_chunk[512] = {0}; // nonce=>[0..24], auth=>[24..40], pk=>[40..72], randomness[72..512]
    try(uninterruptable_readn(ingress->from_fd, (char*)read_chunk, 512))
    || oops_fatal("read failed");
    
    // Unpack chunk
    unsigned char their_nonce[24] = {0}; // DEBUG
    unsigned char their_pk_encrypted[16+16+32+464] = {0}; // zeros=>[0..16], auth=>[16..32], pk=>[32..64], randomness[64..464]
    memcpy(their_nonce, read_chunk, 24);
    memset(their_pk_encrypted, 0, 16);
    memcpy(their_pk_encrypted+16, read_chunk+24, 16+32);
    
    // Decrypt ephemeral public key
    unsigned char their_pk[32+32]; // zeros=>[0..32], pk=>[32..64]
    
    try(crypto_secretbox_xsalsa20poly1305_open(their_pk,their_pk_encrypted,16+16+32,their_nonce,long_term_key))
    || oops_fatal("decryption failed");
    
    // Calculate shared key
    try(crypto_box_curve25519xsalsa20poly1305_beforenm(session_key_out, their_pk+32, my_sk))
    || oops_fatal("diffie-hellman failed");
    //  NOTE: Need to differentiate between server and client keys
    
}
