//
//  saltunnel_exchange_key.c
//  saltunnel
//

#include "saltunnel.h"
#include "uninterruptable.h"
#include "sodium.h"
#include "crypto_secretbox_salsa20poly1305.h"
#include "oops.h"
#include "log.h"
#include "saltunnel_kx.h"
#include <string.h>
#include <errno.h>

int saltunnel_kx_packet0_trywrite(unsigned char* long_term_key,
                                 int to_fd,
                                 unsigned char my_sk_out[32]) {
    
     packet0 my_buffer_plaintext = {0};
     packet0 my_buffer_ciphertext = {0};
    
    //-----------------------
    // Create an ephemeral keypair
    //-----------------------
    
    unsigned char my_sk[32];
    crypto_box_curve25519xsalsa20poly1305_keypair(my_buffer_plaintext.pk,my_sk_out);
    
    //-----------------------
    // Send packet0
    //-----------------------
    
    // Generate a nonce
    unsigned char my_nonce[24];
    randombytes(my_nonce, 24);
    
    // Serialize buffer
    memcpy(my_buffer_plaintext.version, version, 8);
    memcpy(my_buffer_plaintext.pk, my_buffer_plaintext.pk, 32);
    
    // Encrypt buffer
    if(crypto_secretbox_xsalsa20poly1305(my_buffer_ciphertext.prezeros,
                                          my_buffer_plaintext.prezeros,
                                          512+16-24, my_nonce, long_term_key)<0)
    { return oops_warn("encryption failed"); }
    
    // Put nonce in buffer
    memcpy(my_buffer_ciphertext.nonce, my_nonce, 24);
    
    // Send encrypted buffer
    if(uninterruptable_writen(write, to_fd, (char*)&my_buffer_ciphertext, 512)<0)
    { return oops_warn("write failed"); }
    
    return 0;
}

int saltunnel_kx_packet0_tryread(unsigned char* long_term_key,
                                 int from_fd, packet0* their_buffer_plaintext) {
    errno = EBADMSG;
    log_info("kx on fd %d", from_fd);
    
    // Receive encrypted buffer
    packet0 their_buffer_ciphertext = {0};
    ssize_t bytes_read = read(from_fd, (char*)&their_buffer_ciphertext, 512);
    if(bytes_read<0 && errno==EWOULDBLOCK)
        return oops_warn("empty packet0");
    if(bytes_read<0)
        return oops_warn("read failed");
    if(bytes_read != CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT)
        return oops_warn("partial packet0");
    
    // Extract random nonce
    unsigned char their_nonce[24];
    memcpy(their_nonce, their_buffer_ciphertext.nonce, 24);
    
    // Decrypt encrypted buffer
    if(crypto_secretbox_xsalsa20poly1305_open((unsigned char*)&their_buffer_plaintext->prezeros,
                                               (unsigned char*)&their_buffer_ciphertext.prezeros,
                                               512+16-24, their_buffer_ciphertext.nonce, long_term_key)<0)
        return oops_warn("decryption failed");
    
    // Verify version
    if(sodium_compare(their_buffer_plaintext->version, version, 8) != 0)
        return oops_warn("version mismatch");
    
    // Verify timetamp (TODO)
    
    // Verify client-specific incrementing nonce (TODO)
    
    // Success
    return 0;
}

int saltunnel_kx_calculate_shared_key(unsigned char* session_key_out,
                                      unsigned char* their_pk,
                                      unsigned char* my_sk) {
     if(crypto_box_curve25519xsalsa20poly1305_beforenm(session_key_out, their_pk, my_sk)<0)
         return oops_warn("diffie-hellman failed");
     //  NOTE: Need to differentiate between server and client keys
    return 0;
}
    


void exchange_session_key(int from_fd, int to_fd,
                          unsigned char* long_term_key,
                          unsigned char* session_key_out) {
    
    packet0 my_buffer_plaintext = {0};
    packet0 my_buffer_ciphertext = {0};
    packet0 their_buffer_plaintext = {0};
    packet0 their_buffer_ciphertext = {0};
    
    //-----------------------
    // Create an ephemeral keypair
    //-----------------------
    
    unsigned char my_sk[32];
    crypto_box_curve25519xsalsa20poly1305_keypair(my_buffer_plaintext.pk,my_sk);
    
    //-----------------------
    // Send packet0
    //-----------------------
    
    // Generate a nonce
    unsigned char my_nonce[24];
    randombytes(my_nonce, 24);
    
    // Serialize buffer
    memcpy(my_buffer_plaintext.version, version, 8);
    memcpy(my_buffer_plaintext.pk, my_buffer_plaintext.pk, 32);
    
    // Encrypt buffer
    try(crypto_secretbox_xsalsa20poly1305(my_buffer_ciphertext.prezeros,
                                          my_buffer_plaintext.prezeros,
                                          512+16-24, my_nonce, long_term_key))
    || oops_fatal("encryption failed");
    
    // Put nonce in buffer
    memcpy(my_buffer_ciphertext.nonce, my_nonce, 24);
    
    // Send encrypted buffer
    try(uninterruptable_writen(write, to_fd, (char*)&my_buffer_ciphertext, 512))
    || oops_fatal("write failed");
    
    //-----------------------
    // Receive packet0
    //-----------------------
    
    // Receive encrypted buffer
    try(uninterruptable_readn(from_fd, (char*)&their_buffer_ciphertext, 512))
    || oops_fatal("read failed");
    
    // Get nonce
    unsigned char their_nonce[24];
    memcpy(their_nonce, their_buffer_ciphertext.nonce, 24);
    
    // Decrypt encrypted buffer
    try(crypto_secretbox_xsalsa20poly1305_open((unsigned char*)&their_buffer_plaintext.prezeros,
                                               (unsigned char*)&their_buffer_ciphertext.prezeros,
                                               512+16-24, their_buffer_ciphertext.nonce, long_term_key))
    || oops_fatal("decryption failed");
    
    // Verify version
    if(sodium_compare(their_buffer_plaintext.version, version, 8) != 0)
        oops_fatal("version mismatch");
    
    //-----------------------------------------------------------------------------------------------
    // Calculate shared key
    //-----------------------------------------------------------------------------------------------
    
    try(crypto_box_curve25519xsalsa20poly1305_beforenm(session_key_out, their_buffer_plaintext.pk, my_sk))
    || oops_fatal("diffie-hellman failed");
    //  NOTE: Need to differentiate between server and client keys
    
    //-----------------------------------------------------------------------------------------------
    // Send packet1 (i.e., an empty packet which serves as an auth step; i.e., 496 encrypted zeroes)
    //-----------------------------------------------------------------------------------------------
    
    packet1 my_buffer1_plaintext = {0};
    packet1 my_buffer1_ciphertext = {0};
    
    // Both buffer1 nonces will be 0
    const unsigned char buffer1_nonce[8] = {0};
    
    // Encrypt buffer
    try(crypto_secretbox_salsa20poly1305(my_buffer1_ciphertext.prezeros,
                                         my_buffer1_plaintext.prezeros,
                                         512+16, buffer1_nonce, session_key_out))
    || oops_fatal("encryption failed");
    
    // Send encrypted buffer
    try(uninterruptable_writen(write, to_fd, (char*)&my_buffer1_ciphertext.auth, 512))
    || oops_fatal("write failed");
    
    //-----------------------
    // Receive packet1
    //-----------------------
    
    packet1 their_buffer1_ciphertext = {0};
    packet1 their_buffer1_plaintext = {0};
    
    // Receive encrypted buffer
    try(uninterruptable_readn(from_fd, (char*)&their_buffer1_ciphertext.auth, 512))
    || oops_fatal("read failed");
    
    
    // Decrypt encrypted buffer
    try(crypto_secretbox_salsa20poly1305_open((unsigned char*)&their_buffer1_plaintext.prezeros,
                                              (unsigned char*)&their_buffer1_ciphertext.prezeros,
                                              512+16, buffer1_nonce, session_key_out))
    || oops_fatal("authentication failed");
}
