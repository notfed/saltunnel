//
//  saltunnel_kx.c
//  saltunnel
//

#include "saltunnel.h"
#include "rwn.h"
#include "sodium.h"
#include "crypto_secretbox_salsa20poly1305.h"
#include "oops.h"
#include "log.h"
#include "saltunnel_kx.h"
#include "hypercounter.h"
#include "uint64.h"
#include "cache.h"

#include <sodium.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int saltunnel_kx_packet0_trywrite(packet0* my_packet0_plaintext_pinned,
                                  const unsigned char long_term_key[32],
                                  int to_fd,
                                  unsigned char my_sk_out[32]) {
    
    packet0 my_packet0_ciphertext = {0};
    memset(my_packet0_plaintext_pinned, 0, sizeof(packet0));
    
    //-----------------------
    // Create an ephemeral keypair
    //-----------------------
    
    crypto_box_curve25519xsalsa20poly1305_keypair(my_packet0_plaintext_pinned->pk, my_sk_out);
    
    //-----------------------
    // Send packet0
    //-----------------------
    
    // Generate a nonce
    unsigned char my_nonce[24];
    randombytes(my_nonce, 24);
    
    // Put the epoch time (in seconds) in the packet
    uint64_pack_big((char*)&my_packet0_plaintext_pinned->epoch_seconds, time(NULL));
    
    // Place this machine's machine_id and current monotonic_time into the packet
    if(hypercounter(my_packet0_plaintext_pinned->machine_id, my_packet0_plaintext_pinned->monotonic_time)<0)
        return -1;
    
    // Put version in buffer
    memcpy(my_packet0_plaintext_pinned->version, version, 8);
    
    // Encrypt buffer
    if(crypto_secretbox_xsalsa20poly1305(my_packet0_ciphertext.prezeros,
                                          my_packet0_plaintext_pinned->prezeros,
                                          512+16-24, my_nonce, long_term_key)<0)
    { return oops("encryption failed"); }
    
    // Put nonce in buffer
    memcpy(my_packet0_ciphertext.nonce, my_nonce, 24);
    
    // Send encrypted buffer
    if(writen(to_fd, (char*)&my_packet0_ciphertext, 512)<0)
    { return oops_sys("write failed"); }
    
    // Erase keys
    memset(my_packet0_plaintext_pinned->pk, 0, sizeof(my_packet0_plaintext_pinned->pk));
    
    return 0;
}

int saltunnel_kx_packet0_tryread(cache* table,
                                 packet0* their_packet0_plaintext_pinned,
                                 const unsigned char long_term_key[32],
                                 int from_fd,
                                 unsigned char their_pk_out[32]) {
    errno = EBADMSG;
    log_debug("starting key exchange (with fd %d)", from_fd);
    
    packet0 their_buffer_ciphertext = {0};
    memset(their_packet0_plaintext_pinned, 0, sizeof(packet0));
    
    // Receive encrypted buffer
    ssize_t bytes_read = read(from_fd, (char*)&their_buffer_ciphertext, 512);
    if(bytes_read<0 && errno==EWOULDBLOCK)
        return oops_sys("empty packet0");
    if(bytes_read<0)
        return oops_sys("read failed");
    if(bytes_read != CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT)
        return oops_sys("partial packet0");
    
    // Extract random nonce
    unsigned char their_nonce[24];
    memcpy(their_nonce, their_buffer_ciphertext.nonce, 24);
    
    // Decrypt encrypted buffer
    if(crypto_secretbox_xsalsa20poly1305_open((unsigned char*)their_packet0_plaintext_pinned->prezeros,
                                               (unsigned char*)their_buffer_ciphertext.prezeros,
                                               512+16-24, their_buffer_ciphertext.nonce, long_term_key)<0)
        return oops("decryption failed");
    
    // Verify version
    if(sodium_compare(their_packet0_plaintext_pinned->version, version, 8) != 0)
        return oops("version mismatch");
    
    // Verify that their timestamp is less than an hour old
    uint64_t my_now = time(NULL);
    uint64_t their_now;
    uint64_unpack_big((char*)their_packet0_plaintext_pinned->epoch_seconds, &their_now);
    if(their_now < (my_now-3600))
        return oops("received stale packet0");
    
    // DoD prevention: Ensure hypercounter is fresh (only needed on server-side)
    if(table)
    {
        // DoD prevention: Unpack hypercounter timestamp
        uint64_t new_monotonic_time;
        uint64_unpack((char*)their_packet0_plaintext_pinned->monotonic_time, &new_monotonic_time);
        
        // DoD prevention: If we've seen this machine before, ensure timestamp is fresh
        unsigned char* old_monotonic_time_ptr = cache_get(table, their_packet0_plaintext_pinned->machine_id);
        if(old_monotonic_time_ptr) {
            uint64_t old_monotonic_time = ((uint64_t)*old_monotonic_time_ptr);
            if(new_monotonic_time <= old_monotonic_time) {
                return oops("received replayed packet0");
            }
        }
        
        // DoD prevention: Passed. Update cache table
        if(cache_insert(table, their_packet0_plaintext_pinned->machine_id, their_packet0_plaintext_pinned->monotonic_time)<0)
            return -1;
    }
    
    // Copy their_pk to output
    memcpy(their_pk_out, their_packet0_plaintext_pinned->pk, sizeof(their_packet0_plaintext_pinned->pk));
    
    // Erase local copy of their_pk
    memset(their_packet0_plaintext_pinned->pk, 0, sizeof(their_packet0_plaintext_pinned->pk));
    
    // Success
    errno = 0;
    return 0;
}

int saltunnel_kx_calculate_shared_key(unsigned char keys_out[64],
                                      const unsigned char pk[32],
                                      const unsigned char sk[32])
{
    unsigned char s[32];
    if (crypto_scalarmult_curve25519(s, sk, pk) != 0) {
        return oops("failed to derive shared key");
    }
    
    static const unsigned char zero[16] = { 0 };
    crypto_core_salsa20(keys_out, zero, s, NULL);
    
    return 0;
}

static const unsigned char packet1_nonce[24] = {0};
static const packet1 my_packet1_plaintext = {0};
int saltunnel_kx_packet1_exchange(unsigned char session_shared_keys[64],
                                  int client_or_server,
                                  int remote_fd)
{
    // Initialize packets
    packet1 my_packet1_ciphertext;
    packet1 their_packet1_plaintext;
    packet1 their_packet1_ciphertext;

    memset(&my_packet1_ciphertext, 0, 32);
    memset(&their_packet1_plaintext, 0, 32);
    memset(&their_packet1_ciphertext, 0, 32);

    // Clarify keys
    unsigned char* my_key = &session_shared_keys[32*client_or_server];
    unsigned char* their_key = &session_shared_keys[32*!client_or_server];

    // Encrypt my packet1
    if(crypto_secretbox_xsalsa20poly1305(my_packet1_ciphertext.prezeros,
                                         my_packet1_plaintext.prezeros,
                                         sizeof(packet1), 
                                         packet1_nonce, 
                                         my_key)<0)
    { return oops("encryption failed for packet1"); }

    // Send my packet1
    if(writen(remote_fd, (const char*)my_packet1_ciphertext.auth, 512)<0)
        return oops_sys("failed to send packet1");

    // Read their packet1
    if(readn(remote_fd, (char*)their_packet1_ciphertext.auth, 512)<0)
        return oops_sys("failed to send packet1");

    // Decrypt my packet1
    if(crypto_secretbox_xsalsa20poly1305_open(their_packet1_plaintext.prezeros,
                                              their_packet1_ciphertext.prezeros,
                                              sizeof(packet1), 
                                              packet1_nonce, 
                                              their_key)<0)
    { return oops("decryption failed for packet1"); }

    return 0;
}
