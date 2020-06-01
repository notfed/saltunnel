//
//  saltunnel_kx.c
//  saltunnel
//

#include "saltunnel.h"
#include "saltunnel_crypto.h"
#include "rwn.h"
#include "sodium.h"
#include "csprng.h"
#include "oops.h"
#include "log.h"
#include "saltunnel_kx.h"
#include "hypercounter.h"
#include "uint64.h"
#include "cache.h"
#include "consttime.h"

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

static const unsigned char zero[sizeof(message0)] = {0};

int saltunnel_kx_clienthi_trywrite(clienthi* clienthi_plaintext_pinned,
                                  const unsigned char long_term_key_pinned[32],
                                  int to_fd,
                                  unsigned char secret_key_out_pinned[32]) {
    
    // Start with a ciphertext and zeroed-out plaintext
    clienthi clienthi_ciphertext;
    memset(clienthi_plaintext_pinned, 0, sizeof(clienthi));
    
    // Set version
    memcpy(clienthi_plaintext_pinned->version, version, 8);
    
    // Create ephemeral keypair
    crypto_box_keypair(clienthi_plaintext_pinned->public_key, secret_key_out_pinned);
    
    // Generate nonce
    unsigned char my_nonce[24];
    csprng(my_nonce, 24);
    
    // Generate timestamp
    struct timespec time_now;
    if(clock_gettime(CLOCK_REALTIME, &time_now)<0) return oops("failed to get time");
    uint64_pack_big((char*)&clienthi_plaintext_pinned->timestamp, time_now.tv_sec);
    
    // Generate machine_id and machine_counter
    if(hypercounter(clienthi_plaintext_pinned->machine_id, clienthi_plaintext_pinned->machine_counter)<0)
        return -1;
    
    // Encrypt clienthi
    memset(clienthi_ciphertext.prezeros, 0, 32);
    if(crypto_secretbox24(clienthi_ciphertext.prezeros,
                          clienthi_plaintext_pinned->prezeros,
                          512+16-24, my_nonce, long_term_key_pinned)<0)
    { return oops("authentication failed: encryption failed"); }
    
    // Put the nonce at the head of clienthi_ciphertext
    memcpy(clienthi_ciphertext.nonce, my_nonce, 24);
    
    // Send clienthi_ciphertext
    if(writen(to_fd, (char*)&clienthi_ciphertext, 512)<0)
    { return oops_sys("authentication failed: failed to write to destination connection"); }
    
    // Erase public key (no longer needed)
    memset(clienthi_plaintext_pinned->public_key, 0, sizeof(clienthi_plaintext_pinned->public_key));
    
    return 0;
}

int saltunnel_kx_clienthi_tryparse(cache* table,
                                 clienthi* clienthi_plaintext_pinned,
                                 const unsigned char long_term_key_pinned[32],
                                 clienthi* clienthi_ciphertext,
                                 unsigned char their_pk_out_pinned[32]) {
    
    // Start with a ciphertext and zeroed-out plaintext
    memset(clienthi_plaintext_pinned, 0, sizeof(clienthi));
    
    // Extract random nonce
    unsigned char my_nonce[24];
    memcpy(my_nonce, clienthi_ciphertext->nonce, 24);
    
    // Decrypt encrypted buffer
    memset(clienthi_ciphertext->prezeros, 0, 16);
    if(crypto_secretbox24_open((unsigned char*)clienthi_plaintext_pinned->prezeros,
                               (unsigned char*)clienthi_ciphertext->prezeros,
                               512+16-24, my_nonce, long_term_key_pinned)<0)
    {
        return oops("authentication failed: received bad clienthi");
        
    }
    
    // Verify version
    if(!consttime_are_equal(clienthi_plaintext_pinned->version, version, 8))
        return oops("authentication failed: clienthi version mismatch");
    
    // Generate timestamp
    struct timespec my_now;
    if(clock_gettime(CLOCK_REALTIME, &my_now)<0) return oops("failed to get time");
    uint64_t my_now_seconds = my_now.tv_sec;
    
    // Verify that their timestamp is less than an hour old
    uint64_t their_now_seconds;
    uint64_unpack_big((char*)clienthi_plaintext_pinned->timestamp, &their_now_seconds);
    if(their_now_seconds < (my_now_seconds-3600))
        return oops("authentication failed: received stale clienthi");
    
    // DoS prevention: Ensure hypercounter is fresh
    if(table)
    {
        // DoS prevention: Unpack hypercounter timestamp
        uint64_t new_monotonic_time;
        uint64_unpack((char*)clienthi_plaintext_pinned->machine_counter, &new_monotonic_time);
        
        // DoS prevention: If we've seen this machine before, ensure timestamp is fresh
        unsigned char* old_monotonic_time_ptr = cache_get(table, clienthi_plaintext_pinned->machine_id);
        if(old_monotonic_time_ptr) {
            uint64_t old_monotonic_time = ((uint64_t)*old_monotonic_time_ptr);
            if(new_monotonic_time <= old_monotonic_time) {
                return oops("authentication failed: received replayed clienthi");
            }
        }
        
        // DoS prevention: Passed. Update cache table
        if(cache_insert(table, clienthi_plaintext_pinned->machine_id, clienthi_plaintext_pinned->machine_counter)<0)
            return -1;
    }
    
    // Verify zeros
    if(memcmp(clienthi_plaintext_pinned->zeros, zero, sizeof(clienthi_plaintext_pinned->zeros))!=0)
       return oops("authentication failed: clienthi zeros were not zero");
    
    // Copy their_pk to output
    memcpy(their_pk_out_pinned, clienthi_plaintext_pinned->public_key, sizeof(clienthi_plaintext_pinned->public_key));
    
    // Erase local copy of their_pk
    memset(clienthi_plaintext_pinned->public_key, 0, sizeof(clienthi_plaintext_pinned->public_key));
    
    errno = 0;
    return 0;
}

int saltunnel_kx_serverhi_trywrite(serverhi* serverhi_plaintext_pinned,
                                   const unsigned char long_term_key[32],
                                   int to_fd,
                                   unsigned char secret_key_out_pinned[32],
                                   unsigned char their_public_key_pinned[32],
                                   unsigned char session_shared_keys_pinned[64])
{
    
    // Start with a ciphertext and zeroed-out plaintext
    serverhi serverhi_ciphertext;
    memset(serverhi_plaintext_pinned, 0, sizeof(serverhi));
    
    // Set version
    memcpy(serverhi_plaintext_pinned->version, version, 8);
    
    // Create ephemeral keypair
    if(crypto_box_keypair(serverhi_plaintext_pinned->public_key, secret_key_out_pinned)!=0)
        return oops("failed to create ephemeral keypair");
    
    // Calculate shared session keys
    if(saltunnel_kx_calculate_shared_key(session_shared_keys_pinned, their_public_key_pinned, secret_key_out_pinned)<0)
        return -1;
    
    // Generate nonce
    unsigned char my_nonce[24];
    csprng(my_nonce, 24);
    
    // Generate proof that we know both session keys
    for(int i = 0; i<16; i++) {
        serverhi_plaintext_pinned->proof[i] = session_shared_keys_pinned[0+i] ^ session_shared_keys_pinned[48+i];
    }
    
    // Encrypt clienthi
    memset(serverhi_ciphertext.prezeros, 0, 32);
    if(crypto_secretbox24(serverhi_ciphertext.prezeros,
                          serverhi_plaintext_pinned->prezeros,
                          512+16-24, my_nonce, long_term_key)<0)
    { return oops("authentication failed: encryption failed"); }
    
    // Put the nonce at the head of serverhi_ciphertext
    memcpy(serverhi_ciphertext.nonce, my_nonce, 24);
    
    // Send serverhi_ciphertext
    if(writen(to_fd, (char*)&serverhi_ciphertext, 512)<0)
    { return oops_sys("authentication failed: failed to write to source connection"); }
    
    // Erase public key (no longer needed)
    memset(serverhi_plaintext_pinned->public_key, 0, 32);
    
    return 0;
}

int saltunnel_kx_serverhi_tryread(serverhi* serverhi_plaintext_pinned,
                                  const unsigned char long_term_key_pinned[32],
                                  int from_fd,
                                  unsigned char their_pk_out_pinned[32],
                                  unsigned char my_sk[32],
                                  unsigned char session_shared_keys_pinned[64])
{
    // Start with a ciphertext and zeroed-out plaintext
    serverhi serverhi_ciphertext;
    memset(serverhi_plaintext_pinned, 0, sizeof(serverhi));
    
    // Receive encrypted buffer
    ssize_t bytes_read = read(from_fd, (char*)&serverhi_ciphertext, 512);
    if(bytes_read<0 && errno==EWOULDBLOCK)
        return oops("authentication failed: received empty serverhi");
    if(bytes_read<0)
        return oops_sys("authentication failed: failed to read serverhi");
    if(bytes_read == 0)
        return oops("authentication failed: connection was terminated");
    if(bytes_read != CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT)
        return oops("authentication failed: received partial serverhi");
    
    // Extract random nonce
    unsigned char nonce[24];
    memcpy(nonce, serverhi_ciphertext.nonce, 24);
    
    // Decrypt encrypted buffer
    memset(serverhi_ciphertext.prezeros, 0, 16);
    if(crypto_secretbox24_open((unsigned char*)serverhi_plaintext_pinned->prezeros,
                               (unsigned char*)serverhi_ciphertext.prezeros,
                               512+16-24, nonce, long_term_key_pinned)<0)
    { return oops("authentication failed: received bad serverhi"); }
    
    // Verify version
    if(!consttime_are_equal(serverhi_plaintext_pinned->version, version, 8))
        return oops("authentication failed: serverhi version mismatch");
    
    // Calculate shared key
    if(saltunnel_kx_calculate_shared_key(session_shared_keys_pinned, serverhi_plaintext_pinned->public_key, my_sk)<0)
        return -1;
    
    // Verify proof
    unsigned char expected_proof[16];
    for(int i = 0; i<16; i++) {
        expected_proof[i] = session_shared_keys_pinned[0+i]  ^ session_shared_keys_pinned[48+i];
    }
    if(!consttime_are_equal(expected_proof, serverhi_plaintext_pinned->proof, 16))
        return oops("authentication failed: serverhi proof was invalid");
    
    // Verify zeros
    if(memcmp(serverhi_plaintext_pinned->zeros, zero, sizeof(serverhi_plaintext_pinned->zeros))!=0)
       return oops("authentication failed: serverhi zeros were not zero");
        
    // Copy their_pk to output
    memcpy(their_pk_out_pinned, serverhi_plaintext_pinned->public_key, 32);
    
    // Erase local copy of their_pk
    memset(serverhi_plaintext_pinned->public_key, 0, 32);
    
    log_trace("connection %d: client forwarder successfully read serverhi", remote_fd);
    
    return 0;
}

int saltunnel_kx_calculate_shared_key(unsigned char keys_out_pinned[96],
                                      const unsigned char pk_pinned[32],
                                      const unsigned char sk_pinned[32])
{
    unsigned char* dh = &keys_out_pinned[64];
    if (crypto_scalarmult(dh, sk_pinned, pk_pinned) != 0) {
        return oops("authentication failed: failed to derive shared key");
    }
    crypto_stream8(keys_out_pinned, 64, zero, dh);
    memset(dh, 0, 32);
    return 0;
}

int saltunnel_kx_message0_trywrite(unsigned char session_shared_keys[64],  int to_fd)
{
    // Initialize a ciphertext
    message0 message0_ciphertext;
    memset(message0_ciphertext.prezeros, 0, 16);
    
    // Clarify keys
    unsigned char* client_session_key = &session_shared_keys[0];
    
    // Encrypt an empty message0
    if(crypto_secretbox24(message0_ciphertext.prezeros,
                          zero,
                          sizeof(message0),
                          zero,
                          client_session_key)<0)
    { return oops("authentication failed: encryption failed"); }

    // Send message0_ciphertext
    if(writen(to_fd, (const char*)message0_ciphertext.auth, 512)<0)
        return oops_sys("authentication failed: failed to write to connection");

    return 0;
}


int saltunnel_kx_message0_tryread(unsigned char session_shared_keys[64], int from_fd)
{
    // Initialize message
    message0 message0_ciphertext;
    message0 message0_plaintext;
    
    memset(message0_ciphertext.prezeros, 0, 32);
    memset(message0_plaintext.prezeros, 0, 32);
    
    // Clarify keys
    unsigned char* client_session_key = &session_shared_keys[0];
    
    // Read their message0
    if(readn(from_fd, (char*)message0_ciphertext.auth, 512)<0)
        return oops_sys("authentication failed: failed to read from connection");

    // Decrypt my message0
    if(crypto_secretbox24_open(message0_plaintext.prezeros,
                               message0_ciphertext.prezeros,
                               sizeof(message0),
                               zero,
                               client_session_key)<0)
    { return oops("authentication failed: received bad message"); }

    return 0;
}
