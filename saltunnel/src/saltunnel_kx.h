//
//  saltunnel_kx.h
//  saltunnel
//

#ifndef saltunnel_exchange_key_h
#define saltunnel_exchange_key_h

#include "cache.h"

static const unsigned char version[] = { 0x06,0x05,0x28,0x84,0x9a,0x61,0x08,0xc7 }; // saltunnel-1.0.0 (0x060528849a6108c7)

typedef struct clienthi {
    union {
        struct {
            unsigned char nonce[24];
        };
        struct {
            unsigned char unused[8];
            unsigned char prezeros[16];
        };
    };
    unsigned char auth[16];
    unsigned char version[8];
    unsigned char public_key[32];
    unsigned char timestamp[8];       // Seconds since 1970-01-01T00:00:00Z
    unsigned char machine_id[16];     // Unique {machine_id,boot_time} identifier
    unsigned char machine_counter[8]; // Monotonic time since boot
    unsigned char zeros[400];
} clienthi;

typedef struct serverhi {
    union {
        struct {
            unsigned char nonce[24];
        };
        struct {
            unsigned char unused[8];
            unsigned char prezeros[16];
        };
    };
    unsigned char auth[16];
    unsigned char version[8];
    unsigned char public_key[32];
    unsigned char proof[16]; 
    unsigned char zeros[416];
} serverhi;

typedef struct message0 {
    unsigned char prezeros[16];
    unsigned char auth[16];
    unsigned char len[2];
    unsigned char data[494];
} message0;

int saltunnel_kx_clienthi_trywrite(clienthi* clienthi_plaintext_pinned,
                                  const unsigned char long_term_key[32],
                                  int to_fd,
                                  unsigned char secret_key_out_pinned[32]);

int saltunnel_kx_clienthi_tryread(cache* table,
                                 clienthi* clienthi_plaintext_pinned,
                                 const unsigned char long_term_key[32],
                                 int from_fd,
                                 unsigned char their_pk_out[32]);

int saltunnel_kx_serverhi_trywrite(serverhi* serverhi_plaintext_pinned,
                                  const unsigned char long_term_key[32],
                                  int to_fd,
                                  unsigned char secret_key_out_pinned[32],
                                  unsigned char their_public_key_pinned[32],
                                  unsigned char session_shared_keys_pinned[64]);

int saltunnel_kx_serverhi_tryread(serverhi* serverhi_plaintext_pinned,
                                  const unsigned char long_term_key[32],
                                  int from_fd,
                                  unsigned char their_pk_out_pinned[32],
                                  unsigned char my_sk[32],
                                  unsigned char session_shared_keys_pinned[64]);

int saltunnel_kx_calculate_shared_key(unsigned char keys_out[64],
                                      const unsigned char pk[32],
                                      const unsigned char sk[32]);

int saltunnel_kx_message0_trywrite(unsigned char session_shared_keys[64], int to_fd);

int saltunnel_kx_message0_tryread(unsigned char session_shared_keys[64], int from_fd);


#endif /* saltunnel_kx_h */
