//
//  saltunnel_kx.h
//  saltunnel
//

#ifndef saltunnel_exchange_key_h
#define saltunnel_exchange_key_h

#include "cache.h"

static const unsigned char version[] = { 0x06,0x05,0x28,0x84,0x9a,0x61,0x08,0xc7 }; // 0x060528849a6108c7

typedef struct packet0 {
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
    unsigned char pk[32];
    unsigned char epoch_seconds[8];
    unsigned char machine_id[16];
    unsigned char monotonic_time[8];
    unsigned char zeros[408];
} packet0;

typedef struct packet1 {
    unsigned char prezeros[16];
    unsigned char auth[16];
    unsigned char zeros[496];
} packet1;

// New
int saltunnel_kx_packet0_trywrite(packet0* tmp_pinned,
                                  const unsigned char long_term_key[32],
                                  int to_fd,
                                  unsigned char my_sk_out[32],
                                  int writeToSourceOrDestination);

int saltunnel_kx_packet0_tryread(cache* table,
                                 packet0* tmp_pinned,
                                 const unsigned char long_term_key[32],
                                 int from_fd,
                                 unsigned char their_pk_out[32]);

int saltunnel_kx_calculate_shared_key(unsigned char keys_out[64],
                                      const unsigned char pk[32],
                                      const unsigned char sk[32]);

int saltunnel_kx_packet1_exchange(unsigned char session_shared_keys[64], 
		                  int client_or_server, 
				  int remote_fd);

#endif /* saltunnel_kx_h */
