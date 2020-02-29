//
//  saltunnel_kx.h
//  saltunnel
//

#ifndef saltunnel_exchange_key_h
#define saltunnel_exchange_key_h

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
    unsigned char zeros[432];
} packet0;

typedef struct packet1 {
    unsigned char prezeros[16];
    unsigned char auth[16];
    unsigned char zeros[496];
} packet1;

// New
int saltunnel_kx_packet0_tryread(unsigned char* long_term_key,
                                 int from_fd,
                                 unsigned char their_pk_out[32]);
int saltunnel_kx_packet0_trywrite(unsigned char* long_term_key,
                                  int to_fd,
                                  unsigned char my_sk_out[32]);
int saltunnel_kx_calculate_shared_key(unsigned char* session_key_out,
                                      unsigned char* their_pk,
                                      unsigned char* my_sk);

// Old
void exchange_session_key(int from_fd, int to_fd,
                          unsigned char* long_term_key,
                          unsigned char* session_key_out);
#endif /* saltunnel_exchange_key_h */
