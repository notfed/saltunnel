//
//  cryptostream.h
//  saltunnel2
//

#ifndef cryptostream_h
#define cryptostream_h

#include "nonce.h"
#include <unistd.h>


typedef struct cryptostream {
    int (*op)(struct cryptostream*,unsigned char*);
    int from_fd;
    int to_fd;
    nonce24 nonce;
    
    int readvector_is_initialized;
    struct iovec readvector[128];
    
    struct iovec writevector[128];
    
    unsigned char ciphertext[(32+2+494)*128];
    unsigned char plaintext[(32+2+494)*128];
    
    /* Temp variables for coroutines */
    unsigned int ciphertext_packet_size_in_progress;
    int packetcount;
    int flush_progress_bytesleft;
    int flush_progress_totalbytes;
    
    int ctr;
} cryptostream;

int cryptostream_identity_feed(cryptostream*,unsigned char*);
int cryptostream_encrypt_feed(cryptostream*,unsigned char*);
int cryptostream_decrypt_feed(cryptostream*,unsigned char*);

#endif /* cryptostream_h */
