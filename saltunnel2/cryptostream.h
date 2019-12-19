//
//  cryptostream.h
//  saltunnel2
//

#ifndef cryptostream_h
#define cryptostream_h

#include "nonce.h"

#define packetsize 512
#define maxchunksize (packetsize-16-2)
#define maxbufferlen 65536

typedef struct cryptostream {
    int (*op)(struct cryptostream*,unsigned char*);
    int from_fd;
    int to_fd;
    nonce24 nonce;
    unsigned char cipherbuf[32+maxbufferlen];
    unsigned short cipherbufbytes;
} cryptostream;

int cryptostream_identity_feed(cryptostream*,unsigned char*);
int cryptostream_encrypt_feed(cryptostream*,unsigned char*);
int cryptostream_decrypt_feed(cryptostream*,unsigned char*);

#endif /* cryptostream_h */
