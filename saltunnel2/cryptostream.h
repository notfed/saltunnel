//
//  cryptostream.h
//  saltunnel2
//

#ifndef cryptostream_h
#define cryptostream_h

typedef struct cryptostream {
    int (*op)(struct cryptostream*,unsigned char*);
    int from_fd;
    int to_fd;
} cryptostream;

int cryptostream_identity_feed(cryptostream*,unsigned char*);
int cryptostream_encrypt_feed(cryptostream*,unsigned char*);
int cryptostream_decrypt_feed(cryptostream*,unsigned char*);

#endif /* cryptostream_h */
