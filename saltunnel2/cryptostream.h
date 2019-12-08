//
//  cryptostream.h
//  saltunnel2
//

#ifndef cryptostream_h
#define cryptostream_h

typedef struct cryptostream {
    int (*op)(struct cryptostream*);
    int from_fd;
    int to_fd;
} cryptostream;

int cryptostream_identity_feed(cryptostream*);
int cryptostream_encrypt_feed(cryptostream*);
int cryptostream_decrypt_feed(cryptostream*);

#endif /* cryptostream_h */
