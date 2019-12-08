//
//  cryptostream.h
//  saltunnel2
//

#ifndef cryptostream_h
#define cryptostream_h

#define CRYPTOSTREAM_ENCRYPT 0
#define CRYPTOSTREAM_DECRYPT 1

typedef struct cryptostream {
    int op;
    int from_fd;
    int to_fd;
} cryptostream;

int cryptostream_feed(cryptostream*);

#endif /* cryptostream_h */
