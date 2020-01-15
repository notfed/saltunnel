//
//  cryptostream.h
//  saltunnel2
//

#ifndef cryptostream_h
#define cryptostream_h

#include "nonce.h"
#include <unistd.h>

// Glossary:
// - A buffer is a contiguous array of bytes. By default, it can contain:
//      - 494 bytes of data
//      - 494+2=496 bytes of plaintext (includes a 2-byte datalen)
//      - 494+2+16=512 bytes of ciphertext (includes 16-byte auth)
//      - 494+2+32=512 bytes total (includes 16-byte zeros)
//  The format for a buffer is:
//      - u8[16]  zeros;
//      - u8[16]  auth; (zeros for plaintext)
//      - u16     datalen;
//      - u8[494] data;
// - The reason use buffers is to scatter/gather (i.e., writev/readv)
// - A span represents multiple buffers. For example, by default, a span consists of 128 buffers.

// Number of buffers per span (i.e., 128)
#define CRYPTOSTREAM_BUFFER_COUNT                     128

// Number of ciphertext bytes per buffer (i.e., 512)
#define CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT       512

// Number of bytes per buffer (including 32-byte zeros and 16-byte auth) (i.e., 528)
#define CRYPTOSTREAM_BUFFER_MAXBYTES                  (CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT+16)

// Number of plaintext bytes per buffer (i.e., 494)
#define CRYPTOSTREAM_BUFFER_MAXBYTES_PLAINTEXT        (CRYPTOSTREAM_BUFFER_MAXBYTES-32)

// Number of data bytes per buffer (i.e., 494)
#define CRYPTOSTREAM_BUFFER_MAXBYTES_DATA             (CRYPTOSTREAM_BUFFER_MAXBYTES-32-2)

// Maximum number of data bytes across all buffers (i.e., 63232)
#define CRYPTOSTREAM_SPAN_MAXBYTES_DATA       (CRYPTOSTREAM_BUFFER_MAXBYTES_DATA * CRYPTOSTREAM_BUFFER_COUNT)

// Maximum number of plaintext bytes across all buffers (i.e., 63488)
#define CRYPTOSTREAM_SPAN_MAXBYTES_PLAINTEXT  (CRYPTOSTREAM_BUFFER_MAXBYTES_PLAINTEXT * CRYPTOSTREAM_BUFFER_COUNT)

// Maximum number of ciphertext bytes across all buffers (i.e., 65536)
#define CRYPTOSTREAM_SPAN_MAXBYTES_CIPHERTEXT (CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT * CRYPTOSTREAM_BUFFER_COUNT)

// Maximum number of bytes (including ZEROBYTES) across all buffers (i.e., 67584)
#define CRYPTOSTREAM_SPAN_MAXBYTES            (CRYPTOSTREAM_BUFFER_MAXBYTES * CRYPTOSTREAM_BUFFER_COUNT)

typedef struct cryptostream {
    
    // Old

    struct iovec readvector[128];
    struct iovec writevector[128];
    
    unsigned int ciphertext_packet_size_in_progress;
    int packetcount;
    int flush_progress_bytesleft;
    int flush_progress_totalbytes;
    int ctr;
    int readvector_is_initialized;
    
    // New
    
    int (*op)(struct cryptostream*,unsigned char*);
    int from_fd;
    int to_fd;
    nonce24 nonce;
    
    int vector_init_complete;
    
    unsigned char plaintext[CRYPTOSTREAM_SPAN_MAXBYTES];
    struct iovec plaintext_vector[CRYPTOSTREAM_BUFFER_COUNT*2]; // TODO: Rename to 'data_vector' to prevent confusion?
    int plaintext_start;  // TODO: Rename to 'data_start' to prevent confusion?
    int plaintext_len;    // TODO: Rename to 'data_len' to prevent confusion?
    int plaintext_len_buffers;
    
    unsigned char ciphertext[CRYPTOSTREAM_SPAN_MAXBYTES];
    struct iovec ciphertext_vector[CRYPTOSTREAM_BUFFER_COUNT*2];
    int ciphertext_vector_is_initialized;
    int ciphertext_start;
    int ciphertext_len;
    
    
} cryptostream;

int cryptostream_identity_feed(cryptostream*,unsigned char*); //
int cryptostream_decrypt_feed(cryptostream*,unsigned char*); //
int cryptostream_encrypt_feed(cryptostream*,unsigned char*); //

int cryptostream_encrypt_feed_canread(cryptostream* cs);
int cryptostream_encrypt_feed_read(cryptostream* cs, unsigned char* key);
int cryptostream_encrypt_feed_canwrite(cryptostream* cs);
int cryptostream_encrypt_feed_write(cryptostream* cs, unsigned char* key);

int cryptostream_decrypt_feed_canread(cryptostream* cs);
int cryptostream_decrypt_feed_read(cryptostream* cs, unsigned char* key);
int cryptostream_decrypt_feed_canwrite(cryptostream* cs);
int cryptostream_decrypt_feed_write(cryptostream* cs, unsigned char* key);

#endif /* cryptostream_h */
