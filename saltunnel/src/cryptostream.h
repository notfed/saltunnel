//
//  cryptostream.h
//  saltunnel
//

#ifndef cryptostream_h
#define cryptostream_h

#include "nonce.h"
#include "threadpool.h"
#include <sys/uio.h>
#include <unistd.h>

// Glossary:
// - A buffer is a contiguous array of bytes. By default, it can contain:
//      - 494 bytes of data
//      - 494+2=496 bytes of plaintext (includes a 2-byte datalen)
//      - 494+2+16=512 bytes of ciphertext (includes 16-byte auth)
//      - 494+2+32=528 bytes total (includes 16-byte zeros)
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
    
    /* These fields are required input */
    int from_fd;
    int to_fd;
    unsigned char* key;

    /* The remaining fields will be auto-populated */
    nonce8 nonce;
    int vector_init_complete;
    
    unsigned char plaintext[CRYPTOSTREAM_SPAN_MAXBYTES];
    struct iovec plaintext_vector[CRYPTOSTREAM_BUFFER_COUNT*2]; // NOTE: Only points to data (i.e., excl. the 2-byte length of plaintext)
    int vector_start;
    int vector_len;
    
    unsigned char ciphertext[CRYPTOSTREAM_SPAN_MAXBYTES];
    struct iovec ciphertext_vector[CRYPTOSTREAM_BUFFER_COUNT*2];
    
    long debug_write_total;
    long debug_read_total;
    long debug_encrypted_blocks_total;
    long debug_decrypted_blocks_total;
    
} cryptostream;

int cryptostream_encrypt_feed_canread(cryptostream* cs);
int cryptostream_encrypt_feed_read(cryptostream* cs);
int cryptostream_encrypt_feed_canwrite(cryptostream* cs);
int cryptostream_encrypt_feed_write(cryptostream* cs);

void encrypt_all(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs);
void encrypt_all_serial(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs, nonce8 nonce);
void encrypt_all_parallel(int buffer_encrypt_count, int buffer_encrypt_start_i, int bytesread, cryptostream *cs);
void encrypt_one(int buffer_i, int buffer_n, int bytesread, cryptostream *cs, nonce8 nonce);

int cryptostream_decrypt_feed_canread(cryptostream* cs);
int cryptostream_decrypt_feed_read(cryptostream* cs);
int cryptostream_decrypt_feed_canwrite(cryptostream* cs);
int cryptostream_decrypt_feed_write(cryptostream* cs);

void decrypt_all(int buffer_decrypt_count, int buffer_decrypt_start, cryptostream* cs);
void decrypt_all_serial(int buffer_decrypt_count, int buffer_decrypt_start, cryptostream *cs, nonce8 nonce);
void decrypt_all_parallel(int buffer_decrypt_count, int buffer_decrypt_start, cryptostream *cs);
void decrypt_one(int buffer_i, cryptostream *cs, nonce8 nonce);

void vector_init(cryptostream *cs);
void vector_reset_plaintext(struct iovec* iovec_array, unsigned char* span, int vec_i);
void vector_reset_ciphertext(struct iovec* iovec_array, unsigned char* span, int vec_i);
void vector_buffer_set_len(struct iovec* iovec_array, int buffer_i, int len);
void vector_buffer_set_base(struct iovec* iovec_array, int buffer_i, void* base);
ssize_t vector_skip(struct iovec *v, int start_i, size_t count_i, unsigned int n);
ssize_t vector_skip_debug(struct iovec *v, int start_i, size_t count_i, unsigned int n, cryptostream* debug_remove_me);

#endif /* cryptostream_h */
