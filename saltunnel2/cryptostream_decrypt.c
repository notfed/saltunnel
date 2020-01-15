//
//  cryptostream_decrypt.c
//  saltunnel2
//

#include "cryptostream.h"
#include "uninterruptable.h"
#include "oops.h"
#include "tweetnacl.h"
#include "nonce.h"
#include "log.h"
#include "uint16.h"
#include <unistd.h>
#include <stdio.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static void vector_init(cryptostream *cs) {
    for(int j = 0; j<=128; j+=128) {
        for(int i = 0; i<128; i++) {
            cs->plaintext_vector[j+i].iov_base = cs->plaintext + CRYPTOSTREAM_BUFFER_MAXBYTES*i + 32+2;
            cs->plaintext_vector[j+i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_DATA;
        }
    }
    for(int j = 0; j<=128; j+=128) {
        for(int i = 0; i<128; i++) {
            cs->ciphertext_vector[j+i].iov_base = cs->ciphertext + CRYPTOSTREAM_BUFFER_MAXBYTES*i + 16;
            cs->ciphertext_vector[j+i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT;
        }
    }
}

// Only read 1 byte
static int chaos_readv(int fd, struct iovec* vector, int count) {
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = MIN(512,vector[0].iov_len)
    };
    int r = (int)readv(fd,&newvector,1);
    return r;
}

// Is there enough room for 1 buffer of plaintext and 1 buffer of ciphertext?
int cryptostream_decrypt_feed_canread(cryptostream* cs) {
    int plaintext_has_available_buffers = cs->plaintext_len < (CRYPTOSTREAM_SPAN_MAXBYTES_DATA - CRYPTOSTREAM_BUFFER_MAXBYTES_DATA);
    int ciphertext_has_available_buffers = cs->ciphertext_len < (CRYPTOSTREAM_SPAN_MAXBYTES_CIPHERTEXT - CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT);
    return plaintext_has_available_buffers && ciphertext_has_available_buffers;
}

//
// Algorithm:
// - Read up to 65536 (128*512) bytes into 'ciphertext' buffer
// -   (Scatter into 128 512-byte chunks)
// -   (Each chunk must be prefixed with 16 zero-bytes)
// - If we have 1 or more full chunks, decrypt them.
// Returns:
//   >1 => ok
//    0 => read fd closed
//
int cryptostream_decrypt_feed_read(cryptostream* cs, unsigned char* key) {

    // Lazily initialize the plaintext vector
    if(!cs->vector_init_complete) {
      vector_init(cs);
      cs->vector_init_complete = 1;
    }

    //
    // Read
    //
    
    // Perform a scattered read. Read data into the following format:
    //    - u8[16]  zeros;
    //    - u8[16]  auth;
    //    - u16     datalen;
    //    - u8[494] data;
    //    - ... (x128 packets) ...
    int buffer_read_start = cs->ciphertext_start + cs->ciphertext_len;
    int buffer_read_count = CRYPTOSTREAM_BUFFER_COUNT - cs->ciphertext_len;
    int readv_fd = cs->from_fd;
    struct iovec* readv_vector = &cs->ciphertext_vector[buffer_read_start];
    
    int bytesread;
    try((bytesread =  (int)readv(readv_fd, readv_vector, buffer_read_count))) || oops_fatal("error reading from cs->from_fd");
    
    // If the read returned a 0, it means the read fd is closed
    if(bytesread==0)
    {
        log_debug("ingress local fd (%d) was closed", cs->from_fd);
        return 0;
    }
    
    // Bump vector
    int buffers_filled  = (int)iovec_skip2(readv_vector, buffer_read_count, bytesread);

    // Re-initialize the freed-up ciphertext vectors
    for(int buffer_i = buffer_read_start; buffer_i < buffers_filled; buffer_i++) {
        cs->ciphertext_vector[buffer_i].iov_base = cs->ciphertext + CRYPTOSTREAM_BUFFER_MAXBYTES*buffer_i + 16;
        cs->ciphertext_vector[buffer_i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT;
    }
    
    log_debug("cryptostream_decrypt_feed_read: got %d bytes from egress local",(int)bytesread);
    
    // If we didn't fill any buffers, nothing to decrypt
    if(buffers_filled==0) {
        return bytesread;
    }
    
    unsigned char* x = cs->ciphertext_vector[cs->ciphertext_start].iov_base; // JUST TO WATCH
    int xlen = cs->ciphertext_vector[cs->ciphertext_start].iov_len; // JUST TO WATCH

    //`
    // Decrypt
    //
//
//    // Calculate how many buffers are free
//    int ciphertext_free_buffers = CRYPTOSTREAM_BUFFER_COUNT - cs->ciphertext_len;
//    int plaintext_free_buffers  = CRYPTOSTREAM_BUFFER_COUNT - cs->plaintext_len;
//
//    // Calculate which buffer to start at and how many to decrypt
//    int buffer_start = cs->ciphertext_start;
//    int buffer_count = MIN(ciphertext_free_buffers,plaintext_free_buffers);
    
    int buffer_decrypt_start = buffer_read_start;
    int buffer_decrypt_count = buffers_filled;

    // Iterate the decryptable buffers (if any)
    log_debug("decryption started");
    for(int buffer_i = buffer_decrypt_start; buffer_i < buffer_decrypt_count; buffer_i++)
    {
        // Find the pointers to the start of the buffers
        unsigned char* plaintext_buffer_ptr = cs->plaintext_vector[buffer_i].iov_base - 32-2;
        unsigned char* ciphertext_buffer_ptr = cs->ciphertext_vector[buffer_i].iov_base - 16;

        // Decrypt chunk from ciphertext to plaintext (512 bytes)

        // crypto_secretbox_open:
        // - signature: crypto_secretbox_open(m,c,clen,n,k)
        // - input structure:
        //   - [0..16]  == zero
        //   - [16..32] == auth
        //   - [32..]   == ciphertext
        // - output structure:
        //   - [0..32] == zero
        //   - [32..]  == plaintext
        try(crypto_secretbox_open(plaintext_buffer_ptr, ciphertext_buffer_ptr,
                               CRYPTOSTREAM_BUFFER_MAXBYTES,cs->nonce,key)) || oops_fatal("failed to trial decrypt");

        // Increment nonce
        nonce24_increment(cs->nonce);

        // Extract datalen
        uint16 datalen_current = 0;
        uint16_unpack((char*)cs->plaintext + 32, &datalen_current);
        
        // Update vector length
        cs->plaintext_vector[buffer_i].iov_len = datalen_current;

        log_debug("cryptostream_decrypt_feed_read: decrypted %d bytes (buffer %d/%d)", datalen_current, buffer_i+1, buffer_decrypt_count);

        // Increment nonce
        nonce24_increment(cs->nonce);
    }

    // Rotate buffer offsets
    cs->ciphertext_start = (cs->ciphertext_start + buffer_decrypt_count) % CRYPTOSTREAM_BUFFER_COUNT;
    cs->ciphertext_len -= buffer_decrypt_count;
    cs->plaintext_len  += buffer_decrypt_count;
    
    log_debug("decryption ended");

    return 1;
}

int cryptostream_decrypt_feed_canwrite(cryptostream* cs) {
    return cs->plaintext_len > 0;
}

//
// Algorithm:
// - Write as much data as possible to local
// Returns:
//   >1 => ok
//    0 => nothing to write
//
int cryptostream_decrypt_feed_write(cryptostream* cs, unsigned char* key) {
    
    // Calculate the index of the first buffer, the offset into the first buffer, and how many buffers to write
    int buffer_start       = cs->plaintext_start;
    int buffer_count       = cs->plaintext_len;
    
    // Adjust the write-vector lengths to the datalen of each corresponding buffer
    for(int b = 0; b<buffer_count; b++) {
        // Extract datalen
        uint16 datalen_current = 0;
        uint16_unpack((char*)cs->plaintext + 32, &datalen_current);
        
        // Update vector length
        cs->plaintext_vector[buffer_start+b].iov_base = cs->plaintext + CRYPTOSTREAM_BUFFER_MAXBYTES*(buffer_start+b) + 32+2;
        cs->plaintext_vector[buffer_start+b].iov_len = datalen_current;
    }
    
    // Write as much as possible
    int byteswritten;
    try((byteswritten = (int)writev(cs->to_fd,                         // fd
                                 &cs->plaintext_vector[buffer_start],  // vector
                                 buffer_count                          // count
    ))) || oops_fatal("failed to write");
    
    log_debug("cryptostream_decrypt_feed_write: wrote %d bytes", byteswritten);

    // Feed the vector forward this many bytes
    int buffers_filled = (int)iovec_skip2(&cs->plaintext_vector[buffer_start], buffer_count, byteswritten);
    
    // Rotate the buffer offsets
    cs->plaintext_start = (cs->plaintext_start + buffers_filled) % CRYPTOSTREAM_SPAN_MAXBYTES_PLAINTEXT;
    cs->plaintext_len   = (cs->plaintext_len   - buffers_filled);

    return 1;
}
