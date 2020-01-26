//
//  cryptostream_decrypt.c
//  saltunnel2
//

#include "cryptostream.h"
#include "uninterruptable.h"
#include "oops.h"
#include "sodium.h"
#include "nonce.h"
#include "log.h"
#include "uint16.h"
#include "chaos.h"
#include "math.h"
#include "crypto_secretbox_salsa208poly1305.h"
#include <unistd.h>
#include <stdio.h>

// Is there enough room for 1 buffer of plaintext and 1 buffer of ciphertext?
int cryptostream_decrypt_feed_canread(cryptostream* cs) {
    return cs->vector_len < CRYPTOSTREAM_BUFFER_COUNT;
}

static void buffer_decrypt(int buffer_i, cryptostream *cs, unsigned char *key) {
    unsigned char* plaintext_buffer_ptr = cs->plaintext_vector[buffer_i].iov_base - 32-2;
    unsigned char* ciphertext_buffer_ptr = cs->ciphertext_vector[buffer_i].iov_base - 16;
    
    unsigned char* dbg1 = cs->ciphertext_vector[buffer_i%CRYPTOSTREAM_BUFFER_COUNT].iov_base-16;
    unsigned char* dbg2 = cs->ciphertext_vector[buffer_i].iov_base-16;

    // Assertions
    {
        char* a = ((char*)cs->plaintext);
        char* b = ((char*)cs->plaintext_vector[buffer_i].iov_base-32-2);
        long d = b-a;
        if( d % CRYPTOSTREAM_BUFFER_MAXBYTES != 0)
            oops_fatal("assertion failed");
        if(d<0 || d/CRYPTOSTREAM_BUFFER_MAXBYTES>=256)
            oops_fatal("assertion failed");
    }
    {
        char* a = ((char*)cs->ciphertext);
        char* b = ((char*)cs->ciphertext_vector[buffer_i].iov_base-16);
        long d = b-a;
        if( d % CRYPTOSTREAM_BUFFER_MAXBYTES != 0)
            oops_fatal("assertion failed");
        if(d<0 || d/CRYPTOSTREAM_BUFFER_MAXBYTES>=256)
            oops_fatal("assertion failed");
    }
    
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
    try(crypto_secretbox_salsa208poly1305_open(plaintext_buffer_ptr, ciphertext_buffer_ptr,
                              CRYPTOSTREAM_BUFFER_MAXBYTES,cs->nonce,key)) ||
        oops_fatal("failed to decrypt");
    
    // Increment nonce
    nonce8_increment(cs->nonce);
    
    // Extract datalen
    uint16 datalen_current = 0;
    uint16_unpack((char*)plaintext_buffer_ptr + 32, &datalen_current);
    
    // Update vector length
    vector_buffer_set_len(cs->plaintext_vector, buffer_i, datalen_current);
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
    // Read ciphertext
    //
    
    // Perform a scattered read. Read data into the following format:
    //    - u8[16]  zeros;
    //    - u8[16]  auth;
    //    - u16     datalen;
    //    - u8[494] data;
    //    - ... (x128 packets) ...
    int buffer_free_start_i = (cs->vector_start + cs->vector_len) % CRYPTOSTREAM_BUFFER_COUNT;
    int buffer_free_count = CRYPTOSTREAM_BUFFER_COUNT - cs->vector_len;
    struct iovec* buffer_free_start = &cs->ciphertext_vector[buffer_free_start_i];
    
    int bytesread;
    try((bytesread =  (int)readv(cs->from_fd, buffer_free_start, buffer_free_count)))
        || oops_fatal("error reading from cs->from_fd");
    
    cs->debug_read_total += bytesread;
    if(cs->debug_read_total>500000*528)
        oops_fatal("assertion failed");
    
    // If the read returned a 0, it means the read fd is closed
    if(bytesread==0)
    {
        log_debug("ingress local fd (%d) was closed", cs->from_fd);
        return 0;
    }
    
    // DEBUG VARIABLES
    unsigned char* x = buffer_free_start->iov_base;
    int xlen = buffer_free_start->iov_len;
    
    // Bump vector
    if(cs->debug_write_total>1000000) oops_fatal("assertion failed");
    int buffers_filled  = (int)vector_skip_debug(cs->ciphertext_vector, buffer_free_start_i, buffer_free_count, bytesread,cs); // CAUSING debug_write_total=140732920683736
    if(cs->debug_write_total>1000000) oops_fatal("assertion failed");

    // Re-initialize the freed-up ciphertext vectors
    for(int buffer_i = buffer_free_start_i; buffer_i < buffer_free_start_i+buffers_filled; buffer_i++) {
        vector_reset_ciphertext(cs->ciphertext_vector, cs->ciphertext, buffer_i);
    }
    
    // If we didn't fill any buffers, nothing to decrypt
    if(buffers_filled==0) {
        return bytesread;
    }
    
    //`
    // Decrypt ciphertext into plaintext
    //
//
//    // Calculate how many buffers are free
//    int ciphertext_free_buffers = CRYPTOSTREAM_BUFFER_COUNT - cs->ciphertext_len;
//    int plaintext_free_buffers  = CRYPTOSTREAM_BUFFER_COUNT - cs->plaintext_len;
//
//    // Calculate which buffer to start at and how many to decrypt
//    int buffer_start = cs->ciphertext_start;
//    int buffer_count = MIN(ciphertext_free_buffers,plaintext_free_buffers);
    
    int buffer_decrypt_start = buffer_free_start_i; // No longer free
    int buffer_decrypt_count = buffers_filled;

    // Iterate the decryptable buffers (if any)
//    log_debug("decryption started");
    for(int buffer_i = buffer_decrypt_start; buffer_i < buffer_decrypt_start+buffer_decrypt_count; buffer_i++)
    {
        // Find the pointers to the start of the buffers
        buffer_decrypt(buffer_i, cs, key);
        cs->debug_decrypted_blocks_total++;

        log_debug("cryptostream_decrypt_feed_read: decrypted x bytes (buffer %d/%d)", buffer_i-buffer_decrypt_start+1, buffer_decrypt_count);
    }
    log_debug("decrypted %d bytes from %d buffers", bytesread, buffer_decrypt_count);

    // Rotate buffer offsets
//    cs->ciphertext_start = (cs->ciphertext_start + buffer_decrypt_count) % CRYPTOSTREAM_BUFFER_COUNT;
    cs->vector_len += buffer_decrypt_count;
    
//    log_debug("decryption ended");

    return 1;
}

int cryptostream_decrypt_feed_canwrite(cryptostream* cs) {
    return cs->vector_len > 0;
}

//
// Algorithm:
// - Write as much data as possible to local
// Returns:
//   >1 => ok
//    0 => nothing to write
//
int cryptostream_decrypt_feed_write(cryptostream* cs, unsigned char* key) {
    
    if(cs->debug_write_total>1000000)
        oops_fatal("assertion failed");
    
    // Calculate the first writable buffer, and how many buffers to write
    int buffer_full_start_i  = cs->vector_start;
    int buffer_full_count    = cs->vector_len;
    struct iovec* buffer_full_start = &cs->plaintext_vector[buffer_full_start_i];
    
    // Write as much as possible
    int byteswritten;
    try((byteswritten = (int)chaos_writev(cs->to_fd, // fd
                                 buffer_full_start,  // vector
                                 buffer_full_count   // vcount
    ))) || oops_fatal("failed to write");
    
    cs->debug_write_total += byteswritten;
    if(byteswritten != 1)
        oops_fatal("assertion failed");
    if(cs->debug_write_total>1000000)
        oops_fatal("assertion failed");
    
//    log_debug("cryptostream_decrypt_feed_write: wrote %d bytes (total %d)", byteswritten, cs->debug_write_total);
    
    // Seek the vectors so that, if we didn't write all the bytes, then, later, we can try again
    int buffers_flushed = (int)vector_skip(cs->plaintext_vector,
                                buffer_full_start_i,
                                buffer_full_count,
                                byteswritten);
    
    // Re-initialize the freed-up plaintext vectors
    for(int buffer_i = buffer_full_start_i; buffer_i < buffer_full_start_i+buffers_flushed; buffer_i++) {
        vector_reset_plaintext(cs->plaintext_vector, cs->plaintext, buffer_i);
    }
    
    // Rotate the buffer offsets
    cs->vector_start = (cs->vector_start + buffers_flushed) % CRYPTOSTREAM_BUFFER_COUNT;
    cs->vector_len   -= buffers_flushed;

    return 1;
}