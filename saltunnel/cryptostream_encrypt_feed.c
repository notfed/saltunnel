//
//  cryptostream_encrypt_feed.c
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
#include <unistd.h>
#include <stdio.h>

int cryptostream_encrypt_feed_canread(cryptostream* cs) {
    return cs->vector_len < CRYPTOSTREAM_BUFFER_COUNT;
}

//
// Algorithm:
// - Read up to 63232 (128*494) bytes into 'plaintext' buffer
// -   (Scatter into 128 494-byte chunks)
// -   (Each chunk must be prefixed with 32 zero-bytes)
// - If we have 1 or more full chunks, encrypt them.
// Returns:
//   >1 => ok
//    0 => read fd closed
//
int cryptostream_encrypt_feed_read(cryptostream* cs, unsigned char* key) {
    
    // Lazily initialize the plaintext vector
    if(!cs->vector_init_complete) {
        vector_init(cs);
        cs->vector_init_complete = 1;
    }
    
    //
    // Read
    //

    // Calculate how many buffers are free
    int buffer_free_start_i = (cs->vector_start+cs->vector_len) % CRYPTOSTREAM_BUFFER_COUNT;
    int buffer_free_count = MIN(128,CRYPTOSTREAM_BUFFER_COUNT - cs->vector_len);
    struct iovec* buffer_free_start = &cs->plaintext_vector[buffer_free_start_i];
    
    // Perform a scattered read. Read data into the following format:
    //    - u8[32]  zeros;
    //    - u16     datalen;
    //    - u8[494] data;
    //    - ... (x128 packets) ...
    int bytesread;
    try((bytesread =  (int)readv(cs->from_fd,          // fd
                                buffer_free_start,     // vector
                                buffer_free_count)))   // count
    || oops_fatal("error reading from cs->from_fd");
    
    cs->debug_read_total += bytesread;
    
    // If the read returned a 0, it means the read fd is closed
    if(bytesread==0)
    {
        log_debug("egress local fd (%d) was closed", cs->from_fd);
        return 0;
    }
    
    log_debug("cryptostream_encrypt_feed_read: got %d bytes from egress local (total %d)",(int)bytesread,cs->debug_read_total);

    //
    // Encrypt
    //
    
    // Calculate which buffer to start at and how many to decrypt
    int buffer_encrypt_start_i = buffer_free_start_i;
    int buffer_encrypt_count = ((bytesread-1) / CRYPTOSTREAM_BUFFER_MAXBYTES_DATA)+1;

    // Iterate the encryptable buffers (if any)
    encrypt_all(buffer_encrypt_count, buffer_encrypt_start_i, bytesread, cs, key);
    
    // Rotate buffer offsets
    cs->vector_len += buffer_encrypt_count;
    
    return 1;
}


int cryptostream_encrypt_feed_canwrite(cryptostream* cs) {
    return cs->vector_len > 0;
}

//
// Algorithm:
// - Write as much ciphertext as possible to net
// Returns:
//   >1 => ok
//    0 => nothing to write
//
int cryptostream_encrypt_feed_write(cryptostream* cs) {
    
    // Calculate the first writable buffer, and how many buffers to write
    int buffer_full_start_i = cs->vector_start;
    int buffer_full_count   = cs->vector_len;
    struct iovec* buffer_full_start = &cs->ciphertext_vector[buffer_full_start_i];
    
    // Write as much as possible
    int byteswritten;
    try((byteswritten = (int)writev(cs->to_fd,       // fd
                                 buffer_full_start,  // vector
                                 buffer_full_count   // vcount
    ))) || oops_fatal("failed to write");
    
    cs->debug_write_total += byteswritten;
    
    log_debug("cryptostream_encrypt_feed_write: wrote %d bytes (total %d)", byteswritten, (int)cs->debug_write_total);
    
    // Seek the vectors so that, if we didn't write all the bytes, then, later, we can try again
    int buffers_flushed = (int)vector_skip(cs->ciphertext_vector,
                            buffer_full_start_i, // vector
                            buffer_full_count,   // vector count
                            byteswritten);       // seek n bytes
    
    // Re-initialize the freed-up ciphertext vectors
    for(int buffer_i = buffer_full_start_i; buffer_i < buffer_full_start_i+buffers_flushed; buffer_i++) {
        vector_reset_ciphertext(cs->ciphertext_vector, cs->ciphertext, buffer_i);
    }
    
    // Rotate the buffer offsets
    cs->vector_start = (cs->vector_start + buffers_flushed) % CRYPTOSTREAM_BUFFER_COUNT;
    cs->vector_len   -= buffers_flushed;
    
    return 1;
}
