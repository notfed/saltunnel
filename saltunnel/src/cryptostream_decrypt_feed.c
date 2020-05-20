//
//  cryptostream_decrypt_feed.c
//  saltunnel
//

#include "cryptostream.h"
#include "rwn.h"
#include "oops.h"
#include "sodium.h"
#include "nonce.h"
#include "log.h"
#include "uint16.h"
#include "math.h"
#include <unistd.h>
#include <stdio.h>

int cryptostream_decrypt_feed_canread(cryptostream* cs) {
    return cs->vector_len < CRYPTOSTREAM_BUFFER_COUNT;
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
//   -1 => error
//
int cryptostream_decrypt_feed_read(cryptostream* cs) {

    // Lazily initialize the plaintext vector
    if(!cs->vector_init_complete) {
      vector_init(cs);
      cs->vector_init_complete = 1;
    }

    //
    // Read
    //
    
    // Calculate how many buffers are free
    int buffer_free_start_i = (cs->vector_start + cs->vector_len) % CRYPTOSTREAM_BUFFER_COUNT;
    int buffer_free_count = CRYPTOSTREAM_BUFFER_COUNT - cs->vector_len;
    struct iovec* buffer_free_start = &cs->ciphertext_vector[buffer_free_start_i];
    
    // Perform a scattered read. Read data into the following format:
    //    - u8[16]  zeros;
    //    - u8[16]  auth;
    //    - u16     datalen;
    //    - u8[494] data;
    //    - ... (x128 packets) ...
    int bytesread;
    bytesread = (int)readv(cs->from_fd, buffer_free_start, buffer_free_count);
    if(bytesread<0) return oops_sys("failed to read from source");
    
    cs->debug_read_total += bytesread;
    
    // If the read returned a 0, it means the read fd is closed
    if(bytesread==0)
    {
        log_trace("ingress local fd (%d) was closed", cs->from_fd);
        return 0;
    }
    
    // Bump vector
    int buffers_filled  = (int)vector_skip(cs->ciphertext_vector, buffer_free_start_i, buffer_free_count, bytesread);

    // Re-initialize the freed-up ciphertext vectors
    for(int buffer_i = buffer_free_start_i; buffer_i < buffer_free_start_i+buffers_filled; buffer_i++) {
        vector_reset_ciphertext(cs->ciphertext_vector, cs->ciphertext, buffer_i);
    }
    
    // If we didn't fill any buffers, nothing to decrypt
    if(buffers_filled==0) {
        return bytesread;
    }
    
    //
    // Decrypt
    //
    
    int buffer_decrypt_start = buffer_free_start_i; // No longer free
    int buffer_decrypt_count = buffers_filled;

    // Iterate the decryptable buffers (if any)
    if(decrypt_all(buffer_decrypt_count, buffer_decrypt_start, cs)<0)
        return -1;

    log_trace("decrypted %d bytes from %d buffers", bytesread, buffer_decrypt_count);

    // Rotate buffer offsets
    cs->vector_len += buffer_decrypt_count;

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
int cryptostream_decrypt_feed_write(cryptostream* cs) {
    
    // Calculate the first writable buffer, and how many buffers to write
    int buffer_full_start_i  = cs->vector_start;
    int buffer_full_count    = cs->vector_len;
    struct iovec* buffer_full_start = &cs->plaintext_vector[buffer_full_start_i];
    
    // Write as much as possible
    int byteswritten;
    byteswritten = (int)writev(cs->to_fd,          // fd
                               buffer_full_start,  // vector
                               buffer_full_count); // vcount
    if(byteswritten<0) return oops_sys("failed to write to target");
    
    cs->debug_write_total += byteswritten;
    
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
