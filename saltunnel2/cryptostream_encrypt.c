//
//  cryptostream_encrypt.c
//  saltunnel2
//

#include "cryptostream.h"
#include "uninterruptable.h"
#include "oops.h"
#include "tweetnacl.h"
#include "nonce.h"
#include "log.h"
#include "uint16.h"
#include "chaos.h"
#include "math.h"
#include <unistd.h>
#include <stdio.h>

// Is there enough room for 1 buffer of plaintext and 1 buffer of ciphertext?
int cryptostream_encrypt_feed_canread(cryptostream* cs) {
    int free_buffers = CRYPTOSTREAM_BUFFER_COUNT - cs->ciphertext_len;
    return free_buffers>=1;
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
    int free_buffers = CRYPTOSTREAM_BUFFER_COUNT - cs->ciphertext_len;
    
    // Perform a scattered read. Read data into the following format:
    //    - u8[32]  zeros;
    //    - u16     datalen;
    //    - u8[494] data;
    //    - ... (x128 packets) ...
    int bytesread;
    try((bytesread =  (int)readv(cs->from_fd,    // fd
                                 cs->plaintext_vector, // vector
                                 free_buffers)))       // count
    || oops_fatal("error reading from cs->from_fd");
    
    // If the read returned a 0, it means the read fd is closed
    if(bytesread==0)
    {
        log_debug("egress local fd (%d) was closed", cs->from_fd);
        return 0;
    }
    
    log_debug("cryptostream_encrypt_feed_read: got %d bytes from egress local",(int)bytesread);
    
    //
    // Encrypt
    //
    
    // Calculate which buffer to start at and how many to decrypt
    int buffer_start = cs->ciphertext_start;
    int buffer_count = ((bytesread-1) / CRYPTOSTREAM_BUFFER_MAXBYTES_DATA)+1;

    // Iterate the encryptable buffers (if any)
    log_debug("encryption started");
    for(int buffer_i = buffer_start; buffer_i < buffer_count; buffer_i++)
    {
        // Calculate how many bytes to encrypt (for this buffer)
        uint16 current_bytes_to_encrypt = (uint16)MIN(CRYPTOSTREAM_BUFFER_MAXBYTES_DATA, bytesread - buffer_i*CRYPTOSTREAM_BUFFER_MAXBYTES_DATA); 
        
        // Find the pointers to the start of the buffers
        unsigned char* plaintext_buffer_ptr = cs->plaintext_vector[buffer_i].iov_base - 32-2;
        unsigned char* ciphertext_buffer_ptr = cs->ciphertext_vector[cs->ciphertext_start + buffer_i].iov_base - 16;
        
        // Fill zeros (32 bytes)
        memset((void*)plaintext_buffer_ptr, 0, 32);
        
        // Fill len (2 bytes)
        uint16_pack(((void*)plaintext_buffer_ptr+32), current_bytes_to_encrypt);
        
        // Fill unused data (0-494 bytes)
        memset((void*)plaintext_buffer_ptr+32+2+current_bytes_to_encrypt, 0, CRYPTOSTREAM_BUFFER_MAXBYTES_DATA-current_bytes_to_encrypt);
        
        // Encrypt chunk from plaintext to ciphertext (494 bytes)
        
        // crypto_secretbox:
        // - signature: crypto_secretbox(c,m,mlen,n,k);
        // - input structure:
        //   - [0..32] == zero
        //   - [32..]  == plaintext
        // - output structure:
        //   - [0..16]  == zero
        //   - [16..32] == auth
        //   - [32..]   == ciphertext
        try(crypto_secretbox(ciphertext_buffer_ptr, plaintext_buffer_ptr,
                             CRYPTOSTREAM_BUFFER_MAXBYTES, cs->nonce, key)) || oops_fatal("failed to encrypt");

//        // TRIAL DECRYPT  (TODO: Remove this. Just here as a temporary sanity check.)
//        // crypto_secretbox_open(m,c,clen,n,k)
//        try(crypto_secretbox_open(plaintext_buffer_ptr, ciphertext_buffer_ptr,
//                                  CRYPTOSTREAM_BUFFER_MAXBYTES,cs->nonce,key)) || oops_fatal("failed to trial decrypt");
        
        log_debug("cryptostream_encrypt_feed_read: encrypted %d bytes (buffer %d/%d)", current_bytes_to_encrypt, buffer_i+1, buffer_count);
        
        // Increment nonce
        nonce24_increment(cs->nonce);
    }

    log_debug("encryption ended");
    
    // Rotate buffer offsets
    cs->ciphertext_len += buffer_count;
    
    return 1;
}


int cryptostream_encrypt_feed_canwrite(cryptostream* cs) {
    return cs->ciphertext_len > 0;
}


//
// Algorithm:
// - Write as much ciphertext as possible to net
// Returns:
//   >1 => ok
//    0 => nothing to write
//
int cryptostream_encrypt_feed_write(cryptostream* cs, unsigned char* key) {
    
    // DEBUG VARIABLES
    unsigned char* x = cs->ciphertext_vector[cs->ciphertext_start].iov_base; // JUST TO WATCH
    int xlen = (int)cs->ciphertext_vector[cs->ciphertext_start].iov_len; // JUST TO WATCH
    
    // Write as much as possible
    int buffer_start = cs->ciphertext_start;
    int buffer_count = cs->ciphertext_len;
    int byteswritten;
    try((byteswritten = (int)writev(cs->to_fd,                    // fd
                                 &cs->ciphertext_vector[buffer_start],  // vector
                                 buffer_count                           // vcount
    ))) || oops_fatal("failed to write");
    
    // If we failed to flush all ciphertext, seek the vectors so that, later, we can try again
    int buffers_freed = (int)vector_skip(&cs->ciphertext_vector[buffer_start],  // vector
                buffer_count,                                                   // vector count
                byteswritten);                                                  // seek n bytes
    log_debug("cryptostream_encrypt_feed_write: wrote %d bytes", byteswritten);
    
    // Re-initialize the freed-up ciphertext vectors
    for(int buffer_i = buffer_start; buffer_i < buffers_freed; buffer_i++) {
        vector_reset_ciphertext(cs->ciphertext_vector, cs->ciphertext, buffer_i);
    }
    
    // Rotate the buffer offsets
    cs->ciphertext_start  = (cs->ciphertext_start + buffers_freed)  % CRYPTOSTREAM_BUFFER_COUNT;
    cs->ciphertext_len   -= buffers_freed;

    return 1;
}
