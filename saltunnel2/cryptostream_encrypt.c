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
    try((bytesread =  (int)readv(cs->from_fd,          // fd
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
        uint16 current_bytes_to_encrypt = (uint16)(bytesread - buffer_i*CRYPTOSTREAM_BUFFER_MAXBYTES_DATA);
        
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
    
    // Initialize the corresponding ciphertext vectors
    for(int buffer_i = buffer_start; buffer_i < buffer_count; buffer_i++) {
        cs->ciphertext_vector[buffer_i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT;
    }
    
    // Rotate buffer offsets
    cs->ciphertext_len += buffer_count;
    
    return 1;
}


int cryptostream_encrypt_feed_canwrite(cryptostream* cs) {
    return cs->ciphertext_len > 0;
}

// Only write 1 byte
static int chaos_writev(int fd, struct iovec* vector, int count) {
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = 1
    };
    int r = writev(fd,&newvector,1);
    return r;
}

//
// Algorithm:
// - Write as much ciphertext as possible to net
// Returns:
//   >1 => ok
//    0 => nothing to write
//
int cryptostream_encrypt_feed_write(cryptostream* cs, unsigned char* key) {
    
    // Write as much as possible
    unsigned char* x = cs->ciphertext_vector[cs->ciphertext_start].iov_base; // JUST TO WATCH
    int xlen = cs->ciphertext_vector[cs->ciphertext_start].iov_len; // JUST TO WATCH
    int byteswritten;
    try((byteswritten = (int)writev(cs->to_fd,                                  // fd
                                 &cs->ciphertext_vector[cs->ciphertext_start],  // vector
                                 cs->ciphertext_len                             // vcount
    ))) || oops_fatal("failed to write");
    
    // If we failed to do so, seek the vectors for next time
    int buffers_freed = (int)iovec_skip2(&cs->ciphertext_vector[cs->ciphertext_start],  // vector
                cs->ciphertext_len,                                                     // vector count
                byteswritten);                                                          // seek n bytes
    
    log_debug("cryptostream_encrypt_feed_write: wrote %d bytes", byteswritten);
    
    // Rotate the buffer offsets
    cs->ciphertext_start  = (cs->ciphertext_start + buffers_freed)  % CRYPTOSTREAM_BUFFER_COUNT;
    cs->ciphertext_len   -= buffers_freed;

    return 1;
}

//---------------------------------------------
//
//            OBSOLETE
//
//---------------------------------------------


int cryptostream_identity_feed(cryptostream* cs, unsigned char* key) {
    char buf[512];
    ssize_t n;

    try((n = read(cs->from_fd, buf, sizeof(buf)))) || oops_fatal("failed to read");
    if(n==0) {
        log_debug("read EOF from fd %d",cs->from_fd);
        try(close(cs->to_fd)) || oops_fatal("failed to close egress net fd");
        return 0;
    }
    log_debug("read %d bytes from fd %d",(int)n,cs->from_fd);
    try(write(cs->to_fd, buf, (unsigned int)(n))) || oops_fatal("failed to write");
    log_debug("wrote %d bytes to fd %d",(int)n,cs->to_fd);
    
    return (int)n;
}

// TODO: Performance improvement: this keeps retrying to consume UP TO n bytes. Instead, it could consume
//       as many as possible, so if it reaches n, the rest can be picked up later.
static int cryptostream_flush(const char *source, cryptostream* cs) {
    
    int w;
    try((w=writev(cs->to_fd,   // fd
               cs->writevector,   // vector
               cs->packetcount))  // count
    ) || oops_fatal("failed to write");
    
    
    log_debug("%s: flushing progress: wrote %d bytes to ingress local (fd %d)",source,(int)w,cs->to_fd);
    
    if(w < cs->flush_progress_bytesleft) {
        log_debug("%s: flushing progress: w (%d) < bytesleft (%d); will try more later", source, w, cs->flush_progress_bytesleft);
//        int vector_current_len = (int)siovec_len(cs->writevector, cs->packetcount);
        iovec_skip(cs->writevector, cs->packetcount, w);
        cs->flush_progress_bytesleft -= w;
        errno = EINPROGRESS;
        return -1;
    } else if(w>cs->flush_progress_bytesleft){
        oops_fatal("assertion failed");
        return -1;
    } else { // if(w==cs->flush_progress_bytesleft)
        // Flushing complete.
        log_debug("%s: flushing complete (to fd %d)", source, cs->to_fd);

        // But, account for possible remaining partial packet.
        // If last packet was less than 512 bytes (and therefore unprocessed), deal with it by copying it to the beginning of the buffer
        if(cs->ciphertext_packet_size_in_progress>0) {
            oops_fatal("this happened"); // TODO: This shouldn't be an error. I just want to know if this ever happens.
            log_debug("%s: moving incomplete last-packet", source);
            memcpy(cs->ciphertext + (32+2+494)*0 + 16,
                   cs->ciphertext + (32+2+494)*cs->packetcount,
                   cs->ciphertext_packet_size_in_progress);
        }
        cs->flush_progress_bytesleft = 0;
        return w;
    }
}

int cryptostream_encrypt_feed(cryptostream* cs,unsigned char* x)
{
    return 0; // TODO: Get rid of this?
}
    
//
// Algorithm:
// - Cumulatively read up to 65536 (128*512) bytes from net
// - Split into 512-byte packets
// - For each full packet, decrypt, deconstruct to {auth,size,data}, then write data to local
//
int cryptostream_decrypt_feed(cryptostream* cs, unsigned char* key) {
    
    // Are we still flushing? If so, complete the flush.
    if(cs->flush_progress_bytesleft>0) {
        int f;
        // If we attempt to flush, and it's still in progress, then we'll try again later
        if((f=cryptostream_flush("cryptostream_decrypt_feed", cs))<0)
            return -1;
        // If the flushing was successful, we'll need to go back and re-poll
        else
            return f;
    }
    
    // Iniitalize read vector
    if(!cs->readvector_is_initialized) {
        for(int i = 0; i<128; i++) {
            cs->readvector[i].iov_base = cs->ciphertext + (32+2+494)*i + 16;
            cs->readvector[i].iov_len  = 512;
        }
        cs->readvector_is_initialized = 1;
    }
    
    // If we're currently in the middle of reading a packet, update the first read vector
    cs->readvector[0].iov_base = (cs->ciphertext + (32+2+494)*0 + 16) + cs->ciphertext_packet_size_in_progress;
    cs->readvector[0].iov_len  = (512) - cs->ciphertext_packet_size_in_progress;
    
    // Read chunks of bytes (up to 128 chunks; each chunk is size 512)
    int bytesread;
    try((bytesread = (int)readv(cs->from_fd,     // fd
                                cs->readvector,  // vector
                                128              // count
    ))) || oops_fatal("failed to read");

    // If we got zero bytes, it means the fd is closed
    if(bytesread==0) {
        log_debug("closing ingress local fd (%d)", cs->to_fd);
        try(close(cs->to_fd)) || oops_fatal("failed to close ingress local fd");
        return 0;
    }
    
    log_debug("cryptostream_decrypt_feed: got %d bytes from ingress net",(int)bytesread);
    
    unsigned int totalchunkbytes = 0; // Just for debug logging
    
    log_debug("decryption started");
    // Iterate over bytes as packets of 512
    cs->packetcount = 0;
    int packetlen_total_remaining = cs->ciphertext_packet_size_in_progress + bytesread;
    for(int packeti = 0; packetlen_total_remaining > 0; packeti++, packetlen_total_remaining-=512)
    {
        // Current packet will be either 512 or less
        int packetlen_current = MIN(512, packetlen_total_remaining);
        
        // If the current packet is less than 512, it's incomplete; we'll deal with this below
        if(packetlen_current < 512) {
            cs->ciphertext_packet_size_in_progress = packetlen_current;
            break;
        } else {
            cs->ciphertext_packet_size_in_progress = 0;
        }
        
        // We have a full-size packet, so decrypt the packet (to get a chunk)
        cs->packetcount++;
    
        // crypto_secretbox_open:
        // - signature: crypto_secretbox_open(m,c,clen,n,k)
        // - input structure:
        //   - [0..16]  == zero
        //   - [16..32] == auth
        //   - [32..]   == ciphertext
        // - output structure:
        //   - [0..32] == zero
        //   - [32..]  == plaintext
        try(crypto_secretbox_open(cs->plaintext + (32+2+494)*packeti,
                                  cs->ciphertext + (32+2+494)*packeti,
                                  32+2+494, cs->nonce, key)) || oops_fatal("failed to decrypt");
        
        // Increment nonce
        nonce24_increment(cs->nonce);
        
        // Extract chunk size
        uint16 chunklen_current = 0;
        uint16_unpack((char*)cs->plaintext + (32+2+494)*packeti + 32, &chunklen_current);
        
        log_debug("!! cryptostream_decrypt_feed: decrypted packet (#%d) -> %d bytes",cs->ctr++,(int)chunklen_current);
        
        if(cs->ctr==132) {
            int x = 0;
        }
        
        // Setup writevector[packeti]
        cs->writevector[packeti].iov_base = cs->plaintext + (32+2+494)*packeti + 32+2;
        cs->writevector[packeti].iov_len = chunklen_current;
//        log_debug("totalchunkbytes (%d) = totalchunkbytes (%d) + chunklen_current (%d)", totalchunkbytes, totalchunkbytes+chunklen_current, chunklen_current);
        totalchunkbytes += chunklen_current;
        
    }
    log_debug("decryption ended");
    
    // Flush. This means:
    // - We plan to flush 'flush_progress_totalbytes' bytes
    // - If we do a short write, then we'll try again later
    cs->flush_progress_totalbytes  = totalchunkbytes;
    cs->flush_progress_bytesleft = totalchunkbytes;
    log_debug("cryptostream_decrypt_feed: flushing started: writing %d total bytes to ingress local (fd %d)", cs->flush_progress_totalbytes,cs->to_fd);
    if(cryptostream_flush("cryptostream_decrypt_feed", cs)<0) { errno = EINPROGRESS; return -1; }
    
    // Flush complete.
    
    return bytesread;
}
