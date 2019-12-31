//
//  cryptostream.c
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
        oops_fatal("impossible?");
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

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

//
// Algorithm:
// - Read up to 63232 (128*494) bytes
// - Split into 128 494-byte chunks
// - Each chunk must be prefixed with 32 zero-bytes
// - Encrypt each chunk into a 512-byte packet (16-byte auth, 2-byte size, and 494-byte data)
//
int cryptostream_encrypt_feed(cryptostream* cs, unsigned char* key) {
    
    // Are we still flushing? If so, complete the flush.
    if(cs->flush_progress_bytesleft>0) {
        int f;
        // If we attempt to flush, and it's still in progress, then we'll try again later
        if((f=cryptostream_flush("cryptostream_encrypt_feed", cs))<0)
            return -1;
        // If the flushing was successful, we'll need to go back and re-poll
        else
            return f;
    }
    
    // BUFFER USAGE:
    // Read bytes into the following format:
    //    - u8[32]  zeros;
    //    - u16     packetlen;
    //    - u8[494] packet;
    //    - ... (x128 packets) ...
    
    if(!cs->readvector_is_initialized) {
        for(int i = 0; i<128; i++) {
            cs->readvector[i].iov_base = cs->plaintext + (32+2+494)*i + 32+2;
            cs->readvector[i].iov_len  = 494;
        }
        cs->readvector_is_initialized = 1;
    }
    
    // Read chunks of bytes (up to 128 chunks; each chunk is size 494)
    int bytesread;
    try((bytesread = (int)readv(cs->from_fd,     // fd
                                cs->readvector,  // vector
                                128              // count
    ))) || oops_fatal("failed to read");
    
    log_debug("cryptostream_encrypt_feed: got %d bytes from egress local",(int)bytesread);
    
    // If we got zero bytes, it means the fd is closed
    if(bytesread==0) {
        log_debug("closing egress net fd (%d)", cs->to_fd);
        try(close(cs->to_fd)) || oops_fatal("failed to close egress net fd");
        return 0;
    }
    
    // Iterate over bytes as chunks of 494
    cs->packetcount = 0;
    int chunklen_total_remaining = bytesread;
    for(int packeti = 0; chunklen_total_remaining > 0; packeti++, cs->packetcount++, chunklen_total_remaining-=494)
    {
        // Fill pre-zeros (32 bytes)
        memset(cs->plaintext, 0, 32);
        
        // Fill chunk length (2 bytes)
        uint16 chunklen_current = MIN(494, chunklen_total_remaining);
        uint16_pack((char*)cs->plaintext + (32+2+494)*packeti + 32, chunklen_current);
        
        // Fill post-zeros (494-chunklen bytes)
        memset(cs->plaintext+32+2+chunklen_current, 0, 494-chunklen_current);
        
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
        try(crypto_secretbox(cs->ciphertext + (32+2+494)*packeti,
                             cs->plaintext + (32+2+494)*packeti,
                             32+2+494, cs->nonce, key)) || oops_fatal("failed to encrypt");
        
//        // TRIAL DECRYPT
//        // crypto_secretbox_open(m,c,clen,n,k)
//        try(crypto_secretbox_open(plaintext + (32+2+494)*packeti,
//                                  ciphertext + (32+2+494)*packeti,
//                                  32+2+494,cs->nonce,key)) || oops_fatal("failed to decrypt");
        
        // Increment nonce
        nonce24_increment(cs->nonce);
        
        // Setup writevector[packeti]
        cs->writevector[packeti].iov_base = cs->ciphertext + (32+2+494)*packeti + 16;
        cs->writevector[packeti].iov_len  = 512;
    }
    
    // Flush. This means:
    // - We plan to flush 'flush_progress_totalbytes' bytes
    // - If we do a short write, then we'll try again later
    cs->flush_progress_totalbytes  = cs->packetcount*512;
    cs->flush_progress_bytesleft = cs->packetcount*512;
    log_debug("cryptostream_encrypt_feed: flushing started: writing %d total bytes to ingress local (fd %d)", cs->flush_progress_totalbytes,cs->to_fd);
    if(cryptostream_flush("cryptostream_decrypt_feed", cs)<0) { errno = EINPROGRESS; return -1; }
    
    // Flush complete.
    
    log_debug("cryptostream_encrypt_feed: wrote %d total bytes to egress net (fd %d)",(int)cs->packetcount*512,cs->to_fd);
    
    return bytesread;
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
        
//        log_debug("cryptostream_decrypt_feed: decrypted packet -> %d bytes (#%d,%d)",(int)chunklen_current,packeti,cs->ctr++);
        
        if(cs->ctr==132) {
            int x = 0;
        }
        
        // Setup writevector[packeti]
        cs->writevector[packeti].iov_base = cs->plaintext + (32+2+494)*packeti + 32+2;
        cs->writevector[packeti].iov_len = chunklen_current;
        log_debug("totalchunkbytes (%d) = totalchunkbytes (%d) + chunklen_current (%d)", totalchunkbytes, totalchunkbytes+chunklen_current, chunklen_current);
        totalchunkbytes += chunklen_current;
        
    }
    
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
