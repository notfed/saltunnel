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

    try((n = uninterruptable_read(read, cs->from_fd, buf, sizeof(buf)))) || oops_fatal("failed to read");
    if(n==0)
        return 0;
    try(uninterruptable_write(write, cs->to_fd, buf, (unsigned int)(n))) || oops_fatal("failed to write");
    fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
    
    return 0;
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
    
    struct iovec writevector[128];
    
    // Read chunks of bytes (up to 128 chunks; each chunk is size 494)
    int bytesread;
    try((bytesread = (int)uninterruptable_readv(cs->from_fd, // fd
                                                cs->readvector,  // vector
                                                128          // count
    ))) || oops_fatal("failed to read");
    
    log_debug("cryptostream_encrypt_feed: got %d bytes from local",(int)bytesread);
    
    // If we got zero bytes, it means the fd is closed
    if(bytesread==0) {
        log_debug("closing net fd (%d)", cs->to_fd);
        try(close(cs->to_fd)) || oops_fatal("failed to close net fd");
        return 0;
    }
    
    // Iterate over bytes as chunks of 494
    int chunkcount = 0;
    int chunklen_total_remaining = bytesread;
    for(int packeti = 0; chunklen_total_remaining > 0; packeti++, chunkcount++, chunklen_total_remaining-=494)
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
        writevector[packeti].iov_base = cs->ciphertext + (32+2+494)*packeti + 16;
        writevector[packeti].iov_len  = 512;
    }
    
    // Send packets to net
    try(uninterruptable_writev(cs->to_fd,   // fd
                               writevector, // vector
                               chunkcount) // count
     ) || oops_fatal("failed to write");
     
     log_debug("cryptostream_encrypt_feed: wrote %d total bytes to net (fd %d)",(int)chunkcount*512,cs->to_fd);
    
    return bytesread;
}

//
// Algorithm:
// - Cumulatively read up to 65536 (128*512) bytes from net
// - Split into 512-byte packets
// - For each full packet, decrypt, deconstruct to {auth,size,data}, then write data to local
//
int cryptostream_decrypt_feed(cryptostream* cs, unsigned char* key) {
    
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
    
    // The write vector be filled out later
    struct iovec writevector[128];
    
    // Read chunks of bytes (up to 128 chunks; each chunk is size 512)
    int bytesread;
    try((bytesread = (int)uninterruptable_readv(cs->from_fd, // fd
                                                cs->readvector,  // vector
                                                128          // count
    ))) || oops_fatal("failed to read");

    // If we got zero bytes, it means the fd is closed
    if(bytesread==0) {
        log_debug("closing local fd (%d)", cs->to_fd);
        try(close(cs->to_fd)) || oops_fatal("failed to close local fd");
        return 0;
    }
    
    log_debug("cryptostream_decrypt_feed: got %d bytes from net",(int)bytesread);
    
    unsigned int totalchunkbytes = 0; // Just for debug logging
    
    // Iterate over bytes as packets of 512
    int packetcount = 0;
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
        packetcount++;
    
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
        
        log_debug("cryptostream_decrypt_feed: decrypted packet -> %d bytes (#%d,%d)",(int)chunklen_current,packeti,cs->ctr++);
        
        if(cs->ctr==132) {
            int x = 0;
        }
        
        // Setup writevector[packeti]
        writevector[packeti].iov_base = cs->plaintext + (32+2+494)*packeti + 32+2;
        writevector[packeti].iov_len = chunklen_current;
        totalchunkbytes += chunklen_current;
        
    }
    
    // Send chunks to local
    // TODO: This is blocking b/c it is writing 65536+ bytes while no other thread is reading
    try(uninterruptable_writev(cs->to_fd,   // fd
                               writevector, // vector
                               packetcount)  // count
    ) || oops_fatal("failed to write");
     
    log_debug("cryptostream_decrypt_feed: wrote %d total bytes to local (fd %d)",(int)totalchunkbytes,cs->to_fd);
    
    // If last packet was less than 512 bytes (and therefore unprocessed), deal with it by copying it to the beginning of the buffer
    if(cs->ciphertext_packet_size_in_progress>0) {
        memcpy(cs->ciphertext + (32+2+494)*0 + 16,
               cs->ciphertext + (32+2+494)*packetcount,
               cs->ciphertext_packet_size_in_progress);
    }
    
    return bytesread;
}
