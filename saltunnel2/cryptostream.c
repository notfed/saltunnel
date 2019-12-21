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
// - Read up to 65536 bytes
// - Split into 494-byte chunks
// - For each chunk, write a 512-byte packet (16-byte auth, 2-byte size, up to 494-byte data)
//
int cryptostream_encrypt_feed(cryptostream* cs, unsigned char* key) {
    
    unsigned char plainbuffer[32+maxbufferlen] = {0};
    unsigned char zerosAndPacket[16+packetsize] = {0}; // First 16 bytes are always zero; next 16 are auth
    
    // Read a chunk of bytes (up to 65536 bytes)
    unsigned short bytesread;
    try((bytesread = (unsigned short)uninterruptable_read(read,
                                                          cs->from_fd,                       // fd
                                                          (const char*)plainbuffer + 32 + 2, // dest
                                                          maxbufferlen-2                     // maxreadbytes
    ))) || oops_fatal("failed to read");
    
    // If we got zero bytes, it means the fd is closed
    if(bytesread==0) {
        log_debug("closing net fd (%d)", cs->to_fd);
        try(close(cs->to_fd)) || oops_fatal("failed to close net fd");
        return 0;
    }
    
    log_debug("cryptostream_encrypt_feed: got %d bytes from local",(int)bytesread);
    
    // Divide the bytes read into chunks of size (packetsize-16-2)
    for(unsigned short chunkstart = 0; chunkstart < bytesread; chunkstart += (packetsize-16-2)) {
        
        // The size of the current chunk is less than or equal to packetsize
        unsigned short chunksize = MIN(packetsize-16-2, bytesread - chunkstart);
        
        // The first 2 bytes of the chunk are the chunksize
        *(plainbuffer + chunkstart + 32) = chunksize;
        
        // Encrypt chunk (to get a packet)
        
        // crypto_secretbox:
        // - signature: crypto_secretbox(c,m,mlen,n,k);
        // - input structure:
        //   - [0..32] == zero
        //   - [32..]  == plaintext
        // - output structure:
        //   - [0..16]  == zero
        //   - [16..32] == auth
        //   - [32..]   == ciphertext

        try(crypto_secretbox(zerosAndPacket, plainbuffer + chunkstart, 16+packetsize, cs->nonce, key)) || oops_fatal("failed to encrypt");
        
        // TRIAL DECRYPT
        // crypto_secretbox_open(m,c,clen,n,k)
        try(crypto_secretbox_open(plainbuffer + chunkstart,zerosAndPacket,16+packetsize,cs->nonce,key)) || oops_fatal("failed to decrypt");
        
        // Increment nonce
        nonce24_increment(cs->nonce);
        
        // Send packet to net
        try(uninterruptable_write(write,
                                  cs->to_fd,                     // fd
                                  (const char*)zerosAndPacket+16, // src
                                  (unsigned int)packetsize)      // len
        ) || oops_fatal("failed to write");
        
        log_debug("cryptostream_encrypt_feed: wrote %d bytes to net (fd %d)",(int)packetsize,cs->to_fd);
    }
    
    return bytesread;
}

//
// Algorithm:
// - Cumulatively read up to 65536 bytes from net
// - Split into 512-byte packets
// - For each packet, decrypt, deconstruct to {chunksize,data}, then write data
//
int cryptostream_decrypt_feed(cryptostream* cs, unsigned char* key) {

    unsigned char plainbuf[32+packetsize] = {0};
    unsigned short plainbufbytes = 0;
    
    log_debug("cryptostream_decrypt_feed: about to read from net (fd %d)", cs->from_fd);
    
    // Append bytes to cumulative bytes read
    unsigned short bytesread;
    try((bytesread = (unsigned short)uninterruptable_read(read,
                                                          cs->from_fd,                                          // fd
                                                          (const char*)cs->cipherbuf + 16 + cs->cipherbufbytes, // dest
                                                          maxbufferlen - cs->cipherbufbytes                     // maxlen
    ))) || oops_fatal("failed to read");
    
    log_debug("cryptostream_decrypt_feed: done reading from net (fd %d)", cs->from_fd);

    cs->cipherbufbytes += bytesread;

    // If we got zero bytes, it means the fd is closed
    if(bytesread==0) {
        log_debug("closing local fd (%d)", cs->to_fd);
        try(close(cs->to_fd)) || oops_fatal("failed to close local fd");
        return 0;
    }
    
    log_debug("cryptostream_decrypt_feed: got +%d bytes (total %d) from net (fd %d)",(int)bytesread,(int)cs->cipherbufbytes,cs->from_fd);

    // If we have enough bytes for a packet, send it
    while(cs->cipherbufbytes>=packetsize)
    {
        
        // Decrypt packet (to get a chunk)i
    
        // crypto_secretbox_open:
        // - signature: crypto_secretbox_open(m,c,clen,n,k)
        // - input structure:
        //   - [0..16]  == zero
        //   - [16..32] == auth
        //   - [32..]   == ciphertext
        // - output structure:
        //   - [0..32] == zero
        //   - [32..]  == plaintext
        try(crypto_secretbox_open(plainbuf,cs->cipherbuf,16+packetsize,cs->nonce,key)) || oops_fatal("failed to decrypt");
    
        // Increment nonce
        nonce24_increment(cs->nonce);
        
        // The first 2 bytes of the chunk are the chunksize
        unsigned short chunksize = *(plainbuf + 32);
        
        log_debug("cryptostream_decrypt_feed: about to write %d bytes to local (fd %d)",(int)chunksize, cs->to_fd);
        
        // Write to local
        try(uninterruptable_write(write,
                                  cs->to_fd,                   // fd
                                  (const char*)plainbuf+32+2,  // src
                                  (unsigned int)chunksize)     // len
        ) || oops_fatal("cryptostream_decrypt_feed: failed to write");
        
        log_debug("cryptostream_decrypt_feed: wrote %d bytes to local (fd %d)",(int)chunksize,cs->to_fd);
        
        // TBD: Shift cipherbuf to the left by 512
        cs->cipherbufbytes -= packetsize;
    }
    return bytesread;
}
