//
//  cryptostream.c
//  saltunnel2
//

#include "cryptostream.h"
#include "uninterruptable.h"
#include "oops.h"
#include "tweetnacl.h"
#include "nonce.h"
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
    unsigned short readbytes;
    try((readbytes = (unsigned short)uninterruptable_read(read,
                                                          cs->from_fd,                       // fd
                                                          (const char*)plainbuffer + 32 + 2, // dest
                                                          maxbufferlen-2                     // maxreadbytes
    ))) || oops_fatal("failed to read");
    
    // If we got zero bytes, it means the fd is closed
    if(readbytes==0)
        return 0;
    
    fprintf(stderr,"cryptostream_encrypt_feed: got %d bytes from local\n",(int)readbytes);
    
    // Divide the bytes read into chunks of size (packetsize-16-2)
    for(unsigned short chunkstart = 0; chunkstart < readbytes; chunkstart += (packetsize-16-2)) {
        
        // The size of the current chunk is less than or equal to packetsize
        unsigned short chunksize = MIN(packetsize-16-2, readbytes - chunkstart);
        
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
        
        fprintf(stderr,"cryptostream_encrypt_feed: wrote %d bytes to net\n",(int)packetsize);
    }
    
    return readbytes;
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
    
    // Append bytes to cumulative bytes read
    unsigned short bytesread;
    try((bytesread = (unsigned short)uninterruptable_read(read,
                                                          cs->from_fd,                                          // fd
                                                          (const char*)cs->cipherbuf + 16 + cs->cipherbufbytes, // dest
                                                          maxbufferlen - cs->cipherbufbytes                     // maxlen
    ))) || oops_fatal("failed to read");

    cs->cipherbufbytes += bytesread;

    // If we got zero bytes, it means the fd is closed
    if(bytesread==0)
        return 0;
    
    fprintf(stderr,"cryptostream_decrypt_feed: got +%d bytes (total %d) from net\n",(int)bytesread,(int)cs->cipherbufbytes);

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
        
        // Write to local
        try(uninterruptable_write(write,
                                  cs->to_fd,                   // fd
                                  (const char*)plainbuf+32+2,  // src
                                  (unsigned int)chunksize)     // len
        ) || oops_fatal("failed to write");
        
        fprintf(stderr,"cryptostream_decrypt_feed: wrote %d bytes to local\n",(int)chunksize);
        
        // TBD: Shift cipherbuf to the left by 512
        cs->cipherbufbytes -= packetsize;
    }
    return 0;
//
//    // Encrypt chunk
//
//    // crypto_secretbox:
//    // - signature: crypto_secretbox(c,m,mlen,n,k);
//    // - input structure:
//    //   - [0..32] == zero
//    //   - [32..]  == plaintext
//    // - output structure:
//    //   - [0..16] == zero
//    //   - [16..]  == ciphertext
//    crypto_secretbox_open(cipherchunk,plainchunk,maxchunksize,cs->nonce,k);
//
//    // Increment nonce
//    nonce24_increment(cs->nonce);
//
//    // Repeatedly write packets (each sized packetsize)
//    for(unsigned short startofpacket = 0; startofpacket < chunksize; startofpacket+=packetsize) {
//
//        // Send next chunk
//        try(uninterruptable_write(write,
//                                  cs->to_fd,                              // fd
//                                  (const char*)cipherchunk+startofpacket, // src
//                                  (unsigned int)(packetsize))             // len
//        ) || oops_fatal("failed to write");
//
//        fprintf(stderr,"cryptostream_encrypt_feed: wrote %d bytes\n",(int)packetsize);
//    }
//
//    return chunksize;
    return 0;
}
