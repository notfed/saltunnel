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

int cryptostream_identity_feed(cryptostream* cs, unsigned char* k) {
    char buf[512];
    ssize_t n;

    try((n = uninterruptable_read(read, cs->from_fd, buf, sizeof(buf)))) || oops_fatal("failed to read");
    if(n==0)
        return 0;
    try(uninterruptable_write(write, cs->to_fd, buf, (unsigned int)(n))) || oops_fatal("failed to write");
    fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
    
    return 0;
}



//
// High level goal: read some more bytes until we've accumulated an entire packet; once we have
// enough for a packet, ship it off (including a 2-char header), then continue reading.
//
int cryptostream_encrypt_feed(cryptostream* cs, unsigned char* k) {
    
    unsigned short chunksize;
    static unsigned char plainchunk[32+maxchunksize] = {0};
    static unsigned char cipherchunk[32+maxchunksize] = {0};
    
    // Read a chunk of bytes (up to 65536 bytes)
    try((chunksize = (unsigned short)uninterruptable_read(read,
                                                          cs->from_fd,                      // fd
                                                          (const char*)plainchunk + 32 + 2, // dest
                                                          maxchunksize - 2                  // maxlen
    ))) || oops_fatal("failed to read");
    
    fprintf(stderr,"cryptostream_encrypt_feed: got %d bytes\n",(int)chunksize);
    
    // If we got zero bytes, it means the fd is closed
    if(chunksize==0)
        return 0;
    
    // Write (size of chunk) into first two bytes of buffer
    *(plainchunk+32) = chunksize;
    
    // Encrypt chunk
    
    // crypto_secretbox:
    // - signature: crypto_secretbox(c,m,mlen,n,k);
    // - input structure:
    //   - [0..32] == zero
    //   - [32..]  == plaintext
    // - output structure:
    //   - [0..16] == zero
    //   - [16..]  == ciphertext
    crypto_secretbox(cipherchunk,plainchunk,maxchunksize,cs->nonce,k);
    
    // Increment nonce
    nonce24_increment(cs->nonce);
    
    // Repeatedly write packets (each sized packetsize)
    for(unsigned short startofpacket = 0; startofpacket < chunksize; startofpacket+=packetsize) {
    
        // Send next chunk
        try(uninterruptable_write(write,
                                  cs->to_fd,                              // fd
                                  (const char*)cipherchunk+startofpacket, // src
                                  (unsigned int)(packetsize))             // len
        ) || oops_fatal("failed to write");
        
        fprintf(stderr,"cryptostream_encrypt_feed: wrote %d bytes\n",(int)packetsize);
    }
        
    return chunksize;
}

int cryptostream_decrypt_feed(cryptostream* cs, unsigned char* k) {
//    unsigned char cipherbuf[32+2+bufsize] = {0};
//    unsigned char plainbuf[32+2+bufsize] = {0};
//    ssize_t n;
//
//    // Read 512-byte chunk
//    try((n = uninterruptable_read(read, cs->from_fd, (const char*)cipherbuf+16, sizeof(plainbuf)-16))) || oops_fatal("failed to read");
//    if(n>0)
//    {
//        // Decrypt chunk
//
//        //
//        // crypto_secretbox_open:
//        // - signature: crypto_secretbox_open(m,c,clen,n,k);
//        // - input structure:
//        //   - [0..16] == zero
//        //   - [32..]  == ciphertext
//        // - output structure:
//        //   - [0..32] == zero
//        //   - [32..]  == plaintext
//        crypto_secretbox_open(plainbuf,cipherbuf,sizeof(cipherbuf),cs->nonce,k);
//
//        // Read (size of chunk) into first two bytes of buffer
//        unsigned short mlen = *(plainbuf+32);
//
//        // Sanity check mlen
//        if(mlen>(n-2)) oops_fatal("can't handle big message size yet"); // TODO: Allow multi-packet messages
//
//        // Write encrypted chunk
//        try(uninterruptable_write(write, cs->to_fd, (const char*)plainbuf+32+2, (unsigned int)(mlen))) || oops_fatal("failed to write");
//        fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
//    }
//
//    // Increment nonce
//    nonce24_increment(cs->nonce);
        
    return 0;
}
