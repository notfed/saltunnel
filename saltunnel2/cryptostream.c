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

static const unsigned int bufsize = 512;

int cryptostream_encrypt_feed(cryptostream* cs, unsigned char* k) {
    unsigned char plainbuf[32+2+bufsize] = {0};
    unsigned char cipherbuf[32+2+bufsize] = {0};
    ssize_t n;

    // Read 512-byte chunk
    try((n = uninterruptable_readn(read, cs->from_fd, (const char*)plainbuf+32, sizeof(plainbuf)-32))) || oops_fatal("failed to read");
    if(n>0)
    {
        // Write (size of chunk) into first two bytes of buffer
        *(plainbuf+32) = (unsigned short)(n);
        
        // Encrypt chunk
        
        // crypto_secretbox:
        // - signature: crypto_secretbox(c,m,mlen,n,k);
        // - input structure:
        //   - [0..32] == zero
        //   - [32..]  == plaintext
        // - output structure:
        //   - [0..16] == zero
        //   - [16..]  == ciphertext
        crypto_secretbox(cipherbuf,plainbuf,sizeof(plainbuf),cs->nonce,k);
        
        // Write encrypted chunk
        try(uninterruptable_write(write, cs->to_fd, (const char*)plainbuf+16, (unsigned int)(n+2))) || oops_fatal("failed to write");
        fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
    }
    
    // Increment nonce
    nonce24_increment(cs->nonce);
        
    return 0;
}

int cryptostream_decrypt_feed(cryptostream* cs, unsigned char* k) {
    unsigned char cipherbuf[32+2+bufsize] = {0};
    unsigned char plainbuf[32+2+bufsize] = {0};
    ssize_t n;

    // Read 512-byte chunk
    try((n = uninterruptable_readn(read, cs->from_fd, (const char*)cipherbuf+16, sizeof(plainbuf)-16))) || oops_fatal("failed to read");
    if(n>0)
    {
        // Decrypt chunk
        
        //
        // crypto_secretbox_open:
        // - signature: crypto_secretbox_open(m,c,clen,n,k);
        // - input structure:
        //   - [0..16] == zero
        //   - [32..]  == ciphertext
        // - output structure:
        //   - [0..32] == zero
        //   - [32..]  == plaintext
        crypto_secretbox_open(plainbuf,cipherbuf,sizeof(cipherbuf),cs->nonce,k);
        
        // Read (size of chunk) into first two bytes of buffer
        unsigned short mlen = *(plainbuf+32);
        
        // Sanity check mlen
        if(mlen>(n-2)) oops_fatal("can't handle big message size yet"); // TODO: Allow multi-packet messages
        
        // Write encrypted chunk
        try(uninterruptable_write(write, cs->to_fd, (const char*)plainbuf+32+2, (unsigned int)(mlen))) || oops_fatal("failed to write");
        fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
    }
    
    // Increment nonce
    nonce24_increment(cs->nonce);
        
    return 0;
}
