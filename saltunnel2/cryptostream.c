//
//  cryptostream.c
//  saltunnel2
//

#include "cryptostream.h"
#include "uninterruptable.h"
#include "oops.h"
#include "tweetnacl.h"
#include <unistd.h>
#include <stdio.h>

int cryptostream_identity_feed(cryptostream* cs, unsigned char* k) {
    char buf[512];
    ssize_t n;
    for(;;) {
        try((n = uninterruptable_read(read, cs->from_fd, buf, sizeof(buf)))) || oops_fatal("failed to read");
        if(n==0)
            break;
        try(uninterruptable_write(write, cs->to_fd, buf, (unsigned int)(n))) || oops_fatal("failed to write");
        fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
    }
    return 0;
}

int cryptostream_encrypt_feed(cryptostream* cs, unsigned char* k) {
    char buf[32+2+512];
    char buf_enc[16+2+512];
    ssize_t n;
    unsigned long nonce = 0;
    for(unsigned nonce = 0; 1; nonce++) {
        
        // Read 512-byte chunk
        try((n = uninterruptable_read(read, cs->from_fd, buf+32+2, sizeof(buf-2)))) || oops_fatal("failed to read");
        if(n==0)
            break;
        
        // Write (size of chunk) into first two bytes of buffer
        *(buf+32) = (unsigned short)(n);
        
        // Encrypt chunk
        // crypto_secretbox(c,       m,   mlen, n,     k)
        crypto_secretbox(   buf_enc, buf, n,    &nonce, k);
        
        // Write encrypted chunk
        try(uninterruptable_write(write, cs->to_fd, buf, (unsigned int)(n))) || oops_fatal("failed to write");
        fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
    }
    return 0;
}
