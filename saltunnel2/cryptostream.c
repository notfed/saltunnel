//
//  cryptostream.c
//  saltunnel2
//

#include "cryptostream.h"
#include "uninterruptable.h"
#include "oops.h"
#include <unistd.h>
#include <stdio.h>

int cryptostream_feed(cryptostream* cs) {
    char buf[512];
    ssize_t n;
    for(;;) {
        try((n = uninterruptable_read(read, cs->from_fd, buf, 512))) || oops_fatal("failed to read");
        if(n==0)
            break;
        try(uninterruptable_write(write, cs->to_fd, buf, (unsigned int)(n))) || oops_fatal("failed to write");
        fprintf(stderr,"cryptostream: fed %d bytes\n",(int)n);
    }
    return 0;
}

