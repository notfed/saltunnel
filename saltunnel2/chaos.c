//
//  chaos.c
//  saltunnel2
//
//  Created by Jay Sullivan on 1/19/20.
//  Copyright © 2020 Jay Sullivan. All rights reserved.
//

#include "math.h"
#include "chaos.h"
#include <sys/uio.h>

#define chaos_n 1

// Only read chaos_n bytes at a time
int chaos_readv(int fd, struct iovec* vector, int count) {
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = MIN((chaos_n),vector[0].iov_len)
    };
    int r = (int)readv(fd,&newvector,1);
    return r;
}

// Only write chaos_n bytes at a time
int chaos_writev(int fd, struct iovec* vector, int count) {
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = MIN((chaos_n),vector[0].iov_len)
    };
    int r = writev(fd,&newvector,1);
    return r;
}
