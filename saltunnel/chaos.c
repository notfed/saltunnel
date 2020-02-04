//
//  chaos.c
//  saltunnel2
//

#include "math.h"
#include "chaos.h"
#include "oops.h"
#include <sys/uio.h>

#define CHAOS_READ_N 512
#define CHAOS_WRITE_N 512

// Only read chaos_n bytes at a time
int chaos_readv(int fd, struct iovec* vector, int count) {
    if(vector[0].iov_len == 0)
        oops_fatal("chaos_readv currently requires first vector to be non-zero size");
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = MIN((CHAOS_READ_N),vector[0].iov_len)
    };
    int r = (int)readv(fd,&newvector,1);
    return r;
}

// Only write chaos_n bytes at a time
int chaos_writev(int fd, struct iovec* vector, int count) {
    if(vector[0].iov_len == 0)
        oops_fatal("chaos_writev currently requires first vector to be non-zero size");
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = MIN((CHAOS_WRITE_N),vector[0].iov_len)
    };
    int r = (int)writev(fd,&newvector,1);
    return r;
}
