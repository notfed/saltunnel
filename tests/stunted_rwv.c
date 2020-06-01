//
//  stunted_rwv.c
//  saltunnel
//

#include "math.h"
#include "stunted_rwv.h"
#include "oops.h"
#include <sys/uio.h>

#define STUNTED_READ_N 512
#define STUNTED_WRITE_N 512

// Only read at most STUNTED_READ_N bytes at a time (for testing)
int stunted_readv(int fd, struct iovec* vector, int count) {
    if(vector[0].iov_len == 0)
        oops_error("stunted_rwv_readv currently requires first vector to be non-zero size");
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = MIN((STUNTED_READ_N),vector[0].iov_len)
    };
    int r = (int)readv(fd,&newvector,1);
    return r;
}

// Only write at most STUNTED_WRITE_N bytes at a time (for testing)
int stunted_writev(int fd, struct iovec* vector, int count) {
    if(vector[0].iov_len == 0)
        oops_error("stunted_rwv_writev currently requires first vector to be non-zero size");
    struct iovec newvector = {
        .iov_base = vector[0].iov_base,
        .iov_len = MIN((STUNTED_WRITE_N),vector[0].iov_len)
    };
    int r = (int)writev(fd,&newvector,1);
    return r;
}
