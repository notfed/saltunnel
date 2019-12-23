//
//  uninterruptable.c
//  saltunnel2
//

#include "uninterruptable.h"
#include <errno.h>
#include <stdlib.h>

ssize_t uninterruptable_write(ssize_t (*op)(int,const void*,size_t),int fd,const char *buf,unsigned int len)
{
    ssize_t w;
    while (len) {
        w = op(fd,buf,len);
        if (w == -1) {
            if (errno == EINTR) continue;
            return (ssize_t)(-1); /* note that some data may have been written */
        }
        buf += w;
        len -= w;
    }
    return (ssize_t)(0);
}

ssize_t uninterruptable_read(ssize_t (*op)(int,void*,size_t),int fd,const char* buf,unsigned int len)
{
  ssize_t r;
  for (;;) {
    r = op(fd,(void*)buf,len);
    if (r == -1) if (errno == EINTR) continue;
    return r;
  }
}

ssize_t uninterruptable_readv(int fd, const struct iovec *vector, int count)
{
  ssize_t r;
  for (;;) {
    r = readv(fd,vector,count);
    if (r == -1) if (errno == EINTR) continue;
    return r;
  }
}

ssize_t uninterruptable_writev(int fd, const struct iovec *vector, int count)
{
  ssize_t r;
  for (;;) {
    r = writev(fd,vector,count);
    if (r == -1) if (errno == EINTR) continue;
    return r;
  }
}
