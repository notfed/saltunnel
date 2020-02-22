//
//  uninterruptable.c
//  saltunnel2
//

#include "uninterruptable.h"
#include "oops.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t uninterruptable_writen(ssize_t (*op)(int,const void*,size_t),int fd,const char *buf,unsigned int len)
{
    unsigned int left = len;
    ssize_t w;
    while (left) {
        w = op(fd,buf,left);
        if (w == -1) {
            if (errno == EINTR) continue;
            return (ssize_t)(-1); /* note that some data may have been written */
        }
        buf += w;
        left -= w;
    }
    return (ssize_t)(len);
}

ssize_t writen(ssize_t (*op)(int,const void*,size_t),int fd,const char *buf,unsigned int len)
{
    unsigned int left = len;
    ssize_t w;
    while (left) {
        w = op(fd,buf,left);
        if (w == -1) {
            return (ssize_t)(-1); /* note that some data may have been written */
        }
        buf += w;
        left -= w;
    }
    return (ssize_t)(len);
}

// TODO: Get rid of the extra op arg; we never use it
ssize_t uninterruptable_read(ssize_t (*op)(int,void*,size_t),int fd,const char* buf,unsigned int len)
{
  ssize_t r;
  for (;;) {
    r = op(fd,(void*)buf,len);
    if (r == -1) if (errno == EINTR) continue;
    return r;
  }
}

ssize_t uninterruptable_readn(int fd, char *buf, size_t len)
{
  char* buf2 = buf;
  ssize_t bytesread = 0;
  while (len)
  {
    ssize_t r = read(fd, buf2, len);
    if(r==-1 && errno == EINTR) continue;
    if(r==-1) { return -1; }
    if(r==0)  { errno = EIO; return -1; }
    bytesread += r;
    buf2 += r;
    len -= r;
  }
  return bytesread;
}

ssize_t readn(int fd, char *buf, size_t len)
{
  char* buf2 = buf;
  ssize_t bytesread = 0;
  while (len)
  {
    ssize_t r = read(fd, buf2, len);
    if(r==-1) { return -1; }
    if(r==0)  { errno = EIO; return -1; }
    bytesread += r;
    buf2 += r;
    len -= r;
  }
  return bytesread;
}
