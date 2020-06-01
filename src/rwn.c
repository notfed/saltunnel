//
//  rwn.c
//  saltunnel
//

#include "rwn.h"
#include "oops.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t readn(int fd, char *buf, size_t len)
{
  char* buf2 = buf;
  ssize_t bytesread = 0;
  while (len)
  {
    ssize_t r = read(fd, buf2, len);
    if(r<0) { return r; }
    if(r==0)  { errno = EIO; return -1; }
    bytesread += r;
    buf2 += r;
    len -= r;
  }
  return bytesread;
}

ssize_t writen(int fd,const char *buf,unsigned int len)
{
    unsigned int left = len;
    ssize_t w;
    while (left) {
        w = write(fd,buf,left);
        if(w<0) {
            return (ssize_t)(-1); /* note that some data may have been written */
        }
        buf += w;
        left -= w;
    }
    return (ssize_t)(len);
}
