//
//  uninterruptable.c
//  saltunnel2
//

#include "uninterruptable.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t uninterruptable_write(ssize_t (*op)(int,const void*,size_t),int fd,const char *buf,unsigned int len)
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

ssize_t uninterruptable_read(ssize_t (*op)(int,void*,size_t),int fd,const char* buf,unsigned int len)
{
  ssize_t r;
  for (;;) {
    r = op(fd,(void*)buf,len);
    if (r == -1) if (errno == EINTR) continue;
    return r;
  }
}

ssize_t allread(int fd, char *buf, size_t len)
{
  ssize_t bytesread = 0;
  while (len)
  {
    ssize_t r = read(fd, buf, len);
    if(r==-1) { return -1; }
    if(r==0)  {
        errno = EIO; return -1; 
    }
    bytesread += r;
    buf += r;
    len -= r;
  }
  return bytesread;
}

size_t siovec_len (struct iovec const *v, unsigned int n)
{
  size_t w = 0 ;
  while (n--) w += v[n].iov_len ;
  return w ;
}

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

ssize_t iovec_skip(struct iovec *v, size_t vlen, unsigned int n)
{
    for(int i = 0; i < vlen; i++) {
        size_t ncur = MIN(v[i].iov_len, n);
        v[i].iov_len  -= ncur;
        v[i].iov_base += ncur;
        n -= ncur;
        if(n==0) break;
    }
    return n;
}

size_t siovec_seek (struct iovec *v, unsigned int n, size_t len)
{
  size_t w = 0 ;
  unsigned int i = 0 ;
  for (; i < n ; i++)
  {
    if (len < v[i].iov_len) break ;
    w += v[i].iov_len ;
    len -= v[i].iov_len ;
    v[i].iov_base = 0 ;
    v[i].iov_len = 0 ;
  }
  if (i < n)
  {
    v[i].iov_base = (char *)v[i].iov_base + len ;
    v[i].iov_len -= len ;
    w += len ;
  }
  return w ;
}

ssize_t allwritev(int fd, struct iovec const *v, unsigned int vlen)
{
    ssize_t written = 0 ;
    struct iovec vv[vlen ? vlen : 1] ;
    unsigned int i = vlen ;
    while (i--) vv[i] = v[i] ;
    while (siovec_len(vv, vlen))
    {
      ssize_t w = writev(fd, vv, vlen) ;
      if(w==-1) { return -1; }
      if(w==0)  { errno = EIO; return -1; }
      w = siovec_seek(vv, vlen, w) ;
      written += w ;
    }
    return written ;
}

ssize_t uninterruptable_readn(int fd,const char* buf,unsigned int len)
{
  ssize_t w;
  while(len) {
    w = read(fd,(void*)buf,len);
    if (w == -1) {
        if (errno == EINTR) continue;
        return (ssize_t)(-1); /* note that some data may have been read */
    }
    buf += w;
    len -= w;
  }
  return 0;
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

// Skip n bytes, and return how many iovecs have been filled
ssize_t iovec_skip2(struct iovec *v, size_t vlen, unsigned int n)
{
    int filled=0;
    for(int i = 0; i < vlen; i++) {
        int iov_len_was_zero = (v[i].iov_len==0);
        size_t ncur = MIN(v[i].iov_len, n);
        v[i].iov_len  -= ncur;
        v[i].iov_base += ncur;
        n -= ncur;
        int iov_len_is_zero = (v[i].iov_len==0);
        if(!iov_len_was_zero && iov_len_is_zero) filled++;
        if(n==0) break;
    }
    return filled;
}
