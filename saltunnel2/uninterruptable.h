//
//  uninterruptable.h
//  saltunnel2
//

//TODO: Rename to uninterruptible

#ifndef uninterruptable_h
#define uninterruptable_h

#include <sys/uio.h>
#include <stdlib.h>

ssize_t uninterruptable_write(ssize_t (*op)(int,const void*,size_t),int fd,const char *buf,unsigned int len);
ssize_t uninterruptable_read(ssize_t (*op)(int,void*,size_t),int fd,const char* buf,unsigned int len);

size_t allread(int fd, char *buf, size_t len);
ssize_t uninterruptable_readn(ssize_t (*op)(int,void*,size_t),int fd,const char* buf,unsigned int len);

ssize_t uninterruptable_readv(int fd, const struct iovec *vector, int count);
ssize_t uninterruptable_writev(int fd, const struct iovec *vector, int count);

#endif /* uninterruptable_h */
