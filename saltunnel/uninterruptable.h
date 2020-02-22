//
//  uninterruptable.h
//  saltunnel2
//

//TODO: We don't need these if we have SA_RESTART

#ifndef uninterruptable_h
#define uninterruptable_h

#include <sys/uio.h>
#include <stdlib.h>

ssize_t uninterruptable_writen(ssize_t (*op)(int,const void*,size_t),int fd,const char *buf,unsigned int len);
ssize_t uninterruptable_read(ssize_t (*op)(int,void*,size_t),int fd,const char* buf,unsigned int len);
ssize_t uninterruptable_readn(int fd, char *buf, size_t len);

#endif /* uninterruptable_h */
