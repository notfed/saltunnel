//
//  rwn.h
//  saltunnel
//
//  Implementation of read and write which read/write exactly n bytes.
//

#ifndef rwn_h
#define rwn_h

#include <sys/uio.h>
#include <stdlib.h>

ssize_t readn(int fd, char *buf, size_t len);
ssize_t writen(int fd,const char *buf,unsigned int len);

#endif /* rwn_h */
