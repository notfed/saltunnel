//
//  rwn.h
//  saltunnel2
//

#ifndef rwn_h
#define rwn_h

#include <sys/uio.h>
#include <stdlib.h>

ssize_t writen(int fd,const char *buf,unsigned int len);
ssize_t readn(int fd, char *buf, size_t len);

#endif /* rwn_h */
