//
//  chaos.h
//  saltunnel2
//

#ifndef chaos_h
#define chaos_h

#include <sys/uio.h>

int chaos_writev(int fd, struct iovec* vector, int count);
int chaos_readv(int fd, struct iovec* vector, int count);

#endif /* chaos_h */
