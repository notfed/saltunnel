//
//  stunted_rwv.h
//  saltunnel
//
//  Stunted readv and writev. I.e., writes/reads less than you requested.
//  (Used for testing.)
//

#ifndef stunted_rwv_h
#define stunted_rwv_h

#include <sys/uio.h>

int stunted_writev(int fd, struct iovec* vector, int count);
int stunted_readv(int fd, struct iovec* vector, int count);

#endif /* stunted_rwv_h */
