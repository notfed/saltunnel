//
//  uninterruptable.h
//  saltunnel2
//
//  Created by Jay Sullivan on 12/8/19.
//  Copyright © 2019 Jay Sullivan. All rights reserved.
//

#ifndef uninterruptable_h
#define uninterruptable_h

#include <stdlib.h>

ssize_t uninterruptable_write(ssize_t (*op)(int,const void*,size_t),int fd,const char *buf,unsigned int len);
ssize_t uninterruptable_read(ssize_t (*op)(int,void*,size_t),int fd,const char* buf,unsigned int len);
// TODO: Implement readn
#define uninterruptable_readn uninterruptable_read

#endif /* uninterruptable_h */
