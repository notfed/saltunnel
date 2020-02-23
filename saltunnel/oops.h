//
//  oops.h
//  saltunnel2
//

#ifndef oops_h
#define oops_h

#include "log.h"
#include <errno.h>
#include <string.h>

#define try(rc) (rc>=0)

int intexit(int);

// TODO: Make these take varags

#define oops_fatal(msg) ((errno == 0 ? log_fatal(msg) : log_fatal("%s: %s", msg, strerror(errno))), intexit(1))
#define oops_warn(msg) ((errno == 0 ? log_warn(msg) : log_warn("%s: %s", msg, strerror(errno))),-1)

#endif /* oops_h */
