//
//  oops.h
//  saltunnel
//
//     oops_warn	    Non-fatal error, return -1.  Always writes.       Writes to stderr.
//     oops_warn_sys	oops_warn with errno.        Always writes.       Writes to stderr.
//     oops_fatal	    Fatal errors (no errno).     Always writes.       Writes to stderr.
//     oops_fatal_sys	oops_fatal with errno.       Always writes.       Writes to stderr.
//     ^ TODO ^

#ifndef oops_h
#define oops_h

#include "log.h"
#include <errno.h>
#include <string.h>

#define try(rc) (rc>=0)

int intexit(int);

#define oops_fatal(msg) ((errno == 0 ? log_fatal(msg) : log_fatal("%s: %s", msg, strerror(errno))), intexit(1))
#define oops_warn(msg) ((errno == 0 ? log_warn(msg) : log_warn("%s: %s", msg, strerror(errno))),-1)

#endif /* oops_h */
