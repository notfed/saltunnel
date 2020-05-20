//
//  oops.h
//  saltunnel
//
//  To log a warning message:
//
//     oops_warn	    Non-fatal.         Returns -1
//     oops_warn_sys	Non-fatal, errno.  Returns -1
//
//  To log an error message and terminate the program:
//
//     oops_error	    Fatal, no errno.   Calls exit(1)
//     oops_error_sys	Fatal, errno.      Calls exit(1)
//
//  To conditionally call either 'oops_warn' or 'oops_error':
//
//     oops(...)        Conditional, no errno.   (Conditional behavior)
//     oops_sys(...)    Conditional, errno.      (Conditional behavior)
//
//  The behavior of both functions are conditional:
//
//  - If 'oops_should_error()' was called last, it will call 'log_error', then terminate the program
//  - If 'oops_should_warn()' was called last, it will call 'log_warn', then return -1.
//     

#ifndef oops_h
#define oops_h

#include "log.h"

#include <errno.h>
#include <string.h>

extern int oops_mode;
int oops_should_warn();
int oops_should_error();

int intexit(int);

#define try(rc) (rc>=0)

#define oops_warn(msg)    ((errno == 0 ? log_warn(msg)  : log_warn ("%s", msg)), -1)
#define oops_warn_sys(msg)((errno == 0 ? log_warn(msg)  : log_warn ("%s: %s", msg, strerror(errno))), -1)

#define oops_error(msg)     ((errno == 0 ? log_error(msg) : log_error("%s", msg)), intexit(1))
#define oops_error_sys(msg) ((errno == 0 ? log_error(msg) : log_error("%s: %s", msg, strerror(errno))), intexit(1))

#define oops(msg)     (oops_mode == 0 ? oops_warn(msg)     : oops_error(msg))
#define oops_sys(msg) (oops_mode == 0 ? oops_warn_sys(msg) : oops_error_sys(msg))

#endif /* oops_h */
