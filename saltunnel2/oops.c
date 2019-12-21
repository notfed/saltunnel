//
//  oops.c
//  saltunnel2
//

#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int oops_fatal(char* msg)
{
    if(errno == 0)
        log_fatal(msg);
    else
        log_fatal("%s: %s", msg, strerror(errno));
    exit(1);
}

int oops_warn(char* msg)
{
    log_warn("%s", msg);
    return 0;
}
