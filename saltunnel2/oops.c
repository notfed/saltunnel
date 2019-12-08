//
//  oops.c
//  saltunnel2
//

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int oops_fatal(char* msg)
{
    if(errno == 0)
        fprintf(stderr, "saltunnel2: fatal: %s\n", msg);
    else
        fprintf(stderr, "saltunnel2: fatal: %s: %s\n", msg, strerror(errno));
    exit(1);
    return 0;
}

int oops_warn(char* msg)
{
    fprintf(stderr, "saltunnel2: warn: %s\n", msg);
    return 0;
}
