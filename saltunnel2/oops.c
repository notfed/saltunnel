//
//  oops.c
//  saltunnel2
//
//  Created by Jay Sullivan on 12/21/19.
//  Copyright © 2019 Jay Sullivan. All rights reserved.
//

#include "oops.h"
#include "log.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int oops_fatal(char* msg)
{
    if(errno == 0)
        log_fatal(msg);
    else
        log_fatal("%s: %s", msg, strerror(errno));
    _exit(1);
}

int oops_warn(char* msg)
{
    log_warn("%s", msg);
    return 0;
}
