//
//  oops.c
//  saltunnel2
//

#include "oops.h"
#include "log.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int intexit(int exitcode) {
    _exit(exitcode);
    return -1;
}
