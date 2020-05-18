//
//  oops.c
//  saltunnel
//

#include "oops.h"
#include "log.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

int intexit(int exitcode) {
    _exit(exitcode);
    return -1; // Satisfies macro expression requirements
}
