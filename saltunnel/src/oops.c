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

int oops_mode = 1;

void oops_should_warn() {
    oops_mode = 0;
}

void oops_should_error() {
    oops_mode = 1;
}

int intexit(int exitcode) {
    _exit(exitcode);
    return -1; // Satisfies macro expression requirements
}
