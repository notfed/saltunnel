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

int intexit(int exitcode) {
    _exit(exitcode);
    return -1;
}
