//
//  log.c
//  saltunnel2
//

#include "log.h"
#include <stdio.h>

void log_debug(char* msg) {
    fprintf(stderr, "saltunnel2: debug: %s", msg);
}
void log_info(char* msg) {
    fprintf(stderr, "saltunnel2: info: %s", msg);
}
