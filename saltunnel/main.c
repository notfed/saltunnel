//
//  main.c
//  saltunnel2
//

#include "oops.h"
#include "test.h"
#include "threadpool.h"
#include <stdio.h>
#include <errno.h>

#include <unistd.h>

int main(int argc, const char * argv[]) {
    log_info("number of cores: %d", (int)sysconf(_SC_NPROCESSORS_ONLN)); // TODO: Debug
    threadpool_init();
    test();
    threadpool_shutdown();
    return 0;
}
