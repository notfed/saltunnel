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
    threadpool_init_all();
    test();
    threadpool_shutdown_all();
    return 0;
}
