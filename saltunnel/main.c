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
    threadpool_init();
    test();
    threadpool_shutdown();
    return 0;
}
