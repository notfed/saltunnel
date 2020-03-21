//
//  saltunnel_test_main.c
//  saltunnel2
//

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "oops.h"
#include "threadpool.h"
#include "sodium.h"
#include "saltunnel_tests.h"

int main(int argc, const char * argv[]) {
    
    errno = 0;
    
    // Seed random bytes
    try(sodium_init())
    || oops_fatal("sodium init");
    
    // Initialize thread pool
    threadpool_init_all();
    
    // Seed random bytes
    test();
    
    // Shutdown thread pool
    threadpool_shutdown_all();
    return 0;
}
