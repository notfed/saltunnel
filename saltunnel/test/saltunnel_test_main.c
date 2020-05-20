//
//  saltunnel_test_main.c
//  saltunnel
//
#include "test.h"
#include "log.h"
#include "oops.h"
#include "threadpool.h"
#include "sodium.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

int main(int argc, const char * argv[]) {
    
    errno = 0;

    // Set log level
    log_level = 1;
    if(argc==2 && strcmp(argv[1],"-vv")==0) 
        log_level = 0;
    
    // Seed random bytes
    try(sodium_init())
    || oops_error("failed to initialize libsodium");
    
    // Initialize thread pool
    threadpool_init_all();
    
    // Seed random bytes
    test();
    
    // Shutdown thread pool
    threadpool_shutdown_all();
    return 0;
}
