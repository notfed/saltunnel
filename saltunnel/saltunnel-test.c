//
//  saltunnel-test.c
//  saltunnel
//
#include "src/oops.h"
#include "src/hypercounter.h"
#include "src/threadpool.h"

#include "test/cryptostream_vector.test.h"
#include "test/rwn.test.h"
#include "test/saltunnel_tcp_forwarder.test.h"
#include "test/saltunnel.test.h"
#include "test/log.test.h"
#include "test/cache.test.h"
#include "test/nonce.test.h"
#include "test/tcp.test.h"
#include "test/hypercounter.test.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void run(void (*the_test)(void), const char *test_name) {
    log_info("---- %s: started ----", test_name);
    the_test();
    log_info("---- %s: succeeded ----", test_name);
}

// Rename this into saltunnel-test.c
void test() {
    
    log_info("test suite started");
    
    run(tcp_tests, "tcp tests");
//    run(hypercounter_tests, "hypercounter tests");
//    run(saltunnel_tcp_forwarder_tests, "saltunnel tcp forwarder tests");
//    run(rwn_test, "rwn tests");
//    run(log_test, "log tests");
//    run(single_packet_bidirectional_test, "single packet bidirectional tests");
//    run(two_packet_bidirectional_test, "two-packet bidirectional test");
//    run(large_bidirectional_test, "large bidirectional test");
//    run(edge_case_bidirectional_tests, "edge-case bidirectional tests");
//    run(calculate_filled_buffers_tests,"calculate filled buffers tests");
//    run(cryptostream_vector_tests,"cryptostream vector tests");
//    run(cache_test, "cache tests");
//    run(nonce_tests, "nonce tests");
    
    log_info("all tests passed");
}

int main(int argc, const char * argv[]) {
    
    errno = 0;

    // Set log level
    log_level = 1;
    if(argc==2 && strcmp(argv[1],"-vv")==0)
        log_level = 0;
    
    // Seed random bytes
    try(sodium_init())
    || oops_error("failed to initialize libsodium");
    
    // Initialize hypercounter
    try(hypercounter_init())
    || oops_error("failed to initialize hypercounter");
    
    // Initialize thread pool
    threadpool_init_all();
    
    // Seed random bytes
    test();
    
    // Shutdown thread pool
    threadpool_shutdown_all();
    return 0;
}

