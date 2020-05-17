//
//  test.c
//  saltunnel
//
#include "cryptostream_vector.test.h"
#include "oops.h"
#include "rwn.test.h"
#include "saltunnel_tcp_forwarder.test.h"
#include "saltunnel.test.h"
#include "log.test.h"
#include "cache.test.h"
#include "nonce.test.h"
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
    log_debug("%s: started...", test_name);
    the_test();
    log_debug("%s: succeeded.", test_name);
}

void test() {
    
    log_info("test suite started");

    run(rwn_test, "rwn_test");
    run(log_test, "log_test");
    run(single_packet_bidirectional_test, "single_packet_bidirectional_test");
    run(saltunnel_tcp_forwarder_tests, "saltunnel_tcp_forwarder_tests");
    run(two_packet_bidirectional_test, "two_packet_bidirectional_test");
    run(edge_case_bidirectional_tests, "edge_case_bidirectional_tests");
    run(calculate_filled_buffers_tests,"calculate_filled_buffers_tests");
    run(cryptostream_vector_tests,"cryptostrean_vector_tests");
    run(cache_test, "cache_test");
    run(nonce_tests, "nonce_tests");
    
    log_info("all tests passed");
}
