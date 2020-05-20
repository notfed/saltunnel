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
    log_info("---- %s: started ----", test_name);
    the_test();
    log_info("---- %s: succeeded ----", test_name);
}

void test() {
    
    log_info("test suite started");

    run(rwn_test, "rwn tests");
    run(log_test, "log tests");
    run(saltunnel_tcp_forwarder_tests, "saltunnel tcp forwarder tests");
    run(single_packet_bidirectional_test, "single packet bidirectional tests");
    run(two_packet_bidirectional_test, "two-packet bidirectional test");
    run(edge_case_bidirectional_tests, "edge-case bidirectional tests");
    run(calculate_filled_buffers_tests,"calculate filled buffers tests");
    run(cryptostream_vector_tests,"cryptostream vector tests");
    run(cache_test, "cache tests");
    run(nonce_tests, "nonce tests");
    
    log_info("all tests passed");
}
