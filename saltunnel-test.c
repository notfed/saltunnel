//
//  saltunnel-test.c
//  saltunnel
//
#include "src/saltunnel.h"
#include "src/oops.h"
#include "src/hypercounter.h"
#include "src/threadpool.h"

#include "tests/cryptostream_vector.test.h"
#include "tests/rwn.test.h"
#include "tests/saltunnel_tcp_forwarder.test.h"
#include "tests/saltunnel.test.h"
#include "tests/log.test.h"
#include "tests/cache.test.h"
#include "tests/nonce.test.h"
#include "tests/tcp.test.h"
#include "tests/hypercounter.test.h"
#include "tests/waitlist.test.h"
#include "tests/csprng.test.h"
#include "tests/consttime.test.h"
#include "tests/concurrentlist.test.h"
#include "tests/hex2bin.test.h"

#include <signal.h>
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
#include <sys/wait.h>

static void run(void (*the_test)(void), const char *test_name) {
    log_info("---- %s: started ----", test_name);
    the_test();
    log_info("---- %s: succeeded ----", test_name);
}

static void run_as_child_process(void (*the_test)(void), const char *test_name) {
    
   // Run this test as a child process (this allows us to cleanly exit all threads at the end of the test)
   int cfd = fork();
   if(cfd<0)
       oops_error_sys("failed to fork child process");

   if(cfd==0) {
       run(the_test,test_name);
       _exit(0);
   }

   // Wait for test to complete
   int status = -1;
   if(waitpid(cfd, &status, 0)<0)
       oops_error_sys("failed to wait for child process");

   // Ensure test returned 0
   if(status!=0)
       oops_error("test failed");
}

// Rename this into saltunnel-test.c
void test() {

    log_info("test suite started");
//    run(waitlist_tests, "waitlist tests");
//    run(tcp_tests, "tcp tests");
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
//    run(consttime_tests, "consttime tests");
//    run(concurrentlist_tests, "concurrentlist tests");
    run(hex2bin_tests, "hex2bin_tests tests");
    log_info("all tests passed");
}

int main(int argc, const char * argv[]) {
    
    errno = 0;
    
    // Set log level
    log_level = 1;
    if(argc==2 && strcmp(argv[1],"-vv")==0)
        log_level = 0;
    
    // Initialize saltunnel preqrequisites
    saltunnel_init();

    // Perform the test
    for(int i = 0; i < 1; i++)
        test();
    
    // Shutdown thread pool
    threadpool_shutdown_all();
    return 0;
}

