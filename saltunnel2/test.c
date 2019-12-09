//
//  test.c
//  saltunnel2
//
#include "oops.h"
#include "test.h"
#include "uninterruptable.h"
#include "saltunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>

// test1: Can uninterruptably write/read to/from pipes
void test1() {
    // Create two pipes
    int pipe_local[2]; try(pipe(pipe_local)) || oops_fatal("failed to create pipe");
    int pipe_net[2];   try(pipe(pipe_net)) || oops_fatal("failed to create pipe");
        
    // Write "expected value" to both pipes
    const char local_teststr_expected[] = "send_nt_pipe";
    const char net_teststr_expected[] = "send_lc_pipe";
    uninterruptable_write(write, pipe_local[1], local_teststr_expected, 12);
    uninterruptable_write(write, pipe_net[1], net_teststr_expected, 12);
    
    // Read "actual value" from both pipes
    char local_teststr_actual[12+1] = {0};
    char net_teststr_actual[12+1]   = {0};
    uninterruptable_read(read, pipe_local[0], local_teststr_actual, 12);
    uninterruptable_read(read, pipe_net[0], net_teststr_actual, 12);
    
    // Assert "expected value" equals "actual value"
    strcmp(local_teststr_expected, local_teststr_actual) == 0 || oops_fatal("local teststr did not match");
    strcmp(net_teststr_expected, net_teststr_actual) == 0 || oops_fatal("net teststr did not match");
}


// test2: saltunnel works with nullcryptostream
void test2() {
    
    // Create four "fake files" (i.e., pipes)
    int pipe_local_read[2];  try(pipe(pipe_local_read))  || oops_fatal("failed to create pipe");
    int pipe_local_write[2]; try(pipe(pipe_local_write)) || oops_fatal("failed to create pipe");
    int pipe_net_read[2];    try(pipe(pipe_net_read))    || oops_fatal("failed to create pipe");
    int pipe_net_write[2];   try(pipe(pipe_net_write))   || oops_fatal("failed to create pipe");
    
    // Start with "expected value" available in both "readable" pipes
    const char local_teststr_expected[] = "send_nt_pipe";
    const char net_teststr_expected[] = "send_lc_pipe";
    uninterruptable_write(write, pipe_local_read[1], local_teststr_expected, 12); close(pipe_local_read[1]);
    uninterruptable_write(write, pipe_net_read[1],   net_teststr_expected,   12); close(pipe_net_read[1]);
    
    // Run saltunnel
    cryptostream ingress = {
        .op = cryptostream_identity_feed,
        .from_fd = pipe_net_read[0],
        .to_fd = pipe_local_write[1]
    };
    cryptostream egress = {
        .op = cryptostream_identity_feed,
        .from_fd = pipe_local_read[0],
        .to_fd = pipe_net_write[1]
    };
    saltunnel(&ingress, &egress);
    
    // Read "actual value" from both "write" pipes
    char local_teststr_actual[12+1] = {0};
    char net_teststr_actual[12+1] = {0};
    uninterruptable_read(read, pipe_local_write[0], local_teststr_actual, 12);
    uninterruptable_read(read, pipe_net_write[0], net_teststr_actual, 12);
    
    // Assert "expected value" equals "actual value"
    strcmp(local_teststr_expected, net_teststr_actual) == 0 || oops_fatal("local teststr did not match");
    strcmp(net_teststr_expected, local_teststr_actual) == 0 || oops_fatal("net teststr did not match");
}

static void run(void (*the_test)(void), const char *test_name) {
    fprintf(stderr, "test: %s: started...\n", test_name);
    the_test();
    fprintf(stderr, "test: %s: succeeded.\n", test_name);
}

int test() {
    run(test1, "test1");
    run(test2, "test2");
    fprintf(stderr, "test: all tests passed\n");
    return 0;
}
