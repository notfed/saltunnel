//
//  test.c
//  saltunnel2
//
#include "oops.h"
#include "test.h"
#include "uninterruptable.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>

// test1: Can uninterruptably write/read to/from pipes
void test1() {
    // Create two pipes
    int pipe_local[2];
    int pipe_net[2];
    try(pipe(pipe_local)) || oops_fatal("failed to create pipe");
    try(pipe(pipe_net)) || oops_fatal("failed to create pipe");
    
    // Write a test string into both input pipes
    const char local_teststr[] = "send_nt_pipe";
    const char net_teststr[] = "send_lc_pipe";
    uninterruptable_write(write, pipe_local[1], local_teststr, 12);
    uninterruptable_write(write, pipe_net[1], net_teststr, 12);
    
    // Read test string from both pipes
    char local_teststr_actual[12+1] = {0};
    char net_teststr_actual[12+1]= {0};
    uninterruptable_read(read, pipe_local[0], local_teststr_actual, 12);
    uninterruptable_read(read, pipe_net[0], net_teststr_actual, 12);
    
    // Assert both are equal
    strcmp(local_teststr, local_teststr_actual) == 0 || oops_fatal("local teststr did not match");
    strcmp(net_teststr, net_teststr_actual) == 0 || oops_fatal("net teststr did not match");
}

static void run(void (*the_test)(void), const char *test_name) {
    fprintf(stderr, "test: %s: started...\n", test_name);
    the_test();
    fprintf(stderr, "test: %s: succeeded.\n", test_name);
}

int test() {
    run(test1, "test1");
    fprintf(stderr, "test: all tests passed\n");
    return 0;
}
