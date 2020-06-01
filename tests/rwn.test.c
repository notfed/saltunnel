//
//  rwn.test.c
//  saltunnel
//

#include "rwn.test.h"
#include "rwn.h"
#include "oops.h"
#include "uint32.h"

#include <stdint.h>
#include <unistd.h>
#include <assert.h>

void rwn_test() {
    // Create two pipes
    int pipe_local[2]; assert(pipe(pipe_local)==0);
    int pipe_net[2];   assert(pipe(pipe_net)==0);
         
    // Write "expected value" to both pipes
    const char local_teststr_expected[] = "send_nt_pipe";
    const char net_teststr_expected[] = "send_lc_pipe";
    writen(pipe_local[1], local_teststr_expected, 12);
    writen(pipe_net[1], net_teststr_expected, 12);
    
    // Read "actual value" from both pipes
    char local_teststr_actual[12+1] = {0};
    char net_teststr_actual[12+1]   = {0};
    readn(pipe_local[0], local_teststr_actual, 12);
    readn(pipe_net[0], net_teststr_actual, 12);
    
    // Assert "expected value" equals "actual value"
    assert(strcmp(local_teststr_expected, local_teststr_actual) == 0);
    assert(strcmp(net_teststr_expected, net_teststr_actual) == 0);

    close(pipe_local[0]); close(pipe_local[1]);
    close(pipe_net[0]);   close(pipe_net[1]);
}
