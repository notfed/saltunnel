//
//  saltunnel_init.c
//  saltunnel
//

#include "saltunnel_init.h"
#include "hypercounter.h"
#include "csprng.h"
#include "threadpool.h"
#include "oops.h"

#include <signal.h>

void saltunnel_init(void) { // TODO: Return -1 on error
    
    // Seed random bytes
    csprng_seed();
    
    // Don't throw a signal when writing to a bad file descriptor
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        oops_error("failed to ignore SIGPIPE signal");

    // Initialize hypercounter
    if(hypercounter_init()<0)
        oops_error("failed to initialize hypercounter");
    
    // Initialize thread pool
    threadpool_init_all();
}
