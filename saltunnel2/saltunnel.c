//
//  saltunnel_common.c
//  saltunnel2
//

#include <poll.h>
#include "saltunnel.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"

static void exchange_key(cryptostream *ingress, cryptostream *egress, unsigned char* k) {
    // TODO: Perform steps to agree on key
    //       For now, just hard-coding to [0..31].
    for(int i = 0; i<32;  i++)
        k[i] = i;
}

static void exchange_messages(cryptostream *ingress, cryptostream *egress, unsigned char* k) {
    
    // Configure poll (we will poll both "readable" fds)
    struct pollfd pfds[] = {
        { .fd = ingress->from_fd, .events = POLLIN },
        { .fd = egress->from_fd, .events = POLLIN }
    };
    
    for(;;) {
        
        /* Poll */
        log_debug("about to poll\n");
        try(poll(pfds,2,-1)) || oops_fatal("step 2: failed to poll");
        log_debug("successfully polled\n");
        
        // Handle ingress data
        if (pfds[1].revents & POLLIN) {
            try(ingress->op(ingress,k)) || oops_fatal("failed to feed");
        }
        
        // Handle egress data
        if (pfds[0].revents & POLLIN) {
            try(egress->op(egress,k)) || oops_fatal("failed to feed");
        }
        
        /* If both fds are closed, exit */
        if(pfds[0].revents & POLLHUP && pfds[1].revents & POLLHUP) {
            break;
        }
    }
}

void saltunnel(cryptostream* ingress, cryptostream* egress)
{
    unsigned char k[32];
    
    // Key Exchange
    exchange_key(ingress, egress, k);
    
    // Message Exchange
    exchange_messages(ingress, egress, k);
}
