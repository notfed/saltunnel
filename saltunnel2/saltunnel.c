//
//  saltunnel_common.c
//  saltunnel2
//

#include "saltunnel.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"
#include <poll.h>
#include <stdio.h>

static void exchange_key(cryptostream *ingress, cryptostream *egress, unsigned char* key) {
    // TODO: Perform steps to agree on key
    //       For now, just hard-coding to [0..31].
    for(int i = 0; i<32;  i++)
        key[i] = i;
}

static void exchange_messages(cryptostream *ingress, cryptostream *egress, unsigned char* key) {
    
    // Configure poll (we will poll both "readable" fds)
    struct pollfd pfds[] = {
        { .fd = ingress->from_fd, .events = POLLIN },
        { .fd = egress->from_fd,  .events = POLLIN }
    };
    
    for(;;) {
        
        /* Poll */
        log_debug("about to poll\n");
        try(poll(pfds,2,-1)) || oops_fatal("step 2: failed to poll");
        log_debug("successfully polled\n");
        
        // Handle egress data
        if (pfds[0].revents & POLLIN) {
            try(egress->op(egress,key)) || oops_fatal("failed to feed egress");
        }
        
        // Handle ingress data
        if (pfds[1].revents & POLLIN) {
            try(ingress->op(ingress,key)) || oops_fatal("failed to feed ingress");
        }
        
        /* If both fds are closed, exit */
        if(pfds[0].revents & POLLHUP && pfds[1].revents & POLLHUP) {
            fprintf(stderr, "both fds closed; done\n");
            break;
        }
    }
}

void saltunnel(cryptostream* ingress, cryptostream* egress)
{
    unsigned char key[32] = {0};
    
    // Key Exchange
    exchange_key(ingress, egress, key);
    
    // Message Exchange
    exchange_messages(ingress, egress, key);
}
