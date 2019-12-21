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
#include <unistd.h>

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
    int isclosed[] = { 0, 0 };
    
    while(!isclosed[0] && !isclosed[1]) {
        
        /* Poll */
        log_debug("poll: polling [%d,%d]...", pfds[0].fd, pfds[1].fd);
        try(poll(pfds,2,-1)) || oops_fatal("poll: failed to poll");
        
        /* If both fds are closed, exit */
        if(pfds[0].revents & POLLHUP && pfds[1].revents & POLLHUP) {
            log_debug("poll: both fds closed; done");
            break;
        }
        
        // Handle ingress data
        if (pfds[0].revents & POLLIN) {
            log_debug("poll: fd %d is ready for reading", pfds[0].fd);
            int r;
            try((r=ingress->op(ingress,key))) || oops_fatal("failed to feed ingress");
            if(r==0) {
                isclosed[0] = 1;
            }
        }
        
        // Handle egress data
        if (pfds[1].revents & POLLIN) {
            log_debug("poll: fd %d is ready for reading", pfds[1].fd);
            int r;
            try((r=egress->op(egress,key))) || oops_fatal("failed to feed egress");
            if(r==0) {
                isclosed[1] = 1;
            }
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
