//
//  saltunnel_common.c
//  saltunnel2
//

#include <poll.h>
#include "saltunnel.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"

void saltunnel(cryptostream* ingress, cryptostream* egress)
{
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
            try(ingress->op(ingress)) || oops_fatal("failed to feed");
        }
        
        // Handle egress data
        if (pfds[0].revents & POLLIN) {
            try(egress->op(egress)) || oops_fatal("failed to feed");
        }
        
        /* If both fds are closed, exit */
        if(pfds[0].revents & POLLHUP && pfds[1].revents & POLLHUP) {
            break;
        }
    }
}
