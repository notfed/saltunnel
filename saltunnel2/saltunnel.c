//
//  saltunnel_common.c
//  saltunnel2
//

#include <poll.h>
#include "saltunnel.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"

void saltunnel(int fd_local_read, int fd_local_write, int fd_net_read, int fd_net_write)
{
    // We'll take bytes from fd_local_read, encrypt them, and send to fd_net_write
    cryptostream cryptostream_egress =
        { .op = cryptostream_identity_feed, .from_fd = fd_local_read, .to_fd = fd_net_write};
    
    // We'll take bytes from fd_net_read, decrypt them, and send to fd_local_write
    cryptostream cryptostream_ingress =
        { .op = cryptostream_identity_feed, .from_fd = fd_net_read, .to_fd = fd_local_write};
    
    // Define poll (we will poll fd_localin and fd_netin)
    struct pollfd pfds[] = {
        { .fd = fd_local_read, .events = POLLIN }, // egress
        { .fd = fd_net_read,   .events = POLLIN }  // ingress
    };
    
    for(;;) {

        /* Poll */
        log_debug("about to poll\n");
        try(poll(pfds,2,-1)) || oops_fatal("step 2: failed to poll");
        log_debug("successfully polled\n");

        // Handle data on fd_localin
        if (pfds[0].revents & POLLIN) {
            try(cryptostream_egress.op(&cryptostream_egress)) || oops_fatal("failed to feed");
        }
        // Handle data on fd_netin
        if (pfds[1].revents & POLLIN) {
            try(cryptostream_ingress.op(&cryptostream_ingress)) || oops_fatal("failed to feed");
        }
        
        /* If both fds are closed, exit */
        if(pfds[0].revents & POLLHUP && pfds[1].revents & POLLHUP) {
            break;
        }
    }
}
