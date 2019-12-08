//
//  saltunnel_common.c
//  saltunnel2
//

#include <poll.h>
#include "saltunnel.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"

void saltunnel(int fd_localin, int fd_localout, int fd_netin, int fd_netout)
{
    // We'll take bytes from fd_localin, encrypt them, and send to fd_netout
    cryptostream cryptostream_out =
        { .op = CRYPTOSTREAM_ENCRYPT, .from_fd = fd_localin, .to_fd = fd_netout};
    
    // We'll take bytes from fd_netin, decrypt them, and send to fd_localout
    cryptostream cryptostream_in =
        { .op = CRYPTOSTREAM_DECRYPT, .from_fd = fd_netin, .to_fd = fd_localout};
    
    // Define poll (we will poll fd_localin and fd_netin)
    struct pollfd pfds[] = {
        { .fd = fd_localin, .events = POLLIN },
        { .fd = fd_netin,   .events = POLLIN }
    };
    
    for(;;) {

        /* Poll */
        log_debug("about to poll\n");
        try(poll(pfds,2,-1)) || oops_fatal("step 2: failed to poll: ");

        // Handle data on fd_localin
        if (pfds[0].revents & POLLIN) {
            try(cryptostream_feed(&cryptostream_out)) || oops_fatal("step3: failed to feed: ");
        }
        
        // Handle data on fd_netin
        if (pfds[1].revents & POLLIN) {
            try(cryptostream_feed(&cryptostream_in)) || oops_fatal("step3: failed to feed: ");
        }
        
        /* If both fds are closed, exit */
        else if(pfds[0].revents & POLLHUP && pfds[1].revents & POLLHUP) {
            break;
        }
    }
}
