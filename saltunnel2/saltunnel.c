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
#include <fcntl.h>

#define FD_READY (-2)
#define FD_EOF   (-1)

static void exchange_key(cryptostream *ingress, cryptostream *egress, unsigned char* key) {
    // TODO: Perform steps to agree on key
    //       For now, just hard-coding to [0..31].
    for(int i = 0; i<32;  i++)
        key[i] = i;
}

void fd_nonblock(int fd) {
    int flags;
    try((flags=fcntl(fd, F_GETFL, 0))) || oops_fatal("setting O_NONBLOCK");
    try(fcntl(fd, F_SETFL, flags|O_NONBLOCK)) || oops_fatal("setting O_NONBLOCK");
}

static void exchange_messages(cryptostream *ingress, cryptostream *egress, unsigned char* key) {
    
    // PROBLEM: This is doomed? Just do threads.
    
    // Configure poll (we will poll both "readable" fds)
    struct pollfd pfds[] = {
        { .fd = ingress->from_fd, .events = POLLIN|POLLHUP },
        { .fd = ingress->to_fd,   .events = POLLOUT        },
        { .fd = egress->from_fd,  .events = POLLIN|POLLHUP },
        { .fd = egress->to_fd,    .events = POLLOUT        },
    };

    fd_nonblock(ingress->to_fd);
    fd_nonblock(egress->to_fd);
    
    while((pfds[0].fd != FD_EOF) || pfds[2].fd != FD_EOF) {
        
        /* Poll */
//        log_debug("poll: polling [%2d->D->%2d, %2d->E->%2d]...", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);
        try(poll(pfds,4,-1)) || oops_fatal("poll: failed to poll");
//        log_debug("poll: polled  [%2d->D->%2d, %2d->E->%2d].", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);
        
        /* If an fd is ready, mark it as -2 */
        if ((pfds[0].fd >=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { log_debug("%d is ready to read from", pfds[0].fd); pfds[0].fd = FD_READY; }
        if ((pfds[1].fd >=0) && (pfds[1].revents & (POLLOUT)))        { log_debug("%d is ready to write ro",  pfds[1].fd); pfds[1].fd = FD_READY; }
        if ((pfds[2].fd >=0) && (pfds[2].revents & (POLLIN|POLLHUP))) { log_debug("%d is ready to read from", pfds[2].fd); pfds[2].fd = FD_READY; }
        if ((pfds[3].fd >=0) && (pfds[3].revents & (POLLOUT)))        { log_debug("%d is ready to write to",  pfds[3].fd); pfds[3].fd = FD_READY; }
        
        // Handle ingress data
        if (pfds[0].fd == FD_READY && pfds[1].fd == FD_READY) {
//            log_debug("poll: ingress net fd %d is ready for reading", ingress->from_fd);
            int r;
            try((r=ingress->op(ingress,key))) || oops_fatal("failed to feed ingress");
            if(r==0) {
                log_debug("poll: no longer polling ingress net fd %d", ingress->from_fd);
                pfds[0].fd = FD_EOF;
                pfds[1].fd = FD_EOF;
            } else if(r<0 && errno==EINPROGRESS) {
                pfds[0].fd = FD_READY;
                pfds[1].fd = ingress->to_fd;
            } else {
                pfds[0].fd = ingress->from_fd;
                pfds[1].fd = ingress->to_fd;
            }
        }
        
        // Handle egress data
        if (pfds[2].fd == FD_READY && pfds[3].fd == FD_READY) {
//            log_debug("poll: egress local fd %d is ready for reading", egress->from_fd);
            int r;
            try((r=egress->op(egress,key))) || oops_fatal("failed to feed egress");
            if(r==0) {
                log_debug("poll: no longer polling egress local fd %d", egress->from_fd);
                pfds[2].fd = FD_EOF;
                pfds[3].fd = FD_EOF;
            } else if(r<0 && errno==EINPROGRESS) {
                pfds[2].fd = FD_READY;
                pfds[3].fd = egress->to_fd;
            }
            else {
                pfds[2].fd = egress->from_fd;
                pfds[3].fd = egress->to_fd;
            }
        }
    }
    log_debug("both read fds are closed [%d,%d]; done polling", ingress->from_fd, egress->from_fd);
}

void saltunnel(cryptostream* ingress, cryptostream* egress)
{
    unsigned char key[32] = {0};
    
    // Key Exchange
    exchange_key(ingress, egress, key);
    
    // Message Exchange
    exchange_messages(ingress, egress, key);
}
