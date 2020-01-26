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

#define FD_EOF   (-2)
#define FD_READY (-1)

static void WTF_detect(cryptostream* ingress, cryptostream *egress) {
    if(ingress->WTF[0] != 0 || ingress->WTF[31] !=0 || egress->WTF[0] != 0 || egress->WTF[31] !=0)
        oops_fatal("WTF nonzero");
}

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
    
    // Configure poll (we will poll both "readable" fds)
    struct pollfd pfds[] = {
        { .fd = ingress->from_fd, .events = POLLIN|POLLHUP },
        { .fd = ingress->to_fd,   .events = POLLOUT        },
        { .fd = egress->from_fd,  .events = POLLIN|POLLHUP },
        { .fd = egress->to_fd,    .events = POLLOUT        },
    };
    
    // Defensive Programming
    fd_nonblock(ingress->from_fd); fd_nonblock(ingress->to_fd);
    fd_nonblock(egress->from_fd);  fd_nonblock(egress->to_fd);
    
    // Main Loop
    while(pfds[0].fd != FD_EOF || pfds[1].fd != FD_EOF || pfds[2].fd != FD_EOF || pfds[3].fd != FD_EOF) {
        
        WTF_detect(ingress, egress);
        
        /* Poll */
        log_debug("poll: polling [%2d->D->%2d, %2d->E->%2d]...", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);
        try(poll(pfds,4,-1)) || oops_fatal("poll: failed to poll");
        log_debug("poll: polled  [%2d->D->%2d, %2d->E->%2d].", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);
        
        WTF_detect(ingress, egress);
        
        /* If an fd is ready, mark it as FD_READY */
        
        /* Loud Version*/
//        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { log_debug("%d is ready to read from", pfds[0].fd); pfds[0].fd = FD_READY; }
//        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { log_debug("%d is ready to write to",  pfds[1].fd); pfds[1].fd = FD_READY; }
//        if ((pfds[2].fd>=0) && (pfds[2].revents & (POLLIN|POLLHUP))) { log_debug("%d is ready to read from", pfds[2].fd); pfds[2].fd = FD_READY; }
//        if ((pfds[3].fd>=0) && (pfds[3].revents & (POLLOUT)))        { log_debug("%d is ready to write to",  pfds[3].fd); pfds[3].fd = FD_READY; }
//
        /* Quiet Version */
        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { pfds[0].fd = FD_READY; }
        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { pfds[1].fd = FD_READY; }
        if ((pfds[2].fd>=0) && (pfds[2].revents & (POLLIN|POLLHUP))) { pfds[2].fd = FD_READY; }
        if ((pfds[3].fd>=0) && (pfds[3].revents & (POLLOUT)))        { pfds[3].fd = FD_READY; }
        
        WTF_detect(ingress, egress);
//
//        //
//        // Handle ingress data (old)
//        //
//        if (pfds[0].fd == FD_READY && pfds[1].fd == FD_READY) {
////            log_debug("poll: ingress net fd %d is ready for reading", ingress->from_fd);
//            int r = ingress->op(ingress,key);
//            if(r==0) {
//                log_debug("poll: local fd %d is closed; no longer polling ingress", ingress->from_fd);
//                pfds[0].fd = FD_EOF;
//                pfds[1].fd = FD_EOF;
//            } else if(r<0 && errno != EINPROGRESS) {
//                oops_fatal("failed to feed ingress");
//            } else if(r<0 && errno == EINPROGRESS) {
//                pfds[0].fd = FD_READY;
//                pfds[1].fd = ingress->to_fd;
//            } else {
//                pfds[0].fd = ingress->from_fd;
//                pfds[1].fd = ingress->to_fd;
//            }
//        }
        
        //
        // Handle egress data
        //

        // read from 'from' when: 'from' is ready, and buffers not full
        if ((pfds[2].fd == FD_READY) && cryptostream_encrypt_feed_canread(egress)) {
            int r = cryptostream_encrypt_feed_read(egress,key); // TODO: Culprit! Remove this comment later
            if(r>0) { pfds[2].fd = egress->from_fd; }
            if(r==0) { pfds[2].fd = FD_EOF; }
        }
        WTF_detect(ingress, egress);
        
        // write to 'to' when: 'to' is ready, and buffers not empty
        if ((pfds[3].fd == FD_READY) && cryptostream_encrypt_feed_canwrite(egress)) {
            cryptostream_encrypt_feed_write(egress,key);
            pfds[3].fd = egress->to_fd;
        }
        WTF_detect(ingress, egress);
        
        // close 'to' when: 'from' is EOF, and all buffers are empty
        if(pfds[2].fd == FD_EOF && pfds[3].fd != FD_EOF && !cryptostream_encrypt_feed_canwrite(egress)) {
            log_debug("egress is done; closing egress->to_fd (%d)", egress->to_fd);
            try(close(egress->to_fd)) || oops_fatal("failed to close");
            pfds[3].fd = FD_EOF;
        }
        WTF_detect(ingress, egress);
        if(ingress->debug_write_total>1000000) oops_fatal("assertion failed");

        //
        // Handle ingress data
        //

        // read from 'from' when: 'from' is ready, and buffers not full
        if ((pfds[0].fd == FD_READY) && cryptostream_decrypt_feed_canread(ingress)) {
            if(ingress->debug_write_total>1000000) oops_fatal("assertion failed");
            int r = cryptostream_decrypt_feed_read(ingress,key);  // TODO: Culprit! Remove this comment later 123
            if(ingress->debug_write_total>1000000) oops_fatal("assertion failed");
            if(r>0) { pfds[0].fd = ingress->from_fd; }
            if(r==0) { pfds[0].fd = FD_EOF; }
        }
        WTF_detect(ingress, egress);
        if(ingress->debug_write_total>1000000) oops_fatal("assertion failed");
        
        // write to 'to' when: 'to' is ready, and buffers not empty
        if ((pfds[1].fd == FD_READY) && cryptostream_decrypt_feed_canwrite(ingress)) {
            cryptostream_decrypt_feed_write(ingress,key);
            pfds[1].fd = ingress->to_fd;
        }
        WTF_detect(ingress, egress);
        
        // close 'to' when: 'from' is EOF, and all buffers are empty
        if(pfds[0].fd == FD_EOF && pfds[1].fd != FD_EOF && !cryptostream_decrypt_feed_canwrite(ingress)) {
            log_debug("egress is done; closing egress->to_fd (%d)", ingress->to_fd);
            try(close(ingress->to_fd)) || oops_fatal("failed to close");
            pfds[1].fd = FD_EOF;
        }
        int bk = 0;
        WTF_detect(ingress, egress);

    }
    log_debug("all fds are closed [%d,%d,%d,%d]; done polling", ingress->from_fd, ingress->to_fd, egress->from_fd, egress->to_fd);
}

void saltunnel(cryptostream* ingress, cryptostream* egress)
{
    unsigned char key[32] = {0};
    
    // Key Exchange
    exchange_key(ingress, egress, key);
    
    // Message Exchange
    exchange_messages(ingress, egress, key);
}
