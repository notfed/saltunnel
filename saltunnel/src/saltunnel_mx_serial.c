//
//  saltunnel_mx_serial.c
//  saltunnel
//

#include "saltunnel.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define FD_EOF   (-2)
#define FD_READY (-1)

static void fd_nonblock(int fd) {
    int flags;
    try((flags=fcntl(fd, F_GETFL, 0))) || oops_fatal("failed to get file flags");
    try(fcntl(fd, F_SETFL, flags|O_NONBLOCK)) || oops_fatal("failed to set file as non-blocking");
}

static int fd_issocket(int fd) {
    struct stat statbuf;
    if(fstat(fd, &statbuf)<0) oops_fatal("failed to get file status");
    return S_ISSOCK(statbuf.st_mode);
}

void exchange_messages_serial(cryptostream *ingress, cryptostream *egress) {

    int had_error = 0;
    
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
    
    // Determine if fds are sockets
    int ingress_to_fd_is_socket   = fd_issocket(ingress->to_fd);
    int egress_to_fd_is_socket    = fd_issocket(egress->to_fd);
    
    // Main Loop
    while(pfds[0].fd != FD_EOF || pfds[1].fd != FD_EOF || pfds[2].fd != FD_EOF || pfds[3].fd != FD_EOF) {
        
        /* Poll */
        log_debug("poll: polling [%2d->D->%2d, %2d->E->%2d]...", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);
        int rc = poll(pfds,4,-1);
        if(rc<0 && errno == EINTR) continue;
        if(rc<0) oops_fatal("failed to poll");
        
        /* If an fd is ready, mark it as FD_READY */
        
        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { pfds[0].fd = FD_READY; }
        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { pfds[1].fd = FD_READY; }
        if ((pfds[2].fd>=0) && (pfds[2].revents & (POLLIN|POLLHUP))) { pfds[2].fd = FD_READY; }
        if ((pfds[3].fd>=0) && (pfds[3].revents & (POLLOUT)))        { pfds[3].fd = FD_READY; }
        log_debug("poll: polled  [%2d->D->%2d, %2d->E->%2d].", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);

        /* Loud Version*/
//        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { log_debug("%d is ready to read from", pfds[0].fd); pfds[0].fd = FD_READY; }
//        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { log_debug("%d is ready to write to",  pfds[1].fd); pfds[1].fd = FD_READY; }
//        if ((pfds[2].fd>=0) && (pfds[2].revents & (POLLIN|POLLHUP))) { log_debug("%d is ready to read from", pfds[2].fd); pfds[2].fd = FD_READY; }
//        if ((pfds[3].fd>=0) && (pfds[3].revents & (POLLOUT)))        { log_debug("%d is ready to write to",  pfds[3].fd); pfds[3].fd = FD_READY; }
        

        //
        // Handle egress data
        //

        // read from 'from' when: 'from' is ready, and buffers not full
        if ((pfds[2].fd == FD_READY) && cryptostream_encrypt_feed_canread(egress)) {
            int r = cryptostream_encrypt_feed_read(egress);
            if(r>0) { pfds[2].fd = egress->from_fd; }
            if(r==0) { pfds[2].fd = FD_EOF; }
            if(r<0) { had_error = 1; break; }
        }
        
        // write to 'to' when: 'to' is ready, and buffers not empty
        if ((pfds[3].fd == FD_READY) && cryptostream_encrypt_feed_canwrite(egress)) {
            if(cryptostream_encrypt_feed_write(egress)<0)
            { had_error = 1; break; }
            pfds[3].fd = egress->to_fd;
        }
        
        // close 'to' when: 'from' is EOF, and all buffers are empty
        if(pfds[2].fd == FD_EOF && pfds[3].fd != FD_EOF && !cryptostream_encrypt_feed_canwrite(egress)) {
            log_debug("egress is done; closing egress->to_fd (%d)", egress->to_fd);
            if(egress_to_fd_is_socket) {
                try(shutdown(egress->to_fd, SHUT_WR)) || oops_fatal("failed to shutdown socket");
            } else {
                try(close(egress->to_fd)) || oops_fatal("failed to close file descriptor");
            }
            pfds[3].fd = FD_EOF;
        }

        //
        // Handle ingress data
        //

        // read from 'from' when: 'from' is ready, and buffers not full
        if ((pfds[0].fd == FD_READY) && cryptostream_decrypt_feed_canread(ingress)) {
            int r = cryptostream_decrypt_feed_read(ingress);
            if(r>0) { pfds[0].fd = ingress->from_fd; }
            if(r==0) { pfds[0].fd = FD_EOF; }
            if(r<0) { had_error = 1; break; }
        }
        
        // write to 'to' when: 'to' is ready, and buffers not empty
        if ((pfds[1].fd == FD_READY) && cryptostream_decrypt_feed_canwrite(ingress)) {
            if(cryptostream_decrypt_feed_write(ingress)<0)
            { had_error = 1; break; }
            pfds[1].fd = ingress->to_fd;
        }
        
        
        // close 'to' when: 'from' is EOF, and all buffers are empty
        if(pfds[0].fd == FD_EOF && pfds[1].fd != FD_EOF && !cryptostream_decrypt_feed_canwrite(ingress)) {
            log_debug("ingress is done; closing ingress->to_fd (%d)", ingress->to_fd);
            if(ingress_to_fd_is_socket) {
                try(shutdown(ingress->to_fd, SHUT_WR)) || oops_fatal("failed to shutdown socket");
            } else {
                try(close(ingress->to_fd)) || oops_fatal("failed to close file descriptor");
            }
            pfds[1].fd = FD_EOF;
        }
    }

    // If we encountered an error, simply close all fds
    if(had_error) {
        close(ingress->from_fd);
        close(egress->to_fd);
        close(ingress->to_fd);
        close(egress->from_fd);
    }

    log_debug("all fds are closed [%d,%d,%d,%d]; done polling", ingress->from_fd, ingress->to_fd, egress->from_fd, egress->to_fd);
}
