//
//  saltunnel_mx_serial.c
//  saltunnel
//
//  1. Read from  egress->from_fd, encrypt, write to  egress->to_fd
//  2. Read from ingress->from_fd, decrypt, write to ingress->from_fd
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

static int fd_nonblock(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0)|O_NONBLOCK);
}

static int fd_issocket(int fd) {
    struct stat statbuf;
    if(fstat(fd, &statbuf)<0) return -1;
    return S_ISSOCK(statbuf.st_mode);
}

int exchange_messages_serial(cryptostream *ingress, cryptostream *egress) {

    int rc = 0;
    
    // Configure poll (we will poll both "readable" fds)
    struct pollfd pfds[] = {
        { .fd = ingress->from_fd, .events = POLLIN|POLLHUP },
        { .fd = ingress->to_fd,   .events = POLLOUT        },
        { .fd = egress->from_fd,  .events = POLLIN|POLLHUP },
        { .fd = egress->to_fd,    .events = POLLOUT        },
    };
    
    // Ensure all fds are non-blocking
    if(fd_nonblock(ingress->from_fd)<0 || fd_nonblock(ingress->to_fd)<0 ||
       fd_nonblock(egress->from_fd)<0  || fd_nonblock(egress->to_fd)<0)
    { rc = oops_sys("failed to set file descriptor as non-blocking"); goto cleanup; }
    
    // Determine if fds are sockets
    int ingress_to_fd_is_socket = fd_issocket(ingress->to_fd);
    int egress_to_fd_is_socket  = fd_issocket(egress->to_fd);
    if(ingress_to_fd_is_socket<0 || egress_to_fd_is_socket<0)
    { rc = oops_sys("failed to set determine whether file descriptor is a socket"); goto cleanup; }
    
    // Main Loop
    while(pfds[0].fd != FD_EOF || pfds[1].fd != FD_EOF || pfds[2].fd != FD_EOF || pfds[3].fd != FD_EOF) {
        
        /* Poll */
        log_trace("poll: polling [%2d->D->%2d, %2d->E->%2d]...", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);
        int r = poll(pfds,4,-1);
        if(r<0 && errno == EINTR) continue;
        if(r<0) { rc = oops_sys("failed to poll file descriptor"); goto cleanup; }

        /* If an fd is ready, mark it as FD_READY */
        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { pfds[0].fd = FD_READY; }
        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { pfds[1].fd = FD_READY; }
        if ((pfds[2].fd>=0) && (pfds[2].revents & (POLLIN|POLLHUP))) { pfds[2].fd = FD_READY; }
        if ((pfds[3].fd>=0) && (pfds[3].revents & (POLLOUT)))        { pfds[3].fd = FD_READY; }
        log_trace("poll: polled  [%2d->D->%2d, %2d->E->%2d].", pfds[0].fd, pfds[1].fd,pfds[2].fd, pfds[3].fd);

        /* Loud Version*/
//        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { log_trace("%d is ready to read from", pfds[0].fd); pfds[0].fd = FD_READY; }
//        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { log_trace("%d is ready to write to",  pfds[1].fd); pfds[1].fd = FD_READY; }
//        if ((pfds[2].fd>=0) && (pfds[2].revents & (POLLIN|POLLHUP))) { log_trace("%d is ready to read from", pfds[2].fd); pfds[2].fd = FD_READY; }
//        if ((pfds[3].fd>=0) && (pfds[3].revents & (POLLOUT)))        { log_trace("%d is ready to write to",  pfds[3].fd); pfds[3].fd = FD_READY; }
        

        //
        // Handle egress data
        //

        // read from 'from' when: 'from' is ready, and buffers not full
        if ((pfds[2].fd == FD_READY) && cryptostream_encrypt_feed_canread(egress)) {
            int r = cryptostream_encrypt_feed_read(egress);
            if(r>0) { pfds[2].fd = egress->from_fd; }
            if(r==0) { pfds[2].fd = FD_EOF; }
            if(r<0) { rc = -1; goto cleanup; }
        }
        
        // write to 'to' when: 'to' is ready, and buffers not empty
        if ((pfds[3].fd == FD_READY) && cryptostream_encrypt_feed_canwrite(egress)) {
            if(cryptostream_encrypt_feed_write(egress)<0)
            { rc = -1; goto cleanup; }
            pfds[3].fd = egress->to_fd;
        }
        
        // close 'to' when: 'from' is EOF, and all buffers are empty
        if(pfds[2].fd == FD_EOF && pfds[3].fd != FD_EOF && !cryptostream_encrypt_feed_canwrite(egress)) {
            log_trace("egress is done; closing egress->to_fd (%d)", egress->to_fd);
            if(egress_to_fd_is_socket) {
                shutdown(egress->to_fd, SHUT_WR);
            } else {
                if(close(egress->to_fd)<0) oops_warn_sys("failed to close file descriptor");
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
            if(r<0) { rc = -1; goto cleanup; }
        }
        
        // write to 'to' when: 'to' is ready, and buffers not empty
        if ((pfds[1].fd == FD_READY) && cryptostream_decrypt_feed_canwrite(ingress)) {
            if(cryptostream_decrypt_feed_write(ingress)<0)
            { rc = -1; goto cleanup; }
            pfds[1].fd = ingress->to_fd;
        }
        
        
        // close 'to' when: 'from' is EOF, and all buffers are empty
        if(pfds[0].fd == FD_EOF && pfds[1].fd != FD_EOF && !cryptostream_decrypt_feed_canwrite(ingress)) {
            log_trace("ingress is done; closing ingress->to_fd (%d)", ingress->to_fd);
            if(ingress_to_fd_is_socket) {
                shutdown(ingress->to_fd, SHUT_WR);
            } else {
                if(close(ingress->to_fd)<0) oops_warn_sys("failed to close file descriptor");
            }
            pfds[1].fd = FD_EOF;
        }
    }

    // Regardless of error or success, close all fds
    int errno_backup;
cleanup:
    errno_backup = errno;
    close(ingress->from_fd);
    close(egress->to_fd);
    close(ingress->to_fd);
    close(egress->from_fd);
    errno = errno_backup;

    log_trace("all fds are closed [%d,%d,%d,%d]; done polling", ingress->from_fd, ingress->to_fd, egress->from_fd, egress->to_fd);
    
    return rc<0 ? -1 : 0;
}
