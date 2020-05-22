//
//  saltunnel_mx_parallel.c
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
#include <time.h>

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

typedef struct {
    cryptostream *ingress;
    int ingress_rc;
    int ingress_errno;
    struct timespec ingress_exit_timestamp;
    cryptostream *egress;
    int egress_rc;
    int egress_errno;
    struct timespec egress_exit_timestamp;
} exchange_messages_thread_context;

void* exchange_messages_egress(void* ctx_void) {
    
    int rc = 0;
    
    exchange_messages_thread_context* ctx = (exchange_messages_thread_context*)ctx_void;
    cryptostream* egress = ctx->egress;

    // Configure poll (we will poll both "readable" fds)
    struct pollfd pfds[] = {
        { .fd = egress->from_fd,  .events = POLLIN|POLLHUP },
        { .fd = egress->to_fd,    .events = POLLOUT        },
    };
    
    // Ensure all fds are non-blocking
    if(fd_nonblock(egress->from_fd)<0  || fd_nonblock(egress->to_fd)<0)
    { rc = oops_sys("failed to set file descriptor as non-blocking"); goto cleanup; }
    
    // Determine if fds are sockets
    int egress_to_fd_is_socket  = fd_issocket(egress->to_fd);
    if(egress_to_fd_is_socket<0 )
    { rc = oops_sys("failed to set determine whether file descriptor is a socket"); goto cleanup; }

    // Main Loop
    while(pfds[0].fd != FD_EOF || pfds[1].fd != FD_EOF) {
        
        /* Poll */
        log_trace("poll: polling [%2d->D->%2d]...", pfds[0].fd, pfds[1].fd);
        int r = poll(pfds,2,-1);
        if(r<0 && errno == EINTR) continue;
        if(r<0) { rc = oops_sys("failed to poll file descriptor"); goto cleanup; }
        
        log_trace("poll: polled  [%2d->D->%2d].", pfds[0].fd, pfds[1].fd);
        
        /* If an fd is ready, mark it as FD_READY */
        
        /* Loud Version*/
//        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { log_trace("%d is ready to read from", pfds[0].fd); pfds[0].fd = FD_READY; }
//        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { log_trace("%d is ready to write to",  pfds[1].fd); pfds[1].fd = FD_READY; }
//
        /* Quiet Version */
        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { pfds[0].fd = FD_READY; }
        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { pfds[1].fd = FD_READY; }
//
        //
        // Handle egress data
        //

        // read from 'from' when: 'from' is ready, and buffers not full
        if ((pfds[0].fd == FD_READY) && cryptostream_encrypt_feed_canread(egress)) {
            int r = cryptostream_encrypt_feed_read(egress);
            if(r>0) { pfds[0].fd = egress->from_fd; }
            if(r==0) { pfds[0].fd = FD_EOF; }
            if(r<0) { rc = -1; goto cleanup; }
        }
        
        // write to 'to' when: 'to' is ready, and buffers not empty
        if ((pfds[1].fd == FD_READY) && cryptostream_encrypt_feed_canwrite(egress)) {
            if(cryptostream_encrypt_feed_write(egress)<0)
            { rc = -1; goto cleanup; }
            pfds[1].fd = egress->to_fd;
        }
        
        // close 'to' when: 'from' is EOF, and all buffers are empty
        if(pfds[0].fd == FD_EOF && pfds[1].fd != FD_EOF && !cryptostream_encrypt_feed_canwrite(egress)) {
            log_trace("egress is done; closing egress->to_fd (%d)", egress->to_fd);
            if(egress_to_fd_is_socket) {
                if(shutdown(egress->to_fd, SHUT_WR)<0) oops_warn_sys("failed to shutdown socket");
            } else {
                if(close(egress->to_fd)<0) oops_warn_sys("failed to close file descriptor");
            }
            pfds[1].fd = FD_EOF;
        }

    }

cleanup:
    ctx->egress_errno = errno;
    ctx->egress_rc = rc;
    close(ctx->egress->to_fd);
    close(ctx->egress->from_fd);
    if(rc<0) {
        clock_gettime(CLOCK_MONOTONIC, &ctx->egress_exit_timestamp);
        close(ctx->ingress->from_fd);
        close(ctx->ingress->to_fd);
    }

    log_trace("all fds are closed [%d,%d,%d,%d]; done polling", ctx->ingress->from_fd, ctx->ingress->to_fd, ctx->egress->from_fd, ctx->egress->to_fd);
    
    return 0;
}

void* exchange_messages_ingress(void* ctx_void) {
    
    int rc = 0;
    
    exchange_messages_thread_context* ctx = (exchange_messages_thread_context*)ctx_void;
    cryptostream* ingress = ctx->ingress;
    
    // Configure poll (we will poll both "readable" fds)
    struct pollfd pfds[] = {
        { .fd = ingress->from_fd, .events = POLLIN|POLLHUP },
        { .fd = ingress->to_fd,   .events = POLLOUT        },
    };
    
    // Ensure all fds are non-blocking
    if(fd_nonblock(ingress->from_fd)<0  || fd_nonblock(ingress->to_fd)<0)
    { rc = oops_sys("failed to set file descriptor as non-blocking"); goto cleanup; }
    
    // Determine if fds are sockets
    int ingress_to_fd_is_socket  = fd_issocket(ingress->to_fd);
    if(ingress_to_fd_is_socket<0 )
    { rc = oops_sys("failed to set determine whether file descriptor is a socket"); goto cleanup; }
    
    // Main Loop
    while(pfds[0].fd != FD_EOF || pfds[1].fd != FD_EOF) {
        /* Poll */
        log_trace("poll: polling [%2d->D->%2d]...", pfds[0].fd, pfds[1].fd);
        try(poll(pfds,2,-1)) || oops_error_sys("failed to poll");
        log_trace("poll: polled  [%2d->D->%2d].", pfds[0].fd, pfds[1].fd);
        
        /* If an fd is ready, mark it as FD_READY */
        
        /* Loud Version*/
//        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { log_trace("%d is ready to read from", pfds[0].fd); pfds[0].fd = FD_READY; }
//        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { log_trace("%d is ready to write to",  pfds[1].fd); pfds[1].fd = FD_READY; }
//
        /* Quiet Version */
        if ((pfds[0].fd>=0) && (pfds[0].revents & (POLLIN|POLLHUP))) { pfds[0].fd = FD_READY; }
        if ((pfds[1].fd>=0) && (pfds[1].revents & (POLLOUT)))        { pfds[1].fd = FD_READY; }

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
                if(shutdown(ingress->to_fd, SHUT_WR)<0) oops_warn_sys("failed to shutdown socket");
            } else {
                if(close(ingress->to_fd)<0) oops_warn_sys("failed to close file descriptor");
            }
            pfds[1].fd = FD_EOF;
        }
    }

cleanup:
    ctx->ingress_errno = errno;
    ctx->ingress_rc = rc;
    close(ctx->ingress->from_fd);
    close(ctx->ingress->to_fd);
    if(rc<0) {
        clock_gettime(CLOCK_MONOTONIC, &ctx->ingress_exit_timestamp);
        close(ctx->egress->to_fd);
        close(ctx->egress->from_fd);
    }
    
    log_trace("all fds are closed [%d,%d,%d,%d]; done polling", 
              ctx->ingress->from_fd, ctx->ingress->to_fd, ctx->egress->from_fd, ctx->egress->to_fd);
    return 0;
}

static int timespec_lt(struct timespec* lhs, struct timespec* rhs)
{
    if (lhs->tv_sec == rhs->tv_sec)
        return lhs->tv_nsec < rhs->tv_nsec;
    else
        return lhs->tv_sec < rhs->tv_sec;
}

int exchange_messages_parallel(cryptostream *ingress, cryptostream *egress) {
    exchange_messages_thread_context ctx = {0};
    ctx.ingress = ingress;
    ctx.egress = egress;

    pthread_t egress_thread;
    pthread_t ingress_thread;
    
    pthread_create(&egress_thread, NULL, exchange_messages_egress, (void*)&ctx)==0
    || oops_error_sys("failed to create thread");
    
    pthread_create(&ingress_thread, NULL, exchange_messages_ingress, (void*)&ctx)==0
    || oops_error_sys("failed to create thread");
    
    pthread_join(egress_thread, NULL)==0
    || oops_error_sys("failed to join thread");
    
    pthread_join(ingress_thread, NULL)==0
    || oops_error_sys("failed to join thread");
    
    // If both threads had an error, determine which one did first and return its errno
    if(ctx.ingress_errno<0 && ctx.egress_errno<0
       && ctx.ingress_exit_timestamp.tv_sec !=0 && ctx.egress_exit_timestamp.tv_sec !=0)
    {
        if(timespec_lt(&ctx.ingress_exit_timestamp, &ctx.egress_exit_timestamp))
        { errno = ctx.ingress_errno; return -1; }
        else
        { errno = ctx.egress_errno; return -1; }
    }
    // If one thread had an error, return its errno
    else if(ctx.ingress_errno<0) { errno = ctx.ingress_errno; return -1; }
    else if(ctx.egress_errno<0) { errno = ctx.egress_errno; return -1; }
    // Graceful shutdown
    else return 0;
}
