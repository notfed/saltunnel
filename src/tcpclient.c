//
//  tcpclient.c
//  saltunnel
//

#include "tcpclient.h"
#include "oops.h"
#include "math.h"

#include <signal.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>

static int connect_with_cancellable_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
                                            unsigned int timeout_ms, int cancel_fd) {
    int rc = 0;
    
    // Set O_NONBLOCK
    int sockfd_flags_before;
    if((sockfd_flags_before=fcntl(sockfd,F_GETFL,0)<0)) return -1;
    if(fcntl(sockfd,F_SETFL,sockfd_flags_before | O_NONBLOCK)<0) return -1;
    // This one-time 'loop' just lets us 'break' to get out of it
    do {
        // Start connecting (asynchronously)
        if (connect(sockfd, addr, addrlen)<0) {
            // Did connect return an error? If so, we'll fail.
            if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
                rc = -1;
            }
            // Otherwise, asynchronous connect has begun
            // We'll now wait for one of (A) timeout expired, or (B) cancel_fd closed, or (C) connection completed.
            else {
                // Set a deadline timestamp 'timeout' ms from now. (Needed b/c poll can be interrupted.)
                struct timespec now;
                if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                struct timespec deadline = { .tv_sec = now.tv_sec,
                                             .tv_nsec = now.tv_nsec + timeout_ms*1000000l};
                // We'll repeatedly poll in 500ms intervals. (Needed b/c poll won't detect POLLHUP if it happens during poll.)
                do {
                    // Calculate how long until the deadline
                    if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                    int ms_until_deadline = (int)(  (deadline.tv_sec  - now.tv_sec)*1000l
                                                  + (deadline.tv_nsec - now.tv_nsec)/1000000l);
                    // (A) If the timeout has expired, exit.
                    if(ms_until_deadline<0) { rc=0; break; }
                    // Perform the poll
                    struct pollfd pfds[] = { { .fd = sockfd,    .events = POLLHUP|POLLERR|POLLOUT },
                                             { .fd = cancel_fd, .events = POLLHUP|POLLERR } };
                    rc = poll(pfds, 2, MIN(ms_until_deadline+1,500));
                    // (B) If the cancel_fd has a POLLHUP or POLLERR, exit.
                    if(rc>0 && pfds[1].revents>0) {
                        errno = ECONNRESET;
                        rc = -1;
                    }
                    // (C) If the connection has completed, check to see whether it succeeded or failed, then exit.
                    else if(rc>0 && pfds[0].revents>0) {
                        int error = 0; socklen_t len = sizeof(error);
                        int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                        if(retval==0) errno = error;
                        if(error!=0) rc=-1;
                    }
                }
                // If poll had a 500ms-timeout, keep going.
                while(rc==0);
                // Did poll timeout? If so, fail.
                if(rc==0) {
                    errno = ETIMEDOUT;
                    rc = -1;
                }
            }
        }
    } while(0);
    // Restore original O_NONBLOCK state
    if(fcntl(sockfd,F_SETFL,sockfd_flags_before)<0) return -1;
    // Success
    return rc;
}

static int fd_unblock(int sockfd) { return fcntl(sockfd,F_SETFL,fcntl(sockfd,F_GETFL,0) | O_NONBLOCK); }

static int tcpclient_new_inner(int s, const tcpclient_options *options, struct addrinfo *server_address) {
    // Enable TCP_NODELAY
    if(options->OPT_TCP_NODELAY) {
        int historical_api_flag = 1;
        if(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &historical_api_flag, sizeof(int))<0)
            return oops_sys("failed to enable TCP_NODELAY on TCP client socket");
    }
    
    // Set SO_SNDLOWAT
    if(options->OPT_SO_SNDLOWAT>0) {
        const int low_water_mark_bytes = options->OPT_SO_SNDLOWAT;
        if(setsockopt(s, SOL_SOCKET, SO_SNDLOWAT, &low_water_mark_bytes, sizeof(int))<0)
            log_debug("could not set SO_SNDLOWAT on TCP client socket"); // "Not changeable on Linux"
    }
    
    // Connect using the socket
    unsigned int timeout = (options->OPT_CONNECT_TIMEOUT>0 ? options->OPT_CONNECT_TIMEOUT : 3600000);
    int cancel_fd = (options->OPT_CANCELLABLE_CONNECT?options->OPT_CONNECT_CANCEL_FD:-1);
    if(connect_with_cancellable_timeout(s, server_address->ai_addr, server_address->ai_addrlen, timeout, cancel_fd)<0)
    { return oops_sys("failed to connect to destination address"); }
    
    // Make it non-blocking
    if(options->OPT_NONBLOCK) {
        if(fd_unblock(s)<0)
            return oops_sys("failed to set set O_NONBLOCK on TCP client socket");
    }
    return 0;
}

void cleanup_close(void* v) { int s = *(int*)(v); if(s>=0) close(s); }
void cleanup_freeaddrinfo(void* ai) { if(ai) freeaddrinfo(ai); }

int tcpclient_new(const char* ip, const char* port, tcpclient_options options)
{
    int s = -1;
    int rc = -1;
    
    // Resolve address
    struct addrinfo hints = { .ai_family = AF_INET,       .ai_socktype=SOCK_STREAM,
                              .ai_protocol = IPPROTO_TCP, .ai_flags=AI_CANONNAME };
    struct addrinfo* server_address = 0;
    if (getaddrinfo(ip, port, &hints, &server_address)!=0) {
        errno = EHOSTUNREACH; // Why is there no 'Unknown host' errno?
        return oops("failed to resolve ip address of hostname");
    }
    
    // Set a cleanup handler to call freeaddrinfo
    pthread_cleanup_push(cleanup_freeaddrinfo, server_address);
    
    // Open a socket
    s = socket(server_address->ai_family, server_address->ai_socktype, server_address->ai_protocol);
    if (s<0) {
        oops_sys("failed to create TCP client socket");
    }
    
    // Set a cleanup handler to close the socket
    pthread_cleanup_push(cleanup_close, &s);
    
    // Connect the socket to the destination endpoint
    if(s>=0)
        rc = tcpclient_new_inner(s, &options, server_address);
    
    // Only close the socket if an error occurred
    pthread_cleanup_pop(rc<0);
    
    // Regardless of success or failure, call freeaddrinfo
    pthread_cleanup_pop(1);

    return rc<0 ? -1 : s;
}
