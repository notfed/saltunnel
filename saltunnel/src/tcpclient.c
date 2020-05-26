//
//  tcpclient.c
//  saltunnel
//

#include "tcpclient.h"
#include "oops.h"

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

// TODO: Accept an extra "cancellation_fd" which we'll also watch for POLLHUP
static int connect_with_cancellable_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
                                            unsigned int timeout_ms, int cancel_fd) {
    int rc = 0;
    // Set O_NONBLOCK
    int sockfd_flags_before;
    if((sockfd_flags_before=fcntl(sockfd,F_GETFL,0)<0)) return -1;
    if(fcntl(sockfd,F_SETFL,sockfd_flags_before | O_NONBLOCK)<0) return -1;
    // Start connecting (asynchronously)
    do {
        if (connect(sockfd, addr, addrlen)<0) {
            // Did connect return an error? If so, we'll fail.
            if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
                rc = -1;
            }
            // Otherwise, we'll wait for it to complete.
            else {
                // Set a deadline timestamp 'timeout' ms from now (needed b/c poll can be interrupted)
                struct timespec now;
                if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                struct timespec deadline = { .tv_sec = now.tv_sec,
                                             .tv_nsec = now.tv_nsec + timeout_ms*1000000l};
                // Wait for the connection to complete.
                do {
                    // Calculate how long until the deadline
                    if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                    int ms_until_deadline = (int)(  (deadline.tv_sec  - now.tv_sec)*1000l
                                                  + (deadline.tv_nsec - now.tv_nsec)/1000000l);
                    if(ms_until_deadline<0) { rc=0; break; }
                    // Wait for connect to complete (or for the timeout deadline)
                    struct pollfd pfds[] = { { .fd = sockfd, .events = POLLOUT },
                                             { .fd = cancel_fd, .events = POLLHUP } };
                    rc = poll(pfds, 1, ms_until_deadline); // TODO: Need to interrupt when client disconnects
                    // If poll 'succeeded', make sure it *really* succeeded
                    if(rc>0) {
                        int error = 0; socklen_t len = sizeof(error);
                        int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                        if(retval==0) errno = error;
                        if(error!=0) rc=-1;
                    }
                }
                // If poll was interrupted, try again.
                while(rc==-1 && errno==EINTR);
                // Did poll timeout? If so, fail.
                if(rc==0) {
                    errno = ETIMEDOUT;
                    rc=-1;
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

static int cleanup_then_oops_sys(int socket, const char* warning, struct addrinfo* server_address) {
    int e = errno;
    close(socket);
    freeaddrinfo(server_address);
    errno = e;
    return oops_sys(warning);
}

int tcpclient_new(const char* ip, const char* port, tcpclient_options options)
{
    // Resolve address
    struct addrinfo hints = { .ai_family = AF_INET,       .ai_socktype=SOCK_STREAM,
                              .ai_protocol = IPPROTO_TCP, .ai_flags=AI_CANONNAME };
    struct addrinfo* server_address;
    if (getaddrinfo(ip, port, &hints, &server_address)!=0) {
        errno = EHOSTUNREACH; // Why is there no 'Unknown host' errno?
        return oops("failed to resolve ip address of hostname");
    }
    
    // Open a socket
    int s = socket(server_address->ai_family, server_address->ai_socktype, server_address->ai_protocol);
    if (s<0) return cleanup_then_oops_sys(s, "failed to create TCP client socket", server_address);
    
    // Enable TCP_NODELAY
    if(options.OPT_TCP_NODELAY) {
        int historical_api_flag = 1;
        if(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &historical_api_flag, sizeof(int))<0)
            return cleanup_then_oops_sys(s, "failed to enable TCP_NODELAY on TCP client socket", server_address);
    }
    
    // Set SO_SNDLOWAT
    if(options.OPT_SO_SNDLOWAT>0) {
        const int low_water_mark_bytes = options.OPT_SO_SNDLOWAT;
        if(setsockopt(s, SOL_SOCKET, SO_SNDLOWAT, &low_water_mark_bytes, sizeof(int))<0)
            log_debug("could not set SO_SNDLOWAT on TCP client socket"); // "Not changeable on Linux"
    }
    
    // Connect using the socket
    if(options.OPT_CONNECT_TIMEOUT>0) {
        if(connect_with_timeout(s, server_address->ai_addr, server_address->ai_addrlen, options.OPT_CONNECT_TIMEOUT)<0)
            return cleanup_then_oops_sys(s, "failed to connect to destination address", server_address);
    } else {
        if(connect(s, server_address->ai_addr, server_address->ai_addrlen)<0) {
            return cleanup_then_oops_sys(s, "failed to connect to destination address", server_address);
        }
    }
    
    // Free the address
    freeaddrinfo(server_address);
    
    // Make it non-blocking
    if(options.OPT_NONBLOCK) {
        if(fd_unblock(s)<0)
            return cleanup_then_oops_sys(s, "failed to set set O_NONBLOCK on TCP client socket", server_address);
    }

    return s;
}
