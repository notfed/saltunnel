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

static int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned int timeout_ms) {
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
                    struct pollfd pfds[] = { { .fd = sockfd, .events = POLLOUT } };
                    rc = poll(pfds, 1, ms_until_deadline);
                    // Find out whether the connection failed or succeeded.
                    int error = 0; socklen_t len = sizeof(error);
                    int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                    if(retval==0) errno = error;
                    if(error!=0) rc=-1;
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

static int cleanup_then_oops_sys(int socket, const char* warning) {
    int e = errno;
    close(socket);
    errno = e;
    return oops_sys(warning);
}

int tcpclient_new(const char* ip, const char* port, tcpclient_options options)
{
    // Resolve address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(ip);
    server_address.sin_port = htons(atoi(port));
    
    // Open a socket
    int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s<0) return cleanup_then_oops_sys(s, "failed to create TCP client socket");
    
    // Enable TCP_NODELAY
    if(options.OPT_TCP_NODELAY) {
        int historical_api_flag = 1;
        if(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &historical_api_flag, sizeof(int))<0)
            return cleanup_then_oops_sys(s, "failed to enable TCP_NODELAY on TCP client socket");
    }
    
    // Set SO_SNDLOWAT
    if(options.OPT_SO_SNDLOWAT>0) {
        const int low_water_mark_bytes = options.OPT_SO_SNDLOWAT;
        if(setsockopt(s, SOL_SOCKET, SO_SNDLOWAT, &low_water_mark_bytes, sizeof(int))<0)
            log_debug("could not set SO_SNDLOWAT on TCP client socket"); // "Not changeable on Linux"
    }
    
    // Connect using the socket
    if(options.OPT_CONNECT_TIMEOUT>0) {
        if(connect_with_timeout(s, (struct sockaddr*)&server_address, sizeof(server_address), options.OPT_CONNECT_TIMEOUT)<0)
            return cleanup_then_oops_sys(s, "failed to connect to destination address");
    } else {
        if(connect(s, (struct sockaddr*)&server_address, sizeof(server_address))<0)
            return cleanup_then_oops_sys(s, "failed to connect to destination address");
    }
    
    // Make it non-blocking
    if(options.OPT_NONBLOCK) {
        if(fd_unblock(s)<0)
            return cleanup_then_oops_sys(s, "failed to set set O_NONBLOCK on TCP client socket");
    }

    return s;
}
