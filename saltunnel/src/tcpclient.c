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

int fd_block(int sockfd) { return fcntl(sockfd,F_SETFL,fcntl(sockfd,F_GETFL,0) & ~O_NONBLOCK); }
int fd_unblock(int sockfd) { return fcntl(sockfd,F_SETFL,fcntl(sockfd,F_GETFL,0) | O_NONBLOCK); }

static int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned int timeout) {
    int rc = 0;
    // Set O_NONBLOCK
    if(fcntl(sockfd,F_SETFL,fcntl(sockfd,F_GETFL,0) | O_NONBLOCK)<0) return -1;
    // Start connecting
    if (connect(sockfd, addr, addrlen)<0) {
        // Did connect return an error? If so, fail.
        if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
            rc = -1;
        }
        // Did connect begin connecting?
        else {
            // Wait for connect to complete
            struct pollfd pfds[] = { { .fd = sockfd, .events = POLLOUT } };
            rc = poll(pfds, 1, timeout);
            // Did poll timeout? If so, fail.
            if(rc==0) {
                close(sockfd);
                errno = ETIMEDOUT;
                return -1;
            }
        }
    }
    // Unset O_NONBLOCK
    if(fcntl(sockfd,F_SETFL,fcntl(sockfd,F_GETFL,0) & ~O_NONBLOCK)<0) return -1;
    // Success
    return rc;
}

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
    if(connect_with_timeout(s, (struct sockaddr*)&server_address, sizeof(server_address), options.OPT_CONNECT_TIMEOUT)<0)
        return cleanup_then_oops_sys(s, "failed to connect to TCP server");
    
    // Make it non-blocking
    if(options.OPT_NONBLOCK) {
        if(fd_unblock(s)<0)
            return cleanup_then_oops_sys(s, "failed to set set O_NONBLOCK on TCP client connection");
    }

    return s;
}
