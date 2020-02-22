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

static int fd_nonblock(int fd)
{
  return fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) | O_NONBLOCK);
}

static int enable_tcp_defer_accept(int socket_fd) {
#ifdef TCP_DEFER_ACCEPT
    int on = 1;
    try(setsockopt(s, SOL_SOCKET, TCP_DEFER_ACCEPT, &on, sizeof(int))) || return -1;
#endif
    return 0;
}

static int ignore_sigpipe() {
    return (signal(SIGPIPE, SIG_IGN) == SIG_ERR ? -1 : 1);
}

int tcpclient_new(const char* ip, const char* port, tcpclient_options options)
{
    // Resolve address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(ip);
    server_address.sin_port = htons(atoi(port));
    
    sa_endpoints_t endpoints = {0};
    endpoints.sae_dstaddr = (struct sockaddr *)&server_address;
    endpoints.sae_dstaddrlen = sizeof(server_address);
        
    // Open a socket
    int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s<0) return oops_warn("error creating socket");
    
    // Enable TCP_NODELAY
    if(options.OPT_TCP_NODELAY) {
        int historical_api_flag = 1;
        if(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &historical_api_flag, sizeof(int))<0)
            return oops_warn("error enabling TCP_NODELAY");
    }
    
    // Set send-low-water-mark
    if(options.OPT_SO_SNDLOWAT>0) {
        const int low_water_mark_bytes = options.OPT_SO_SNDLOWAT;
        if(setsockopt(s, SOL_SOCKET, SO_SNDLOWAT, &low_water_mark_bytes, sizeof(int))<0)
            return oops_warn("error setting SO_SNDLOWAT");
    }
    
    log_info("tcpclient_socket created, fd %d", s);
    
    // Connect using the socket
    for(;;) {
        int MAYBE_CONNECT_DATA_IDEMPOTENT = options.OPT_TCP_FASTOPEN ? 1 : 0;
        unsigned int connectx_options = CONNECT_RESUME_ON_READ_WRITE | MAYBE_CONNECT_DATA_IDEMPOTENT;
        if(connectx(s, &endpoints, SAE_ASSOCID_ANY, connectx_options, NULL, 0, NULL, NULL)<0) {
            if(options.OPT_RETRY_FOREVER && errno == ECONNREFUSED) {
                log_info("TCP client connection refused; trying again...");
                sleep(1);
                continue;
            }
            if(close(s)<0) oops_warn("failed to close TCP client connection");
            return oops_warn("error establishing connection to TCP server");
        }
        break;
    }
    
    // Make it non-blocking
    if(options.OPT_NONBLOCK) {
        if(fd_nonblock(s)<0)
            return oops_warn("failed setting fd as O_NONBLOCK");
    }
        
    return s;
}
