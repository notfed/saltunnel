//
//  tcpserver.c
//  saltunnel
//

#include "tcpserver.h"
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
    if(setsockopt(socket_fd, SOL_SOCKET, TCP_DEFER_ACCEPT, &on, sizeof(int))<0) 
        return -1;
#endif
    return 0; // Not available on OS X
}

static int ignore_sigpipe() {
    return (signal(SIGPIPE, SIG_IGN) == SIG_ERR ? -1 : 1);
}

static int cleanup_oops_warn(int socket, const char* warning) {
    close(socket);
    return oops_warn(warning);
}

int tcpserver_new(const char* ip, const char* port, tcpserver_options options)
{
    // Ignore SIGPIPE
    if(ignore_sigpipe()<0)
        return oops_warn("failed to set signal handler to ignore SIGPIPE");
    
    // Resolve address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(ip);
    server_address.sin_port = htons(atoi(port));
        
    // Open a socket
    int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == -1)
        return oops_warn("failed to create TCP server socket");
    
    log_info("from_socket created, fd %d", s);
    
    // Enable O_NONBLOCK
    if(options.OPT_NONBLOCK) {
        if(fd_nonblock(s)<0)
            return cleanup_oops_warn(s, "failed to enable O_NONBLOCK on TCP server socket");
    }
    
    // Enable TCP_NODELAY
    if(options.OPT_TCP_NODELAY) {
        int historical_api_flag = 1;
        if(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &historical_api_flag, sizeof(int))<0)
            return cleanup_oops_warn(s, "failed to enable TCP_NODELAY on TCP server socket");
    }
    
    // Enable TCP_DEFER_ACCEPT
    if(options.OPT_TCP_DEFER_ACCEPT) {
        if(enable_tcp_defer_accept(s)<0)
            return cleanup_oops_warn(s, "failed to enable TCP_DEFER_ACCEPT on TCP server socket");
    }
    
    // Enable SO_REUSEADDR
    if(options.OPT_SO_REUSEADDR) {
        int reuse_addr_opt = 1;
        if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&reuse_addr_opt,sizeof(int))<0)
            return cleanup_oops_warn(s, "failed to enable SO_REUSEADDR TCP server socket");
    }
    
    // Bind to a port
    if(bind(s, (struct sockaddr*) &server_address, sizeof(server_address))<0)
        return cleanup_oops_warn(s, "failed to bind TCP server socket to address");
    
    // Start listening for connections
    if(listen(s,1000)<0)
        return cleanup_oops_warn(s, "failed to start listening for connections on TCP server socket");
    
    // Set receive-low-water-mark
    if(options.OPT_SO_RCVLOWAT>0) {
        const int low_water_mark_bytes = options.OPT_SO_RCVLOWAT;
        if(setsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &low_water_mark_bytes, sizeof(int))<0)
            return cleanup_oops_warn(s, "failed to set SO_RCVLOWAT on TCP server socket");
    }
   
    // Enable TCP_FASTOPEN
    if(options.OPT_TCP_FASTOPEN>0) {
        int enable_tcp_fastopen = 1;
        if(setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &enable_tcp_fastopen, sizeof(int))<0)
            return cleanup_oops_warn(s, "failed to enable TCP_FASTOPEN on TCP server socket");
    }
    
    return s;
}

int tcpserver_accept(int s) {
    // Accept a new connection
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    int fd_conn = accept(s, (struct sockaddr *) &client_address, &client_address_len);
    if(fd_conn<0)
        return oops_warn("failed to accept new connection from TCP server socket");
    log_info("tcp_server from_socket connection created, fd %d", fd_conn);
    return fd_conn;
}

int tcpserver_accept_nonblock(int s) {
    // Accept a new connection
    int fd_conn = tcpserver_accept(s);
    if(fd_conn<0)
      return -1;
    
    // Make it non-blocking
    if(fd_nonblock(fd_conn)<0) {
        if(close(fd_conn)<0) oops_warn("failed to close TCP server connection");
        return oops_warn("failed to set connection file descriptor as non-blocking");
    }
    
    return fd_conn;
}
