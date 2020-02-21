//
//  saltunnel_tcp_server.h
//  saltunnel
//
#include "oops.h"
#include "uint16.h"
#include "saltunnel.h"
#include "saltunnel_kx.h"
#include "saltunnel_tcp_server_forwarder.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


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

static int tcp_init(void) {
    return (signal(SIGPIPE, SIG_IGN) == SIG_ERR ? -1 : 1);
}


static int tcpclient_new(const char* ip, const char* port)
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
    if (s<0) return -1;
    
    // Enable TCP_NODELAY
    int historical_api_flag = 1;
    try(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &historical_api_flag, sizeof(int)))
    || oops_fatal("error enabling TCP_NODELAY");
    
    log_info("tcpclient_socket created, fd %d", s);
    
    // Connect using the socket
    if(connectx(s, &endpoints, SAE_ASSOCID_ANY,
                CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                NULL, 0, NULL, NULL)<0) {
        close(s); return -1;
    }
        
    return s;
}

static int tcpserver_new(const char* ip, const char* port)
{
    // Resolve address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(ip);
    server_address.sin_port = htons(atoi(port));
        
    // Open a socket
    int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    log_info("from_socket created, fd %d", s);
    if (s == -1) return -1;
    // Enable TCP_NODELAY
    int historical_api_flag = 1;
    try(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &historical_api_flag, sizeof(int)))
    || oops_fatal("error enabling TCP_NODELAY");
    // Enable TCP_DEFER_ACCEPT
    try(enable_tcp_defer_accept(s))
    || oops_fatal("error enabling TCP_DEFER_ACCEPT");
    // Enable SO_REUSEADDR (TODO: Do graceful shutdown via signal handler, etc.)
    int reuse_addr_opt = 1;
    try(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&reuse_addr_opt,sizeof(int)))
    || oops_fatal("error enabling SO_REUSEADDR");
    // Bind to a port
    if(bind(s, (struct sockaddr*) &server_address, sizeof(server_address)) < 0)
        oops_fatal("error binding");
    // Start listening for connections
    listen(s,1000);
    // Set SO_RCVLOWAT=512
    const int low_water_mark_bytes = 512;
    try(setsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &low_water_mark_bytes, sizeof(int)))
    || oops_fatal("error setting SO_RCLOWAT");
    // Enable TCP_FASTOPEN
    int enable_tcp_fastopen = 1;
    try(setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &enable_tcp_fastopen, sizeof(int)))
    || oops_fatal("enabling TCP_FASTOPEN");
    
    return s;
}

static int tcpserver_accept(int s) {
    // Accept a new connection
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    int fd_conn = accept(s, (struct sockaddr *) &client_address_len, &client_address_len);
    if(fd_conn<0) oops_fatal("error accepting connection");
    log_info("tcp_server from_socket connection created, fd %d", fd_conn);
    // Make it non-blocking
    if(fd_nonblock(fd_conn) == -1) { close(fd_conn); return -1; }
    return fd_conn;
}

typedef struct connection_thread_context {
    unsigned char* long_term_key;
    int fd_conn;
    const char* to_ip;
    const char* to_port;
    packet0 their_packet_zero;
    packet0 my_packet_zero;
    packet1 their_packet_one;
    packet1 my_packet_one;
} connection_thread_context;

static void* connection_thread(void* v)
{
    connection_thread_context* c = (connection_thread_context*)v;
    log_set_thread_name("conn");
    
    log_debug("connection thread entered");
    
//    if(saltunnel_kx_packet0_trywrite(long_term_key, c, &packet)<0)
//        return;
    
    free(v);
    return 0;
}

static pthread_t connection_thread_spawn(unsigned char* long_term_key,
                                         int fd_conn, packet0* their_packet_zero,
                                         const char* to_ip, const char* to_port)
{
    connection_thread_context* c = calloc(1,sizeof(connection_thread_context));
    log_info("handling connection");
    
    c->long_term_key = long_term_key;
    c->fd_conn = fd_conn;
    c->to_ip = to_ip;
    c->to_port = to_port;
    memcpy(&c->their_packet_zero, their_packet_zero, sizeof(packet0));
    
    pthread_t thread;
    if(pthread_create(&thread, NULL, connection_thread, (void*)c)!=0) {
        oops_warn("failed to spawn thread");
        return 0;
    }
    return thread;
}

static int maybe_handle_connection(unsigned char* long_term_key,
                                   int fd_conn,
                                   const char* to_ip, const char* to_port) {
    log_info("maybe handling connection");
    // Read packet0
    packet0 packet_zero = {0};
    if(saltunnel_kx_packet0_tryread(long_term_key, fd_conn, &packet_zero)<0)
    return oops_warn("failed to read packet0");
    // If it succeeded, handle the connection
    pthread_t thread = connection_thread_spawn(long_term_key, fd_conn, &packet_zero, to_ip, to_port);
    if(thread==0) return -1;
    else return 1;
}

int saltunnel_tcp_server_forwarder(const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
    
    // Input Long-term Key (For now, just hard-coding to [0..31])
    unsigned char long_term_key[32] = {0};
    for(int i = 0; i<32;  i++)
        long_term_key[i] = i;
    
    // Init TCP Listener
    try(tcp_init()) || oops_fatal("initializing tcp settings");
    
    // Create socket
    int s = tcpserver_new(from_ip, from_port);
    if(s<0) oops_fatal("error creating socket");
    
    // Listen for new connections
    log_info("waiting for connections on %s:%s", from_ip, from_port);
    for(;;) {
        // Accept a new connection
        int fd_conn = tcpserver_accept(s);
        if(fd_conn<0) oops_fatal("accepting connection");
        
        // Handle the connection
        if(maybe_handle_connection(long_term_key, fd_conn, to_ip,to_port)<0) {
            try(close(fd_conn)) || oops_fatal("failed to close connection");
        }
    }
    
    
    return s;
}
