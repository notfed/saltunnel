//
//  saltunnel_tcp_server.h
//  saltunnel
//
#include "oops.h"
#include "uint16.h"
#include "saltunnel.h"
#include "saltunnel_kx.h"
#include "saltunnel_tcp_server_forwarder.h"
#include "tcpserver.h"
#include "tcpclient.h"
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
    
    log_info("saltunnel_tcp_server_forwarder about to write packet0");
    
    // Write packet0
    unsigned char my_sk[32];
    if(saltunnel_kx_packet0_trywrite(c->long_term_key, c->fd_conn, my_sk)<0)
    { oops_warn("failed to write packet0"); return 0; }
    
    log_info("saltunnel_tcp_server_forwarder wrote packet0 !!!!!!!!!!!!");
    
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
    
    // Create socket
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1,
     .OPT_TCP_DEFER_ACCEPT = 1,
     .OPT_TCP_FASTOPEN = 1,
     .OPT_SO_RCVLOWAT = 512
    };
    int s = tcpserver_new(from_ip, from_port, options);
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
