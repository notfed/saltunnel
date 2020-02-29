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
    int remote_fd;
    const char* to_ip;
    const char* to_port;
    packet0 their_packet_zero;
} connection_thread_context;

static void* connection_thread(void* v)
{
    connection_thread_context* c = (connection_thread_context*)v;
    log_set_thread_name(" sf ");
    
    log_info("connection thread entered");

    // Create a TCP Client
    tcpclient_options options = {
     .OPT_TCP_NODELAY = 1,
//     .OPT_TCP_FASTOPEN = 1, // This will only work if the root-originating-client writes first. Make this an option.
//     .OPT_SO_SNDLOWAT = 512
    };
    log_info("(SERVER FORWARDER) ABOUT TO CONNECT TO %s:%s", c->to_ip, c->to_port);
    
    int local_fd = tcpclient_new(c->to_ip, c->to_port, options);
    if(local_fd<0)
    { oops_warn("!!!!!!!!!!!!!!! failed to create TCP client connection"); return 0; }
    
    // Write packet0
    unsigned char my_sk[32];
    if(saltunnel_kx_packet0_trywrite(c->long_term_key, c->remote_fd, my_sk)<0)
    { close(local_fd); oops_warn("failed to write packet0"); return 0; }
    
    log_info("(SERVER FORWARDER) SUCCESSFULLY CONNECTED TO %s:%s", c->to_ip, c->to_port);
    
    log_info("server forwarder successfully wrote packet0");
    
    // Exchange packet1
    
    // TODO: Exchange single packet to completely prevent replay attacks
    
    
    // Calculate shared key
    unsigned char session_key[32];
    if(saltunnel_kx_calculate_shared_key(session_key, c->their_packet_zero.pk, my_sk)<0)
    { close(local_fd); oops_warn("failed to calculate shared key"); return 0; }
    
    log_info("calculated shared key");
    
    // Run saltunnel
    cryptostream ingress = {
        .from_fd = c->remote_fd,
        .to_fd = local_fd
    };
    cryptostream egress = {
        .from_fd = local_fd,
        .to_fd = c->remote_fd
    };
    log_info("running saltunnel");
    log_info("server forwarder [%2d->D->%2d, %2d->E->%2d]...", ingress.from_fd, ingress.to_fd, egress.from_fd, egress.to_fd);
    saltunnel(&ingress, &egress);
    
    free(v);
    return 0;
}

static pthread_t connection_thread_spawn(unsigned char* long_term_key,
                                         int remote_fd, packet0* their_packet_zero,
                                         const char* to_ip, const char* to_port)
{
    connection_thread_context* c = calloc(1,sizeof(connection_thread_context));
    log_info("handling connection");
    
    c->long_term_key = long_term_key;
    c->remote_fd = remote_fd;
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
                                   int remote_fd,
                                   const char* to_ip, const char* to_port) {
    log_info("maybe handling connection");
    
    // Read packet0
    packet0 packet_zero = {0};
    if(saltunnel_kx_packet0_tryread(long_term_key, remote_fd, &packet_zero)<0)
        return oops_warn("failed to read packet0");
    
    log_info("server forwarder successfully read packet0");
    
    // If it succeeded, handle the connection
    pthread_t thread = connection_thread_spawn(long_term_key, remote_fd, &packet_zero, to_ip, to_port);
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
    if(s<0)
        return oops_warn("error creating socket");
    
    for(;;) {
        log_info("(SERVER FORWARDER) WAITING FOR ACCEPT ON %s:%s", from_ip, from_port);
        
        // Accept a new connection (or wait for one to arrive)
        int remote_fd = tcpserver_accept(s);
        if(remote_fd<0) {
            log_warn("failed to accept connection");
            sleep(1); errno = 0;
            continue;
        }
        
        log_info("(SERVER FORWARDER) ACCEPTED ON %s:%s", from_ip, from_port);

        // Handle the connection
        if(maybe_handle_connection(long_term_key, remote_fd, to_ip, to_port)<0) {
            try(close(remote_fd)) || log_warn("failed to close connection");
            log_warn("encountered error with TCP connection");
        }
    }
    
    
    return s;
}
