//
//  saltunnel_tcp_client_forwarder.c
//  saltunnel
//

#include "oops.h"
#include "uint16.h"
#include "saltunnel.h"
#include "saltunnel_kx.h"
#include "saltunnel_tcp_client_forwarder.h"
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
#include <sys/mman.h>

typedef struct connection_thread_context {
    unsigned char long_term_shared_key[32];
    unsigned char session_secret_key[32];
    unsigned char session_shared_key[32];
    int local_fd;
    const char* remote_ip;
    const char* remote_port;
} connection_thread_context;

static void* connection_thread_cleanup(void* ctx, int fd) {
    memset(ctx,0,sizeof(connection_thread_context));
    if(munlock(ctx, sizeof(connection_thread_context))<0)
       oops_warn("failed to munlock");
    free(ctx);
    if(fd>=0)
        if(close(fd)<0)
            oops_warn("failed to close fd");
    return 0;
}

static void* connection_thread(void* v)
{
    connection_thread_context* ctx = (connection_thread_context*)v;
    log_set_thread_name(" cf ");
    
    log_info("connection thread entered");

    // Create a TCP Client
    tcpclient_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_TCP_FASTOPEN = 1,
     .OPT_SO_SNDLOWAT = 512
    };
    log_info("(CLIENT FORWARDER) ABOUT TO CONNECT TO %s:%s", ctx->remote_ip, ctx->remote_port);
    int remote_fd = tcpclient_new(ctx->remote_ip, ctx->remote_port, options);
    if(remote_fd<0) {
        log_warn("failed to create TCP client connection");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    
    // Write packet0
    if(saltunnel_kx_packet0_trywrite(ctx->long_term_shared_key, remote_fd, ctx->session_secret_key)<0) {
        log_warn("failed to write packet0");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    log_info("(CLIENT FORWARDER) SUCCESSFULLY CONNECTED TO %s:%s", ctx->remote_ip, ctx->remote_port);
    
    log_info("client forwarder successfully wrote packet0");
                                     
    // Read packet0
    packet0 their_packet0 = {0};
    if(saltunnel_kx_packet0_tryread(ctx->long_term_shared_key, remote_fd, &their_packet0)<0) {
        log_warn("failed to read packet0");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    
    log_info("client forwarder successfully read packet0");
    
    // Exchange packet1
    
    // TODO: Exchange single packet to completely prevent replay attacks
        
    // Calculate shared key
    if(saltunnel_kx_calculate_shared_key(ctx->session_shared_key, their_packet0.pk, ctx->session_secret_key)<0) {
        log_warn("failed to calculate shared key");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    
    log_info("calculated shared key");
    
    log_info("running saltunnel");
    
    // Run saltunnel
    cryptostream ingress = {
        .from_fd = remote_fd,
        .to_fd = ctx->local_fd,
        .key = ctx->session_shared_key
    };
    cryptostream egress = {
        .from_fd = ctx->local_fd,
        .to_fd = remote_fd,
        .key = ctx->session_shared_key
    };
    
    log_info("client forwarder [%2d->D->%2d, %2d->E->%2d]...", ingress.from_fd, ingress.to_fd, egress.from_fd, egress.to_fd);
    
    saltunnel(&ingress, &egress);
    
    return connection_thread_cleanup(ctx, remote_fd);
}

static pthread_t connection_thread_spawn(connection_thread_context* ctx)
{
    pthread_t thread;
    if(pthread_create(&thread, NULL, connection_thread, (void*)ctx)!=0) {
        oops_warn("failed to spawn thread");
        return 0;
    }
    return thread;
}

static int handle_connection(connection_thread_context* ctx) {
    pthread_t thread = connection_thread_spawn(ctx);
    if(thread==0) return -1;
    else return 1;
}


int saltunnel_tcp_client_forwarder(unsigned char* long_term_shared_key,
                         const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
    
    log_info("handling connection");
    
    // Create socket
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1,
     .OPT_TCP_FASTOPEN = 1
    };
    int s = tcpserver_new(from_ip, from_port, options);
    if(s<0)
        return oops_warn("error creating socket");
    
    for(;;) {
        log_info("(CLIENT FORWARDER) WAITING FOR ACCEPT ON %s:%s", from_ip, from_port);
        
        // Accept a new connection (or wait for one to arrive)
        int local_fd = tcpserver_accept(s);
        if(local_fd<0) {
            log_warn("failed to accept connection");
            continue;
        }
        
        log_info("(CLIENT FORWARDER) ACCEPTED ON %s:%s", from_ip, from_port);
        
        // Handle the connection
        connection_thread_context* ctx = calloc(1,sizeof(connection_thread_context));
        if(mlock(ctx, sizeof(connection_thread_context))<0)
           oops_warn("failed to mlock");
        ctx->local_fd = local_fd;
        ctx->remote_ip = to_ip;
        ctx->remote_port = to_port;
        memcpy(ctx->long_term_shared_key, long_term_shared_key, 32);
        
        if(handle_connection(ctx)<0) {
            if(munlock(ctx, sizeof(connection_thread_context))<0)
               oops_warn("failed to munlock");
            free(ctx);
            try(close(local_fd)) || log_warn("failed to close connection");
            log_warn("encountered error with TCP connection");
        }
    }
    
    // The above loop should never exit
    oops_fatal("this should never happen");
    return 0;
}
