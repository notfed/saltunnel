//
//  saltunnel_tcp_server_forwarder.h
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
#include <sys/mman.h>

typedef struct connection_thread_context {
    packet0 tmp_pinned;
    unsigned char long_term_shared_key[32];
    unsigned char my_sk[32];
    unsigned char their_pk[32];
    unsigned char session_shared_key[32];
    int remote_fd;
    const char* to_ip;
    const char* to_port;
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
    log_set_thread_name(" sf ");
    
    log_info("connection thread entered");

    // Create a TCP Client
    tcpclient_options options = {
     .OPT_TCP_NODELAY = 1,
//     .OPT_TCP_FASTOPEN = 1, // This will only work if the root-originating-client writes first. Make this an option.
    };
    log_info("(SERVER FORWARDER) ABOUT TO CONNECT TO %s:%s", ctx->to_ip, ctx->to_port);
    
    int local_fd = tcpclient_new(ctx->to_ip, ctx->to_port, options);
    if(local_fd<0) {
        oops_warn("failed to create TCP client connection");
        return connection_thread_cleanup(v,local_fd);
    }
    
    // Write packet0
    if(saltunnel_kx_packet0_trywrite(&ctx->tmp_pinned, ctx->long_term_shared_key, ctx->remote_fd, ctx->my_sk)<0) {
        oops_warn("failed to write packet0");
        return connection_thread_cleanup(v,local_fd);
    }
    
    log_info("(SERVER FORWARDER) SUCCESSFULLY CONNECTED TO %s:%s", ctx->to_ip, ctx->to_port);
    
    log_info("server forwarder successfully wrote packet0");
    
    // Exchange packet1
    
    // TODO: Exchange single packet to completely prevent replay attacks
    
    // Calculate shared key
    if(saltunnel_kx_calculate_shared_key(ctx->session_shared_key, ctx->their_pk, ctx->my_sk)<0) {
        oops_warn("failed to calculate shared key");
        return connection_thread_cleanup(v,local_fd);
    }
    
    log_info("calculated shared key");
    
    log_info("running saltunnel");
    
    // Initialize saltunnel parameters
    cryptostream ingress = {
        .from_fd = ctx->remote_fd,
        .to_fd = local_fd,
        .key = ctx->session_shared_key
    };
    cryptostream egress = {
        .from_fd = local_fd,
        .to_fd = ctx->remote_fd,
        .key = ctx->session_shared_key
    };

    // Memory-lock the plaintext buffers
    if(mlock(ingress.plaintext, sizeof(ingress.plaintext))<0)
        oops_warn("failed to mlock");
    if(mlock(egress.plaintext, sizeof(egress.plaintext))<0)
        oops_warn("failed to mlock");
     
     // Run saltunnel
    log_info("server forwarder [%2d->D->%2d, %2d->E->%2d]...", ingress.from_fd, ingress.to_fd, egress.from_fd, egress.to_fd);
    saltunnel(&ingress, &egress);
    
    // Clear the plaintext buffers
    memset(ingress.plaintext, 0, sizeof(ingress.plaintext));
    memset(egress.plaintext, 0, sizeof(egress.plaintext));
    
    // Un-memory-lock the plaintext buffers
    if(munlock(ingress.plaintext, sizeof(ingress.plaintext))<0)
        oops_warn("failed to munlock");
    if(munlock(egress.plaintext, sizeof(egress.plaintext))<0)
        oops_warn("failed to munlock");
    
    // Clean up
    return connection_thread_cleanup(v,local_fd);
}

static pthread_t connection_thread_spawn(connection_thread_context* ctx)
{
    log_info("handling connection");
    
    pthread_t thread;
    if(pthread_create(&thread, NULL, connection_thread, (void*)ctx)!=0) {
        oops_warn("failed to spawn thread");
        return 0;
    }
    return thread;
}

static int maybe_handle_connection(connection_thread_context* ctx) {
    log_info("maybe handling connection");
    
    // Read packet0
    if(saltunnel_kx_packet0_tryread(&ctx->tmp_pinned, ctx->long_term_shared_key, ctx->remote_fd, ctx->their_pk)<0) {
        return oops_warn("failed to read packet0");
    }
    
    log_info("server forwarder successfully read packet0");
    
    // If packet0 was good, spawn a thread to handle subsequent packets
    pthread_t thread = connection_thread_spawn(ctx);
    if(thread==0) return -1;
    else return 1;
}

int saltunnel_tcp_server_forwarder(unsigned char* long_term_shared_key,
                         const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
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
            continue;
        }
        
        log_info("(SERVER FORWARDER) ACCEPTED ON %s:%s", from_ip, from_port);

        // Handle the connection
        connection_thread_context* ctx = calloc(1,sizeof(connection_thread_context));
        if(mlock(ctx, sizeof(connection_thread_context))<0)
            oops_warn("error with mlock");
        ctx->remote_fd = remote_fd;
        ctx->to_ip = to_ip;
        ctx->to_port = to_port;
        memcpy(ctx->long_term_shared_key, long_term_shared_key, 32);
        
        if(maybe_handle_connection(ctx)<0) {
            if(munlock(ctx, sizeof(connection_thread_context))<0)
               oops_warn("failed to munlock");
            free(ctx);
            try(close(remote_fd)) || log_warn("failed to close connection");
            log_warn("encountered error with TCP connection");
        }
    }
    
    // The above loop should never exit
    oops_fatal("this should never happen");
    return 0;
}
