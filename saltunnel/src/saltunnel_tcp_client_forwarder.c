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

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>

typedef struct connection_thread_context {
    packet0 tmp_pinned;
    unsigned char long_term_shared_key[32];
    unsigned char my_sk[32];
    unsigned char their_pk[32];
    unsigned char session_shared_keys[64]; // Client = [0..32), Server = [32..64)
    int local_fd;
    const char* remote_ip;
    const char* remote_port;
} connection_thread_context;

static void* connection_thread_cleanup(void* v, int remote_fd, int force_close) {
    connection_thread_context* ctx = (connection_thread_context*)v;

    if(force_close) {
        close(ctx->local_fd);
        if(remote_fd>=0) close(remote_fd);
    } else {
        shutdown(ctx->local_fd, SHUT_RDWR);
        if(remote_fd>=0)
            shutdown(remote_fd, SHUT_RDWR);
    }
    log_info("connection with source address terminated (fd %d)", ctx->local_fd);
    if(remote_fd>=0) log_info("connection with destination address terminated (fd %d)", remote_fd);

    memset(ctx,0,sizeof(connection_thread_context));
    if(munlock(ctx, sizeof(connection_thread_context))<0)
       oops_warn_sys("failed to munlock");
    free(ctx);
    return 0;
}

static void* connection_thread(void* v)
{
    connection_thread_context* ctx = (connection_thread_context*)v;
    log_set_thread_name(" cf ");
    
    log_trace("connection thread entered");

    // Create a TCP Client to connect to server
    tcpclient_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_SNDLOWAT = 512,
     .OPT_CONNECT_TIMEOUT = config_connection_timeout_ms
    };

    log_trace("connecting to %s:%s", ctx->remote_ip, ctx->remote_port);
    int remote_fd = tcpclient_new(ctx->remote_ip, ctx->remote_port, options);
    if(remote_fd<0) {
        log_trace("failed to connect to remote endpoint");
        return connection_thread_cleanup(ctx, remote_fd, 1);
    }

    log_info("connection established (but not yet authenticated) with destination address (fd %d)", remote_fd);
    
    // Write packet0 to server
    if(saltunnel_kx_packet0_trywrite(&ctx->tmp_pinned, ctx->long_term_shared_key, remote_fd, ctx->my_sk, 1)<0) {
        log_trace("connection %d: failed to write packet0 to server", remote_fd);
        return connection_thread_cleanup(ctx, remote_fd, 1);
    }
    
    log_trace("connection %d: client forwarder successfully wrote packet0 to server", remote_fd);
                                     
    // Read packet0
    if(saltunnel_kx_packet0_tryread(NULL, &ctx->tmp_pinned, ctx->long_term_shared_key, remote_fd, ctx->their_pk)<0) {
        log_trace("connection %d: failed to read packet0", remote_fd);
        return connection_thread_cleanup(ctx, remote_fd, 1);
    }
    
    log_trace("connection %d: client forwarder successfully read packet0", remote_fd);
    
    // Calculate shared key
    if(saltunnel_kx_calculate_shared_key(ctx->session_shared_keys, ctx->their_pk, ctx->my_sk)<0) {
        return connection_thread_cleanup(ctx, remote_fd, 1);
    }
    
    log_trace("connection %d: successfully calculated shared key", remote_fd);

    // Exchange packet1 (to prevent replay-attack from exploiting server-sends-first scenarios)
    
    log_trace("connection %d: about to exchange packet1 with server", remote_fd);
    if(saltunnel_kx_packet1_exchange(ctx->session_shared_keys, 0, remote_fd)<0) {
        log_trace("failed to exchange packet1 with server");
        return connection_thread_cleanup(ctx, remote_fd, 1);
    }
    
    log_info("authentication succeeded (fd %d)", remote_fd);
    
    // Initialize saltunnel parameters
    cryptostream ingress = {
        .from_fd = remote_fd,
        .to_fd = ctx->local_fd,
        .key = &ctx->session_shared_keys[32]
    };
    cryptostream egress = {
        .from_fd = ctx->local_fd,
        .to_fd = remote_fd,
        .key = &ctx->session_shared_keys[0]
    };

    // Nonces should start at 1
    nonce8_increment(ingress.nonce, ingress.nonce);
    nonce8_increment(egress.nonce, egress.nonce);
    
    // Memory-lock the plaintext buffers
    if(mlock(ingress.plaintext, sizeof(ingress.plaintext))<0)
       oops_warn_sys("failed to mlock client data");
    if(mlock(egress.plaintext, sizeof(egress.plaintext))<0)
       oops_warn_sys("failed to mlock client data");
    
    // Run saltunnel
    log_trace("client forwarder [%2d->D->%2d, %2d->E->%2d]...", ingress.from_fd, ingress.to_fd, egress.from_fd, egress.to_fd);
    saltunnel(&ingress, &egress);
    
    // Clear the plaintext buffers/keys
    memset(ingress.key, 0, 32);
    memset(egress.key, 0, 32);
    memset(ingress.plaintext, 0, sizeof(ingress.plaintext));
    memset(egress.plaintext, 0, sizeof(egress.plaintext));
    
    // Un-memory-lock the plaintext buffers
    if(munlock(ingress.plaintext, sizeof(ingress.plaintext))<0)
        oops_warn_sys("failed to munlock client data");
    if(munlock(egress.plaintext, sizeof(egress.plaintext))<0)
        oops_warn_sys("failed to munlock client data");
    
    // Clean up
    return connection_thread_cleanup(ctx, remote_fd, 0);
}

static pthread_t handle_connection(connection_thread_context* ctx)
{
    pthread_t thread;
    if(pthread_create(&thread, NULL, connection_thread, (void*)ctx)!=0) {
        oops_error_sys("failed to spawn thread");
        return 0;
    }
    return thread;
}

int saltunnel_tcp_client_forwarder(unsigned char* long_term_shared_key,
                         const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
    
    log_trace("entered");
    
    // Create socket
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1,
     .OPT_TCP_FASTOPEN = 1
    };
    int s  = tcpserver_new(from_ip, from_port, options);
    if(s<0) {
        return -1;
    }
    
    log_info("waiting for new connections on source address (socket %d)", s);
    
    oops_should_warn();
    for(;;) {
        
        // Accept a new connection (or wait for one to arrive)
        int local_fd = tcpserver_accept(s);
        if(local_fd<0) {
            log_warn("failed to accept incoming TCP connection");
            continue;
        }
        
        log_info("connection accepted from source address (fd %d)", local_fd);
        
        // Handle the connection
        connection_thread_context* ctx = calloc(1,sizeof(connection_thread_context));
        if(mlock(ctx, sizeof(connection_thread_context))<0)
           oops_warn_sys("failed to mlock client thread context");
        ctx->local_fd = local_fd;
        ctx->remote_ip = to_ip;
        ctx->remote_port = to_port;
        memcpy(ctx->long_term_shared_key, long_term_shared_key, 32);
        
        handle_connection(ctx);
    }
    
    // The above loop should never exit
    return -1;
}
