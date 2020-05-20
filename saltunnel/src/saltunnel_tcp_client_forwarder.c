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

static void* connection_thread_cleanup(void* ctx, int fd) {
    memset(ctx,0,sizeof(connection_thread_context));
    if(munlock(ctx, sizeof(connection_thread_context))<0)
       oops_warn_sys("failed to munlock");
    free(ctx);
    if(fd>=0)
        if(close(fd))
            oops_error_sys("failed to close fd");
    return 0;
}

static void* connection_thread(void* v)
{
    connection_thread_context* ctx = (connection_thread_context*)v;
    log_set_thread_name(" cf ");
    
    log_info("connection thread entered");

    // Create a TCP Client to connect to server
    tcpclient_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_SNDLOWAT = 512
    };
    log_info("(CLIENT FORWARDER) ABOUT TO CONNECT TO %s:%s", ctx->remote_ip, ctx->remote_port);
    int remote_fd = tcpclient_new(ctx->remote_ip, ctx->remote_port, options);
    if(remote_fd<0) {
        log_warn("failed to connect to server");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    
    // Write packet0 to server
    if(saltunnel_kx_packet0_trywrite(&ctx->tmp_pinned, ctx->long_term_shared_key, remote_fd, ctx->my_sk)<0) {
        log_warn("failed to write packet0 to server");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    log_info("(CLIENT FORWARDER) SUCCESSFULLY CONNECTED TO %s:%s", ctx->remote_ip, ctx->remote_port);
    
    log_info("client forwarder successfully wrote packet0 to server");
                                     
    // Read packet0
    if(saltunnel_kx_packet0_tryread(NULL, &ctx->tmp_pinned, ctx->long_term_shared_key, remote_fd, ctx->their_pk)<0) {
        log_warn("failed to read packet0");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    
    log_info("client forwarder successfully read packet0");
    
    // Calculate shared key
    if(saltunnel_kx_calculate_shared_key(ctx->session_shared_keys, ctx->their_pk, ctx->my_sk)<0) {
        log_warn("failed to calculate shared key");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    
    log_info("successfully calculated shared key");

    // Exchange packet1 (to prevent replay-attack from exploiting server-sends-first scenarios)
    
    log_info("about to exchange packet1 with server");
    if(saltunnel_kx_packet1_exchange(ctx->session_shared_keys, 0, remote_fd)<0) {
        log_warn("failed to exchange packet1 with server");
        return connection_thread_cleanup(ctx, remote_fd);
    }
    log_info("successfully exchanged packet1 with server");
    
    log_info("running saltunnel");
    
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
    log_info("client forwarder [%2d->D->%2d, %2d->E->%2d]...", ingress.from_fd, ingress.to_fd, egress.from_fd, egress.to_fd);
    saltunnel(&ingress, &egress);
    
    // Clear the plaintext buffers/keys
    memset(ingress.plaintext, 0, sizeof(ingress.plaintext));
    memset(egress.plaintext, 0, sizeof(egress.plaintext));
    
    // Un-memory-lock the plaintext buffers
    if(munlock(ingress.plaintext, sizeof(ingress.plaintext))<0)
        oops_warn_sys("failed to munlock client data");
    if(munlock(egress.plaintext, sizeof(egress.plaintext))<0)
        oops_warn_sys("failed to munlock client data");
    
    // Clean up
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
    
    log_debug("entered");
    
    // Create socket
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1,
     .OPT_TCP_FASTOPEN = 1
    };
    int s = tcpserver_new(from_ip, from_port, options);
    if(s<0)
        return -1;

    log_debug("created socket %d\n", s);
    
    for(;;) {
        log_info("(CLIENT FORWARDER) WAITING FOR ACCEPT ON %s:%s", from_ip, from_port);
        
        // Accept a new connection (or wait for one to arrive)
        int local_fd = tcpserver_accept(s);
        if(local_fd<0) {
            log_warn("failed to accept incoming TCP connection");
            continue;
        }
        
        log_info("(CLIENT FORWARDER) ACCEPTED ON %s:%s", from_ip, from_port);
        
        // Handle the connection
        connection_thread_context* ctx = calloc(1,sizeof(connection_thread_context));
        if(mlock(ctx, sizeof(connection_thread_context))<0)
           oops_warn_sys("failed to mlock client thread context");
        ctx->local_fd = local_fd;
        ctx->remote_ip = to_ip;
        ctx->remote_port = to_port;
        memcpy(ctx->long_term_shared_key, long_term_shared_key, 32);
        
        if(handle_connection(ctx)<0) {
            if(munlock(ctx, sizeof(connection_thread_context))<0)
               oops_warn_sys("failed to munlock client thread context");
            free(ctx);
            close(local_fd);
            log_warn("encountered error with TCP connection");
        }
    }
    
    // The above loop should never exit
    oops_error("saltunnel exited unexpectedly");
    return 0;
}
