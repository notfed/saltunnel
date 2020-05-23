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
#include "cache.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>

typedef struct connection_thread_context {
    packet0 tmp_pinned;
    unsigned char long_term_shared_key[32];
    unsigned char my_sk[32];
    unsigned char their_pk[32];
    unsigned char session_shared_keys[64]; // Client = [0..32), Server = [32..64)
    int remote_fd;
    const char* to_ip;
    const char* to_port;
} connection_thread_context;

static void* connection_thread_cleanup(void* v, int force_close) {
    connection_thread_context* ctx = (connection_thread_context*)v;

    if(force_close) {
        close(ctx->remote_fd);
    } else {
        shutdown(ctx->remote_fd, SHUT_RDWR);
    }
    log_info("connection with source address terminated (fd %d)", ctx->remote_fd);

    memset(ctx,0,sizeof(connection_thread_context));
    if(munlock(ctx, sizeof(connection_thread_context))<0)
       oops_warn_sys("failed to munlock");
    free(ctx);
    return 0;
}

static void* connection_thread(void* v)
{
    connection_thread_context* ctx = (connection_thread_context*)v;
    log_set_thread_name(" sf ");
    
    log_trace("connection thread entered");
    
    // Write packet0 to client
    if(saltunnel_kx_packet0_trywrite(&ctx->tmp_pinned, ctx->long_term_shared_key, ctx->remote_fd, ctx->my_sk, 0)<0) {
        oops_warn("failed to write packet0 to client");
        return connection_thread_cleanup(v,1);
    }
    
    log_trace("server forwarder successfully wrote packet0 to client");
    
    // Calculate shared key
    if(saltunnel_kx_calculate_shared_key(ctx->session_shared_keys, ctx->their_pk, ctx->my_sk)<0) {
        return connection_thread_cleanup(v,1);
    }

    // Exchange packet1 (to prevent replay-attack from exploiting server-sends-first scenarios)

    log_trace("about to exchange packet1");
    if(saltunnel_kx_packet1_exchange(ctx->session_shared_keys, 1, ctx->remote_fd)<0) {
        return connection_thread_cleanup(ctx,1);
    }
    log_trace("successfully exchanged packet1");
    
    // Create a TCP Client to connect to target
    tcpclient_options options = {
        .OPT_TCP_NODELAY = 1,
        .OPT_CONNECT_TIMEOUT = 100000
    };
    log_trace("connecting to %s:%s", ctx->to_ip, ctx->to_port);
    
    int local_fd = tcpclient_new(ctx->to_ip, ctx->to_port, options);
    if(local_fd<0) {
        return connection_thread_cleanup(v,1);
    }

    log_info("connection established with destination address (fd %d)", local_fd);
    
    log_trace("calculated shared key");
    
    log_trace("running saltunnel");
    
    // Initialize saltunnel parameters
    cryptostream ingress = {
        .from_fd = ctx->remote_fd,
        .to_fd = local_fd,
        .key = &ctx->session_shared_keys[0]
    };
    cryptostream egress = {
        .from_fd = local_fd,
        .to_fd = ctx->remote_fd,
        .key = &ctx->session_shared_keys[32]
    };

    // Nonces should start at 1
    nonce8_increment(ingress.nonce, ingress.nonce);
    nonce8_increment(egress.nonce, egress.nonce);

    // Memory-lock the plaintext buffers
    if(mlock(ingress.plaintext, sizeof(ingress.plaintext))<0)
        oops_warn_sys("failed to mlock server data");
    if(mlock(egress.plaintext, sizeof(egress.plaintext))<0)
        oops_warn_sys("failed to mlock server data");
     
     // Run saltunnel
    log_trace("server forwarder [%2d->D->%2d, %2d->E->%2d]...", ingress.from_fd, ingress.to_fd, egress.from_fd, egress.to_fd);
    log_debug("entering saltunnel (dest fd %d)", local_fd); // TODO
    if(saltunnel(&ingress, &egress)<0) {
        if(close(local_fd)<0) oops_warn_sys("failed to shutdown socket");
        log_debug("destination closed (fd %d)", local_fd); // TODO
    }
    else {
        if(shutdown(local_fd, SHUT_RDWR)<0) oops_warn_sys("failed to shutdown socket");
        log_debug("destination shutdown (fd %d)", local_fd); // TODO
    }
    log_info("connection with destination address terminated (fd %d)", local_fd);
    
    // Clear the plaintext buffers
    memset(ingress.plaintext, 0, sizeof(ingress.plaintext));
    memset(egress.plaintext, 0, sizeof(egress.plaintext));
    
    // Un-memory-lock the plaintext buffers
    if(munlock(ingress.plaintext, sizeof(ingress.plaintext))<0)
        oops_warn_sys("failed to munlock server data");
    if(munlock(egress.plaintext, sizeof(egress.plaintext))<0)
        oops_warn_sys("failed to munlock server data");
    
    // Clean up
    return connection_thread_cleanup(v,0);
}

static pthread_t connection_thread_spawn(connection_thread_context* ctx)
{
    pthread_t thread;
    if(pthread_create(&thread, NULL, connection_thread, (void*)ctx)!=0)
        oops_error_sys("failed to spawn thread");
    return thread;
}

static int maybe_handle_connection(cache* table, connection_thread_context* ctx) {
    log_trace("maybe handling connection");
    
    // Read packet0
    if(saltunnel_kx_packet0_tryread(table, &ctx->tmp_pinned, ctx->long_term_shared_key, ctx->remote_fd, ctx->their_pk)<0) {
        return -1;
    }
    
    log_trace("server forwarder successfully read packet0");
    
    // If packet0 was good, spawn a thread to handle subsequent packets
    log_info("authentication succeeded (fd %d)", ctx->remote_fd);
    pthread_t thread = connection_thread_spawn(ctx);
    if(thread==0) return -1;
    else return 1;
}

int saltunnel_tcp_server_forwarder(cache* table,
                         unsigned char* long_term_shared_key,
                         const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
    
    // Create socket
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1,
     .OPT_TCP_DEFER_ACCEPT = 1,
     .OPT_SO_RCVLOWAT = 512
    };
    
    int s = tcpserver_new(from_ip, from_port, options); // TODO: Shouldn't this keep re-trying?
    if(s<0)
        return -1;
    
    log_info("waiting for new connections on source address (socket %d)", s);
    
    
    oops_should_warn();
    for(;;) {

        // Accept a new connection (or wait for one to arrive)
        int remote_fd = tcpserver_accept(s);
        if(remote_fd<0) {
            continue;
        }
        log_info("connection accepted (but not yet authenticated) from source address (fd %d)", remote_fd);

        // Handle the connection (but do some DoS prevention checks first)
        connection_thread_context* ctx = calloc(1,sizeof(connection_thread_context));
        if(mlock(ctx, sizeof(connection_thread_context))<0)
            oops_warn_sys("failed to mlock server thread context");
        ctx->remote_fd = remote_fd;
        ctx->to_ip = to_ip;
        ctx->to_port = to_port;
        memcpy(ctx->long_term_shared_key, long_term_shared_key, 32);
        
        if(maybe_handle_connection(table, ctx)<0) {
            if(munlock(ctx, sizeof(connection_thread_context))<0)
               oops_warn_sys("failed to munlock server data");
            free(ctx);
            close(remote_fd);
            log_info("connection with source address terminated (fd %d)", remote_fd);
        }
    }
    
    // The above loop should never exit
    return -1;
}
