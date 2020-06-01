//
//  saltunnel_tcp_forwarder_thread.c
//  saltunnel
//

#include "saltunnel_tcp_forwarder_thread.h"
#include "oops.h"
#include "uint16.h"
#include "saltunnel.h"
#include "saltunnel_kx.h"
#include "tcpserver.h"
#include "tcpclient.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/socket.h>

static void connection_thread_cleanup_close(void* v) {
    connection_thread_context* ctx = v;
    
    if(ctx->src_fd>=0) {
        log_info("connection with source address terminated (fd %d)", ctx->src_fd);
        close(ctx->src_fd);
    }
    if(ctx->dest_fd>=0) {
        log_info("connection with destination address terminated (fd %d)", ctx->dest_fd);
        close(ctx->dest_fd);
    }
}

static void connection_thread_cleanup_free(void* v) {
    connection_thread_context* ctx = v;

    // Assert
    assert(ctx!=0);
    assert(ctx->active_thread_list!=0);
    assert(ctx->active_thread_list->initialized==1);
    assert(ctx->joinable_thread_list!=0);
    assert(ctx->joinable_thread_list->initialized==1);

    // Remove this thread from the active thread list
    int old_cancel_type;
    concurrentlist_lock(ctx->active_thread_list, &old_cancel_type);
    assert(ctx->thread!=0);
    assert(ctx->active_thread_list_entry!=0);
    concurrentlist_remove(ctx->active_thread_list, ctx->active_thread_list_entry);
    concurrentlist_unlock(ctx->active_thread_list, &old_cancel_type);

    // Add this thread to the joinable thread list
        // TODO: thread_tracker_add_new_thread
    concurrentlist_lock(ctx->joinable_thread_list, &old_cancel_type);
    concurrentlist_val val = { .t = ctx->thread };
    concurrentlist_add(ctx->joinable_thread_list, val, 0);
    concurrentlist_unlock(ctx->joinable_thread_list, &old_cancel_type);

    // Free all of this thread's resources 
    memset(ctx,0,sizeof(connection_thread_context));
    if(munlock(ctx, sizeof(connection_thread_context))<0)
       oops_warn_sys("failed to munlock");
    free(ctx);
}

static int connection_thread_inner(connection_thread_context *ctx) {
    log_trace("connection thread entered");
    
    if(ctx->is_server) {
        // (Already received clienthi)
        
        // Write serverhi
        if(saltunnel_kx_serverhi_trywrite(&ctx->serverhi_plaintext_pinned, ctx->long_term_key, ctx->src_fd,
                                          ctx->my_sk, ctx->their_pk, ctx->session_shared_keys)<0) {
            return -1;
        }
        log_trace("sent serverhi");
        
        // Read message0
        // TODO: Update saltunnel to not read from server's local fd until receiving at least one packet, making this step unnecessary.
        if(saltunnel_kx_message0_tryread(ctx->session_shared_keys, ctx->src_fd)<0) {
            return -1;
        }
        log_info("authentication succeeded (fd %d)", ctx->src_fd);
    }
    
    // Create a TCP Client to connect to server
    tcpclient_options options = {
        .OPT_TCP_NODELAY = 1,
        .OPT_CONNECT_TIMEOUT = config_connection_timeout_ms,
        .OPT_CANCELLABLE_CONNECT = 1,
        .OPT_CONNECT_CANCEL_FD = ctx->src_fd
    };
    
    log_trace("connecting to %s:%s", ctx->dest_ip, ctx->dest_port);
    int dest_fd = tcpclient_new(ctx->dest_ip, ctx->dest_port, options);
    ctx->dest_fd = dest_fd;
    if(dest_fd<0) {
        log_trace("failed to connect to destination endpoint");
        return -1;
    }
    
    log_info("connection established (but not yet authenticated) with destination address (fd %d)", dest_fd);
    
    if(!ctx->is_server) {
        // Write clienthi to server (also generate a keypair)
        if(saltunnel_kx_clienthi_trywrite(&ctx->clienthi_plaintext_pinned, ctx->long_term_key, dest_fd, ctx->my_sk)<0) {
            log_trace("connection %d: failed to write clienthi to server", dest_fd);
            return -1;
        }
        
        log_trace("connection %d: client forwarder successfully wrote clienthi to server", dest_fd);
        
        // Read serverhi (also get server's public key and calculate shared session keys)
        if(saltunnel_kx_serverhi_tryread(&ctx->serverhi_plaintext_pinned, ctx->long_term_key, dest_fd, ctx->their_pk, ctx->my_sk, ctx->session_shared_keys)<0) {
            log_trace("connection %d: failed to read serverhi", dest_fd);
            return -1;
        }
        
        log_trace("connection %d: successfully calculated shared key", dest_fd);
        
        // Send message0
        // TODO: Detect whether data is available on ctx->local_fd, making this step unnecessary.
        log_trace("connection %d: about to send first message to server", dest_fd);
        if(saltunnel_kx_message0_trywrite(ctx->session_shared_keys, dest_fd)<0) {
            log_trace("failed to send first message to server");
            return -1;
        }
        
        log_info("authentication succeeded (fd %d)", dest_fd);
    }
    
    // Initialize saltunnel parameters
    cryptostream* ingress = &ctx->ingress;
    cryptostream* egress = &ctx->egress;
    if(ctx->is_server) {
        ingress->from_fd = ctx->src_fd;
        ingress->to_fd = dest_fd;
        ingress->key = &ctx->session_shared_keys[0];
        egress->from_fd = dest_fd;
        egress->to_fd = ctx->src_fd;
        egress->key = &ctx->session_shared_keys[32];
        // Client already sent message0, so client nonce should start at 1
        nonce8_increment(ingress->nonce, ingress->nonce);
    } else {
        ingress->from_fd = dest_fd;
        ingress->to_fd = ctx->src_fd;
        ingress->key = &ctx->session_shared_keys[32];
        egress->from_fd = ctx->src_fd;
        egress->to_fd = dest_fd;
        egress->key = &ctx->session_shared_keys[0];
        // Client already sent message0, so client nonce should start at 1
        nonce8_increment(egress->nonce, egress->nonce);
    }
    
    // Run saltunnel
    log_trace("client forwarder [%2d->D->%2d, %2d->E->%2d]...", ingress->from_fd, ingress->to_fd, egress->from_fd, egress->to_fd);
    saltunnel_mx(ingress, egress);
    
    return 0;
}

static void* connection_thread(void* v)
{
    int should_close_fds = 0;

    connection_thread_context* ctx = v;
    log_set_thread_name(ctx->is_server ? " sf " : " cf ");
    
    // Define thread cleanup handler (cleanup_free)
    pthread_cleanup_push(connection_thread_cleanup_free, ctx);
    
    // Define thread cleanup handler (cleanup_close)
    pthread_cleanup_push(connection_thread_cleanup_close, ctx);
    
    // Run the core logic for this connection thread
    int rc = connection_thread_inner(ctx);

    // We're done; don't let this thread be cancelled
    assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)==0);
    
    // Unregister cleanup handler (cleanup_close)
    should_close_fds = (rc<0);
    pthread_cleanup_pop(should_close_fds);
    
    // Run cleanup handler (cleanup_free)
    pthread_cleanup_pop(1); 
    
    return 0;
}

pthread_t handle_connection(connection_thread_context* ctx)
{
    pthread_t thread;
    if(pthread_create(&thread, NULL, connection_thread, ctx)!=0) oops_error_sys("failed to spawn thread");
    return thread;
}
