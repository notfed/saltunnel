//
//  saltunnel_tcp_client_forwarder.c
//  saltunnel
//

#include "oops.h"
#include "uint16.h"
#include "saltunnel.h"
#include "saltunnel_kx.h"
#include "saltunnel_tcp_client_forwarder.h"
#include "saltunnel_tcp_forwarder_thread.h"
#include "tcpserver.h"
#include "tcpclient.h"
#include "concurrentlist.h"
#include "thread_tracker.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/socket.h>

typedef struct main_thread_context {
    int s;
    concurrentlist* cl;
} main_thread_context;

static void cleanup_close(void* v) { close(*(int*)v); }

int saltunnel_tcp_client_forwarder(unsigned char* long_term_shared_key,
                         const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
    log_trace("client forwarder entered");
    
    // Create socket
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1
    };
    int s  = tcpserver_new(from_ip, from_port, options);
    if(s<0) {
        return -1;
    }
    pthread_cleanup_push(cleanup_close, &s);

    // Initialize a concurrentlist which will keep track of active, running threads
    concurrentlist active_thread_list = {0};
    if(concurrentlist_init(&active_thread_list)<0) { close(s); return -1; }

    // Initialize a concurrentlist which will keep track of finished, joinable threads
    concurrentlist joinable_thread_list = {0};
    if(concurrentlist_init(&joinable_thread_list)<0) { concurrentlist_free(&active_thread_list); close(s); return -1; }

    // Register a cleanup handler to free/flush both thread lists
    thread_tracker tracker = {
        .unjoined_thread_count = 0,
        .active_thread_list = &active_thread_list,
        .joinable_thread_list = &joinable_thread_list
    };
    pthread_cleanup_push(thread_tracker_cleanup_free_threads, &tracker);
    
    log_info("waiting for new connections on source address (socket %d)", s);

    for(;;) {
        // Take this moment to join with any finished threads
        thread_tracker_join_with_joinable_threads(&tracker);

        // Accept a new connection (or wait for one to arrive)
        int local_fd = tcpserver_accept(s, options);
        if(local_fd<0)
            continue;
        
        log_info("connection accepted from source address (fd %d)", local_fd);

        // Allocate a (memory-pinned and memory-aligned) context for the connection
        connection_thread_context* ctx;
        if(posix_memalign((void**)&ctx, 32, sizeof(connection_thread_context))<0)
            oops_error("failed to allocate memory");
        if(mlock(ctx, sizeof(connection_thread_context))<0)
            oops_warn_sys("failed to mlock client thread context");
        memset(ctx, 0, sizeof(connection_thread_context));
        ctx->dest_fd = -1;
        ctx->src_fd = local_fd;
        ctx->dest_ip = to_ip;
        ctx->dest_port = to_port;
        ctx->is_server = 0;
        ctx->active_thread_list = &active_thread_list;
        ctx->joinable_thread_list = &joinable_thread_list;
        assert(ctx->joinable_thread_list!=0);
        memcpy(ctx->long_term_key, long_term_shared_key, 32);

        int old_cancel_type;
        concurrentlist_lock(tracker.active_thread_list, &old_cancel_type);

        // Spawn off a thread to handle the connection
        pthread_t thread = handle_connection(ctx);
        ctx->thread = thread;
        
        // Add the thread context to the active_thread_list
        ctx->active_thread_list_entry = thread_tracker_add_new_thread(&tracker, thread);

        concurrentlist_unlock(&active_thread_list, &old_cancel_type);

    }
    
    // The above loop never exits
    pthread_cleanup_pop(1); // cleanup_close
    pthread_cleanup_pop(1); // cleanup_free_threads
    return -1;
}

typedef struct saltunnel_tcp_client_forwarder_async_ctx {
    unsigned char* long_term_shared_key;
    const char* from_ip; const char* from_port;
    const char* to_ip; const char* to_port;
} saltunnel_tcp_client_forwarder_async_ctx;

static void* saltunnel_tcp_client_forwarder_async_inner(void* v)
{
    saltunnel_tcp_client_forwarder_async_ctx* ctx = v;
    unsigned char* long_term_shared_key = ctx->long_term_shared_key;
    const char* from_ip = ctx->from_ip;
    const char* from_port = ctx->from_port;
    const char* to_ip = ctx->to_ip;
    const char* to_port = ctx->to_port;
    free(ctx);
    saltunnel_tcp_client_forwarder(long_term_shared_key,
                                   from_ip, from_port,
                                   to_ip, to_port);
    return 0;
}

pthread_t saltunnel_tcp_client_forwarder_async(unsigned char* long_term_shared_key,
                         const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
    saltunnel_tcp_client_forwarder_async_ctx* c = malloc(sizeof(saltunnel_tcp_client_forwarder_async_ctx));
    c->long_term_shared_key = long_term_shared_key;
    c->from_ip = from_ip;
    c->from_port = from_port;
    c->to_ip = to_ip;
    c->to_port = to_port;
    pthread_t thread;
    if(pthread_create(&thread, NULL, saltunnel_tcp_client_forwarder_async_inner, c)!=0)
        oops_error_sys("pthread_create failed");
    return thread;
}
