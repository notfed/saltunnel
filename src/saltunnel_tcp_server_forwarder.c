//
//  saltunnel_tcp_server_forwarder.c
//  saltunnel
//


#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "saltunnel_kx.h"
#include "cache.h"
#include "concurrentlist.h"
#include "oops.h"
#include "tcpserver.h"
#include "saltunnel_tcp_server_forwarder.h"
#include "saltunnel_tcp_forwarder_thread.h"
#include "iopoll.h"
#include "waitlist.h"
#include "config.h"
#include "thread_tracker.h"

static int fd_block(int fd)
{
  return fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) & ~O_NONBLOCK);
}
 
static int fd_nonblock(int fd)
{
  return fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) | O_NONBLOCK);
}

int cancel_conn(waitlist_value val, void* q_ptr) {
    int fd = val.i;
    if(iopoll_delete(*(int*)q_ptr, fd)<0)
        return -1;
    close(fd);
    log_info("connection with source address terminated (fd %d)", fd);
    return 0;
}

static void cleanup_close(void* v) { int fd = *(int*)(v); if(fd>=0) close(fd); }

typedef struct cleanup_free_waitlist_ctx {
    waitlist* list;
    int* q;
} free_waitlist_ctx;

static void cleanup_free_waitlist(void* v) {
    free_waitlist_ctx* ctx = v;
    waitlist_cancel_all(ctx->list, cancel_conn, ctx->q);
}

static int maybe_handle_connection(
                            thread_tracker* tracker,
                            cache* table, clienthi* clienthi_ciphertext,
                            int remote_fd,
                            unsigned char* long_term_shared_key,
                            const char* from_ip, const char* from_port,
                            const char* to_ip, const char* to_port) {
    log_trace("maybe handling connection");

    // Allocate a (memory-pinned and memory-aligned) thread context
    connection_thread_context* ctx;
    if(posix_memalign((void**)&ctx, 32, sizeof(connection_thread_context))<0)
        oops_error("failed to allocate memory");
    if(mlock(ctx, sizeof(connection_thread_context))<0)
        oops_warn_sys("failed to mlock server thread context");
    memset(ctx, 0, sizeof(connection_thread_context));
    ctx->dest_fd = -1;
    ctx->src_fd = remote_fd;
    ctx->dest_ip = to_ip;
    ctx->dest_port = to_port;
    ctx->is_server = 1;
    ctx->active_thread_list = tracker->active_thread_list;
    ctx->joinable_thread_list = tracker->joinable_thread_list;
    assert(ctx->joinable_thread_list!=0);
    memcpy(ctx->long_term_key, long_term_shared_key, 32);

    // Decrypt+verify the clienthi
    if(saltunnel_kx_clienthi_tryparse(table, &ctx->clienthi_plaintext_pinned, ctx->long_term_key,
                                      clienthi_ciphertext, ctx->their_pk)<0) {
        munlock(ctx, sizeof(connection_thread_context));
        free(ctx);
        return -1;
    }
    log_trace("successfully received clienthi");
    
    int old_cancel_type;
    concurrentlist_lock(tracker->active_thread_list, &old_cancel_type);

    // If clienthi was good, spawn a thread to handle subsequent packets
    pthread_t thread = handle_connection(ctx);
    ctx->thread = thread;
    
    // Add the thread context to the concurrentlist
    ctx->active_thread_list_entry = thread_tracker_add_new_thread(tracker, thread);
    
    concurrentlist_unlock(tracker->active_thread_list, &old_cancel_type);

    return 1;
}

int saltunnel_tcp_server_forwarder(cache* table,
                         unsigned char* long_term_shared_key,
                         const char* from_ip, const char* from_port,
                         const char* to_ip, const char* to_port)
{
    clienthi clienthi_ciphertext;
    
    // Create socket "s"
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1,
     .OPT_SO_RCVLOWAT = 512
    };
    int s = tcpserver_new(from_ip, from_port, options);
    if(s<0)
        return -1;
    pthread_cleanup_push(cleanup_close, &s);

    // Create an incoming-connection kqueue/epoll "q"d
    int q = iopoll_create();
    if(q<0)
        oops_error_sys("failed to create poll handle");
    pthread_cleanup_push(cleanup_close, &q);
    
    // Keep a linked list of incoming connections, which will close/unregister fds after 1 second
    waitlist list = { .max_age_ms = 1000, .max_items=262144 };
    free_waitlist_ctx free_waitlist_ctx = { .list = &list, .q = &q };
    pthread_cleanup_push(cleanup_free_waitlist, &free_waitlist_ctx);

    // Initialize a concurrentlist which will keep track of active, running threads
    concurrentlist active_thread_list = {0};
    if(concurrentlist_init(&active_thread_list)<0) { close(q); close(s); return -1; }

    // Initialize a concurrentlist which will keep track of finished, joinable threads
    concurrentlist joinable_thread_list = {0};
    if(concurrentlist_init(&joinable_thread_list)<0) { concurrentlist_free(&active_thread_list); close(q); close(s); return -1; }

    // Register a cleanup handler to free/flush both thread lists
    thread_tracker tracker = {
        .unjoined_thread_count = 0,
        .active_thread_list = &active_thread_list,
        .joinable_thread_list = &joinable_thread_list
    };
    pthread_cleanup_push(thread_tracker_cleanup_free_threads, &tracker);
    
    // Add the socket to the queue (wait for incoming connections)
    waitlist_item socket_item = { .val = { .i = s } };
    if(iopoll_add(q, s, &socket_item)<0)
        oops_error_sys("failed to add poll event");

    log_info("waiting for new connections on source address (socket %d)", s);
    
    const int max_num_events = 4096;
    iopoll_event eventlist[max_num_events];
    for(;;) {
        // Take this moment to purge all completed/overdue connections
        waitlist_cancel_expired(&list, cancel_conn, &q);

        // Take this moment to join with any finished threads
        thread_tracker_join_with_joinable_threads(&tracker);

        // Wait for any queue events
        int eventcount = iopoll_wait(q, eventlist, max_num_events, waitlist_ms_until_next_expiration(&list));
        if(eventcount<0)
            oops_error_sys("failed to poll");

        // If we timed out, do a purge and poll again
        if(eventcount==0) {
            continue;
        }

        // Loop through eventlist
        for(int i = 0; i<eventcount; i++) {
            iopoll_event* e = &eventlist[i];
            waitlist_item* item = (waitlist_item*)iopoll_event_get_data(e);
            int fd = item->val.i;
            
            // If we received a new connection, accept it, and add it to the list and queue
            if(fd==s) {

                // Accept the new connection;
                int conn_fd = tcpserver_accept(s, options);
                if(conn_fd<0) continue;
                log_info("connection accepted (but not yet authenticated) from source address (fd %d)", conn_fd);
                
                // Defensively make the connection have non-blocking reads
                if(fd_nonblock(conn_fd)<0) 
                    oops_warn_sys("failed to set fd as non-blocking");
                
                // Start polling this fd
                waitlist_value val = { .i = conn_fd };
                waitlist_item* item = waitlist_add(&list,val);
                if(item==NULL) { oops_warn_sys("failed to add connection to list"); close(conn_fd); continue;}
                
                if(iopoll_add_oneshot(q, conn_fd, item)<0)
                    oops_warn_sys("failed to add poll event");
            }
            // If we received data, handle the clienthi
            else {
                // Remove this fd from the list
                waitlist_remove((waitlist_item*)iopoll_event_get_data(e));

                // If the connection disconnected, close it // TODO: Test this?
                if(iopoll_event_did_error(e)) {
                    close(fd);
                    log_info("connection with source address terminated (fd %d)", fd);
                    continue;
                }
                
                // Read the 512-byte clienthi from the connection
                ssize_t bytes_read = read(fd, (char*)&clienthi_ciphertext, 512);
                
                // If we didn't read 512 bytes, or if the connection was dropped, close it and move on
                if(bytes_read!=512) {
                    oops_warn_sys("failed to read clienthi");
                    close(fd);
                    log_info("connection with source address terminated (fd %d)", fd);
                    continue;
                }

                // The fd can block now (will be handled in thread)        
                if(fd_block(fd)<0) 
                    oops_warn_sys("failed to set fd as blocking");
                    
                // Otherwise, verify the clienthi
                // If verification succeeds, spawn a thread to handle it
                int rc = maybe_handle_connection(&tracker, table, &clienthi_ciphertext, fd,
                                           long_term_shared_key,
                                           from_ip, from_port,
                                           to_ip, to_port);

                // If verification failed, close the fd and move on
                if(rc<0) {
                    close(fd);
                    log_info("connection with source address terminated (fd %d)", fd);
                }
            }
        }
    }
    
    // The above loop should never exit
    pthread_cleanup_pop(1); // cleanup_free_threads
    pthread_cleanup_pop(1); // cleanup_free_waitlist
    pthread_cleanup_pop(1); // cleanup_close(q)
    pthread_cleanup_pop(1); // cleanup_close(s)
    return -1;
}
