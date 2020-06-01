//
//  saltunnel_mx_parallel.c
//  saltunnel
//

#include "saltunnel.h"
#include "saltunnel_mx.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"

#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

typedef struct exchange_messages_thread_context {
    // Accessed by child thread
    cryptostream *ingress;
    cryptostream *egress;
    // Accessed by main thread
    pthread_t egress_thread;
    pthread_t ingress_thread;
} exchange_messages_thread_context;

void exchange_messages_parallel_cleanup(void* v) {
    exchange_messages_thread_context* ctx = v;
    if(ctx->egress_thread) {
        pthread_cancel(ctx->egress_thread);
        pthread_join(ctx->egress_thread, NULL);
    }
    if(ctx->ingress_thread) {
        pthread_cancel(ctx->ingress_thread);
        pthread_join(ctx->ingress_thread, NULL);
    }
}

typedef struct exchange_messages_parallel_child_thread_ctx {
    cryptostream *ingress; cryptostream *egress; int direction;
} exchange_messages_parallel_child_thread_ctx;

void* exchange_messages_parallel_child_thread(void* v) {
    exchange_messages_parallel_child_thread_ctx* ctx = v;
    int rc = exchange_messages_serial(ctx->ingress, ctx->egress, ctx->direction);
    return rc==0 ? 0 : (void*)1;
}

int exchange_messages_parallel(cryptostream *ingress, cryptostream *egress) {
    exchange_messages_thread_context ctx = {0};
    ctx.ingress = ingress;
    ctx.egress = egress;
    int create_1_rc = -1;
    int create_2_rc = -1;
    int join_1_rc = -1;
    int join_2_rc = -1;
    int ingress_thread_rc = -1;
    int egress_thread_rc = -1;
    
    // Define thread cleanup handler
    int both_threads_were_created = 0;
    pthread_cleanup_push(exchange_messages_parallel_cleanup, &ctx);
    
    // Spawn off two threads
    exchange_messages_parallel_child_thread_ctx egress_ctx =
        { .ingress = ingress, egress = egress, .direction = DIRECTION_EGRESS };
    create_1_rc = pthread_create(&ctx.egress_thread, NULL, exchange_messages_parallel_child_thread, &egress_ctx);
    
    exchange_messages_parallel_child_thread_ctx ingress_ctx =
        { .ingress = ingress, egress = egress, .direction = DIRECTION_INGRESS };
    create_2_rc = pthread_create(&ctx.ingress_thread, NULL, exchange_messages_parallel_child_thread, &ingress_ctx);
    
    // If either thread failed to create, cancel both
    both_threads_were_created = (create_1_rc==0 && create_2_rc==0);
    if(!both_threads_were_created) {
        pthread_cancel(ctx.egress_thread);
        pthread_cancel(ctx.ingress_thread);
    }

    // Wait for both threads to end
    join_1_rc = pthread_join(ctx.egress_thread, (void*)&egress_thread_rc);
    ctx.egress_thread = 0;
    join_2_rc = pthread_join(ctx.ingress_thread, (void*)&ingress_thread_rc);
    ctx.ingress_thread = 0;
    
    // Unregister cleanup handler
    pthread_cleanup_pop(!both_threads_were_created);
    
    int success = (create_1_rc==0 && create_2_rc==0
                   && join_1_rc==0 && join_2_rc==0
                   && egress_thread_rc==0 && ingress_thread_rc==0);
    return success ? 0 : -1;
}
