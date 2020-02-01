//
//  threadpool.c
//  saltunnel2
//

#include "cryptostream.h"
#include "threadpool.h"
#include "oops.h"
#include "pthread_barrier.h"
#include <pthread.h>
#include <stdlib.h>

//typedef struct threadpool_task {
//    void (*action)(void*);
//    void* param;
//} threadpool_task;
//
//typedef struct threadpool_thread_context {
//    threadpool* tp;
//    int thread_i;
//} threadpool_thread_context;

static void* threadpool_loop(void* ctx_void) {
    threadpool_thread_context* ctx = (threadpool_thread_context*)ctx_void;
    int thread_i = ctx->thread_i;
    threadpool* tp = ctx->tp;

    for(;;) {
        log_info("---- beginning of loop");
        
        // Wait for start signal
        try(pthread_mutex_lock(&tp->mutex)) || oops_fatal("pthread_mutex_lock");
        while(!ctx->tp->started)
            try(pthread_cond_wait(&ctx->tp->start, &ctx->tp->mutex)) || oops_fatal("pthread_cond_wait");
        try(pthread_mutex_unlock(&tp->mutex)) || oops_fatal("pthread_mutex_unlock");
        
        log_info("---- start done");
        
        // Run the thread action
        threadpool_task* task = &tp->tasks[thread_i];
        task->action(task->param);
        
        // Finish all threads together
        pthread_barrier_wait(&tp->finish, &tp->started);
        
        log_info("---- end of loop");
        
        // TODO: Break when shutdown is requested
    }
    
    return 0;
}

void threadpool_init(threadpool* tp, int threads) {
    
//    pthread_t threads[THREADPOOL_THREAD_COUNT];
//    thread_context thread_contexts[THREADPOOL_THREAD_COUNT];
//
//    pthread_mutex_t mutex;
//    pthread_cond_t start;  // Protected by mutex
//    pthread_barrier_t finish; // Protected by mutex
    
    try(pthread_mutex_init(&tp->mutex, 0))
      || oops_fatal("pthread_mutex_init");
    
    try(pthread_cond_init(&tp->start, NULL))
    || oops_fatal("pthread_cond_init");
    
    try(pthread_barrier_init(&tp->finish, NULL, THREADPOOL_THREAD_COUNT+1))
     || oops_fatal("pthread_barrier_init");
    
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT; thread_i++) {
        tp->thread_contexts[thread_i].thread_i = thread_i;
        tp->thread_contexts[thread_i].tp = tp;
        pthread_create(&tp->threads[thread_i], NULL, threadpool_loop, (void*)&tp->thread_contexts[thread_i])==0
        || oops_fatal("pthread_create failed");
    }
}

void threadpool_for(threadpool *tp) {
    
    // Broadcast start signal
    try(pthread_mutex_lock(&tp->mutex)) || oops_fatal("pthread_mutex_lock");
        tp->started = 1;
        try(pthread_cond_broadcast(&tp->start)) || oops_fatal("pthread_cond_wait");
    try(pthread_mutex_unlock(&tp->mutex)) || oops_fatal("pthread_mutex_unlock");
    
    // Wait for all threads to finish
    pthread_barrier_wait(&tp->finish, &tp->started);
    int yy = 0;
}

void threadpool_shutdown(threadpool *tp) {
    // TODO: Close all threads
}
