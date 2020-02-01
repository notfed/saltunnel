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

static threadpool tp = {0};

static void* threadpool_loop(void* ctx_void) {
    if(!tp.tp_init_complete)
        oops_fatal("threadpool not initialized");
    
    threadpool_thread_context* ctx = (threadpool_thread_context*)ctx_void;
    int thread_i = ctx->thread_i;

    for(;;) {
        log_debug("threadpool_loop: about to wait for 'start' signal");
        
        // Wait for start signal
        try(pthread_mutex_lock(&tp.mutex)) || oops_fatal("pthread_mutex_lock");
        while(!tp.started)
            try(pthread_cond_wait(&tp.start, &tp.mutex)) || oops_fatal("pthread_cond_wait");
        try(pthread_mutex_unlock(&tp.mutex)) || oops_fatal("pthread_mutex_unlock");
        
        log_debug("threadpool_loop: received 'start' signal; encrypting...");
        
        // Run the thread action
        threadpool_task* task = &tp.tasks[thread_i];
        task->action(task->param);
        
        log_debug("threadpool_loop: done encrypting; about to wait for 'finish' barrier");
        // Finish all threads together
        pthread_barrier_wait(&tp.finish, &tp.started);
        
        log_debug("threadpool_loop: 'finish' barrier completed");
        
        // TODO: Break when shutdown is requested
    }
    
    return 0;
}

void threadpool_init() {
    
    if(!tp.tp_init_complete) {
        tp.tp_init_complete = 1;
    } else {
        oops_fatal("attempted to initialialize threadpool twice");
    }

    try(pthread_mutex_init(&tp.parallel_for_mutex, NULL))
      || oops_fatal("pthread_mutex_init");
    
    try(pthread_mutex_init(&tp.mutex, NULL))
      || oops_fatal("pthread_mutex_init");
    
    try(pthread_cond_init(&tp.start, NULL))
    || oops_fatal("pthread_cond_init");
    
    try(pthread_barrier_init(&tp.finish, NULL, THREADPOOL_THREAD_COUNT+1))
     || oops_fatal("pthread_barrier_init");
    
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT; thread_i++) {
        tp.thread_contexts[thread_i].thread_i = thread_i;
        pthread_create(&tp.threads[thread_i], NULL, threadpool_loop, (void*)&tp.thread_contexts[thread_i])==0
        || oops_fatal("pthread_create failed");
    }
}

void threadpool_for(threadpool_task* tasks) {
    if(!tp.tp_init_complete)
        oops_fatal("threadpool not initialized");
    
    // Take big lock
    try(pthread_mutex_lock(&tp.parallel_for_mutex)) || oops_fatal("pthread_mutex_lock");
    
    // Point to tasks
    tp.tasks = tasks;
    
    // Broadcast start signal
    try(pthread_mutex_lock(&tp.mutex)) || oops_fatal("pthread_mutex_lock");
    log_debug("threadpool_for: about to send 'start' signal");
        tp.started = 1;
        try(pthread_cond_broadcast(&tp.start)) || oops_fatal("pthread_cond_wait");
    log_debug("threadpool_for: sent 'start' signal");
    try(pthread_mutex_unlock(&tp.mutex)) || oops_fatal("pthread_mutex_unlock");
    
    // Wait for all threads to finish
    log_debug("threadpool_for: about to wait for 'finish' barrier");
    pthread_barrier_wait(&tp.finish, &tp.started);
    log_debug("threadpool_for: 'finish' barrier completed");
    
    // Release big lock
    tp.tasks = 0; // TODO: Debug
    try(pthread_mutex_unlock(&tp.parallel_for_mutex)) || oops_fatal("pthread_mutex_unlock");
}

void threadpool_shutdown() {
    for(int i = 0; i<THREADPOOL_THREAD_COUNT; i++) {
        // TODO: Gracefully exit each thread
    }
}
