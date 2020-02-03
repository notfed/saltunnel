//
//  threadpool.c
//  saltunnel2
//

#include "cryptostream.h"
#include "threadpool.h"
#include "oops.h"
#include "threadpool_barrier.h"
#include "stopwatch.h"
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

    stopwatch sw={0}; unsigned long c=0;
    for(;;) {
//        stopwatch_start(&sw);
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
        threadpool_barrier_wait(&tp.finish, &tp.started);
        
        log_debug("threadpool_loop: 'finish' barrier completed");
        
        // TODO: Break when shutdown is requested
//        log_info("threadpool_loop took %dus (#%d)", (int)stopwatch_elapsed(&sw), c++);
    }
    
    return 0;
}

void threadpool_init(void) {
    
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
    
    try(threadpool_barrier_init(&tp.finish, NULL, THREADPOOL_THREAD_COUNT))
     || oops_fatal("pthread_barrier_init");
    
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT-1; thread_i++) {
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
    
    // Point the threadpool to (except, we'll do the first task in the current thread)
    tp.tasks = &tasks[1];
    
    // Broadcast start signal
    try(pthread_mutex_lock(&tp.mutex)) || oops_fatal("pthread_mutex_lock");
    log_debug("threadpool_for: about to send 'start' signal");
        tp.started = 1;
        try(pthread_cond_broadcast(&tp.start)) || oops_fatal("pthread_cond_wait");
    log_debug("threadpool_for: sent 'start' signal");
    try(pthread_mutex_unlock(&tp.mutex)) || oops_fatal("pthread_mutex_unlock");
    
    // Run the first task in the current thread
    tasks[0].action(tasks[0].param);
    
    // Wait for all threads to finish
    log_debug("threadpool_for: about to wait for 'finish' barrier");
    threadpool_barrier_wait(&tp.finish, &tp.started);
    log_debug("threadpool_for: 'finish' barrier completed");
    
    // Release big lock
    tp.tasks = 0; // TODO: Debug
    try(pthread_mutex_unlock(&tp.parallel_for_mutex)) || oops_fatal("pthread_mutex_unlock");
}

void threadpool_shutdown(void) {
    for(int i = 0; i<THREADPOOL_THREAD_COUNT-1; i++) {
        // TODO: Gracefully exit each thread
    }
}
