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

threadpool tp1 = {0};
threadpool tp2 = {0};

static int enough_cpus_for_parallel;
int threadpool_enough_cpus_for_parallel() {
    return enough_cpus_for_parallel;
}

static void* threadpool_loop(void* ctx_void) {
    
    threadpool_thread_context* ctx = (threadpool_thread_context*)ctx_void;
    threadpool* tp = ctx->tp;
    
    if(!tp->tp_init_complete)
        oops_fatal("threadpool not initialized");
        int thread_i = ctx->thread_i;

//    stopwatch sw={0}; unsigned long c=0;
    for(;;) {
//        stopwatch_start(&sw);
        log_debug("threadpool_loop: about to wait for 'start' signal");
        
        // Wait for start signal
        pthread_mutex_lock(&tp->mutex)==0 || oops_fatal("pthread_mutex_lock");
        while(!tp->started)
            pthread_cond_wait(&tp->start, &tp->mutex)==0 || oops_fatal("pthread_cond_wait");
        pthread_mutex_unlock(&tp->mutex)==0 || oops_fatal("pthread_mutex_unlock");
        
        log_debug("threadpool_loop: received 'start' signal; encrypting...");
        
        // Run the thread action
        threadpool_task* task = &tp->tasks[thread_i];
        task->action(task->param);
        
        log_debug("threadpool_loop: done encrypting; about to wait for 'finish' barrier");
        // Finish all threads together
        threadpool_barrier_wait(&tp->finish, &tp->started);
        
        log_debug("threadpool_loop: 'finish' barrier completed");
        
        // TODO: Break when shutdown is requested
//        log_info("threadpool_loop took %dus (#%d)", (int)stopwatch_elapsed(&sw), c++);
    }
    
    return 0;
}

void threadpool_init(threadpool* tp) {
    
    if(!tp->tp_init_complete) {
        tp->tp_init_complete = 1;
    } else {
        oops_fatal("attempted to initialialize threadpool twice");
    }
    
    enough_cpus_for_parallel = (sysconf(_SC_NPROCESSORS_ONLN)>=4);
    if(!enough_cpus_for_parallel)
        return;
    
    pthread_mutex_init(&tp->parallel_for_mutex, NULL)==0 || oops_fatal("pthread_mutex_init");
    
    pthread_mutex_init(&tp->mutex, NULL)==0 || oops_fatal("pthread_mutex_init");
    
    pthread_cond_init(&tp->start, NULL)==0 || oops_fatal("pthread_cond_init");
    
    threadpool_barrier_init(&tp->finish, NULL, THREADPOOL_THREAD_COUNT)==0
    || oops_fatal("pthread_barrier_init");
    
    for(int thread_i = 0; thread_i < THREADPOOL_THREAD_COUNT-1; thread_i++) {
        tp->thread_contexts[thread_i].tp = tp;
        tp->thread_contexts[thread_i].thread_i = thread_i;
        pthread_create(&tp->threads[thread_i], NULL, threadpool_loop, (void*)&tp->thread_contexts[thread_i])==0
        || oops_fatal("pthread_create failed");
    }
}

void threadpool_for(threadpool* tp, threadpool_task* tasks) {
    if(!tp->tp_init_complete)
        oops_fatal("threadpool not initialized");
    
    // Take big lock
    pthread_mutex_lock(&tp->parallel_for_mutex)==0 || oops_fatal("pthread_mutex_lock");
    
    // Point the threadpool to (except, we'll do the first task in the current thread)
    tp->tasks = &tasks[1];
    
    // Broadcast start signal
    pthread_mutex_lock(&tp->mutex)==0 || oops_fatal("pthread_mutex_lock");
    log_debug("threadpool_for: about to send 'start' signal");
        tp->started = 1;
        pthread_cond_broadcast(&tp->start)==0 || oops_fatal("pthread_cond_wait");
    log_debug("threadpool_for: sent 'start' signal");
    pthread_mutex_unlock(&tp->mutex)==0 || oops_fatal("pthread_mutex_unlock");
    
    // Run the first task in the current thread
    tasks[0].action(tasks[0].param);
    
    // Wait for all threads to finish
    log_debug("threadpool_for: about to wait for 'finish' barrier");
    int r = threadpool_barrier_wait(&tp->finish, &tp->started);
    if(r<0 || r>1) oops_fatal("barrier_wait");
    log_debug("threadpool_for: 'finish' barrier completed");
    
    // Release big lock
    tp->tasks = 0; // TODO: Debug
    pthread_mutex_unlock(&tp->parallel_for_mutex)==0 || oops_fatal("pthread_mutex_unlock");
}

void threadpool_shutdown(threadpool* tp) {
    for(int i = 0; i<THREADPOOL_THREAD_COUNT-1; i++) {
        // TODO: Gracefully exit each thread
    }
}
