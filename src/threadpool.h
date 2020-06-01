//
//  threadpool.h
//  saltunnel
//
//  A parallel task executor which retains a pool of threads. Give it a list of
//  tasks and it will use its thread pool to execute the the specified tasks.
//

#ifndef threadpool_h
#define threadpool_h

#include "config.h"
#include "threadpool_barrier.h"
#include <pthread.h>

struct threadpool;

typedef struct threadpool_task {
    void (*action)(void*);
    void* param;
} threadpool_task;

typedef struct threadpool_thread_context {
    struct threadpool* tp;
    int thread_i;
} threadpool_thread_context;

typedef struct threadpool {
    pthread_mutex_t parallel_for_mutex;
    
    int tp_init_complete;
    
    pthread_t threads[THREADPOOL_THREAD_COUNT-1];
    threadpool_thread_context thread_contexts[THREADPOOL_THREAD_COUNT-1];
    threadpool_task* tasks;
    
    pthread_mutex_t mutex;
    int started;              // Protected by mutex
    pthread_cond_t start;     // Protected by mutex
    threadpool_barrier_t finish; // Protected by mutex
    
} threadpool;

int threadpool_enough_cpus_for_parallel(void);

void threadpool_init(threadpool* tp);
void threadpool_shutdown(threadpool* tp);

void threadpool_init_all(void);
void threadpool_shutdown_all(void);

void threadpool_for(threadpool*, threadpool_task* task);

threadpool* threadpool_get_pool(int threadpool_index);
extern threadpool tps[2];

#endif /* threadpool_h */
