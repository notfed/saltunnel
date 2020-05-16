//
//  threadpool.h
//  saltunnel2
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

//void threadpool_for(threadpool* tp, threadpool_task* task);
void threadpool_for(int threadpool_index, threadpool_task* task);

extern threadpool tp[2];

#endif /* threadpool_h */
