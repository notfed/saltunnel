//
//  threadpool.h
//  saltunnel2
//

#ifndef threadpool_h
#define threadpool_h

#define THREADPOOL_THREAD_COUNT 4

#include "pthread_barrier.h"
#include <pthread.h>

struct threadpool;

typedef struct threadpool_task {
    void (*action)(void*);
    void* param;
} threadpool_task;

typedef struct threadpool_thread_context {
    int thread_i;
} threadpool_thread_context;

typedef struct threadpool {
    pthread_mutex_t parallel_for_mutex;
    
    int tp_init_complete;
    
    pthread_t threads[THREADPOOL_THREAD_COUNT];
    threadpool_thread_context thread_contexts[THREADPOOL_THREAD_COUNT];
    threadpool_task* tasks;
    
    pthread_mutex_t mutex;
    int started;              // Protected by mutex
    pthread_cond_t start;     // Protected by mutex
    int finished;             // Protected by mutex
    pthread_barrier_t finish; // Protected by mutex
    
} threadpool;

void threadpool_init(void);
void threadpool_for(threadpool_task* task);
void threadpool_shutdown(void);

#endif /* threadpool_h */
