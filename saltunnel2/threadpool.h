//
//  threadpool.h
//  saltunnel2
//

#ifndef threadpool_h
#define threadpool_h

#define THREADPOOL_THREAD_COUNT 8

#include "pthread_barrier.h"
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
    
    pthread_t threads[THREADPOOL_THREAD_COUNT];
    threadpool_thread_context thread_contexts[THREADPOOL_THREAD_COUNT];
    threadpool_task tasks[THREADPOOL_THREAD_COUNT];
    
    pthread_mutex_t mutex;
    int started;              // Protected by mutex
    pthread_cond_t start;     // Protected by mutex
    int finished;             // Protected by mutex
    pthread_barrier_t finish; // Protected by mutex
    
} threadpool;


void threadpool_init(threadpool* tp, int threads);
void threadpool_for(threadpool *tp);
void threadpool_shutdown(threadpool *tp);

#endif /* threadpool_h */
