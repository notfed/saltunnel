//
//  threadpool.h
//  saltunnel2
//

#ifndef threadpool_h
#define threadpool_h

#define THREAD_COUNT 8

#include "pthread_barrier.h"
#include <pthread.h>

typedef struct thread_context {
    void (*action)(void*);
    void* context;
} thread_context;

typedef struct threadpool {
    
    pthread_t threads[THREAD_COUNT];
    thread_context thread_contexts[THREAD_COUNT];
    
    pthread_mutex_t mutex;
    pthread_cond_t start;  // Protected by mutex
    pthread_barrier_t finish; // Protected by mutex
    
} threadpool;

#endif /* threadpool_h */
