//
//  threadpool_barrier.h
//  saltunnel2
//
#ifndef pthread_barrier_h
#define pthread_barrier_h

#include <pthread.h>
#include <errno.h>

typedef int threadpool_barrierattr_t;
typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t phase_changed;
    unsigned long count;
    unsigned long num_threads;
    unsigned long phase;
} threadpool_barrier_t;

int threadpool_barrier_destroy(threadpool_barrier_t *barrier);
int threadpool_barrier_init(threadpool_barrier_t *barrier, const threadpool_barrierattr_t *attr, unsigned int num_threads);
int threadpool_barrier_wait(threadpool_barrier_t *barrier, int* started);

#endif /* pthread_barrier_h */
