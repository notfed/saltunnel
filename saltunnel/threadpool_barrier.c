//
//  threadpool_barrier.c
//  saltunnel2
//

#include "threadpool_barrier.h"
#include "oops.h"

int threadpool_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int num_threads)
{
    if(num_threads <= 0) oops_fatal("assertion failed");
    
    try(pthread_mutex_init(&barrier->mutex, 0)) || oops_fatal("pthread_mutex_init");
    try(pthread_cond_init(&barrier->phase_changed, 0)) || oops_fatal("pthread_cond_init");
    
    barrier->num_threads = num_threads;
    barrier->count = 0;
    barrier->phase = 0;

    return 0;
}

int threadpool_barrier_destroy(pthread_barrier_t *barrier)
{
    try(pthread_cond_destroy(&barrier->phase_changed)) || oops_fatal("pthread_cond_init");
    try(pthread_mutex_destroy(&barrier->mutex)) || oops_fatal("pthread_cond_init");
    return 0;
}

int threadpool_barrier_wait(pthread_barrier_t *barrier, int* started)
{
    pthread_mutex_lock(&barrier->mutex);
    if(*started==0) oops_fatal("assertion failed");
    barrier->count++;
    if(barrier->count > barrier->num_threads) oops_fatal("assertion failed");
    if(barrier->count == barrier->num_threads)
    {
        barrier->phase++;
        barrier->count = 0;
        *started = 0;
        pthread_cond_broadcast(&barrier->phase_changed);
        pthread_mutex_unlock(&barrier->mutex);
        return 1;
    }
    else
    {
        // Wait until phase changes
        unsigned long prev_phase = barrier->phase;
        do {
          pthread_cond_wait(&barrier->phase_changed, &barrier->mutex);
        } while(prev_phase == barrier->phase);
        pthread_mutex_unlock(&barrier->mutex);
        return 0;
    }
}