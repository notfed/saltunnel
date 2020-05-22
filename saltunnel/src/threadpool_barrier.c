//
//  threadpool_barrier.c
//  saltunnel
//

#include "threadpool_barrier.h"
#include "oops.h"

#include <pthread.h>

int threadpool_barrier_init(threadpool_barrier_t *barrier, const threadpool_barrierattr_t *attr, unsigned int num_threads)
{
    if(num_threads <= 0) oops_error("assertion failed: negative thread count");
    
    pthread_mutex_init(&barrier->mutex, 0)==0 || oops_error_sys("failed to initialize thread mutex");
    pthread_cond_init(&barrier->phase_changed, 0)==0 || oops_error_sys("failed to initialize thread condition");
    
    barrier->num_threads = num_threads;
    barrier->count = 0;
    barrier->phase = 0;

    return 0;
}

int threadpool_barrier_destroy(threadpool_barrier_t *barrier)
{
    pthread_cond_destroy(&barrier->phase_changed)==0 || oops_error_sys("failed to destroy thread condition");
    pthread_mutex_destroy(&barrier->mutex)==0 || oops_error_sys("failed to destroy thread mutex");
    return 0;
}

int threadpool_barrier_wait(threadpool_barrier_t *barrier, int* started)
{
    pthread_mutex_lock(&barrier->mutex)==0 || oops_error_sys("failed to lock thread mutex");
    if(*started==0) 
        oops_error("assertion failed: thread barrier was in an invalid state");
    barrier->count++;
    if(barrier->count > barrier->num_threads) 
        oops_error("assertion failed: thread barrier was in an invalid state");
    if(barrier->count == barrier->num_threads)
    {
        barrier->phase++;
        barrier->count = 0;
        *started = 0;
        pthread_cond_broadcast(&barrier->phase_changed)==0 || oops_error_sys("failed to broadcast thread condition");
        pthread_mutex_unlock(&barrier->mutex)==0 || oops_error_sys("failed to unlock thread mutex");
        return 1;
    }
    else
    {
        // Wait until phase changes
        unsigned long prev_phase = barrier->phase;
        do {
          pthread_cond_wait(&barrier->phase_changed, &barrier->mutex)==0 || oops_error_sys("failed to wait for thread condition");
        } while(prev_phase == barrier->phase);
        pthread_mutex_unlock(&barrier->mutex)==0 || oops_error_sys("failed to unlock thread mutex");
        return 0;
    }
}
