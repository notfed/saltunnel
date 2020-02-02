//
//  pthread_barrier.c
//  saltunnel2
//

#include "pthread_barrier.h"
#include "oops.h"

int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int num_threads)
{
    if(num_threads <= 0)
    {
        errno = EINVAL;
        return -1;
    }
    
    try(pthread_mutex_init(&barrier->mutex, 0)) || oops_fatal("pthread_mutex_init");
    try(pthread_cond_init(&barrier->count_was_reset, 0)) || oops_fatal("pthread_cond_init");
    
    barrier->num_threads = num_threads;
    barrier->count = 0;

    return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
    pthread_cond_destroy(&barrier->count_was_reset);
    pthread_mutex_destroy(&barrier->mutex);
    return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier, int* started)
{
    pthread_mutex_lock(&barrier->mutex);
    if(*started==0) oops_fatal("assertion failed");
    barrier->count++;
    if(barrier->count > barrier->num_threads) oops_fatal("assertion failed");
    if(barrier->count == barrier->num_threads)
    {
        barrier->count = 0;
        *started = 0;
        pthread_cond_broadcast(&barrier->count_was_reset);
        pthread_mutex_unlock(&barrier->mutex);
        return 1;
    }
    else
    {
        // Wait until count is zero
        while(barrier->count>0) {
          pthread_cond_wait(&barrier->count_was_reset, &barrier->mutex);
          if(barrier->count>0) log_info("!!!!!! THIS IS BAD");
        }
        pthread_mutex_unlock(&barrier->mutex);
        return 0;
    }
}
