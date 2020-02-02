//
//  pthread_barrier.h
//  saltunnel2
//
#ifdef __APPLE__

#ifndef pthread_barrier_h
#define pthread_barrier_h

#include <pthread.h>
#include <errno.h>

typedef int pthread_barrierattr_t;
typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t count_was_reset;
    int count;
    int num_threads;
} pthread_barrier_t;

int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int num_threads);
int pthread_barrier_wait(pthread_barrier_t *barrier, int* started);

#endif /* pthread_barrier_h */
#endif // __APPLE__
