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
    pthread_cond_t cond;
    int count;
    int tripCount;
} pthread_barrier_t;

#endif /* pthread_barrier_h */
#endif // __APPLE__
