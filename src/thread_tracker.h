//
//  thread_tracker.h
//  saltunnel
//
//  Concurrently register new threads, or join/cancel previously-registered threads.
//

#ifndef thread_tracker_h
#define thread_tracker_h

#include "concurrentlist.h"

#include <pthread.h>

typedef struct thread_tracker {
    unsigned long unjoined_thread_count;
    concurrentlist* active_thread_list;
    concurrentlist* joinable_thread_list;
} thread_tracker;

concurrentlist_entry* thread_tracker_add_new_thread(thread_tracker* tracker, pthread_t thread);
void thread_tracker_join_with_joinable_threads(thread_tracker* tracker);
void thread_tracker_cleanup_free_threads(void* v) ;

#endif /* thread_tracker_h */
