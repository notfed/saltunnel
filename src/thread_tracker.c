#include "thread_tracker.h"
#include "concurrentlist.h"
#include "oops.h"

#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <pthread.h>

concurrentlist_entry* thread_tracker_add_new_thread(thread_tracker* tracker, pthread_t thread) {
    tracker->unjoined_thread_count++;
    concurrentlist_entry* e;
    concurrentlist_val val = { .t=thread };
    concurrentlist_add(tracker->active_thread_list, val, &e);
    return e;
}

static int cancel_child_thread(concurrentlist_val val) {
    pthread_t thread = (pthread_t)val.t;
    assert(thread!=0);
    assert(pthread_cancel(thread)==0);
    return 0;
}

static int join_child_thread(concurrentlist_val val) {
    pthread_t thread = (pthread_t)val.t;
    assert(thread!=0);
    int rc = pthread_join(thread, NULL);
    if(rc!=0) { log_error("(client forwarder) pthread_join failed: to join thread: %s", strerror(rc)); return -1; }
    return 0;
}

void thread_tracker_join_with_joinable_threads(thread_tracker* tracker) {

    concurrentlist* joinable_thread_list = tracker->joinable_thread_list;
    // Join with (a snapshot of) all joinable threads. Repeat until we've joined exactly 'unjoined_thread_count' threads.
    while(tracker->unjoined_thread_count>0) {
        int old_cancel_type;
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_type);
        concurrentlist_lock(joinable_thread_list, 0);
        concurrentlist_snapshot* snapshot_joinable = concurrentlist_snapshot_create(joinable_thread_list);
        concurrentlist_remove_all(joinable_thread_list);
        concurrentlist_unlock(joinable_thread_list, 0);
        for(int i = 0; i<snapshot_joinable->len; i++) {
            join_child_thread(snapshot_joinable->vals[i]);
            tracker->unjoined_thread_count--;
        }
        concurrentlist_snapshot_free(snapshot_joinable);
        pthread_setcancelstate(old_cancel_type, 0);
        if(tracker->unjoined_thread_count>0) usleep(50000);
    }
}

void thread_tracker_cleanup_free_threads(void* v) {
    thread_tracker* tracker = v;
    concurrentlist* active_thread_list = tracker->active_thread_list;
    concurrentlist* joinable_thread_list = tracker->joinable_thread_list;

    assert(active_thread_list!=0);
    assert(active_thread_list->initialized==1);
    assert(joinable_thread_list!=0);
    assert(joinable_thread_list->initialized==1);

    // Cancel all active threads
    concurrentlist_lock(active_thread_list, 0);
    concurrentlist_snapshot* snapshot_active = concurrentlist_snapshot_create(active_thread_list);
    for(int i = 0; i<snapshot_active->len; i++)
        cancel_child_thread(snapshot_active->vals[i]);
    concurrentlist_snapshot_free(snapshot_active);
    concurrentlist_unlock(active_thread_list, 0);

    // Join with all joinable threads
    thread_tracker_join_with_joinable_threads(tracker);

    // Free the concurrent lists
    assert(active_thread_list->count==0);
    assert(joinable_thread_list->count==0);
    concurrentlist_free(active_thread_list);
    concurrentlist_free(joinable_thread_list);

}
