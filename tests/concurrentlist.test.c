//
//  concurrentlist.test.c
//  saltunnel-test
//

#include "concurrentlist.test.h"
#include "concurrentlist.h"
#include "oops.h"

#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#define THREAD_COUNT 1000

typedef struct thread_func_ctx { uint64_t tid; } thread_func_ctx;

concurrentlist cl = {0};

pthread_t threads[THREAD_COUNT] = {0};
thread_func_ctx contexts[THREAD_COUNT] = {0};
concurrentlist_entry* added_entries[THREAD_COUNT] = {0};
int entry_hit_count[THREAD_COUNT] = {0};

void* thread_func(void* v) {
    thread_func_ctx* ctx = v;
    int old_cancel_type;
    concurrentlist_lock(&cl, &old_cancel_type);
    concurrentlist_val val = { .v =  v };
    concurrentlist_add(&cl, val, &added_entries[ctx->tid]);
    concurrentlist_unlock(&cl, &old_cancel_type);
    return 0;
}

int iterate_entries(concurrentlist_val val) {
    thread_func_ctx* ctx = val.v;
    entry_hit_count[ctx->tid]++;
    return 0;
}

#define clear(bs) memset(bs, 0, sizeof(bs));
#define clearlen(bs,len) memset(bs, 0, len);

void concurrentlist_tests() {
    // Arrange: Clear variable for re-use across test runs
    clear(threads);
    clear(contexts);
    clear(added_entries);
    clear(entry_hit_count);
    
    // Arrange: Create a concurrentlist
    concurrentlist_init(&cl);
    for(int i = 0; i < THREAD_COUNT; i++)
        contexts[i].tid = i;
    
    // Arrange: Create 1000 threads, each which adds a unique [0..1000] value to the list
    for(int i = 0; i < THREAD_COUNT; i++)
        assert(pthread_create(&threads[i], NULL, thread_func, &contexts[i])==0);

    // Arrange: Wait for all threads to complete
    for(int i = 0; i < THREAD_COUNT; i++)
        assert(pthread_join(threads[i], NULL)==0);

    // Arrange: Count how many of each unique value were in the list
    int old_cancel_type;
    concurrentlist_lock(&cl, &old_cancel_type);
    concurrentlist_snapshot* snapshot = concurrentlist_snapshot_create(&cl);
    concurrentlist_unlock(&cl, &old_cancel_type);
    for(int i = 0; i < snapshot->len; i++) {
        iterate_entries(snapshot->vals[i]);
    }
    concurrentlist_snapshot_free(snapshot);
    
    // Assert: Ensure we found 1 of each 1000 possible values
    concurrentlist_lock(&cl, &old_cancel_type);
    assert(concurrentlist_count(&cl)==THREAD_COUNT);
    concurrentlist_unlock(&cl, &old_cancel_type);
    for(int i = 0; i < THREAD_COUNT; i++)
        assert(entry_hit_count[i]==1);

    // Clean Up: free the list
    assert(concurrentlist_free(&cl)>=0);
    
               
}
