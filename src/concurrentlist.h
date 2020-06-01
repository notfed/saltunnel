//
//  concurrentlist.h
//  saltunnel
//
//  A doubly-linked list with lock/unlock functions.
//  You must surround most functions with lock/unlock (except "...init" and "...free")
//

#ifndef concurrentlist_h
#define concurrentlist_h

#include <pthread.h>
#include <stdint.h>

typedef union concurrentlist_val {
    unsigned long long u;
    long long i;
    void* v;
    pthread_t t;
} concurrentlist_val;

typedef struct concurrentlist_snapshot {
    unsigned long len;
    concurrentlist_val vals[];
} concurrentlist_snapshot;

typedef struct concurrentlist_entry {
    struct concurrentlist_entry* prev;
    struct concurrentlist_entry* next;
    concurrentlist_val val;
} concurrentlist_entry;

typedef struct concurrentlist {
    pthread_mutex_t mutex;
    long count;
    concurrentlist_entry* head;
    concurrentlist_entry* tail;
    int initialized;
} concurrentlist;

// Call this function first, before any others, on this struct
int concurrentlist_init(concurrentlist* cl);

// Use to lock this struct
int concurrentlist_lock(concurrentlist* cl, int* old_cancel_type);

// Must call these while the struct is locked
int concurrentlist_add(concurrentlist* cl, concurrentlist_val val, concurrentlist_entry** new_entry_out);
int concurrentlist_remove(concurrentlist* cl, concurrentlist_entry* entry);
int concurrentlist_remove_all(concurrentlist* cl);
long concurrentlist_count(concurrentlist* cl);
concurrentlist_snapshot* concurrentlist_snapshot_create(concurrentlist* cl);

// Use to unlock this struct
int concurrentlist_unlock(concurrentlist* cl, int* old_cancel_type);

// Can be called regardless of whether struct is locked
void concurrentlist_snapshot_free(concurrentlist_snapshot* snapshot);

// Call this function last, after all others, on this struct
int concurrentlist_free(concurrentlist* cl);

#endif /* concurrentlist_h */
