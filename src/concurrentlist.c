//
//  concurrentlist.c
//  saltunnel
//

#include "concurrentlist.h"
#include "oops.h"

#include <pthread.h>
#include <stdlib.h>
#include <assert.h>

int concurrentlist_init(concurrentlist* cl) {
    assert(cl->initialized==0);
    cl->count = 0;
    cl->head = 0;
    cl->tail = 0;
    if(pthread_mutex_init(&cl->mutex, 0)!=0)
        oops_error_sys("failed to initialize thread mutex");
    cl->initialized = 1;
    return 0;
}

int concurrentlist_lock(concurrentlist* cl, int* old_cancel_type) {
    assert(cl->initialized==1);
    if(old_cancel_type)
        assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, old_cancel_type)==0);
    if(pthread_mutex_lock(&cl->mutex)!=0)
        oops_error_sys("failed to lock thread mutex");
    return 0;
}

int concurrentlist_unlock(concurrentlist* cl, int* old_cancel_type) {
    assert(cl->initialized==1);
    if(pthread_mutex_unlock(&cl->mutex)!=0)
        oops_error_sys("failed to unlock thread mutex");
    if(old_cancel_type)
        assert(pthread_setcancelstate(*old_cancel_type, 0)==0);
    return 0;
}

int concurrentlist_add(concurrentlist* cl, concurrentlist_val val, concurrentlist_entry** new_entry_out) {
    assert(cl!=0);
    assert(cl->initialized==1);

    int rc = 1;
    
    concurrentlist_entry* new_entry = (concurrentlist_entry*)malloc(sizeof(concurrentlist_entry));
    if(new_entry==0) {
        oops_sys("failed to allocate memory");
    } else {
        concurrentlist_entry* old_tail = cl->tail;
        if(cl->head) old_tail->next = new_entry;
        else         cl->head = new_entry;
        new_entry->prev = old_tail;
        new_entry->next = NULL;
        new_entry->val = val;
        if(!cl->head) cl->head = new_entry;
        cl->tail = new_entry;
        cl->count++;
        if(new_entry_out)
            *new_entry_out = new_entry;
    }

    return rc;
}

int concurrentlist_remove(concurrentlist* cl, concurrentlist_entry* entry) {
    assert(cl!=0);
    assert(cl->initialized==1);
    assert(entry!=0);

    cl->count--;
    if(entry->prev) entry->prev->next = entry->next;
    if(entry->next) entry->next->prev = entry->prev;
    if(cl->head==entry) cl->head = entry->next;
    if(cl->tail==entry) cl->tail = NULL; 
    free(entry);
    
    return 1;
}

long concurrentlist_count(concurrentlist* cl) {
    assert(cl!=0);
    assert(cl->initialized==1);

    return cl->count;
}

concurrentlist_snapshot* concurrentlist_snapshot_create(concurrentlist* cl) {
    assert(cl!=0);
    assert(cl->initialized==1);
    
    unsigned long valcount = cl->count;
    concurrentlist_snapshot* snapshot = malloc(sizeof(unsigned long)+sizeof(concurrentlist_val)*(valcount));
    if(snapshot==0) { return 0; }
    snapshot->len = valcount;
    unsigned long i = 0;
    for(concurrentlist_entry* entry = cl->head; entry!=NULL; entry=entry->next) {
        snapshot->vals[i] = entry->val;
        i++;
    }
    return snapshot;
}

void concurrentlist_snapshot_free(concurrentlist_snapshot* snapshot) {
    free(snapshot);
}

int concurrentlist_remove_all(concurrentlist* cl) {
    assert(cl!=0);
    assert(cl->initialized==1);

    while(cl->count>0)
        concurrentlist_remove(cl, cl->head);
    
    return 0;
}

int concurrentlist_free(concurrentlist* cl) {
    int rc = 0;
    assert(cl!=0);
    assert(cl->initialized==1);
    
    if(pthread_mutex_lock(&cl->mutex)!=0)
        oops_error_sys("failed to lock thread mutex");
    
    concurrentlist_remove_all(cl);
    cl->initialized = 0;
    
    if(pthread_mutex_unlock(&cl->mutex)!=0)
        oops_error_sys("failed to unlock thread mutex");
    
    if(pthread_mutex_destroy(&cl->mutex)!=0)
        oops_error_sys("failed to destroy thread mutex");
    
    return rc;
}
