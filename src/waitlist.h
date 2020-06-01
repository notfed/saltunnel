//
//  waitlist.h
//  saltunnel
//
//  A linked-list which keeps track of *when* items were added, how long until
//  they *expire*, and offers a "cancel_expired" function which runs a
//  caller-defined cancellation function against each expired item. 
//

#ifndef waitlist_h
#define waitlist_h

#include <stdint.h>

typedef union waitlist_value {
    int i;
    void *v;
} waitlist_value;

typedef struct waitlist_item {
    int64_t expire_at_ms;
    struct waitlist_item* next;
    waitlist_value val;
} waitlist_item;

typedef struct waitlist {
    uint64_t max_age_ms;
    uint64_t max_items;
    uint64_t cur_items;
    waitlist_item* waitlist_head;
    waitlist_item* waitlist_tail;
} waitlist;

waitlist_item* waitlist_add(waitlist* list, waitlist_value fd);
void waitlist_remove(waitlist_item* i);
void waitlist_remove_all(waitlist* list);
int waitlist_cancel_expired(waitlist* list, int (*cancel_func)(waitlist_value,void*), void* cancel_func_arg2);
int waitlist_cancel_all(waitlist* list, int (*cancel_func)(waitlist_value,void*), void* cancel_func_arg2);
int waitlist_ms_until_next_expiration(waitlist* list);

#endif /* waitlist_h */
