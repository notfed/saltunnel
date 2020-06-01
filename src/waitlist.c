//
//  waitlist.c
//  saltunnel
//

#include "waitlist.h"
#include "oops.h"

#include <stdlib.h>
#include <time.h>

static int64_t alternate_now_ms_used_for_testing = -1;
void waitlist_set_now_ms(int64_t now_ms) {
    alternate_now_ms_used_for_testing = now_ms;
}

static int64_t get_now_ms() {
    if(alternate_now_ms_used_for_testing>=0)
        return alternate_now_ms_used_for_testing;
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC, &now)<0) oops_error_sys("failed to get time");
    int64_t now_ms = (now.tv_sec*1000 + now.tv_nsec/1000000);
    return now_ms;
}

waitlist_item* waitlist_add(waitlist* list, waitlist_value val) {
    // Check item count
    if(list->cur_items >= list->max_items)
    { errno=EUSERS; return NULL; }
    list->cur_items++;
    // Calculate deadline_ms
    int64_t now_ms = get_now_ms();
    int64_t deadline_ms = now_ms + list->max_age_ms;
    // Create a new item
    waitlist_item* i = (waitlist_item*)malloc(sizeof(waitlist_item));
    if(i<0) return NULL;
    i->expire_at_ms = deadline_ms;
    i->next = NULL;
    i->val = val;
    // Add it to the list
    if(list->waitlist_head==NULL) {
        list->waitlist_head = i;
        list->waitlist_tail = i;
    } else {
        list->waitlist_tail->next = i;
        list->waitlist_tail = i;
    }
    return i;
}

// Soft-remove the item from the list
void waitlist_remove(waitlist_item* i) {
    i->expire_at_ms = -1;
}

void waitlist_remove_all(waitlist* list) {
    waitlist_item* cur = list->waitlist_head;
    waitlist_item* next;
    while(cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }
    list->waitlist_head = 0;
    list->waitlist_tail = 0;
    list->cur_items = 0;
}

int waitlist_ms_until_next_expiration(waitlist* list) {
    int64_t now_ms = get_now_ms();
    return (int)(list->waitlist_head
    ? (list->waitlist_head->expire_at_ms <= now_ms ? 0 : (list->waitlist_head->expire_at_ms - now_ms))+1
    : -1);
}

// Keep closing the head items as long as (1) they've already been manually removed, or
//                                        (2) they expire at a time less than the "than_ms" timestamp
static int waitlist_cancel_less_than(waitlist* list, int (*cancel_func)(waitlist_value,void*), void* cancel_func_arg2, int64_t than_ms) {
    for(;;) {
        waitlist_item* head = list->waitlist_head;
        if(head==NULL) break;
        int head_was_already_removed = head->expire_at_ms==-1;
        int head_is_overdue = !head_was_already_removed && head->expire_at_ms <= than_ms;
        if(head_was_already_removed || head_is_overdue) {
            if(head_is_overdue) {
                if(cancel_func(head->val,cancel_func_arg2)<0)
                    return -1;
            }
            list->waitlist_head = head->next;
            free(head);
            list->cur_items--;
        } else {
            break;
        }
    }
    // If head is now gone, also remove tail
    if(list->waitlist_head == NULL) {
        list->waitlist_tail = NULL;
    }
    return 0;
}

int waitlist_cancel_expired(waitlist* list, int (*cancel_func)(waitlist_value,void*), void* cancel_func_arg2) {
    return waitlist_cancel_less_than(list, cancel_func, cancel_func_arg2, get_now_ms());
}

int waitlist_cancel_all(waitlist* list, int (*cancel_func)(waitlist_value,void*), void* cancel_func_arg2) {
    return waitlist_cancel_less_than(list, cancel_func, cancel_func_arg2, INT64_MAX);
}
