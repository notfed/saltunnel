//
//  waitlist.test.c
//  saltunnel
//

#include "oops.h"
#include "waitlist.h"
#include "waitlist.test.h"

#include <assert.h>

void waitlist_can_add_and_purge_all() {
    waitlist w = { w.max_age_ms = 99999, w.max_items = 1000 };
    // Verify empty
    assert(w.waitlist_head==0);
    assert(w.waitlist_tail==0);
    assert(w.cur_items==0);
    // Add 0
    waitlist_value val = { .i = 0 };
    assert(waitlist_add(&w, val)!=0);
    // Verify
    assert(w.waitlist_head!=0);
    assert(w.waitlist_tail!=0);
    assert(w.waitlist_head->val.i==0);
    assert(w.waitlist_tail->val.i==0);
    assert(w.cur_items==1);
    // Add 1..999
    for(int i = 1; i < 1000; i++) {
        waitlist_value val2 = { .i = i };
        assert(waitlist_add(&w, val2)!=0);
    }
    // Verify
    assert(w.waitlist_head!=0);
    assert(w.waitlist_tail!=0);
    assert(w.cur_items==1000);
    assert(w.waitlist_head->val.i==0);
    assert(w.waitlist_tail->val.i==999);
    waitlist_item* item = w.waitlist_head;
    for(int i = 0; i < 1000; i++) {
        assert(item->val.i==i);
        item = item->next;
    }
    // Try to add another; should fail
    waitlist_value val3 = { .i = 1000 };
    assert(waitlist_add(&w, val3)==0);
    // Purge all
    waitlist_remove_all(&w);
    // Verify
    assert(w.waitlist_head==0);
    assert(w.waitlist_tail==0);
    assert(w.cur_items==0);
    // Clean up
    waitlist_remove_all(&w);
}

char did_purge[10] = {0};

typedef struct purge_context {
    int dummy;
} purge_context;

purge_context the_purge_context;

int the_purge_action(waitlist_value val, void* contextv) {
    int fd = val.i;
    purge_context* context = (purge_context*)contextv;
    assert(context==&the_purge_context);
    did_purge[fd] = 1;
    return 0;
}

void waitlist_can_purge_old_entries() {
    waitlist w = { w.max_age_ms = 5, w.max_items = 99999 };
    // Add ms=0..9
    for(int i = 0; i < 10; i++) {
        waitlist_set_now_ms(i);
        waitlist_value val = { .i = i };
        assert(waitlist_add(&w, val)!=0);
    }
    assert(w.cur_items==10);
    // Set time to 9
    waitlist_set_now_ms(9);
    // Do the purge (should purge 0...4)
    assert(waitlist_cancel_expired(&w, the_purge_action, &the_purge_context)==0);
    // Verify that we purged 0...4, and kept 5...9
    assert(w.cur_items==5);
    for(int i = 0; i < 5; i++)
        assert(did_purge[i]==1);
    for(int i = 5; i < 10; i++)
        assert(did_purge[i]==0);
    // Verify actual items in list
    assert(w.waitlist_head->val.i==5);
    assert(w.waitlist_tail->val.i==9);
    waitlist_item* item = w.waitlist_head;
    for(int i = 5; i < 10; i++) {
        assert(item->val.i==i);
        item = item->next;
    }
    assert(item==0);
    // Reset waitlist time
    waitlist_set_now_ms(-1);
    // Clean up
    waitlist_remove_all(&w);
}

void waitlist_tests() {
    waitlist_can_add_and_purge_all();
    waitlist_can_purge_old_entries();
}
    
