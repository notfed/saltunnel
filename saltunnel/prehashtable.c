//
//  prehashtable.c
//  saltunnel
//

#include "prehashtable.h"

void* prehashtable_get(prehashtable table, uint32_t key) {
    for(prehashtable_entry* maybe_entry = &table[key%PREHASHTABLE_NUM_ENTRIES];
        maybe_entry != NULL;
        maybe_entry = maybe_entry->chain)
    {
        if(maybe_entry->key == key)
            return maybe_entry->value;
    }
    return NULL;
}

int prehashtable_set(prehashtable table, uint32_t key, void* value) {
    for(prehashtable_entry* maybe_entry = &table[key%PREHASHTABLE_NUM_ENTRIES];
        maybe_entry != NULL;
        maybe_entry = maybe_entry->chain)
    {
        if(maybe_entry->key == key) {
            // ALLOCATE AND RETURN
            return 1;
        }
    }
    return -1;
}

int prehashtable_delete(prehashtable table, uint32_t key) {
    for(prehashtable_entry* maybe_entry = &table[key%PREHASHTABLE_NUM_ENTRIES];
        maybe_entry != NULL;
        maybe_entry = maybe_entry->chain)
    {
        if(maybe_entry->key == key) {
            // DEALLOCATE AND RETURN
            return 1 ;
        }
    }
    return -1;
}

