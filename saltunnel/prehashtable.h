//
//  prehashtable.h
//  saltunnel
//

#ifndef prehashtable_h
#define prehashtable_h

#include <stdint.h>

#define PREHASHTABLE_NUM_ENTRIES 65536

typedef struct prehashtable_entry prehashtable_entry;
struct prehashtable_entry {
    uint32_t key;
    void* value;
    prehashtable_entry* chain;
};

typedef prehashtable_entry prehashtable[PREHASHTABLE_NUM_ENTRIES];

void* prehashtable_get(prehashtable table, uint32_t key);
int prehashtable_delete(prehashtable table, uint32_t key);
int prehashtable_set(prehashtable table, uint32_t key, void* value);

#endif /* prehashtable_h */
