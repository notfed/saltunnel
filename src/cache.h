//
//  cache.h
//  saltunnel
//
//  A hash table which will only keep at most CACHE_NUM_ENTRIES_MAX number of
//  entries at a time. Once this limit is reached, each new entry added will
//  result in the oldest entry being deleted.
//

#ifndef cache_h
#define cache_h

#define CACHE_NUM_BUCKETS 65536
#define CACHE_NUM_ENTRIES_MAX 262144
#define CACHE_KEY_BYTES 16
#define CACHE_VALUE_BYTES 8

typedef struct cache_entry cache_entry;
struct cache_entry {
    unsigned char key[CACHE_KEY_BYTES];
    unsigned char value[CACHE_VALUE_BYTES];
    cache_entry* chain_prev;
    cache_entry* chain_next;
    cache_entry* list_next;
    cache_entry* list_prev;
};

typedef struct cache {
    unsigned int list_size;
    cache_entry* list_head;
    cache_entry* list_tail;
    cache_entry* e[CACHE_NUM_BUCKETS];
} cache;

int cache_insert(cache* table, unsigned char* key, unsigned char* value);
unsigned char* cache_get(cache* table, unsigned char* key);
int cache_delete(cache* table, unsigned char* key);
int cache_clear(cache* table);

#endif /* cache_h */
