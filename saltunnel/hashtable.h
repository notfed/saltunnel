//
//  hashtable.h
//  saltunnel
//
//  This hash table implementation ...
//

#ifndef hashtable_h
#define hashtable_h

#define HASHTABLE_NUM_BUCKETS 65536
#define HASHTABLE_NUM_ENTRIES_MAX 262144
#define HASHTABLE_KEY_BYTES 16
#define HASHTABLE_VALUE_BYTES 8

typedef struct hashtable_entry hashtable_entry;
struct hashtable_entry {
    unsigned char key[HASHTABLE_KEY_BYTES];
    unsigned char value[HASHTABLE_VALUE_BYTES];
    hashtable_entry* chain_prev;
    hashtable_entry* chain_next;
    hashtable_entry* list_next;
    hashtable_entry* list_prev;
};

typedef struct hashtable {
    unsigned int list_size;
    hashtable_entry* list_head;
    hashtable_entry* list_tail;
    hashtable_entry* e[HASHTABLE_NUM_BUCKETS];
} hashtable;

int hashtable_insert(hashtable* table, unsigned char* key, unsigned char* value);
unsigned char* hashtable_get(hashtable* table, unsigned char* key);
int hashtable_delete(hashtable* table, unsigned char* key);

#endif /* hashtable_h */
